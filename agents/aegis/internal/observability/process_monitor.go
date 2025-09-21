package observability

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"agents/aegis/internal/telemetry"
)

// ProcessMonitor manages process tracking and monitoring
type ProcessMonitor struct {
	collection    *ebpf.Collection
	links         []link.Link
	eventHandler  *ProcessEventHandler
	auditLogger   *telemetry.AuditLogger
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.RWMutex
	running       bool
}

// ProcessInfo represents process information from eBPF
type ProcessInfo struct {
	PID               uint32
	PPID              uint32
	TGID              uint32
	UID               uint32
	GID               uint32
	Comm              [16]byte
	ExePath           [256]byte
	StartTime         uint64
	LastSeen          uint64
	NamespaceID       uint32
	MountNamespace    uint32
	NetNamespace      uint32
	PIDNamespace      uint32
	UserNamespace     uint32
	UTSNamespace      uint32
	IPCNamespace      uint32
	CgroupNamespace   uint32
	Capabilities      uint32
	SessionID         uint32
	Flags             uint32
}

// ProcessNetworkConn represents a process network connection
type ProcessNetworkConn struct {
	ProcessID    uint32
	SocketFD     uint32
	SrcIP        uint32
	DstIP        uint32
	SrcPort      uint16
	DstPort      uint16
	Protocol     uint8
	State        uint8
	BytesSent    uint64
	BytesRecv    uint64
	PacketsSent  uint64
	PacketsRecv  uint64
	StartTime    uint64
	LastActivity uint64
	SocketType   uint32
	SocketFamily uint32
	ProcessName  [16]byte
}

// ProcessFileAccess represents file access by a process
type ProcessFileAccess struct {
	ProcessID   uint32
	FileFD      uint32
	FileInode   uint32
	FileDev     uint32
	AccessMode  uint32
	OpenFlags   uint32
	FilePath    [256]byte
	ProcessName [16]byte
	Timestamp   uint64
	FileSize    uint64
	FileMode    uint32
	FileUID     uint32
	FileGID     uint32
}

// ProcessSyscall represents a system call by a process
type ProcessSyscall struct {
	ProcessID   uint32
	SyscallNr   uint32
	SyscallArgs [6]uint64
	ReturnValue uint64
	Timestamp   uint64
	ProcessName [16]byte
	UID         uint32
	GID         uint32
	NamespaceID uint32
	Success     uint8
}

// ProcessExecution represents process execution information
type ProcessExecution struct {
	ProcessID      uint32
	ParentPID      uint32
	ExecutablePath [256]byte
	CommandLine    [512]byte
	ProcessName    [16]byte
	StartTime      uint64
	EndTime        uint64
	UID            uint32
	GID            uint32
	NamespaceID    uint32
	ExitCode       uint32
	Success        uint8
}

// ProcessEventHandler handles process events from eBPF
type ProcessEventHandler struct {
	processMonitor *ProcessMonitor
	eventChan      chan interface{}
	auditLogger    *telemetry.AuditLogger
}

// NewProcessMonitor creates a new process monitor
func NewProcessMonitor(auditLogger *telemetry.AuditLogger) (*ProcessMonitor, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memory limit: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pm := &ProcessMonitor{
		auditLogger: auditLogger,
		ctx:         ctx,
		cancel:      cancel,
	}
	
	// Initialize event handler
	pm.eventHandler = &ProcessEventHandler{
		processMonitor: pm,
		eventChan:      make(chan interface{}, 1000),
		auditLogger:    auditLogger,
	}
	
	// Load eBPF collection
	if err := pm.loadEBPFCollection(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load eBPF collection: %w", err)
	}
	
	// Attach tracepoints
	if err := pm.attachTracepoints(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to attach tracepoints: %w", err)
	}
	
	// Start event processing
	go pm.eventHandler.processEvents()
	
	log.Printf("[process_monitor] Process monitor initialized successfully")
	return pm, nil
}

// loadEBPFCollection loads the eBPF collection
func (pm *ProcessMonitor) loadEBPFCollection() error {
	// Load the eBPF object file
	spec, err := ebpf.LoadCollectionSpec("/opt/aegis/ebpf/aegis_process_tracker.o")
	if err != nil {
		return fmt.Errorf("failed to load eBPF collection spec: %w", err)
	}
	
	// Create collection
	pm.collection, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create eBPF collection: %w", err)
	}
	
	log.Printf("[process_monitor] Loaded eBPF collection successfully")
	return nil
}

// attachTracepoints attaches tracepoints to the eBPF program
func (pm *ProcessMonitor) attachTracepoints() error {
	// Attach to process execution tracepoint
	execLink, err := link.Tracepoint("sched", "sched_process_exec", pm.collection.Programs["trace_process_exec"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach to sched_process_exec: %w", err)
	}
	pm.links = append(pm.links, execLink)
	
	// Attach to process exit tracepoint
	exitLink, err := link.Tracepoint("sched", "sched_process_exit", pm.collection.Programs["trace_process_exit"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach to sched_process_exit: %w", err)
	}
	pm.links = append(pm.links, exitLink)
	
	// Attach to socket creation tracepoint
	socketEnterLink, err := link.Tracepoint("syscalls", "sys_enter_socket", pm.collection.Programs["trace_socket_enter"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach to sys_enter_socket: %w", err)
	}
	pm.links = append(pm.links, socketEnterLink)
	
	socketExitLink, err := link.Tracepoint("syscalls", "sys_exit_socket", pm.collection.Programs["trace_socket_exit"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach to sys_exit_socket: %w", err)
	}
	pm.links = append(pm.links, socketExitLink)
	
	// Attach to connect tracepoint
	connectEnterLink, err := link.Tracepoint("syscalls", "sys_enter_connect", pm.collection.Programs["trace_connect_enter"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach to sys_enter_connect: %w", err)
	}
	pm.links = append(pm.links, connectEnterLink)
	
	// Attach to file open tracepoint
	openatEnterLink, err := link.Tracepoint("syscalls", "sys_enter_openat", pm.collection.Programs["trace_openat_enter"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach to sys_enter_openat: %w", err)
	}
	pm.links = append(pm.links, openatEnterLink)
	
	openatExitLink, err := link.Tracepoint("syscalls", "sys_exit_openat", pm.collection.Programs["trace_openat_exit"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach to sys_exit_openat: %w", err)
	}
	pm.links = append(pm.links, openatExitLink)
	
	// Attach to system call tracepoints
	syscallEnterLink, err := link.Tracepoint("syscalls", "sys_enter", pm.collection.Programs["trace_syscall_enter"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach to sys_enter: %w", err)
	}
	pm.links = append(pm.links, syscallEnterLink)
	
	syscallExitLink, err := link.Tracepoint("syscalls", "sys_exit", pm.collection.Programs["trace_syscall_exit"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach to sys_exit: %w", err)
	}
	pm.links = append(pm.links, syscallExitLink)
	
	log.Printf("[process_monitor] Attached %d tracepoints successfully", len(pm.links))
	return nil
}

// GetProcessInfo retrieves process information by PID
func (pm *ProcessMonitor) GetProcessInfo(pid uint32) (*ProcessInfo, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	if pm.collection == nil {
		return nil, fmt.Errorf("eBPF collection not loaded")
	}
	
	// Look up process in the tracking map
	var info ProcessInfo
	if err := pm.collection.Maps["process_tracking_map"].Lookup(pid, &info); err != nil {
		return nil, fmt.Errorf("process %d not found: %w", pid, err)
	}
	
	return &info, nil
}

// GetProcessNetworkConnections retrieves network connections for a process
func (pm *ProcessMonitor) GetProcessNetworkConnections(pid uint32) ([]ProcessNetworkConn, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	if pm.collection == nil {
		return nil, fmt.Errorf("eBPF collection not loaded")
	}
	
	var connections []ProcessNetworkConn
	
	// Iterate through the process network map
	iter := pm.collection.Maps["process_network_map"].Iterate()
	var key uint64
	var conn ProcessNetworkConn
	
	for iter.Next(&key, &conn) {
		// Check if this connection belongs to our process
		if conn.ProcessID == pid {
			connections = append(connections, conn)
		}
	}
	
	return connections, nil
}

// GetProcessFileAccess retrieves file access information for a process
func (pm *ProcessMonitor) GetProcessFileAccess(pid uint32) ([]ProcessFileAccess, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	if pm.collection == nil {
		return nil, fmt.Errorf("eBPF collection not loaded")
	}
	
	var fileAccess []ProcessFileAccess
	
	// Iterate through the process file map
	iter := pm.collection.Maps["process_file_map"].Iterate()
	var key uint64
	var access ProcessFileAccess
	
	for iter.Next(&key, &access) {
		// Check if this file access belongs to our process
		if access.ProcessID == pid {
			fileAccess = append(fileAccess, access)
		}
	}
	
	return fileAccess, nil
}

// GetAllProcesses retrieves information about all tracked processes
func (pm *ProcessMonitor) GetAllProcesses() ([]ProcessInfo, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	if pm.collection == nil {
		return nil, fmt.Errorf("eBPF collection not loaded")
	}
	
	var processes []ProcessInfo
	
	// Iterate through the process tracking map
	iter := pm.collection.Maps["process_tracking_map"].Iterate()
	var pid uint32
	var info ProcessInfo
	
	for iter.Next(&pid, &info) {
		processes = append(processes, info)
	}
	
	return processes, nil
}

// GetProcessStatistics returns statistics about tracked processes
func (pm *ProcessMonitor) GetProcessStatistics() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	stats := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"processes": map[string]interface{}{
			"total_tracked":       0,
			"active_processes":    0,
			"network_connections": 0,
			"file_accesses":       0,
		},
	}
	
	if pm.collection == nil {
		return stats
	}
	
	// Count processes
	processCount := 0
	iter := pm.collection.Maps["process_tracking_map"].Iterate()
	for iter.Next(nil, nil) {
		processCount++
	}
	
	// Count network connections
	connCount := 0
	iter = pm.collection.Maps["process_network_map"].Iterate()
	for iter.Next(nil, nil) {
		connCount++
	}
	
	// Count file accesses
	fileCount := 0
	iter = pm.collection.Maps["process_file_map"].Iterate()
	for iter.Next(nil, nil) {
		fileCount++
	}
	
	stats["processes"].(map[string]interface{})["total_tracked"] = processCount
	stats["processes"].(map[string]interface{})["active_processes"] = processCount
	stats["processes"].(map[string]interface{})["network_connections"] = connCount
	stats["processes"].(map[string]interface{})["file_accesses"] = fileCount
	
	return stats
}

// Start starts the process monitor
func (pm *ProcessMonitor) Start() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if pm.running {
		return fmt.Errorf("process monitor already running")
	}
	
	pm.running = true
	log.Printf("[process_monitor] Process monitor started")
	
	// Log startup event
	pm.auditLogger.LogSystemEvent("process_monitor_start", "Process monitor started", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"links":     len(pm.links),
	})
	
	return nil
}

// Stop stops the process monitor
func (pm *ProcessMonitor) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if !pm.running {
		return fmt.Errorf("process monitor not running")
	}
	
	pm.cancel()
	pm.running = false
	
	// Close all links
	for _, l := range pm.links {
		l.Close()
	}
	
	// Close collection
	if pm.collection != nil {
		pm.collection.Close()
	}
	
	log.Printf("[process_monitor] Process monitor stopped")
	
	// Log shutdown event
	pm.auditLogger.LogSystemEvent("process_monitor_stop", "Process monitor stopped", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	
	return nil
}

// Close closes the process monitor
func (pm *ProcessMonitor) Close() error {
	return pm.Stop()
}

// ProcessEventHandler methods
func (peh *ProcessEventHandler) processEvents() {
	// Process events from ring buffers
	go peh.processSyscallEvents()
	go peh.processExecutionEvents()
	
	log.Printf("[process_monitor] Event handler started")
}

func (peh *ProcessEventHandler) processSyscallEvents() {
	// Read from syscall ring buffer
	rd, err := peh.processMonitor.collection.Maps["process_syscall_ringbuf"].NewReader()
	if err != nil {
		log.Printf("[process_monitor] Failed to create syscall ring buffer reader: %v", err)
		return
	}
	defer rd.Close()
	
	for {
		record, err := rd.Read()
		if err != nil {
			if err == ebpf.ErrClosed {
				break
			}
			continue
		}
		
		// Parse syscall event
		var syscall ProcessSyscall
		if err := binary.Read(record.RawSample, binary.LittleEndian, &syscall); err != nil {
			log.Printf("[process_monitor] Failed to parse syscall event: %v", err)
			continue
		}
		
		// Process the syscall event
		peh.handleSyscallEvent(&syscall)
	}
}

func (peh *ProcessEventHandler) processExecutionEvents() {
	// Read from execution ring buffer
	rd, err := peh.processMonitor.collection.Maps["process_exec_ringbuf"].NewReader()
	if err != nil {
		log.Printf("[process_monitor] Failed to create execution ring buffer reader: %v", err)
		return
	}
	defer rd.Close()
	
	for {
		record, err := rd.Read()
		if err != nil {
			if err == ebpf.ErrClosed {
				break
			}
			continue
		}
		
		// Parse execution event
		var exec ProcessExecution
		if err := binary.Read(record.RawSample, binary.LittleEndian, &exec); err != nil {
			log.Printf("[process_monitor] Failed to parse execution event: %v", err)
			continue
		}
		
		// Process the execution event
		peh.handleExecutionEvent(&exec)
	}
}

func (peh *ProcessEventHandler) handleSyscallEvent(syscall *ProcessSyscall) {
	// Log system call event
	peh.auditLogger.LogCustomEvent(telemetry.EventTypeSecurityEvent, telemetry.SeverityInfo, 
		fmt.Sprintf("System call: %d by process %d", syscall.SyscallNr, syscall.ProcessID), 
		map[string]interface{}{
			"syscall_nr":   syscall.SyscallNr,
			"process_id":   syscall.ProcessID,
			"process_name": string(syscall.ProcessName[:]),
			"uid":          syscall.UID,
			"gid":          syscall.GID,
			"success":      syscall.Success,
			"timestamp":    time.Unix(0, int64(syscall.Timestamp)).UTC().Format(time.RFC3339),
		})
}

func (peh *ProcessEventHandler) handleExecutionEvent(exec *ProcessExecution) {
	eventType := "process_execution"
	if exec.EndTime > 0 {
		eventType = "process_exit"
	}
	
	// Log execution event
	peh.auditLogger.LogCustomEvent(telemetry.EventTypeSecurityEvent, telemetry.SeverityInfo, 
		fmt.Sprintf("Process %s: PID %d", eventType, exec.ProcessID), 
		map[string]interface{}{
			"process_id":      exec.ProcessID,
			"parent_pid":      exec.ParentPID,
			"process_name":    string(exec.ProcessName[:]),
			"executable_path": string(exec.ExecutablePath[:]),
			"command_line":    string(exec.CommandLine[:]),
			"uid":             exec.UID,
			"gid":             exec.GID,
			"exit_code":       exec.ExitCode,
			"success":         exec.Success,
			"start_time":      time.Unix(0, int64(exec.StartTime)).UTC().Format(time.RFC3339),
			"end_time":        time.Unix(0, int64(exec.EndTime)).UTC().Format(time.RFC3339),
		})
}
