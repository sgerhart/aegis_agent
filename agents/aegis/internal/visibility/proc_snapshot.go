package visibility

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProcessInfo represents process information from /proc
type ProcessInfo struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Exe       string    `json:"exe"`
	Args      []string  `json:"args"`
	StartTime time.Time `json:"start_time"`
	State     string    `json:"state"`
	Threads   int       `json:"threads"`
}

// ProcSnapshotter takes snapshots of /proc filesystem
type ProcSnapshotter struct {
	lastSnapshot map[uint32]ProcessInfo
	interval     time.Duration
	stopChan     chan struct{}
	running      bool
}

// NewProcSnapshotter creates a new proc snapshotter
func NewProcSnapshotter(interval time.Duration) *ProcSnapshotter {
	return &ProcSnapshotter{
		lastSnapshot: make(map[uint32]ProcessInfo),
		interval:     interval,
		stopChan:     make(chan struct{}),
		running:      false,
	}
}

// Start starts taking periodic snapshots
func (ps *ProcSnapshotter) Start() error {
	if ps.running {
		return fmt.Errorf("proc snapshotter already running")
	}

	ps.running = true
	go ps.snapshotLoop()
	
	log.Printf("[visibility] Started proc snapshotter (interval: %v)", ps.interval)
	return nil
}

// Stop stops taking snapshots
func (ps *ProcSnapshotter) Stop() error {
	if !ps.running {
		return fmt.Errorf("proc snapshotter not running")
	}

	close(ps.stopChan)
	ps.running = false
	
	log.Printf("[visibility] Stopped proc snapshotter")
	return nil
}

// snapshotLoop takes periodic snapshots
func (ps *ProcSnapshotter) snapshotLoop() {
	ticker := time.NewTicker(ps.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := ps.takeSnapshot(); err != nil {
				log.Printf("[visibility] Error taking proc snapshot: %v", err)
			}
		case <-ps.stopChan:
			return
		}
	}
}

// takeSnapshot takes a snapshot of the current processes
func (ps *ProcSnapshotter) takeSnapshot() error {
	processes, err := ps.scanProcesses()
	if err != nil {
		return fmt.Errorf("failed to scan processes: %w", err)
	}

	// Update last snapshot
	ps.lastSnapshot = processes

	log.Printf("[visibility] Proc snapshot: %d processes", len(processes))
	return nil
}

// scanProcesses scans all processes from /proc
func (ps *ProcSnapshotter) scanProcesses() (map[uint32]ProcessInfo, error) {
	processes := make(map[uint32]ProcessInfo)

	// Read /proc directory
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		// Skip non-numeric directories
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		// Read process info
		procInfo, err := ps.readProcessInfo(uint32(pid))
		if err != nil {
			// Process might have exited, skip
			continue
		}

		processes[uint32(pid)] = procInfo
	}

	return processes, nil
}

// readProcessInfo reads process information from /proc/PID
func (ps *ProcSnapshotter) readProcessInfo(pid uint32) (ProcessInfo, error) {
	procInfo := ProcessInfo{PID: pid}

	// Read /proc/PID/stat
	if err := ps.readProcessStat(pid, &procInfo); err != nil {
		return procInfo, fmt.Errorf("failed to read stat: %w", err)
	}

	// Read /proc/PID/status
	if err := ps.readProcessStatus(pid, &procInfo); err != nil {
		return procInfo, fmt.Errorf("failed to read status: %w", err)
	}

	// Read /proc/PID/cmdline
	if err := ps.readProcessCmdline(pid, &procInfo); err != nil {
		return procInfo, fmt.Errorf("failed to read cmdline: %w", err)
	}

	// Read /proc/PID/exe (symlink)
	if err := ps.readProcessExe(pid, &procInfo); err != nil {
		// This might fail for some processes, not critical
		procInfo.Exe = "unknown"
	}

	return procInfo, nil
}

// readProcessStat reads /proc/PID/stat
func (ps *ProcSnapshotter) readProcessStat(pid uint32, procInfo *ProcessInfo) error {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	file, err := os.Open(statPath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return fmt.Errorf("no data in stat file")
	}

	line := scanner.Text()
	fields := strings.Fields(line)

	if len(fields) < 24 {
		return fmt.Errorf("invalid stat format")
	}

	// Parse fields (simplified)
	ppid, _ := strconv.ParseUint(fields[3], 10, 32)
	procInfo.PPID = uint32(ppid)
	procInfo.State = fields[2]

	// Parse start time (field 21)
	startTime, _ := strconv.ParseUint(fields[21], 10, 64)
	// Convert from jiffies to time
	procInfo.StartTime = time.Unix(int64(startTime/100), 0)

	return nil
}

// readProcessStatus reads /proc/PID/status
func (ps *ProcSnapshotter) readProcessStatus(pid uint32, procInfo *ProcessInfo) error {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(statusPath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "Uid:":
			if len(fields) >= 2 {
				uid, _ := strconv.ParseUint(fields[1], 10, 32)
				procInfo.UID = uint32(uid)
			}
		case "Gid:":
			if len(fields) >= 2 {
				gid, _ := strconv.ParseUint(fields[1], 10, 32)
				procInfo.GID = uint32(gid)
			}
		case "Threads:":
			if len(fields) >= 2 {
				threads, _ := strconv.Atoi(fields[1])
				procInfo.Threads = threads
			}
		}
	}

	return scanner.Err()
}

// readProcessCmdline reads /proc/PID/cmdline
func (ps *ProcSnapshotter) readProcessCmdline(pid uint32, procInfo *ProcessInfo) error {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	file, err := os.Open(cmdlinePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return fmt.Errorf("no data in cmdline file")
	}

	line := scanner.Text()
	// Split by null bytes
	args := strings.Split(line, "\x00")
	
	// Filter out empty strings
	procInfo.Args = make([]string, 0)
	for _, arg := range args {
		if arg != "" {
			procInfo.Args = append(procInfo.Args, arg)
		}
	}

	// Set exe from first argument
	if len(procInfo.Args) > 0 {
		procInfo.Exe = procInfo.Args[0]
	}

	return nil
}

// readProcessExe reads /proc/PID/exe symlink
func (ps *ProcSnapshotter) readProcessExe(pid uint32, procInfo *ProcessInfo) error {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	
	// Read the symlink
	exe, err := os.Readlink(exePath)
	if err != nil {
		return err
	}

	procInfo.Exe = exe
	return nil
}

// GetLastSnapshot returns the last snapshot
func (ps *ProcSnapshotter) GetLastSnapshot() map[uint32]ProcessInfo {
	return ps.lastSnapshot
}

// GetProcessTree builds a process tree from the snapshot
func (ps *ProcSnapshotter) GetProcessTree() map[uint32][]uint32 {
	tree := make(map[uint32][]uint32)

	for pid, procInfo := range ps.lastSnapshot {
		ppid := procInfo.PPID
		tree[ppid] = append(tree[ppid], pid)
	}

	return tree
}

// GetProcessesByUID returns processes grouped by UID
func (ps *ProcSnapshotter) GetProcessesByUID() map[uint32][]ProcessInfo {
	byUID := make(map[uint32][]ProcessInfo)

	for _, procInfo := range ps.lastSnapshot {
		byUID[procInfo.UID] = append(byUID[procInfo.UID], procInfo)
	}

	return byUID
}

// IsRunning returns true if the snapshotter is running
func (ps *ProcSnapshotter) IsRunning() bool {
	return ps.running
}
