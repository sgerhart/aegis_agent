package ebpf

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// EBPFManager manages eBPF programs and their lifecycle
type EBPFManager struct {
	programsDir   string
	loadedProgs   map[string]*EBPFProgram
	telemetry     *telemetry.EventEmitter
	mu            sync.RWMutex
}

// EBPFProgram represents a loaded eBPF program
type EBPFProgram struct {
	Name        string
	Type        string
	ObjectPath  string
	ProgramID   int
	AttachedTo  string
	Maps        map[string]string // map name -> pinned path
	LoadTime    time.Time
	AttachTime  time.Time
}

// NewEBPFManager creates a new eBPF manager
func NewEBPFManager(programsDir string, telemetry *telemetry.EventEmitter) *EBPFManager {
	return &EBPFManager{
		programsDir: programsDir,
		loadedProgs: make(map[string]*EBPFProgram),
		telemetry:   telemetry,
	}
}

// LoadProgram loads an eBPF program into the kernel
func (em *EBPFManager) LoadProgram(name, objectFile string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	start := time.Now()
	objectPath := filepath.Join(em.programsDir, objectFile)

	// Check if object file exists
	if _, err := os.Stat(objectPath); os.IsNotExist(err) {
		em.telemetry.EmitEBPF(name, "unknown", "load", "", "", fmt.Sprintf("Object file not found: %s", objectPath), nil)
		return fmt.Errorf("eBPF object file not found: %s", objectPath)
	}

	// Load program using bpftool
	cmd := exec.Command("bpftool", "prog", "load", objectPath, "/sys/fs/bpf/"+name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to load eBPF program: %s", string(output))
		em.telemetry.EmitEBPF(name, "classifier", "load", "", "", errorMsg, nil)
		return fmt.Errorf("failed to load eBPF program %s: %v", name, err)
	}

	// Get program ID
	progID, err := em.getProgramID(name)
	if err != nil {
		em.telemetry.EmitEBPF(name, "classifier", "load", "", "", fmt.Sprintf("Failed to get program ID: %v", err), nil)
		return fmt.Errorf("failed to get program ID for %s: %v", name, err)
	}

	// Create program record
	prog := &EBPFProgram{
		Name:       name,
		Type:       "classifier", // Default type, can be detected
		ObjectPath: objectPath,
		ProgramID:  progID,
		Maps:       make(map[string]string),
		LoadTime:   time.Now(),
	}

	// Pin maps if they exist
	em.pinProgramMaps(prog)

	em.loadedProgs[name] = prog

	// Emit telemetry
	em.telemetry.EmitEBPF(name, prog.Type, "load", "", "", "", map[string]uint64{
		"program_id":   uint64(progID),
		"load_time_ms": uint64(time.Since(start).Milliseconds()),
	})

	log.Printf("[eBPF] Successfully loaded program: %s (ID: %d)", name, progID)
	return nil
}

// AttachToInterface attaches an eBPF program to a network interface
func (em *EBPFManager) AttachToInterface(programName, interface_ string, direction string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	start := time.Now()
	prog, exists := em.loadedProgs[programName]
	if !exists {
		em.telemetry.EmitEBPF(programName, "unknown", "attach", interface_, "", "Program not loaded", nil)
		return fmt.Errorf("program %s not loaded", programName)
	}

	// Attach using tc (Traffic Control)
	var cmd *exec.Cmd
	if direction == "ingress" {
		// tc qdisc add dev eth0 ingress
		exec.Command("tc", "qdisc", "add", "dev", interface_, "ingress").Run()
		// tc filter add dev eth0 ingress bpf direct-action obj /sys/fs/bpf/program
		cmd = exec.Command("tc", "filter", "add", "dev", interface_, "ingress", "bpf", "direct-action", "obj", "/sys/fs/bpf/"+programName)
	} else {
		// tc qdisc add dev eth0 root handle 1: htb
		exec.Command("tc", "qdisc", "add", "dev", interface_, "root", "handle", "1:", "htb").Run()
		// tc filter add dev eth0 parent 1: bpf direct-action obj /sys/fs/bpf/program
		cmd = exec.Command("tc", "filter", "add", "dev", interface_, "parent", "1:", "bpf", "direct-action", "obj", "/sys/fs/bpf/"+programName)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to attach to interface: %s", string(output))
		em.telemetry.EmitEBPF(programName, prog.Type, "attach", interface_, "", errorMsg, nil)
		return fmt.Errorf("failed to attach program %s to %s: %v", programName, interface_, err)
	}

	prog.AttachedTo = interface_
	prog.AttachTime = time.Now()

	// Emit telemetry
	em.telemetry.EmitEBPF(programName, prog.Type, "attach", interface_, "", "", map[string]uint64{
		"program_id":    uint64(prog.ProgramID),
		"attach_time_ms": uint64(time.Since(start).Milliseconds()),
	})

	log.Printf("[eBPF] Successfully attached program %s to interface %s", programName, interface_)
	return nil
}

// DetachFromInterface detaches an eBPF program from a network interface
func (em *EBPFManager) DetachFromInterface(programName, interface_ string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	start := time.Now()
	prog, exists := em.loadedProgs[programName]
	if !exists {
		return fmt.Errorf("program %s not loaded", programName)
	}

	// Remove tc filters
	cmd := exec.Command("tc", "filter", "del", "dev", interface_, "ingress")
	output, err := cmd.CombinedOutput()
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to detach from interface: %s", string(output))
		em.telemetry.EmitEBPF(programName, prog.Type, "detach", interface_, "", errorMsg, nil)
		return fmt.Errorf("failed to detach program %s from %s: %v", programName, interface_, err)
	}

	prog.AttachedTo = ""

	// Emit telemetry
	em.telemetry.EmitEBPF(programName, prog.Type, "detach", interface_, "", "", map[string]uint64{
		"program_id":      uint64(prog.ProgramID),
		"detach_time_ms":  uint64(time.Since(start).Milliseconds()),
	})

	log.Printf("[eBPF] Successfully detached program %s from interface %s", programName, interface_)
	return nil
}

// UnloadProgram unloads an eBPF program from the kernel
func (em *EBPFManager) UnloadProgram(programName string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	prog, exists := em.loadedProgs[programName]
	if !exists {
		return fmt.Errorf("program %s not loaded", programName)
	}

	// Detach if still attached
	if prog.AttachedTo != "" {
		em.DetachFromInterface(programName, prog.AttachedTo)
	}

	// Remove pinned program
	cmd := exec.Command("rm", "-f", "/sys/fs/bpf/"+programName)
	cmd.Run()

	// Unpin maps
	for _, mapPath := range prog.Maps {
		exec.Command("rm", "-f", mapPath).Run()
	}

	delete(em.loadedProgs, programName)

	log.Printf("[eBPF] Successfully unloaded program: %s", programName)
	return nil
}

// GetProgramStats retrieves statistics for an eBPF program
func (em *EBPFManager) GetProgramStats(programName string) (map[string]uint64, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	prog, exists := em.loadedProgs[programName]
	if !exists {
		return nil, fmt.Errorf("program %s not loaded", programName)
	}

	stats := make(map[string]uint64)
	
	// Get program runtime stats
	cmd := exec.Command("bpftool", "prog", "show", "id", fmt.Sprintf("%d", prog.ProgramID))
	output, err := cmd.CombinedOutput()
	if err == nil {
		// Parse bpftool output for runtime stats
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "run_time_ns") {
				// Parse runtime stats - simplified for demo
				stats["runtime_ns"] = 0 // Would parse actual value
			}
		}
	}

	// Get map statistics
	for mapName, mapPath := range prog.Maps {
		mapStats, err := em.getMapStats(mapPath)
		if err == nil {
			for k, v := range mapStats {
				stats[mapName+"_"+k] = v
			}
		}
	}

	return stats, nil
}

// GetLoadedPrograms returns a list of loaded programs
func (em *EBPFManager) GetLoadedPrograms() map[string]*EBPFProgram {
	em.mu.RLock()
	defer em.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[string]*EBPFProgram)
	for k, v := range em.loadedProgs {
		result[k] = v
	}
	return result
}

// getProgramID gets the program ID from bpftool
func (em *EBPFManager) getProgramID(programName string) (int, error) {
	cmd := exec.Command("bpftool", "prog", "show", "pinned", "/sys/fs/bpf/"+programName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}

	// Parse program ID from output (simplified)
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) > 0 {
			var id int
			if _, err := fmt.Sscanf(parts[0], "%d:", &id); err == nil {
				return id, nil
			}
		}
	}

	return 0, fmt.Errorf("could not parse program ID")
}

// pinProgramMaps pins any maps associated with the program
func (em *EBPFManager) pinProgramMaps(prog *EBPFProgram) {
	// This is a simplified implementation
	// In reality, we would inspect the object file to find map names
	// and pin them appropriately
	mapNames := []string{"aegis_blocked_destinations", "aegis_enforcement_stats", "aegis_policy_rules"}
	
	for _, mapName := range mapNames {
		mapPath := "/sys/fs/bpf/" + mapName
		prog.Maps[mapName] = mapPath
	}
}

// getMapStats retrieves statistics for a BPF map
func (em *EBPFManager) getMapStats(mapPath string) (map[string]uint64, error) {
	stats := make(map[string]uint64)
	
	// Get map info
	cmd := exec.Command("bpftool", "map", "show", "pinned", mapPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return stats, err
	}

	// Count entries (simplified)
	cmd = exec.Command("bpftool", "map", "dump", "pinned", mapPath)
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		entryCount := 0
		for _, line := range lines {
			if strings.Contains(line, "key:") {
				entryCount++
			}
		}
		stats["entries"] = uint64(entryCount)
	}

	return stats, nil
}
