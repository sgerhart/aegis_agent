package loader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// SegmentationLoader handles eBPF program loading and attachment for segmentation
type SegmentationLoader struct {
	programs    map[string]*ebpf.Program
	links       map[string]link.Link
	maps        map[string]*ebpf.Map
	pinnedMaps  map[string]string // map name -> pinned path
	mu          sync.RWMutex
	bpfPath     string
	generation  int64
}

// AttachedHook represents an attached eBPF hook
type AttachedHook struct {
	ProgramName string    `json:"program_name"`
	HookType    string    `json:"hook_type"` // cgroup_connect4, cgroup_connect6, tc_ingress, xdp
	Target      string    `json:"target"`    // cgroup path, interface name, etc.
	AttachedAt  time.Time `json:"attached_at"`
	Status      string    `json:"status"`    // active, failed, detached
}

// NewSegmentationLoader creates a new segmentation loader
func NewSegmentationLoader() *SegmentationLoader {
	return &SegmentationLoader{
		programs:   make(map[string]*ebpf.Program),
		links:      make(map[string]link.Link),
		maps:       make(map[string]*ebpf.Map),
		pinnedMaps: make(map[string]string),
		bpfPath:    "/sys/fs/bpf/aegis",
	}
}

// LoadProgram loads an eBPF program from object file
func (sl *SegmentationLoader) LoadProgram(ctx context.Context, objFile, programName string) (*ebpf.Program, error) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	// Load the object file
	spec, err := ebpf.LoadCollectionSpec(objFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection spec: %w", err)
	}
	
	// Load the collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection: %w", err)
	}
	defer coll.Close()
	
	// Find the program
	prog, exists := coll.Programs[programName]
	if !exists {
		return nil, fmt.Errorf("program %s not found in object file", programName)
	}
	
	// Store the program
	sl.programs[programName] = prog
	
	// Store maps
	for name, m := range coll.Maps {
		sl.maps[name] = m
	}
	
	return prog, nil
}

// AttachCgroupConnect4 attaches a program to cgroup connect4 hook
func (sl *SegmentationLoader) AttachCgroupConnect4(ctx context.Context, programName, cgroupPath string) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	prog, exists := sl.programs[programName]
	if !exists {
		return fmt.Errorf("program %s not loaded", programName)
	}
	
	// Create cgroup link
	cgroupLink, err := link.OpenCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to cgroup connect4: %w", err)
	}
	
	// Store the link
	linkName := fmt.Sprintf("%s_cgroup_connect4_%s", programName, filepath.Base(cgroupPath))
	sl.links[linkName] = cgroupLink
	
	return nil
}

// AttachCgroupConnect6 attaches a program to cgroup connect6 hook
func (sl *SegmentationLoader) AttachCgroupConnect6(ctx context.Context, programName, cgroupPath string) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	prog, exists := sl.programs[programName]
	if !exists {
		return fmt.Errorf("program %s not loaded", programName)
	}
	
	// Create cgroup link
	cgroupLink, err := link.OpenCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet6Connect,
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to cgroup connect6: %w", err)
	}
	
	// Store the link
	linkName := fmt.Sprintf("%s_cgroup_connect6_%s", programName, filepath.Base(cgroupPath))
	sl.links[linkName] = cgroupLink
	
	return nil
}

// AttachTCIngress attaches a program to TC ingress
func (sl *SegmentationLoader) AttachTCIngress(ctx context.Context, programName, iface string) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	prog, exists := sl.programs[programName]
	if !exists {
		return fmt.Errorf("program %s not loaded", programName)
	}
	
	// Create TC link
	tcLink, err := link.AttachTC(link.TCOptions{
		Program:   prog,
		Interface: iface,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to TC ingress: %w", err)
	}
	
	// Store the link
	linkName := fmt.Sprintf("%s_tc_ingress_%s", programName, iface)
	sl.links[linkName] = tcLink
	
	return nil
}

// AttachXDP attaches a program to XDP
func (sl *SegmentationLoader) AttachXDP(ctx context.Context, programName, iface string) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	prog, exists := sl.programs[programName]
	if !exists {
		return fmt.Errorf("program %s not loaded", programName)
	}
	
	// Create XDP link
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to XDP: %w", err)
	}
	
	// Store the link
	linkName := fmt.Sprintf("%s_xdp_%s", programName, iface)
	sl.links[linkName] = xdpLink
	
	return nil
}

// PinMaps pins all maps to /sys/fs/bpf/aegis
func (sl *SegmentationLoader) PinMaps() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	// Ensure BPF directory exists
	if err := os.MkdirAll(sl.bpfPath, 0755); err != nil {
		return fmt.Errorf("failed to create BPF directory: %w", err)
	}
	
	// Pin each map
	for name, m := range sl.maps {
		pinPath := filepath.Join(sl.bpfPath, name)
		if err := m.Pin(pinPath); err != nil {
			return fmt.Errorf("failed to pin map %s: %w", name, err)
		}
		sl.pinnedMaps[name] = pinPath
	}
	
	return nil
}

// UnpinMaps unpins all maps
func (sl *SegmentationLoader) UnpinMaps() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	for name, pinPath := range sl.pinnedMaps {
		if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to unpin map %s: %w", name, err)
		}
		delete(sl.pinnedMaps, name)
	}
	
	return nil
}

// UpdateMapAtomic performs atomic map updates with generation swap
func (sl *SegmentationLoader) UpdateMapAtomic(mapName string, key, value interface{}) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	m, exists := sl.maps[mapName]
	if !exists {
		return fmt.Errorf("map %s not found", mapName)
	}
	
	// Increment generation for atomic updates
	sl.generation++
	
	// Update the map
	if err := m.Put(key, value); err != nil {
		return fmt.Errorf("failed to update map %s: %w", mapName, err)
	}
	
	return nil
}

// GetMapValue retrieves a value from a map
func (sl *SegmentationLoader) GetMapValue(mapName string, key, value interface{}) error {
	sl.mu.RLock()
	defer sl.mu.RUnlock()
	
	m, exists := sl.maps[mapName]
	if !exists {
		return fmt.Errorf("map %s not found", mapName)
	}
	
	return m.Lookup(key, value)
}

// GetAttachedHooks returns information about attached hooks
func (sl *SegmentationLoader) GetAttachedHooks() []AttachedHook {
	sl.mu.RLock()
	defer sl.mu.RUnlock()
	
	var hooks []AttachedHook
	for linkName, link := range sl.links {
		hook := AttachedHook{
			ProgramName: linkName,
			AttachedAt:  time.Now(), // In real implementation, track actual attach time
			Status:      "active",
		}
		
		// Determine hook type and target from link name
		if contains(linkName, "cgroup_connect4") {
			hook.HookType = "cgroup_connect4"
			hook.Target = extractTarget(linkName, "cgroup_connect4")
		} else if contains(linkName, "cgroup_connect6") {
			hook.HookType = "cgroup_connect6"
			hook.Target = extractTarget(linkName, "cgroup_connect6")
		} else if contains(linkName, "tc_ingress") {
			hook.HookType = "tc_ingress"
			hook.Target = extractTarget(linkName, "tc_ingress")
		} else if contains(linkName, "xdp") {
			hook.HookType = "xdp"
			hook.Target = extractTarget(linkName, "xdp")
		}
		
		hooks = append(hooks, hook)
	}
	
	return hooks
}

// GetPinnedMaps returns information about pinned maps
func (sl *SegmentationLoader) GetPinnedMaps() map[string]string {
	sl.mu.RLock()
	defer sl.mu.RUnlock()
	
	result := make(map[string]string)
	for name, path := range sl.pinnedMaps {
		result[name] = path
	}
	
	return result
}

// GetGeneration returns the current generation number
func (sl *SegmentationLoader) GetGeneration() int64 {
	sl.mu.RLock()
	defer sl.mu.RUnlock()
	
	return sl.generation
}

// DetachHook detaches a specific hook
func (sl *SegmentationLoader) DetachHook(linkName string) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	link, exists := sl.links[linkName]
	if !exists {
		return fmt.Errorf("link %s not found", linkName)
	}
	
	if err := link.Close(); err != nil {
		return fmt.Errorf("failed to detach link %s: %w", linkName, err)
	}
	
	delete(sl.links, linkName)
	return nil
}

// DetachAllHooks detaches all hooks
func (sl *SegmentationLoader) DetachAllHooks() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	var lastErr error
	for linkName, link := range sl.links {
		if err := link.Close(); err != nil {
			lastErr = fmt.Errorf("failed to detach link %s: %w", linkName, err)
		}
	}
	
	sl.links = make(map[string]link.Link)
	return lastErr
}

// Close closes all programs and links
func (sl *SegmentationLoader) Close() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	
	// Close all links
	for _, link := range sl.links {
		link.Close()
	}
	
	// Close all programs
	for _, prog := range sl.programs {
		prog.Close()
	}
	
	// Close all maps
	for _, m := range sl.maps {
		m.Close()
	}
	
	// Unpin maps
	sl.UnpinMaps()
	
	return nil
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}

func extractTarget(linkName, hookType string) string {
	// Extract target from link name like "program_cgroup_connect4_target"
	prefix := fmt.Sprintf("_%s_", hookType)
	idx := len(linkName) - len(prefix) - len(hookType)
	if idx > 0 {
		return linkName[idx:]
	}
	return "unknown"
}
