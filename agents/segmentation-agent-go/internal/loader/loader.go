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

// Loader manages eBPF program loading and attachment
type Loader struct {
	programs map[string]*ebpf.Program
	links    map[string]link.Link
	maps     map[string]*ebpf.Map
	mu       sync.RWMutex
}

// ProgramInfo contains information about a loaded program
type ProgramInfo struct {
	Name        string
	Type        ebpf.ProgramType
	AttachType  ebpf.AttachType
	ID          ebpf.ProgramID
	Size        uint32
	LoadTime    time.Duration
	Attached    bool
	AttachPoint string
}

// MapInfo contains information about a loaded map
type MapInfo struct {
	Name       string
	Type       ebpf.MapType
	ID         ebpf.MapID
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

// NewLoader creates a new eBPF loader
func NewLoader() *Loader {
	return &Loader{
		programs: make(map[string]*ebpf.Program),
		links:    make(map[string]link.Link),
		maps:     make(map[string]*ebpf.Map),
	}
}

// LoadProgram loads an eBPF program from an object file
func (l *Loader) LoadProgram(ctx context.Context, objFile, programName string) (*ProgramInfo, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	start := time.Now()
	
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
	l.programs[programName] = prog
	
	// Store maps
	for name, m := range coll.Maps {
		l.maps[name] = m
	}
	
	loadTime := time.Since(start)
	
	info := &ProgramInfo{
		Name:       programName,
		Type:       prog.Type(),
		AttachType: prog.Type(), // Default to program type
		ID:         prog.ID(),
		Size:       prog.Instructions()[0].Size,
		LoadTime:   loadTime,
		Attached:   false,
	}
	
	return info, nil
}

// AttachCgroupConnect4 attaches a program to cgroup connect4 hook
func (l *Loader) AttachCgroupConnect4(ctx context.Context, programName, cgroupPath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	prog, exists := l.programs[programName]
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
		return fmt.Errorf("failed to attach to cgroup: %w", err)
	}
	
	// Store the link
	linkName := fmt.Sprintf("%s_cgroup_connect4", programName)
	l.links[linkName] = cgroupLink
	
	// Update program info
	if info := l.getProgramInfo(programName); info != nil {
		info.Attached = true
		info.AttachPoint = cgroupPath
	}
	
	return nil
}

// AttachCgroupConnect6 attaches a program to cgroup connect6 hook
func (l *Loader) AttachCgroupConnect6(ctx context.Context, programName, cgroupPath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	prog, exists := l.programs[programName]
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
		return fmt.Errorf("failed to attach to cgroup: %w", err)
	}
	
	// Store the link
	linkName := fmt.Sprintf("%s_cgroup_connect6", programName)
	l.links[linkName] = cgroupLink
	
	// Update program info
	if info := l.getProgramInfo(programName); info != nil {
		info.Attached = true
		info.AttachPoint = cgroupPath
	}
	
	return nil
}

// AttachTCIngress attaches a program to TC ingress
func (l *Loader) AttachTCIngress(ctx context.Context, programName, iface string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	prog, exists := l.programs[programName]
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
	l.links[linkName] = tcLink
	
	// Update program info
	if info := l.getProgramInfo(programName); info != nil {
		info.Attached = true
		info.AttachPoint = iface
	}
	
	return nil
}

// AttachXDP attaches a program to XDP
func (l *Loader) AttachXDP(ctx context.Context, programName, iface string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	prog, exists := l.programs[programName]
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
	l.links[linkName] = xdpLink
	
	// Update program info
	if info := l.getProgramInfo(programName); info != nil {
		info.Attached = true
		info.AttachPoint = iface
	}
	
	return nil
}

// UpdatePolicy updates a policy map
func (l *Loader) UpdatePolicy(policy interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	// This would update the policy maps based on the policy structure
	// For now, just log the update
	fmt.Printf("Updating policy: %+v\n", policy)
	
	return nil
}

// CollectStats collects statistics from eBPF maps
func (l *Loader) CollectStats() (map[string]interface{}, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	stats := make(map[string]interface{})
	
	// Collect stats from each map
	for name, m := range l.maps {
		if m.Type() == ebpf.Array {
			// Read array map stats
			var value uint64
			if err := m.Lookup(uint32(0), &value); err == nil {
				stats[name] = value
			}
		}
	}
	
	return stats, nil
}

// GetProgramInfo returns information about a loaded program
func (l *Loader) GetProgramInfo(programName string) *ProgramInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	return l.getProgramInfo(programName)
}

// getProgramInfo internal method without locking
func (l *Loader) getProgramInfo(programName string) *ProgramInfo {
	prog, exists := l.programs[programName]
	if !exists {
		return nil
	}
	
	return &ProgramInfo{
		Name:       programName,
		Type:       prog.Type(),
		AttachType: prog.Type(),
		ID:         prog.ID(),
		Size:       prog.Instructions()[0].Size,
		Attached:   false, // Would need to track this separately
	}
}

// ListPrograms returns all loaded programs
func (l *Loader) ListPrograms() []ProgramInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	var programs []ProgramInfo
	for name := range l.programs {
		if info := l.getProgramInfo(name); info != nil {
			programs = append(programs, *info)
		}
	}
	
	return programs
}

// UnloadProgram unloads a program
func (l *Loader) UnloadProgram(ctx context.Context, programName string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	// Close all links for this program
	for linkName, link := range l.links {
		if len(linkName) > len(programName) && linkName[:len(programName)] == programName {
			link.Close()
			delete(l.links, linkName)
		}
	}
	
	// Close the program
	if prog, exists := l.programs[programName]; exists {
		prog.Close()
		delete(l.programs, programName)
	}
	
	return nil
}

// Close closes all loaded programs and links
func (l *Loader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	// Close all links
	for _, link := range l.links {
		link.Close()
	}
	
	// Close all programs
	for _, prog := range l.programs {
		prog.Close()
	}
	
	// Close all maps
	for _, m := range l.maps {
		m.Close()
	}
	
	return nil
}

// LoadFromTemplate loads a program from a template
func (l *Loader) LoadFromTemplate(ctx context.Context, templateName, programName string, params map[string]interface{}) (*ProgramInfo, error) {
	// This would integrate with the build system
	// For now, just return an error
	return nil, fmt.Errorf("template loading not implemented")
}

// GetMap returns a loaded map by name
func (l *Loader) GetMap(name string) *ebpf.Map {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	return l.maps[name]
}

// UpdateMap updates a map with new data
func (l *Loader) UpdateMap(mapName string, key, value interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	m, exists := l.maps[mapName]
	if !exists {
		return fmt.Errorf("map %s not found", mapName)
	}
	
	return m.Put(key, value)
}

// GetMapValue retrieves a value from a map
func (l *Loader) GetMapValue(mapName string, key interface{}, value interface{}) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	m, exists := l.maps[mapName]
	if !exists {
		return fmt.Errorf("map %s not found", mapName)
	}
	
	return m.Lookup(key, value)
}
