package loader

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// SegEgressLoader handles egress segmentation eBPF programs
type SegEgressLoader struct {
	collection *ebpf.Collection
	programs   map[string]*ebpf.Program
	links      map[string]link.Link
}

// NewSegEgressLoader creates a new egress segmentation loader
func NewSegEgressLoader() *SegEgressLoader {
	// Increase resource limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[seg_egress] Failed to remove memlock rlimit: %v", err)
	}

	return &SegEgressLoader{
		programs: make(map[string]*ebpf.Program),
		links:    make(map[string]link.Link),
	}
}

// LoadProgram loads the egress segmentation eBPF program from object file
func (sel *SegEgressLoader) LoadProgram(ctx context.Context, objectPath string) error {
	// Load the eBPF collection from the object file
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return fmt.Errorf("failed to load eBPF collection spec from %s: %w", objectPath, err)
	}

	// Load the collection into the kernel
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to load eBPF collection: %w", err)
	}

	sel.collection = collection
	log.Printf("[seg_egress] Loaded eBPF collection from %s", objectPath)
	return nil
}

// AttachCgroupConnect4 attaches the seg_connect4 program to a cgroup
func (sel *SegEgressLoader) AttachCgroupConnect4(ctx context.Context, cgroupPath string) error {
	if sel.collection == nil {
		return fmt.Errorf("eBPF collection not loaded")
	}

	// Get the seg_connect4 program
	prog, ok := sel.collection.Programs["seg_connect4"]
	if !ok {
		return fmt.Errorf("program 'seg_connect4' not found in collection")
	}

	// Verify the program type
	if prog.Type() != ebpf.CGroupSockAddr {
		return fmt.Errorf("program 'seg_connect4' is not a CGroupSockAddr type, got %v", prog.Type())
	}

	// Open the cgroup path
	cgroupFile, err := os.Open(cgroupPath)
	if err != nil {
		return fmt.Errorf("failed to open cgroup path %s: %w", cgroupPath, err)
	}
	defer cgroupFile.Close()

	// Attach the program to the cgroup using link.AttachCgroup
	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("failed to attach seg_connect4 to cgroup %s: %w", cgroupPath, err)
	}

	// Store the program and link
	sel.programs["seg_connect4"] = prog
	sel.links["seg_connect4"] = link
	log.Printf("[seg_egress] Successfully attached seg_connect4 to cgroup %s", cgroupPath)
	return nil
}

// AttachCgroupConnect6 attaches the seg_connect6 program to a cgroup
func (sel *SegEgressLoader) AttachCgroupConnect6(ctx context.Context, cgroupPath string) error {
	if sel.collection == nil {
		return fmt.Errorf("eBPF collection not loaded")
	}

	// Get the seg_connect6 program
	prog, ok := sel.collection.Programs["seg_connect6"]
	if !ok {
		return fmt.Errorf("program 'seg_connect6' not found in collection")
	}

	// Verify the program type
	if prog.Type() != ebpf.CGroupSockAddr {
		return fmt.Errorf("program 'seg_connect6' is not a CGroupSockAddr type, got %v", prog.Type())
	}

	// Open the cgroup path
	cgroupFile, err := os.Open(cgroupPath)
	if err != nil {
		return fmt.Errorf("failed to open cgroup path %s: %w", cgroupPath, err)
	}
	defer cgroupFile.Close()

	// Attach the program to the cgroup using link.AttachCgroup
	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet6Connect,
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("failed to attach seg_connect6 to cgroup %s: %w", cgroupPath, err)
	}

	// Store the program and link
	sel.programs["seg_connect6"] = prog
	sel.links["seg_connect6"] = link
	log.Printf("[seg_egress] Successfully attached seg_connect6 to cgroup %s", cgroupPath)
	return nil
}

// AttachAll attaches both connect4 and connect6 programs to a cgroup
func (sel *SegEgressLoader) AttachAll(ctx context.Context, cgroupPath string) error {
	if err := sel.AttachCgroupConnect4(ctx, cgroupPath); err != nil {
		return fmt.Errorf("failed to attach connect4: %w", err)
	}

	if err := sel.AttachCgroupConnect6(ctx, cgroupPath); err != nil {
		// Clean up connect4 if connect6 fails
		delete(sel.programs, "seg_connect4")
		return fmt.Errorf("failed to attach connect6: %w", err)
	}

	log.Printf("[seg_egress] Successfully attached all egress programs to cgroup %s", cgroupPath)
	return nil
}

// DetachAll detaches all attached programs
func (sel *SegEgressLoader) DetachAll() error {
	log.Printf("[seg_egress] Detaching all programs")
	
	// Close all links
	for name, link := range sel.links {
		if err := link.Close(); err != nil {
			log.Printf("[seg_egress] Error closing link %s: %v", name, err)
		}
	}
	
	sel.programs = make(map[string]*ebpf.Program)
	sel.links = make(map[string]link.Link)
	return nil
}

// GetAttachedPrograms returns a list of currently attached programs
func (sel *SegEgressLoader) GetAttachedPrograms() []string {
	programs := make([]string, 0, len(sel.programs))
	for name := range sel.programs {
		programs = append(programs, name)
	}
	return programs
}

// GetMaps returns the eBPF maps from the loaded collection
func (sel *SegEgressLoader) GetMaps() map[string]*ebpf.Map {
	if sel.collection == nil {
		return nil
	}
	return sel.collection.Maps
}

// UpdatePolicy updates a policy in the egress_policies map
func (sel *SegEgressLoader) UpdatePolicy(ctx context.Context, policyID uint32, policy EgressPolicy) error {
	if sel.collection == nil {
		return fmt.Errorf("eBPF collection not loaded")
	}

	egressPolicies, ok := sel.collection.Maps["egress_policies"]
	if !ok {
		return fmt.Errorf("egress_policies map not found")
	}

	return egressPolicies.Put(policyID, policy)
}

// UpdateAllowedPort updates the allowed_ports map
func (sel *SegEgressLoader) UpdateAllowedPort(ctx context.Context, port uint16, allowed bool) error {
	if sel.collection == nil {
		return fmt.Errorf("eBPF collection not loaded")
	}

	allowedPorts, ok := sel.collection.Maps["allowed_ports"]
	if !ok {
		return fmt.Errorf("allowed_ports map not found")
	}

	var value uint8
	if allowed {
		value = 1
	}

	return allowedPorts.Put(port, value)
}

// GetStats retrieves statistics from the egress_stats_map
func (sel *SegEgressLoader) GetStats(ctx context.Context) (*EgressStats, error) {
	if sel.collection == nil {
		return nil, fmt.Errorf("eBPF collection not loaded")
	}

	statsMap, ok := sel.collection.Maps["egress_stats_map"]
	if !ok {
		return nil, fmt.Errorf("egress_stats_map not found")
	}

	var stats EgressStats
	key := uint32(0)
	if err := statsMap.Lookup(key, &stats); err != nil {
		return nil, fmt.Errorf("failed to lookup stats: %w", err)
	}

	return &stats, nil
}

// Close cleans up resources
func (sel *SegEgressLoader) Close() error {
	// Detach all programs
	if err := sel.DetachAll(); err != nil {
		log.Printf("[seg_egress] Error detaching programs: %v", err)
	}

	// Close the collection
	if sel.collection != nil {
		sel.collection.Close()
		sel.collection = nil
	}

	log.Printf("[seg_egress] Closed egress segmentation loader")
	return nil
}

// EgressPolicy represents an egress policy structure
type EgressPolicy struct {
	SrcIP      uint32 `json:"src_ip"`
	DstIP      uint32 `json:"dst_ip"`
	SrcMask    uint32 `json:"src_mask"`
	DstMask    uint32 `json:"dst_mask"`
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	Protocol   uint8  `json:"protocol"`
	Action     uint8  `json:"action"` // 0=BLOCK, 1=ALLOW, 2=LOG
	Priority   uint8  `json:"priority"`
	ProcessUID uint32 `json:"process_uid"`
	ProcessGID uint32 `json:"process_gid"`
}

// EgressStats represents statistics from the eBPF program
type EgressStats struct {
	TotalConnections    uint64   `json:"total_connections"`
	AllowedConnections  uint64   `json:"allowed_connections"`
	BlockedConnections  uint64   `json:"blocked_connections"`
	LoggedConnections   uint64   `json:"logged_connections"`
	PolicyHits          [256]uint64 `json:"policy_hits"`
}
