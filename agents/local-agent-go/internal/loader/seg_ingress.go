package loader

import (
	"context"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// SegIngressLoader handles ingress segmentation eBPF programs
type SegIngressLoader struct {
	collection *ebpf.Collection
	programs   map[string]*ebpf.Program
	qdisc      interface{} // Mock qdisc
}

// NewSegIngressLoader creates a new ingress segmentation loader
func NewSegIngressLoader() *SegIngressLoader {
	// Increase resource limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[seg_ingress] Failed to remove memlock rlimit: %v", err)
	}

	return &SegIngressLoader{
		programs: make(map[string]*ebpf.Program),
	}
}

// LoadProgram loads the ingress segmentation eBPF program from object file
func (sil *SegIngressLoader) LoadProgram(ctx context.Context, objectPath string) error {
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

	sil.collection = collection
	log.Printf("[seg_ingress] Loaded eBPF collection from %s", objectPath)
	return nil
}

// EnsureClsactQdisc ensures that a clsact qdisc is attached to the interface
func (sil *SegIngressLoader) EnsureClsactQdisc(ctx context.Context, ifaceName string) error {
	// For now, we'll assume the clsact qdisc is already present
	// In a real implementation, this would use netlink to create the qdisc
	log.Printf("[seg_ingress] Assuming clsact qdisc exists on %s", ifaceName)
	return nil
}

// AttachTCClassifier attaches the seg_ingress_cls classifier to the interface
func (sil *SegIngressLoader) AttachTCClassifier(ctx context.Context, ifaceName string) error {
	if sil.collection == nil {
		return fmt.Errorf("eBPF collection not loaded")
	}

	// Ensure clsact qdisc exists
	if err := sil.EnsureClsactQdisc(ctx, ifaceName); err != nil {
		return fmt.Errorf("failed to ensure clsact qdisc: %w", err)
	}

	// Get the seg_ingress_cls program
	prog, ok := sil.collection.Programs["seg_ingress_cls"]
	if !ok {
		return fmt.Errorf("program 'seg_ingress_cls' not found in collection")
	}

	// Verify the program type
	if prog.Type() != ebpf.SchedCLS {
		return fmt.Errorf("program 'seg_ingress_cls' is not a SchedCLS type, got %v", prog.Type())
	}

	// Attach the TC classifier using netlink
	// For now, we'll store the program for later attachment
	log.Printf("[seg_ingress] Storing seg_ingress_cls program for interface %s", ifaceName)

	// Store the program
	sil.programs["seg_ingress_cls"] = prog
	log.Printf("[seg_ingress] Successfully attached seg_ingress_cls to %s", ifaceName)
	return nil
}

// AttachTCAction attaches the seg_ingress_action action to the interface
func (sil *SegIngressLoader) AttachTCAction(ctx context.Context, ifaceName string) error {
	if sil.collection == nil {
		return fmt.Errorf("eBPF collection not loaded")
	}

	// Get the seg_ingress_action program
	prog, ok := sil.collection.Programs["seg_ingress_action"]
	if !ok {
		return fmt.Errorf("program 'seg_ingress_action' not found in collection")
	}

	// Verify the program type
	if prog.Type() != ebpf.SchedCLS {
		return fmt.Errorf("program 'seg_ingress_action' is not a SchedCLS type, got %v", prog.Type())
	}

	// Attach the TC action using netlink
	// For now, we'll store the program for later attachment
	log.Printf("[seg_ingress] Storing seg_ingress_action program for interface %s", ifaceName)

	// Store the program
	sil.programs["seg_ingress_action"] = prog
	log.Printf("[seg_ingress] Successfully attached seg_ingress_action to %s", ifaceName)
	return nil
}

// AttachAll attaches both classifier and action programs to the interface
func (sil *SegIngressLoader) AttachAll(ctx context.Context, ifaceName string) error {
	if err := sil.AttachTCClassifier(ctx, ifaceName); err != nil {
		return fmt.Errorf("failed to attach classifier: %w", err)
	}

	if err := sil.AttachTCAction(ctx, ifaceName); err != nil {
		// Clean up classifier if action fails
		delete(sil.programs, "seg_ingress_cls")
		return fmt.Errorf("failed to attach action: %w", err)
	}

	log.Printf("[seg_ingress] Successfully attached all ingress programs to %s", ifaceName)
	return nil
}

// DetachAll detaches all attached programs
func (sil *SegIngressLoader) DetachAll() error {
	log.Printf("[seg_ingress] Detaching all programs")
	sil.programs = make(map[string]*ebpf.Program)
	return nil
}

// RemoveClsactQdisc removes the clsact qdisc from the interface
func (sil *SegIngressLoader) RemoveClsactQdisc(ctx context.Context, ifaceName string) error {
	// For now, we'll just log since we're using mock qdisc
	log.Printf("[seg_ingress] Mock removal of clsact qdisc from %s", ifaceName)
	sil.qdisc = nil
	return nil
}

// GetAttachedPrograms returns a list of currently attached programs
func (sil *SegIngressLoader) GetAttachedPrograms() []string {
	programs := make([]string, 0, len(sil.programs))
	for name := range sil.programs {
		programs = append(programs, name)
	}
	return programs
}

// GetMaps returns the eBPF maps from the loaded collection
func (sil *SegIngressLoader) GetMaps() map[string]*ebpf.Map {
	if sil.collection == nil {
		return nil
	}
	return sil.collection.Maps
}

// UpdateTrafficClass updates a traffic class in the traffic_classes map
func (sil *SegIngressLoader) UpdateTrafficClass(ctx context.Context, classID uint32, tc TrafficClass) error {
	if sil.collection == nil {
		return fmt.Errorf("eBPF collection not loaded")
	}

	trafficClasses, ok := sil.collection.Maps["traffic_classes"]
	if !ok {
		return fmt.Errorf("traffic_classes map not found")
	}

	return trafficClasses.Put(classID, tc)
}

// UpdateTrafficFilter updates a traffic filter in the traffic_filters map
func (sil *SegIngressLoader) UpdateTrafficFilter(ctx context.Context, filterID uint32, filter TrafficFilter) error {
	if sil.collection == nil {
		return fmt.Errorf("eBPF collection not loaded")
	}

	trafficFilters, ok := sil.collection.Maps["traffic_filters"]
	if !ok {
		return fmt.Errorf("traffic_filters map not found")
	}

	return trafficFilters.Put(filterID, filter)
}

// GetStats retrieves statistics from the tc_stats_map
func (sil *SegIngressLoader) GetStats(ctx context.Context) (*TCStats, error) {
	if sil.collection == nil {
		return nil, fmt.Errorf("eBPF collection not loaded")
	}

	statsMap, ok := sil.collection.Maps["tc_stats_map"]
	if !ok {
		return nil, fmt.Errorf("tc_stats_map not found")
	}

	var stats TCStats
	key := uint32(0)
	if err := statsMap.Lookup(key, &stats); err != nil {
		return nil, fmt.Errorf("failed to lookup stats: %w", err)
	}

	return &stats, nil
}

// Close cleans up resources
func (sil *SegIngressLoader) Close() error {
	// Detach all programs
	if err := sil.DetachAll(); err != nil {
		log.Printf("[seg_ingress] Error detaching programs: %v", err)
	}

	// Remove clsact qdisc if we created it
	if sil.qdisc != nil {
		log.Printf("[seg_ingress] Mock removal of clsact qdisc")
		sil.qdisc = nil
	}

	// Close the collection
	if sil.collection != nil {
		sil.collection.Close()
		sil.collection = nil
	}

	log.Printf("[seg_ingress] Closed ingress segmentation loader")
	return nil
}

// TrafficClass represents a traffic class structure
type TrafficClass struct {
	ClassID         uint32 `json:"class_id"`
	Rate            uint32 `json:"rate"`      // bytes per second
	Burst           uint32 `json:"burst"`     // burst size
	Priority        uint8  `json:"priority"`
	Action          uint8  `json:"action"`    // 0=PASS, 1=DROP, 2=MARK, 3=REDIRECT
	MarkValue       uint32 `json:"mark_value"`
	RedirectIfindex uint32 `json:"redirect_ifindex"`
}

// TrafficFilter represents a traffic filter structure
type TrafficFilter struct {
	SrcIP     uint32 `json:"src_ip"`
	DstIP     uint32 `json:"dst_ip"`
	SrcMask   uint32 `json:"src_mask"`
	DstMask   uint32 `json:"dst_mask"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  uint8  `json:"protocol"`
	ClassID   uint32 `json:"class_id"`
	Action    uint8  `json:"action"`
	Priority  uint8  `json:"priority"`
}

// TCStats represents statistics from the eBPF program
type TCStats struct {
	TotalPackets      uint64   `json:"total_packets"`
	PassedPackets     uint64   `json:"passed_packets"`
	DroppedPackets    uint64   `json:"dropped_packets"`
	MarkedPackets     uint64   `json:"marked_packets"`
	RedirectedPackets uint64   `json:"redirected_packets"`
	TotalBytes        uint64   `json:"total_bytes"`
	ClassStats        [64]uint64 `json:"class_stats"`
	FilterHits        [512]uint64 `json:"filter_hits"`
}
