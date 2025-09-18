package policy

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Writer handles writing policy data to eBPF maps
type Writer struct {
	policyEdgesMap *ebpf.Map
	allowLPM4Map   *ebpf.Map
	metadataMap    *ebpf.Map
}

// NewWriter creates a new policy writer
func NewWriter() (*Writer, error) {
	// Remove memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[policy_writer] Failed to remove memlock rlimit: %v", err)
	}

	w := &Writer{}
	
	// Try to open existing pinned maps
	if err := w.openPinnedMaps(); err != nil {
		log.Printf("[policy_writer] Failed to open pinned maps: %v", err)
		// Continue with mock implementation for non-Linux systems
	}

	return w, nil
}

// openPinnedMaps opens the existing pinned eBPF maps
func (w *Writer) openPinnedMaps() error {
	// Try to open policy_edges map
	if policyEdgesMap, err := ebpf.LoadPinnedMap(filepath.Join(PinPolicyEdges), nil); err == nil {
		w.policyEdgesMap = policyEdgesMap
		log.Printf("[policy_writer] Opened pinned policy_edges map")
	} else {
		log.Printf("[policy_writer] Could not open policy_edges map: %v", err)
	}

	// Try to open allow_lpm4 map
	if allowLPM4Map, err := ebpf.LoadPinnedMap(filepath.Join(PinAllowLPM4), nil); err == nil {
		w.allowLPM4Map = allowLPM4Map
		log.Printf("[policy_writer] Opened pinned allow_lpm4 map")
	} else {
		log.Printf("[policy_writer] Could not open allow_lpm4 map: %v", err)
	}

	return nil
}

// Close closes the policy writer and its maps
func (w *Writer) Close() error {
	if w.policyEdgesMap != nil {
		w.policyEdgesMap.Close()
	}
	if w.allowLPM4Map != nil {
		w.allowLPM4Map.Close()
	}
	if w.metadataMap != nil {
		w.metadataMap.Close()
	}
	return nil
}

// PolicyEdge represents a network segmentation policy edge
type PolicyEdge struct {
	ID          uint32 `json:"id"`
	SrcIP       uint32 `json:"src_ip"`
	DstIP       uint32 `json:"dst_ip"`
	SrcMask     uint32 `json:"src_mask"`
	DstMask     uint32 `json:"dst_mask"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    uint8  `json:"protocol"`
	Action      uint8  `json:"action"` // 0=BLOCK, 1=ALLOW, 2=LOG
	Priority    uint8  `json:"priority"`
	ProcessUID  uint32 `json:"process_uid"`
	ProcessGID  uint32 `json:"process_gid"`
	Timestamp   uint64 `json:"timestamp"`
}

// AllowCIDR represents a CIDR allowlist entry
type AllowCIDR struct {
	PrefixLen uint32 `json:"prefix_len"`
	IP        uint32 `json:"ip"`
	Action    uint8  `json:"action"` // 0=BLOCK, 1=ALLOW
	Priority  uint8  `json:"priority"`
	Timestamp uint64 `json:"timestamp"`
}

// WriteEdges writes policy edges to the eBPF map
func (w *Writer) WriteEdges(ctx context.Context, edges []PolicyEdge) error {
	if w.policyEdgesMap == nil {
		log.Printf("[policy_writer] Mock: Writing %d policy edges", len(edges))
		return w.writeEdgesMock(edges)
	}

	log.Printf("[policy_writer] Writing %d policy edges to eBPF map", len(edges))
	
	for _, edge := range edges {
		key := edge.ID
		if err := w.policyEdgesMap.Put(key, edge); err != nil {
			return fmt.Errorf("failed to write policy edge %d: %w", edge.ID, err)
		}
		log.Printf("[policy_writer] Wrote policy edge %d: %s -> %s", edge.ID, 
			formatIP(edge.SrcIP), formatIP(edge.DstIP))
	}

	return nil
}

// WriteAllowCIDRs writes allow CIDRs to the eBPF map
func (w *Writer) WriteAllowCIDRs(ctx context.Context, cidrs []AllowCIDR) error {
	if w.allowLPM4Map == nil {
		log.Printf("[policy_writer] Mock: Writing %d allow CIDRs", len(cidrs))
		return w.writeAllowCIDRsMock(cidrs)
	}

	log.Printf("[policy_writer] Writing %d allow CIDRs to eBPF map", len(cidrs))
	
	for _, cidr := range cidrs {
		if err := w.allowLPM4Map.Put(cidr, uint8(1)); err != nil {
			return fmt.Errorf("failed to write allow CIDR %s/%d: %w", 
				formatIP(cidr.IP), cidr.PrefixLen, err)
		}
		log.Printf("[policy_writer] Wrote allow CIDR %s/%d", 
			formatIP(cidr.IP), cidr.PrefixLen)
	}

	return nil
}

// WriteMetadata writes metadata to the eBPF map
func (w *Writer) WriteMetadata(ctx context.Context, metadata map[string]string) error {
	log.Printf("[policy_writer] Writing metadata: %+v", metadata)
	// For now, just log the metadata
	// In a real implementation, this would write to a metadata map
	return nil
}

// writeEdgesMock writes policy edges to mock files for testing
func (w *Writer) writeEdgesMock(edges []PolicyEdge) error {
	// Create mock directory
	mockDir := "/tmp/sys/fs/bpf/aegis"
	if err := os.MkdirAll(mockDir, 0755); err != nil {
		return fmt.Errorf("failed to create mock directory: %w", err)
	}

	// Write edges to mock file
	edgesFile := filepath.Join(mockDir, "policy_edges")
	content := fmt.Sprintf("Policy Edges (%d entries):\n", len(edges))
	for _, edge := range edges {
		content += fmt.Sprintf("  ID=%d: %s -> %s (TCP %d->%d, %s)\n", 
			edge.ID, formatIP(edge.SrcIP), formatIP(edge.DstIP), 
			edge.SrcPort, edge.DstPort, actionToString(edge.Action))
	}

	return os.WriteFile(edgesFile, []byte(content), 0644)
}

// writeAllowCIDRsMock writes allow CIDRs to mock files for testing
func (w *Writer) writeAllowCIDRsMock(cidrs []AllowCIDR) error {
	// Create mock directory
	mockDir := "/tmp/sys/fs/bpf/aegis"
	if err := os.MkdirAll(mockDir, 0755); err != nil {
		return fmt.Errorf("failed to create mock directory: %w", err)
	}

	// Write CIDRs to mock file
	cidrsFile := filepath.Join(mockDir, "allow_lpm4")
	content := fmt.Sprintf("Allow CIDRs (%d entries):\n", len(cidrs))
	for _, cidr := range cidrs {
		content += fmt.Sprintf("  %s/%d (%s)\n", 
			formatIP(cidr.IP), cidr.PrefixLen, actionToString(cidr.Action))
	}

	return os.WriteFile(cidrsFile, []byte(content), 0644)
}

// formatIP formats an IP address from uint32
func formatIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", 
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}

// actionToString converts action code to string
func actionToString(action uint8) string {
	switch action {
	case 0:
		return "BLOCK"
	case 1:
		return "ALLOW"
	case 2:
		return "LOG"
	default:
		return "UNKNOWN"
	}
}
