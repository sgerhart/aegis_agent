package ebpf

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
)

// MapManager manages eBPF maps for policy enforcement
type MapManager struct {
	policyEdgesMap *ebpf.Map
	allowLPM4Map   *ebpf.Map
	modeMap        *ebpf.Map
	statsMap       *ebpf.Map
}

// NewMapManager creates a new map manager and loads pinned maps
func NewMapManager() (*MapManager, error) {
	mm := &MapManager{}
	
	// Load policy_edges map
	policyEdgesMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/policy_edges", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy_edges map: %w", err)
	}
	mm.policyEdgesMap = policyEdgesMap

	// Load allow_lpm4 map
	allowLPM4Map, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/allow_lpm4", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load allow_lpm4 map: %w", err)
	}
	mm.allowLPM4Map = allowLPM4Map

	// Load mode map
	modeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/mode", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load mode map: %w", err)
	}
	mm.modeMap = modeMap

	// Load stats map
	statsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/policy_stats_map", nil)
	if err != nil {
		log.Printf("[maps] Warning: failed to load stats map: %v", err)
		// Stats map is optional
	}
	mm.statsMap = statsMap

	log.Printf("[maps] Loaded eBPF maps successfully")
	return mm, nil
}

// PolicyEdge represents a policy edge for network segmentation
type PolicyEdge struct {
	SrcIP      uint32
	DstIP      uint32
	SrcMask    uint32
	DstMask    uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	Action     uint8 // 0=BLOCK, 1=ALLOW, 2=LOG
	Priority   uint8
	ProcessUID uint32
	ProcessGID uint32
	Timestamp  uint64
}

// AllowCIDR represents an LPM entry for IPv4 CIDR allow/deny
type AllowCIDR struct {
	IP        uint32
	PrefixLen uint32
	Action    uint8 // 0=BLOCK, 1=ALLOW
	Priority  uint8
	Timestamp uint64
}

// WritePolicyEdge writes a policy edge to the policy_edges map
func (mm *MapManager) WritePolicyEdge(edgeID uint32, edge PolicyEdge) error {
	if mm.policyEdgesMap == nil {
		return fmt.Errorf("policy_edges map not loaded")
	}

	// Convert to eBPF struct format
	ebpfEdge := struct {
		SrcIP      uint32
		DstIP      uint32
		SrcMask    uint32
		DstMask    uint32
		SrcPort    uint16
		DstPort    uint16
		Protocol   uint8
		Action     uint8
		Priority   uint8
		ProcessUID uint32
		ProcessGID uint32
		Timestamp  uint64
	}{
		SrcIP:      edge.SrcIP,
		DstIP:      edge.DstIP,
		SrcMask:    edge.SrcMask,
		DstMask:    edge.DstMask,
		SrcPort:    edge.SrcPort,
		DstPort:    edge.DstPort,
		Protocol:   edge.Protocol,
		Action:     edge.Action,
		Priority:   edge.Priority,
		ProcessUID: edge.ProcessUID,
		ProcessGID: edge.ProcessGID,
		Timestamp:  edge.Timestamp,
	}

	if err := mm.policyEdgesMap.Put(edgeID, ebpfEdge); err != nil {
		return fmt.Errorf("failed to write policy edge %d: %w", edgeID, err)
	}

	log.Printf("[maps] Wrote policy edge %d: %s -> %s (action=%d)", 
		edgeID, formatIP(edge.SrcIP), formatIP(edge.DstIP), edge.Action)
	return nil
}

// WriteAllowCIDR writes an allow CIDR to the allow_lpm4 map
func (mm *MapManager) WriteAllowCIDR(cidr AllowCIDR) error {
	if mm.allowLPM4Map == nil {
		return fmt.Errorf("allow_lpm4 map not loaded")
	}

	// Create LPM key (prefix_len + ip)
	key := struct {
		PrefixLen uint32
		IP        uint32
	}{
		PrefixLen: cidr.PrefixLen,
		IP:        cidr.IP,
	}

	// Create value (action + priority + timestamp)
	value := struct {
		Action    uint8
		Priority  uint8
		Timestamp uint64
	}{
		Action:    cidr.Action,
		Priority:  cidr.Priority,
		Timestamp: cidr.Timestamp,
	}

	if err := mm.allowLPM4Map.Put(key, value); err != nil {
		return fmt.Errorf("failed to write allow CIDR: %w", err)
	}

	log.Printf("[maps] Wrote allow CIDR: %s/%d (action=%d)", 
		formatIP(cidr.IP), cidr.PrefixLen, cidr.Action)
	return nil
}

// SetMode sets the enforcement mode (0=observe, 1=block)
func (mm *MapManager) SetMode(mode uint32) error {
	if mm.modeMap == nil {
		return fmt.Errorf("mode map not loaded")
	}

	key := uint32(0) // Single global mode
	if err := mm.modeMap.Put(key, mode); err != nil {
		return fmt.Errorf("failed to set mode to %d: %w", mode, err)
	}

	modeStr := "observe"
	if mode == 1 {
		modeStr = "block"
	}
	log.Printf("[maps] Set enforcement mode to %s (%d)", modeStr, mode)
	return nil
}

// GetMode gets the current enforcement mode
func (mm *MapManager) GetMode() (uint32, error) {
	if mm.modeMap == nil {
		return 0, fmt.Errorf("mode map not loaded")
	}

	key := uint32(0)
	var mode uint32
	if err := mm.modeMap.Lookup(key, &mode); err != nil {
		return 0, fmt.Errorf("failed to get mode: %w", err)
	}

	return mode, nil
}

// ClearPolicyEdges clears all policy edges
func (mm *MapManager) ClearPolicyEdges() error {
	if mm.policyEdgesMap == nil {
		return fmt.Errorf("policy_edges map not loaded")
	}

	// Iterate and delete all entries
	var key uint32
	var nextKey uint32
	iter := mm.policyEdgesMap.Iterate()
	
	for iter.Next(&key, &nextKey) {
		if err := mm.policyEdgesMap.Delete(key); err != nil {
			log.Printf("[maps] Warning: failed to delete policy edge %d: %v", key, err)
		}
		key = nextKey
	}

	log.Printf("[maps] Cleared all policy edges")
	return nil
}

// ClearAllowCIDRs clears all allow CIDRs
func (mm *MapManager) ClearAllowCIDRs() error {
	if mm.allowLPM4Map == nil {
		return fmt.Errorf("allow_lpm4 map not loaded")
	}

	// Iterate and delete all entries
	key := struct {
		PrefixLen uint32
		IP        uint32
	}{}
	nextKey := struct {
		PrefixLen uint32
		IP        uint32
	}{}
	iter := mm.allowLPM4Map.Iterate()
	
	for iter.Next(&key, &nextKey) {
		if err := mm.allowLPM4Map.Delete(key); err != nil {
			log.Printf("[maps] Warning: failed to delete allow CIDR: %v", err)
		}
		key = nextKey
	}

	log.Printf("[maps] Cleared all allow CIDRs")
	return nil
}

// Close closes all maps
func (mm *MapManager) Close() error {
	if mm.policyEdgesMap != nil {
		mm.policyEdgesMap.Close()
	}
	if mm.allowLPM4Map != nil {
		mm.allowLPM4Map.Close()
	}
	if mm.modeMap != nil {
		mm.modeMap.Close()
	}
	if mm.statsMap != nil {
		mm.statsMap.Close()
	}
	return nil
}

// Helper functions

// formatIP formats an IP address for logging
func formatIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", 
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}

// parseCIDR parses a CIDR string and returns IP and prefix length
func parseCIDR(cidrStr string) (uint32, uint32, error) {
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return 0, 0, err
	}

	ip := network.IP.To4()
	if ip == nil {
		return 0, 0, fmt.Errorf("not an IPv4 address")
	}

	prefixLen, _ := network.Mask.Size()
	
	// Convert IP to uint32
	ipUint32 := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	
	return ipUint32, uint32(prefixLen), nil
}

// CreateAllowCIDRFromString creates an AllowCIDR from a CIDR string
func CreateAllowCIDRFromString(cidrStr string, action uint8, priority uint8) (*AllowCIDR, error) {
	ip, prefixLen, err := parseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	return &AllowCIDR{
		IP:        ip,
		PrefixLen: prefixLen,
		Action:    action,
		Priority:  priority,
		Timestamp: 0, // Will be set by caller
	}, nil
}

