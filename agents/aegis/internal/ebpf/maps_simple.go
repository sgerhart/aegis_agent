package ebpf

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
)

// SimpleMapManager manages eBPF maps with simplified structures
type SimpleMapManager struct {
	policyEdgesMap *ebpf.Map
	allowLPM4Map   *ebpf.Map
	modeMap        *ebpf.Map
	statsMap       *ebpf.Map
}

// NewSimpleMapManager creates a new simple map manager
func NewSimpleMapManager() (*SimpleMapManager, error) {
	sm := &SimpleMapManager{}
	
	// Load policy_edges map
	policyEdgesMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/policy_edges", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy_edges map: %w", err)
	}
	sm.policyEdgesMap = policyEdgesMap

	// Load allow_lpm4 map
	allowLPM4Map, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/allow_lpm4", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load allow_lpm4 map: %w", err)
	}
	sm.allowLPM4Map = allowLPM4Map

	// Load mode map
	modeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/mode", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load mode map: %w", err)
	}
	sm.modeMap = modeMap

	// Load stats map
	statsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/policy_stats_map", nil)
	if err != nil {
		log.Printf("[maps] Warning: failed to load stats map: %v", err)
		// Stats map is optional
	}
	sm.statsMap = statsMap

	log.Printf("[maps] Loaded eBPF maps successfully")
	return sm, nil
}

// SimplePolicyEdge represents a simplified policy edge (32 bytes total)
type SimplePolicyEdge struct {
	SrcIP    uint32 // 4 bytes
	DstIP    uint32 // 4 bytes
	SrcPort  uint16 // 2 bytes
	DstPort  uint16 // 2 bytes
	Protocol uint8  // 1 byte
	Action   uint8  // 1 byte
	_        [18]byte // padding to 32 bytes
}

// SimpleAllowCIDR represents a simplified allow CIDR (16 bytes total)
type SimpleAllowCIDR struct {
	IP        uint32 // 4 bytes
	PrefixLen uint32 // 4 bytes
	Action    uint8  // 1 byte
	Priority  uint8  // 1 byte
	_         [6]byte // padding to 16 bytes
}

// WritePolicyEdge writes a policy edge to the eBPF map
func (sm *SimpleMapManager) WritePolicyEdge(edgeID uint32, edge PolicyEdge) error {
	if sm.policyEdgesMap == nil {
		return fmt.Errorf("policy_edges map not loaded")
	}

	// Convert to simple format
	simpleEdge := SimplePolicyEdge{
		SrcIP:    edge.SrcIP,
		DstIP:    edge.DstIP,
		SrcPort:  edge.SrcPort,
		DstPort:  edge.DstPort,
		Protocol: edge.Protocol,
		Action:   edge.Action,
	}

	if err := sm.policyEdgesMap.Put(edgeID, simpleEdge); err != nil {
		return fmt.Errorf("failed to write policy edge %d: %w", edgeID, err)
	}

	log.Printf("[maps] Wrote policy edge %d: %s -> %s (action=%d)", 
		edgeID, formatIP(edge.SrcIP), formatIP(edge.DstIP), edge.Action)
	return nil
}

// WriteAllowCIDR writes an allow CIDR to the eBPF map
func (sm *SimpleMapManager) WriteAllowCIDR(cidr AllowCIDR) error {
	if sm.allowLPM4Map == nil {
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

	// Create simple value
	value := SimpleAllowCIDR{
		IP:        cidr.IP,
		PrefixLen: cidr.PrefixLen,
		Action:    cidr.Action,
		Priority:  cidr.Priority,
	}

	if err := sm.allowLPM4Map.Put(key, value); err != nil {
		return fmt.Errorf("failed to write allow CIDR: %w", err)
	}

	log.Printf("[maps] Wrote allow CIDR: %s/%d (action=%d)", 
		formatIP(cidr.IP), cidr.PrefixLen, cidr.Action)
	return nil
}

// SetMode sets the enforcement mode (0=observe, 1=block)
func (sm *SimpleMapManager) SetMode(mode uint32) error {
	if sm.modeMap == nil {
		return fmt.Errorf("mode map not loaded")
	}

	key := uint32(0) // Single global mode
	if err := sm.modeMap.Put(key, mode); err != nil {
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
func (sm *SimpleMapManager) GetMode() (uint32, error) {
	if sm.modeMap == nil {
		return 0, fmt.Errorf("mode map not loaded")
	}

	key := uint32(0)
	var mode uint32
	if err := sm.modeMap.Lookup(key, &mode); err != nil {
		return 0, fmt.Errorf("failed to get mode: %w", err)
	}

	return mode, nil
}

// ClearPolicyEdges clears all policy edges
func (sm *SimpleMapManager) ClearPolicyEdges() error {
	if sm.policyEdgesMap == nil {
		return fmt.Errorf("policy_edges map not loaded")
	}

	// Iterate and delete all entries
	var key uint32
	var nextKey uint32
	iter := sm.policyEdgesMap.Iterate()
	
	for iter.Next(&key, &nextKey) {
		if err := sm.policyEdgesMap.Delete(key); err != nil {
			log.Printf("[maps] Warning: failed to delete policy edge %d: %v", key, err)
		}
		key = nextKey
	}

	log.Printf("[maps] Cleared all policy edges")
	return nil
}

// ClearAllowCIDRs clears all allow CIDRs
func (sm *SimpleMapManager) ClearAllowCIDRs() error {
	if sm.allowLPM4Map == nil {
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
	iter := sm.allowLPM4Map.Iterate()
	
	for iter.Next(&key, &nextKey) {
		if err := sm.allowLPM4Map.Delete(key); err != nil {
			log.Printf("[maps] Warning: failed to delete allow CIDR: %v", err)
		}
		key = nextKey
	}

	log.Printf("[maps] Cleared all allow CIDRs")
	return nil
}

// Close closes all maps
func (sm *SimpleMapManager) Close() error {
	if sm.policyEdgesMap != nil {
		sm.policyEdgesMap.Close()
	}
	if sm.allowLPM4Map != nil {
		sm.allowLPM4Map.Close()
	}
	if sm.modeMap != nil {
		sm.modeMap.Close()
	}
	if sm.statsMap != nil {
		sm.statsMap.Close()
	}
	return nil
}

// Ensure SimpleMapManager implements MapManagerInterface
var _ MapManagerInterface = (*SimpleMapManager)(nil)

