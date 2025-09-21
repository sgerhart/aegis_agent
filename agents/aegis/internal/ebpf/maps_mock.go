package ebpf

import (
	"fmt"
	"log"
)

// MockMapManager manages eBPF maps for testing (no real eBPF)
type MockMapManager struct {
	policyEdgesMap map[uint32]PolicyEdge
	allowLPM4Map   map[string]AllowCIDR
	modeMap        map[uint32]uint32
	statsMap       map[string]interface{}
}

// NewMockMapManager creates a new mock map manager
func NewMockMapManager() *MockMapManager {
	return &MockMapManager{
		policyEdgesMap: make(map[uint32]PolicyEdge),
		allowLPM4Map:   make(map[string]AllowCIDR),
		modeMap:        make(map[uint32]uint32),
		statsMap:       make(map[string]interface{}),
	}
}

// WritePolicyEdge writes a policy edge to the mock map
func (mm *MockMapManager) WritePolicyEdge(edgeID uint32, edge PolicyEdge) error {
	mm.policyEdgesMap[edgeID] = edge
	log.Printf("[mock_maps] Wrote policy edge %d: %s -> %s (action=%d)", 
		edgeID, formatIP(edge.SrcIP), formatIP(edge.DstIP), edge.Action)
	return nil
}

// WriteAllowCIDR writes an allow CIDR to the mock map
func (mm *MockMapManager) WriteAllowCIDR(cidr AllowCIDR) error {
	key := fmt.Sprintf("%d.%d.%d.%d/%d", 
		(cidr.IP>>24)&0xFF, (cidr.IP>>16)&0xFF, (cidr.IP>>8)&0xFF, cidr.IP&0xFF,
		cidr.PrefixLen)
	mm.allowLPM4Map[key] = cidr
	log.Printf("[mock_maps] Wrote allow CIDR: %s (action=%d)", key, cidr.Action)
	return nil
}

// SetMode sets the enforcement mode
func (mm *MockMapManager) SetMode(mode uint32) error {
	mm.modeMap[0] = mode
	modeStr := "observe"
	if mode == 1 {
		modeStr = "block"
	}
	log.Printf("[mock_maps] Set enforcement mode to %s (%d)", modeStr, mode)
	return nil
}

// GetMode gets the current enforcement mode
func (mm *MockMapManager) GetMode() (uint32, error) {
	mode, exists := mm.modeMap[0]
	if !exists {
		return 0, nil // Default to observe
	}
	return mode, nil
}

// ClearPolicyEdges clears all policy edges
func (mm *MockMapManager) ClearPolicyEdges() error {
	mm.policyEdgesMap = make(map[uint32]PolicyEdge)
	log.Printf("[mock_maps] Cleared all policy edges")
	return nil
}

// ClearAllowCIDRs clears all allow CIDRs
func (mm *MockMapManager) ClearAllowCIDRs() error {
	mm.allowLPM4Map = make(map[string]AllowCIDR)
	log.Printf("[mock_maps] Cleared all allow CIDRs")
	return nil
}

// Close closes all maps
func (mm *MockMapManager) Close() error {
	log.Printf("[mock_maps] Closed mock maps")
	return nil
}

// GetPolicyEdges returns all policy edges
func (mm *MockMapManager) GetPolicyEdges() map[uint32]PolicyEdge {
	return mm.policyEdgesMap
}

// GetAllowCIDRs returns all allow CIDRs
func (mm *MockMapManager) GetAllowCIDRs() map[string]AllowCIDR {
	return mm.allowLPM4Map
}

