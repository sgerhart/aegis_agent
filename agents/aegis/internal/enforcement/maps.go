package enforcement

import (
	"fmt"
	"net"

	"agents/aegis/pkg/models"
	"github.com/cilium/ebpf"
)

// PolicyEdge represents a policy edge in eBPF maps
type PolicyEdge struct {
	SrcIP    uint32
	DstIP    uint32
	Protocol uint8
	Action   uint8 // 0=BLOCK, 1=ALLOW
	Port     uint16
	Flags    uint16
}

// AllowCIDR represents an allowed CIDR range
type AllowCIDR struct {
	Prefix uint32
	Len    uint32
	Action uint8
}

// MapManager manages eBPF maps for policy enforcement
type MapManager struct {
	blockedDestinations *ebpf.Map
	policyEdges        *ebpf.Map
	allowLPM4          *ebpf.Map
	mode               *ebpf.Map
}

// NewMapManager creates a new map manager
func NewMapManager() (*MapManager, error) {
	mm := &MapManager{}
	
	// Load maps
	if err := mm.loadMaps(); err != nil {
		return nil, fmt.Errorf("failed to load maps: %w", err)
	}
	
	return mm, nil
}

// loadMaps loads eBPF maps
func (mm *MapManager) loadMaps() error {
	// Load blocked destinations map
	blockedMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/aegis_blocked_destinations", nil)
	if err != nil {
		return fmt.Errorf("failed to load blocked destinations map: %w", err)
	}
	mm.blockedDestinations = blockedMap
	
	// Load policy edges map
	edgesMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/policy_edges", nil)
	if err != nil {
		return fmt.Errorf("failed to load policy edges map: %w", err)
	}
	mm.policyEdges = edgesMap
	
	// Load allow LPM4 map
	allowMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/allow_lpm4", nil)
	if err != nil {
		return fmt.Errorf("failed to load allow LPM4 map: %w", err)
	}
	mm.allowLPM4 = allowMap
	
	// Load mode map
	modeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/mode", nil)
	if err != nil {
		return fmt.Errorf("failed to load mode map: %w", err)
	}
	mm.mode = modeMap
	
	return nil
}

// WritePolicyEdge writes a policy edge to the map
func (mm *MapManager) WritePolicyEdge(edgeID uint32, edge PolicyEdge) error {
	return mm.policyEdges.Put(edgeID, edge)
}

// WriteAllowCIDR writes an allowed CIDR to the map
func (mm *MapManager) WriteAllowCIDR(cidr AllowCIDR) error {
	// Create LPM key: prefix length (4 bytes) + IP address (4 bytes)
	key := make([]byte, 8)
	key[0] = byte(cidr.Len >> 24)
	key[1] = byte(cidr.Len >> 16)
	key[2] = byte(cidr.Len >> 8)
	key[3] = byte(cidr.Len)
	key[4] = byte(cidr.Prefix >> 24)
	key[5] = byte(cidr.Prefix >> 16)
	key[6] = byte(cidr.Prefix >> 8)
	key[7] = byte(cidr.Prefix)
	
	return mm.allowLPM4.Put(key, uint32(cidr.Action))
}

// SetMode sets the enforcement mode
func (mm *MapManager) SetMode(mode uint32) error {
	return mm.mode.Put(uint32(0), mode)
}

// GetMode gets the current enforcement mode
func (mm *MapManager) GetMode() (uint32, error) {
	var mode uint32
	err := mm.mode.Lookup(uint32(0), &mode)
	return mode, err
}

// BlockDestination blocks a destination IP
func (mm *MapManager) BlockDestination(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("IPv6 not supported")
	}
	
	key := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
	value := uint32(1) // Block
	
	return mm.blockedDestinations.Put(key, value)
}

// AllowDestination allows a destination IP
func (mm *MapManager) AllowDestination(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("IPv6 not supported")
	}
	
	key := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
	
	return mm.blockedDestinations.Delete(key)
}

// ApplyPolicy applies a policy to the maps
func (mm *MapManager) ApplyPolicy(policy *models.Policy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	
	// Apply each rule in the policy
	for _, rule := range policy.Rules {
		if err := mm.applyRule(rule); err != nil {
			return fmt.Errorf("failed to apply rule %s: %w", rule.ID, err)
		}
	}
	
	return nil
}

// applyRule applies a single rule to the maps
func (mm *MapManager) applyRule(rule models.Rule) error {
	// Convert action to numeric value
	var action uint8
	switch rule.Action {
	case "allow":
		action = 1
	case "deny", "drop":
		action = 0
	case "log":
		action = 2
	default:
		action = 0
	}
	
	// Process conditions
	for _, condition := range rule.Conditions {
		if err := mm.applyCondition(condition, action); err != nil {
			return fmt.Errorf("failed to apply condition: %w", err)
		}
	}
	
	return nil
}

// applyCondition applies a condition to the maps
func (mm *MapManager) applyCondition(condition models.Condition, action uint8) error {
	switch condition.Field {
	case "destination_ip":
		return mm.applyDestinationIPCondition(condition, action)
	case "source_ip":
		return mm.applySourceIPCondition(condition, action)
	case "protocol":
		return mm.applyProtocolCondition(condition, action)
	case "port":
		return mm.applyPortCondition(condition, action)
	default:
		return fmt.Errorf("unsupported condition field: %s", condition.Field)
	}
}

// applyDestinationIPCondition applies destination IP condition
func (mm *MapManager) applyDestinationIPCondition(condition models.Condition, action uint8) error {
	ipStr := fmt.Sprintf("%v", condition.Value)
	
	if action == 0 { // Block
		return mm.BlockDestination(ipStr)
	} else { // Allow
		return mm.AllowDestination(ipStr)
	}
}

// applySourceIPCondition applies source IP condition
func (mm *MapManager) applySourceIPCondition(condition models.Condition, action uint8) error {
	// For now, we'll treat source IP the same as destination IP
	// In production, this would use a separate map or different logic
	ipStr := fmt.Sprintf("%v", condition.Value)
	
	if action == 0 { // Block
		return mm.BlockDestination(ipStr)
	} else { // Allow
		return mm.AllowDestination(ipStr)
	}
}

// applyProtocolCondition applies protocol condition
func (mm *MapManager) applyProtocolCondition(condition models.Condition, action uint8) error {
	// Protocol-based conditions would require more complex eBPF programs
	// For now, we'll log and skip
	return nil
}

// applyPortCondition applies port condition
func (mm *MapManager) applyPortCondition(condition models.Condition, action uint8) error {
	// Port-based conditions would require more complex eBPF programs
	// For now, we'll log and skip
	return nil
}

// ClearPolicyEdges clears all policy edges
func (mm *MapManager) ClearPolicyEdges() error {
	return mm.clearMap(mm.policyEdges)
}

// ClearAllowCIDRs clears all allowed CIDRs
func (mm *MapManager) ClearAllowCIDRs() error {
	return mm.clearMap(mm.allowLPM4)
}

// clearMap clears all entries from a map
func (mm *MapManager) clearMap(m *ebpf.Map) error {
	var key []byte
	iter := m.Iterate()
	
	for iter.Next(&key, nil) {
		if err := m.Delete(key); err != nil {
			return fmt.Errorf("failed to delete map entry: %w", err)
		}
	}
	
	return nil
}

// Close closes all maps
func (mm *MapManager) Close() error {
	var errors []error
	
	if mm.blockedDestinations != nil {
		if err := mm.blockedDestinations.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close blocked destinations map: %w", err))
		}
	}
	
	if mm.policyEdges != nil {
		if err := mm.policyEdges.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close policy edges map: %w", err))
		}
	}
	
	if mm.allowLPM4 != nil {
		if err := mm.allowLPM4.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close allow LPM4 map: %w", err))
		}
	}
	
	if mm.mode != nil {
		if err := mm.mode.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close mode map: %w", err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("failed to close maps: %v", errors)
	}
	
	return nil
}
