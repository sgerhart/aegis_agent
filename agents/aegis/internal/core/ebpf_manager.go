package core

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"agents/aegis/pkg/models"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// EBPFManager manages eBPF programs and maps
type EBPFManager struct {
	// eBPF programs
	programs map[string]*ebpf.Program
	links    map[string]link.Link
	
	// eBPF maps
	maps map[string]*ebpf.Map
	
	// State
	initialized bool
	mu          sync.RWMutex
}

// NewEBPFManager creates a new eBPF manager
func NewEBPFManager() (*EBPFManager, error) {
	em := &EBPFManager{
		programs: make(map[string]*ebpf.Program),
		links:    make(map[string]link.Link),
		maps:     make(map[string]*ebpf.Map),
	}
	
	if err := em.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize eBPF manager: %w", err)
	}
	
	log.Printf("[ebpf_manager] eBPF manager initialized successfully")
	return em, nil
}

// initialize initializes the eBPF manager
func (em *EBPFManager) initialize() error {
	em.mu.Lock()
	defer em.mu.Unlock()
	
	if em.initialized {
		return fmt.Errorf("eBPF manager already initialized")
	}
	
	// Load eBPF maps
	if err := em.loadMaps(); err != nil {
		return fmt.Errorf("failed to load eBPF maps: %w", err)
	}
	
	// Load eBPF programs
	if err := em.loadPrograms(); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}
	
	// Attach programs
	if err := em.attachPrograms(); err != nil {
		return fmt.Errorf("failed to attach eBPF programs: %w", err)
	}
	
	em.initialized = true
	return nil
}

// loadMaps loads eBPF maps
func (em *EBPFManager) loadMaps() error {
	// Load basic eBPF maps
	mapNames := []string{
		"aegis_blocked_destinations",
		"policy_edges",
		"allow_lpm4",
		"mode",
	}
	
	for _, mapName := range mapNames {
		m, err := em.loadMap(mapName)
		if err != nil {
			log.Printf("[ebpf_manager] Warning: failed to load map %s: %v", mapName, err)
			continue
		}
		em.maps[mapName] = m
		log.Printf("[ebpf_manager] Loaded map: %s", mapName)
	}
	
	return nil
}

// loadMap loads a specific eBPF map
func (em *EBPFManager) loadMap(mapName string) (*ebpf.Map, error) {
	// Try to load pinned map first
	pinnedPath := fmt.Sprintf("/sys/fs/bpf/aegis/%s", mapName)
	m, err := ebpf.LoadPinnedMap(pinnedPath, nil)
	if err == nil {
		return m, nil
	}
	
	// If pinned map doesn't exist, create a new one
	// This is a simplified approach - in production, maps should be created by eBPF programs
	log.Printf("[ebpf_manager] Pinned map %s not found, creating new map", mapName)
	
	// Define map specs based on map name
	var mapSpec *ebpf.MapSpec
	switch mapName {
	case "aegis_blocked_destinations":
		mapSpec = &ebpf.MapSpec{
			Type:       ebpf.Hash,
			KeySize:    4, // uint32
			ValueSize:  4, // uint32
			MaxEntries: 1024,
		}
	case "policy_edges":
		mapSpec = &ebpf.MapSpec{
			Type:       ebpf.Hash,
			KeySize:    4, // uint32
			ValueSize:  16, // PolicyEdge struct
			MaxEntries: 1024,
		}
	case "allow_lpm4":
		mapSpec = &ebpf.MapSpec{
			Type:       ebpf.LPMTrie,
			KeySize:    8, // 4 bytes prefix + 4 bytes IP
			ValueSize:  4, // uint32
			MaxEntries: 1024,
		}
	case "mode":
		mapSpec = &ebpf.MapSpec{
			Type:       ebpf.Array,
			KeySize:    4, // uint32
			ValueSize:  4, // uint32
			MaxEntries: 1,
		}
	default:
		return nil, fmt.Errorf("unknown map type: %s", mapName)
	}
	
	m, err = ebpf.NewMap(mapSpec)
	if err != nil {
		// Check if it's a MEMLOCK permission issue
		if strings.Contains(err.Error(), "MEMLOCK") || strings.Contains(err.Error(), "operation not permitted") {
			log.Printf("[ebpf_manager] Warning: failed to create map %s due to insufficient permissions (MEMLOCK may be too low): %v", mapName, err)
			log.Printf("[ebpf_manager] Consider running: sudo ulimit -l unlimited")
			return nil, fmt.Errorf("failed to create map %s: creating map: map create: operation not permitted (MEMLOCK may be too low, consider rlimit.RemoveMemlock)", mapName)
		}
		return nil, fmt.Errorf("failed to create map %s: %w", mapName, err)
	}
	
	return m, nil
}

// loadPrograms loads eBPF programs
func (em *EBPFManager) loadPrograms() error {
	// For now, we'll skip program loading as it requires compiled eBPF objects
	// In production, this would load the actual eBPF programs
	log.Printf("[ebpf_manager] Program loading skipped (requires compiled eBPF objects)")
	return nil
}

// attachPrograms attaches eBPF programs
func (em *EBPFManager) attachPrograms() error {
	// For now, we'll skip program attachment
	// In production, this would attach programs to appropriate hooks
	log.Printf("[ebpf_manager] Program attachment skipped (requires eBPF programs)")
	return nil
}

// ApplyPolicy applies a policy to eBPF maps
func (em *EBPFManager) ApplyPolicy(policy *models.Policy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	
	em.mu.RLock()
	defer em.mu.RUnlock()
	
	if !em.initialized {
		return fmt.Errorf("eBPF manager not initialized")
	}
	
	// Apply policy rules to eBPF maps
	for _, rule := range policy.Rules {
		if err := em.applyRule(rule); err != nil {
			return fmt.Errorf("failed to apply rule %s: %w", rule.ID, err)
		}
	}
	
	log.Printf("[ebpf_manager] Policy %s applied successfully", policy.ID)
	return nil
}

// applyRule applies a single rule to eBPF maps
func (em *EBPFManager) applyRule(rule models.Rule) error {
	// Convert rule to eBPF map entries
	for _, condition := range rule.Conditions {
		if err := em.applyCondition(condition, rule.Action); err != nil {
			return fmt.Errorf("failed to apply condition: %w", err)
		}
	}
	
	return nil
}

// applyCondition applies a condition to eBPF maps
func (em *EBPFManager) applyCondition(condition models.Condition, action string) error {
	switch condition.Field {
	case "destination_ip":
		return em.applyDestinationIPCondition(condition, action)
	case "source_ip":
		return em.applySourceIPCondition(condition, action)
	case "protocol":
		return em.applyProtocolCondition(condition, action)
	case "port":
		return em.applyPortCondition(condition, action)
	default:
		log.Printf("[ebpf_manager] Unsupported condition field: %s", condition.Field)
		return nil
	}
}

// applyDestinationIPCondition applies destination IP condition
func (em *EBPFManager) applyDestinationIPCondition(condition models.Condition, action string) error {
	// Parse IP address
	ip := net.ParseIP(fmt.Sprintf("%v", condition.Value))
	if ip == nil {
		return fmt.Errorf("invalid IP address: %v", condition.Value)
	}
	
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("IPv6 not supported")
	}
	
	// Convert action to uint32
	var actionValue uint32
	switch action {
	case "allow":
		actionValue = 1
	case "deny", "drop":
		actionValue = 0
	default:
		actionValue = 0
	}
	
	// Apply to blocked destinations map
	if blockedMap, exists := em.maps["aegis_blocked_destinations"]; exists {
		key := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
		
		if actionValue == 0 { // Block
			if err := blockedMap.Put(key, uint32(1)); err != nil {
				return fmt.Errorf("failed to add blocked destination: %w", err)
			}
		} else { // Allow
			if err := blockedMap.Delete(key); err != nil {
				log.Printf("[ebpf_manager] Warning: failed to remove blocked destination: %v", err)
			}
		}
	}
	
	return nil
}

// applySourceIPCondition applies source IP condition
func (em *EBPFManager) applySourceIPCondition(condition models.Condition, action string) error {
	// Similar to destination IP but for source
	// For now, we'll log and skip
	log.Printf("[ebpf_manager] Source IP condition not yet implemented")
	return nil
}

// applyProtocolCondition applies protocol condition
func (em *EBPFManager) applyProtocolCondition(condition models.Condition, action string) error {
	// Protocol-based conditions
	// For now, we'll log and skip
	log.Printf("[ebpf_manager] Protocol condition not yet implemented")
	return nil
}

// applyPortCondition applies port condition
func (em *EBPFManager) applyPortCondition(condition models.Condition, action string) error {
	// Port-based conditions
	// For now, we'll log and skip
	log.Printf("[ebpf_manager] Port condition not yet implemented")
	return nil
}

// UpdatePolicy updates an existing policy in eBPF maps
func (em *EBPFManager) UpdatePolicy(policy *models.Policy) error {
	// For now, we'll treat update as remove + add
	if err := em.RemovePolicy(policy.ID); err != nil {
		log.Printf("[ebpf_manager] Warning: failed to remove old policy: %v", err)
	}
	
	return em.ApplyPolicy(policy)
}

// RemovePolicy removes a policy from eBPF maps
func (em *EBPFManager) RemovePolicy(policyID string) error {
	em.mu.RLock()
	defer em.mu.RUnlock()
	
	if !em.initialized {
		return fmt.Errorf("eBPF manager not initialized")
	}
	
	// For now, we'll clear all maps
	// In production, this would track and remove specific policy entries
	for mapName, m := range em.maps {
		if err := em.clearMap(m); err != nil {
			log.Printf("[ebpf_manager] Warning: failed to clear map %s: %v", mapName, err)
		}
	}
	
	log.Printf("[ebpf_manager] Policy %s removed", policyID)
	return nil
}

// clearMap clears all entries from a map
func (em *EBPFManager) clearMap(m *ebpf.Map) error {
	// Iterate through map and delete all entries
	var key []byte
	iter := m.Iterate()
	
	for iter.Next(&key, nil) {
		if err := m.Delete(key); err != nil {
			log.Printf("[ebpf_manager] Warning: failed to delete map entry: %v", err)
		}
	}
	
	return nil
}

// GetMap retrieves an eBPF map by name
func (em *EBPFManager) GetMap(mapName string) (*ebpf.Map, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()
	
	m, exists := em.maps[mapName]
	if !exists {
		return nil, fmt.Errorf("map %s not found", mapName)
	}
	
	return m, nil
}

// GetMapCount returns the number of loaded maps
func (em *EBPFManager) GetMapCount() int {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return len(em.maps)
}

// GetProgramCount returns the number of loaded programs
func (em *EBPFManager) GetProgramCount() int {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return len(em.programs)
}

// IsInitialized returns whether the eBPF manager is initialized
func (em *EBPFManager) IsInitialized() bool {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.initialized
}

// Close closes the eBPF manager and cleans up resources
func (em *EBPFManager) Close() error {
	em.mu.Lock()
	defer em.mu.Unlock()
	
	var errors []error
	
	// Close all links
	for name, l := range em.links {
		if err := l.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close link %s: %w", name, err))
		}
	}
	
	// Close all maps
	for name, m := range em.maps {
		if err := m.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close map %s: %w", name, err))
		}
	}
	
	em.initialized = false
	
	if len(errors) > 0 {
		return fmt.Errorf("failed to close eBPF manager: %v", errors)
	}
	
	log.Printf("[ebpf_manager] eBPF manager closed successfully")
	return nil
}
