package core

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"agents/aegis/pkg/models"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
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
	supported   bool // Whether eBPF is supported on this platform
	mu          sync.RWMutex
}

// NewEBPFManager creates a new eBPF manager
func NewEBPFManager() (*EBPFManager, error) {
	em := &EBPFManager{
		programs: make(map[string]*ebpf.Program),
		links:    make(map[string]link.Link),
		maps:     make(map[string]*ebpf.Map),
	}
	
	// Check if eBPF is supported on this platform
	em.supported = isEBPFSupported()
	
	if !em.supported {
		log.Printf("[ebpf_manager] eBPF not supported on %s/%s, running in compatibility mode", runtime.GOOS, runtime.GOARCH)
		em.initialized = true
		return em, nil
	}
	
	// Remove MEMLOCK limit to allow eBPF map creation
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[ebpf_manager] Warning: failed to remove MEMLOCK limit: %v", err)
		log.Printf("[ebpf_manager] eBPF functionality may be limited due to MEMLOCK restrictions")
		// Continue anyway - some functionality might still work
	} else {
		log.Printf("[ebpf_manager] MEMLOCK limit removed successfully")
	}
	
	if err := em.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize eBPF manager: %w", err)
	}
	
	log.Printf("[ebpf_manager] eBPF manager initialized successfully")
	return em, nil
}

// isEBPFSupported checks if eBPF is supported on the current platform
func isEBPFSupported() bool {
	// eBPF is only supported on Linux
	return runtime.GOOS == "linux"
}

// initialize initializes the eBPF manager
func (em *EBPFManager) initialize() error {
	em.mu.Lock()
	defer em.mu.Unlock()
	
	if em.initialized {
		return fmt.Errorf("eBPF manager already initialized")
	}
	
	// If eBPF is not supported, skip initialization
	if !em.supported {
		em.initialized = true
		log.Printf("[ebpf_manager] Skipping eBPF initialization on unsupported platform")
		return nil
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
	// If eBPF is not supported, skip loading maps
	if !em.supported {
		log.Printf("[ebpf_manager] Skipping eBPF map loading on unsupported platform")
		return nil
	}
	
	// Load basic eBPF maps
	mapNames := []string{
		"blocked_destinations",
		"stats",
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
	case "blocked_destinations":
		mapSpec = &ebpf.MapSpec{
			Type:       ebpf.Hash,
			KeySize:    4, // uint32
			ValueSize:  4, // uint32
			MaxEntries: 1024,
		}
	case "stats":
		mapSpec = &ebpf.MapSpec{
			Type:       ebpf.Array,
			KeySize:    4, // uint32
			ValueSize:  8, // uint64
			MaxEntries: 1,
		}
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
			log.Printf("[ebpf_manager] Error: failed to create map %s due to insufficient permissions: %v", mapName, err)
			log.Printf("[ebpf_manager] Solutions:")
			log.Printf("[ebpf_manager]   1. Run as root: sudo ./aegis-agent")
			log.Printf("[ebpf_manager]   2. Set ulimit: sudo ulimit -l unlimited")
			log.Printf("[ebpf_manager]   3. Check if rlimit.RemoveMemlock() was called during initialization")
			return nil, fmt.Errorf("failed to create map %s: MEMLOCK permission denied - run as root or set ulimit -l unlimited", mapName)
		}
		return nil, fmt.Errorf("failed to create map %s: %w", mapName, err)
	}
	
	return m, nil
}

// loadPrograms loads eBPF programs
func (em *EBPFManager) loadPrograms() error {
	// If eBPF is not supported, skip loading programs
	if !em.supported {
		log.Printf("[ebpf_manager] Skipping eBPF program loading on unsupported platform")
		return nil
	}
	
	// Load the policy enforcer eBPF program
	if err := em.loadPolicyEnforcerProgram(); err != nil {
		log.Printf("[ebpf_manager] Warning: failed to load policy enforcer program: %v", err)
		// Continue without this program - enforcement will be limited
	}
	
	log.Printf("[ebpf_manager] eBPF program loading completed")
	return nil
}

// loadPolicyEnforcerProgram loads the policy enforcer eBPF program
func (em *EBPFManager) loadPolicyEnforcerProgram() error {
	// Try to load from the compiled eBPF object file
	objFile := "/home/steve/aegis_agent/bpf/aegis_tc_egress_enforcer.bpf.o"
	
	// Load the eBPF object file
	spec, err := ebpf.LoadCollectionSpec(objFile)
	if err != nil {
		return fmt.Errorf("failed to load eBPF collection spec from %s: %w", objFile, err)
	}
	
	// Load the collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to load eBPF collection: %w", err)
	}
	
	// Store the programs and maps
	for name, prog := range coll.Programs {
		em.programs[name] = prog
		log.Printf("[ebpf_manager] Loaded eBPF program: %s", name)
	}
	
	for name, m := range coll.Maps {
		em.maps[name] = m
		log.Printf("[ebpf_manager] Loaded eBPF map: %s", name)
	}
	
	log.Printf("[ebpf_manager] Policy enforcer eBPF program loaded successfully")
	return nil
}

// attachPrograms attaches eBPF programs
func (em *EBPFManager) attachPrograms() error {
	// If eBPF is not supported, skip program attachment
	if !em.supported {
		log.Printf("[ebpf_manager] Skipping eBPF program attachment on unsupported platform")
		return nil
	}
	
	// Attach the policy enforcer program to cgroup egress
	if err := em.attachPolicyEnforcerProgram(); err != nil {
		log.Printf("[ebpf_manager] Warning: failed to attach policy enforcer program: %v", err)
		// Continue without attachment - enforcement will be limited
	}
	
	log.Printf("[ebpf_manager] eBPF program attachment completed")
	return nil
}

// attachPolicyEnforcerProgram attaches the policy enforcer to network interface
func (em *EBPFManager) attachPolicyEnforcerProgram() error {
	// Find the policy enforcer program
	prog, exists := em.programs["aegis_tc_egress_filter"]
	if !exists {
		return fmt.Errorf("policy enforcer program not found")
	}
	
	// Try TC egress attachment (most effective for outgoing traffic filtering)
	interfaceName := "ens160" // Main network interface
	
	// Create TC qdisc if it doesn't exist
	cmd := exec.Command("tc", "qdisc", "add", "dev", interfaceName, "clsact")
	cmd.Run() // Ignore error if qdisc already exists
	
	// Try to attach to TC egress using tc command
	cmd = exec.Command("tc", "filter", "add", "dev", interfaceName, "egress", "bpf", "direct-action", "object-file", "/home/steve/aegis_agent/bpf/aegis_tc_egress_enforcer.bpf.o", "section", "tc")
	if err := cmd.Run(); err != nil {
		log.Printf("[ebpf_manager] Warning: TC egress attachment failed: %v", err)
		
		// Fallback to cgroup egress
		cgroupPath := "/sys/fs/cgroup"
		cgroup, err := os.Open(cgroupPath)
		if err != nil {
			return fmt.Errorf("failed to open cgroup %s: %w", cgroupPath, err)
		}
		defer cgroup.Close()

		linkObj, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: prog,
		})
		if err != nil {
			return fmt.Errorf("failed to attach eBPF program to cgroup: %w", err)
		}
		em.links["aegis_tc_egress_filter"] = linkObj
		log.Printf("[ebpf_manager] Policy enforcer program attached to cgroup egress (fallback)")
	} else {
		log.Printf("[ebpf_manager] Policy enforcer program attached to TC egress on %s successfully", interfaceName)
		em.links["aegis_tc_egress_filter"] = nil
	}

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
	
	log.Printf("[ebpf_manager] Applying policy %s with %d rules", policy.ID, len(policy.Rules))
	
	// Apply policy rules to eBPF maps
	for i, rule := range policy.Rules {
		log.Printf("[ebpf_manager] Processing rule %d: %s (action: %s, conditions: %d)", i, rule.ID, rule.Action, len(rule.Conditions))
		if err := em.applyRule(rule); err != nil {
			return fmt.Errorf("failed to apply rule %s: %w", rule.ID, err)
		}
	}
	
	log.Printf("[ebpf_manager] Policy %s applied successfully", policy.ID)
	return nil
}

// applyRule applies a single rule to eBPF maps
func (em *EBPFManager) applyRule(rule models.Rule) error {
	log.Printf("[ebpf_manager] Applying rule %s with %d conditions", rule.ID, len(rule.Conditions))
	
	// Convert rule to eBPF map entries
	for i, condition := range rule.Conditions {
		log.Printf("[ebpf_manager] Processing condition %d: field=%s, operator=%s, value=%v", i, condition.Field, condition.Operator, condition.Value)
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
	log.Printf("[ebpf_manager] applyDestinationIPCondition called: value=%v, action=%s", condition.Value, action)
	
	// Parse IP address
	ip := net.ParseIP(fmt.Sprintf("%v", condition.Value))
	if ip == nil {
		return fmt.Errorf("invalid IP address: %v", condition.Value)
	}
	
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("IPv6 not supported")
	}
	
	log.Printf("[ebpf_manager] Parsed IPv4 address: %s", ipv4.String())
	
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
	if blockedMap, exists := em.maps["blocked_destinations"]; exists {
		// Store IP in network byte order (big-endian) to match eBPF program expectations
		// The eBPF program uses bpf_ntohl(ip->daddr) which converts network to host byte order
		// So we need to store in network byte order (big-endian)
		key := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
		log.Printf("[ebpf_manager] Map key for %s: %d (0x%x) - network byte order", ipv4.String(), key, key)
		
		if actionValue == 0 { // Block
			log.Printf("[ebpf_manager] Adding blocked destination %s to map", ipv4.String())
			if err := blockedMap.Put(key, uint32(1)); err != nil {
				return fmt.Errorf("failed to add blocked destination: %w", err)
			}
			log.Printf("[ebpf_manager] Successfully added blocked destination %s to map", ipv4.String())
		} else { // Allow
			log.Printf("[ebpf_manager] Removing allowed destination %s from map", ipv4.String())
			if err := blockedMap.Delete(key); err != nil {
				log.Printf("[ebpf_manager] Warning: failed to remove blocked destination: %v", err)
			}
			log.Printf("[ebpf_manager] Successfully removed allowed destination %s from map", ipv4.String())
		}
	} else {
		log.Printf("[ebpf_manager] Warning: blocked_destinations map not found, cannot apply IP condition")
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
	// For ICMP, we'll just log and continue - the destination IP condition will handle the blocking
	protocol := fmt.Sprintf("%v", condition.Value)
	log.Printf("[ebpf_manager] Protocol condition: %s (action: %s) - continuing with other conditions", protocol, action)
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
