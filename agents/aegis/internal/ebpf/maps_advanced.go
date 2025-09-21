package ebpf

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// AdvancedMapManager manages specialized eBPF maps for complex network policies
type AdvancedMapManager struct {
	// Core maps
	policyEdgesMap   *ebpf.Map
	allowLPM4Map     *ebpf.Map
	modeMap          *ebpf.Map
	statsMap         *ebpf.Map
	
	// New specialized maps
	networkPoliciesMap *ebpf.Map  // Complex network policies
	serviceDepsMap     *ebpf.Map  // Service dependencies
	processConnMap     *ebpf.Map  // Process-to-network connections
	flowStatsMap       *ebpf.Map  // Network flow statistics
	policyRulesMap     *ebpf.Map  // Policy rule definitions
	
	// Coordination
	mu sync.RWMutex
}

// NewAdvancedMapManager creates a new advanced map manager
func NewAdvancedMapManager() (*AdvancedMapManager, error) {
	am := &AdvancedMapManager{}
	
	// Load existing core maps
	if err := am.loadCoreMaps(); err != nil {
		return nil, fmt.Errorf("failed to load core maps: %w", err)
	}
	
	// Load new specialized maps
	if err := am.loadSpecializedMaps(); err != nil {
		return nil, fmt.Errorf("failed to load specialized maps: %w", err)
	}
	
	log.Printf("[advanced_maps] Loaded all eBPF maps successfully")
	return am, nil
}

// loadCoreMaps loads the existing core maps
func (am *AdvancedMapManager) loadCoreMaps() error {
	// Load policy_edges map
	policyEdgesMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/policy_edges", nil)
	if err != nil {
		return fmt.Errorf("failed to load policy_edges map: %w", err)
	}
	am.policyEdgesMap = policyEdgesMap

	// Load allow_lpm4 map
	allowLPM4Map, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/allow_lpm4", nil)
	if err != nil {
		return fmt.Errorf("failed to load allow_lpm4 map: %w", err)
	}
	am.allowLPM4Map = allowLPM4Map

	// Load mode map
	modeMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/mode", nil)
	if err != nil {
		return fmt.Errorf("failed to load mode map: %w", err)
	}
	am.modeMap = modeMap

	// Load stats map (optional)
	statsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/policy_stats_map", nil)
	if err != nil {
		log.Printf("[advanced_maps] Warning: failed to load stats map: %v", err)
		// Stats map is optional
	}
	am.statsMap = statsMap
	
	return nil
}

// loadSpecializedMaps loads the new specialized maps
func (am *AdvancedMapManager) loadSpecializedMaps() error {
	// Load network_policies map
	networkPoliciesMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/network_policies", nil)
	if err != nil {
		log.Printf("[advanced_maps] Warning: network_policies map not found, will create: %v", err)
		// Map doesn't exist yet, will be created by eBPF program
	}
	am.networkPoliciesMap = networkPoliciesMap

	// Load service_deps map
	serviceDepsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/service_deps", nil)
	if err != nil {
		log.Printf("[advanced_maps] Warning: service_deps map not found, will create: %v", err)
		// Map doesn't exist yet, will be created by eBPF program
	}
	am.serviceDepsMap = serviceDepsMap

	// Load process_connections map
	processConnMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/process_connections", nil)
	if err != nil {
		log.Printf("[advanced_maps] Warning: process_connections map not found, will create: %v", err)
		// Map doesn't exist yet, will be created by eBPF program
	}
	am.processConnMap = processConnMap

	// Load flow_stats map
	flowStatsMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/flow_stats", nil)
	if err != nil {
		log.Printf("[advanced_maps] Warning: flow_stats map not found, will create: %v", err)
		// Map doesn't exist yet, will be created by eBPF program
	}
	am.flowStatsMap = flowStatsMap

	// Load policy_rules map
	policyRulesMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/aegis/policy_rules", nil)
	if err != nil {
		log.Printf("[advanced_maps] Warning: policy_rules map not found, will create: %v", err)
		// Map doesn't exist yet, will be created by eBPF program
	}
	am.policyRulesMap = policyRulesMap
	
	return nil
}

// NetworkPolicy represents a complex network policy
type NetworkPolicy struct {
	PolicyID      uint32
	SrcIP         uint32
	DstIP         uint32
	SrcMask       uint32
	DstMask       uint32
	SrcPort       uint16
	DstPort       uint16
	Protocol      uint8
	Action        uint8 // 0=BLOCK, 1=ALLOW, 2=LOG, 3=RATE_LIMIT
	Priority      uint8
	RateLimit     uint32 // packets per second
	ProcessName   [16]byte // process name filter
	UserID        uint32
	GroupID       uint32
	Namespace     uint32
	Timestamp     uint64
	TTL           uint32 // time to live in seconds
	Flags         uint32 // additional flags
}

// ServiceDependency represents a service dependency
type ServiceDependency struct {
	ServiceID     uint32
	ServiceName   [32]byte
	DependsOnID   uint32
	DependsOnName [32]byte
	Port          uint16
	Protocol      uint8
	Health        uint8 // 0=unknown, 1=healthy, 2=unhealthy, 3=degraded
	LastCheck     uint64
	CheckInterval uint32
	Timeout       uint32
	Retries       uint8
	Weight        uint8
	_             [2]byte // padding
}

// ProcessConnection represents a process-to-network connection
type ProcessConnection struct {
	ProcessID     uint32
	ProcessName   [32]byte
	UserID        uint32
	GroupID       uint32
	Namespace     uint32
	SrcIP         uint32
	DstIP         uint32
	SrcPort       uint16
	DstPort       uint16
	Protocol      uint8
	State         uint8 // 0=unknown, 1=established, 2=time_wait, 3=close_wait
	BytesIn       uint64
	BytesOut      uint64
	PacketsIn     uint64
	PacketsOut    uint64
	StartTime     uint64
	LastActivity  uint64
}

// FlowStats represents network flow statistics
type FlowStats struct {
	SrcIP         uint32
	DstIP         uint32
	SrcPort       uint16
	DstPort       uint16
	Protocol      uint8
	_             [1]byte // padding
	BytesTotal    uint64
	PacketsTotal  uint64
	Duration      uint32
	LastSeen      uint64
	FlowCount     uint32
	_             [4]byte // padding
}

// PolicyRule represents a policy rule definition
type PolicyRule struct {
	RuleID        uint32
	PolicyID      uint32
	RuleType      uint8 // 0=network, 1=process, 2=file, 3=syscall
	Action        uint8 // 0=BLOCK, 1=ALLOW, 2=LOG, 3=RATE_LIMIT
	Priority      uint8
	Enabled       uint8
	ConditionType uint8 // 0=simple, 1=complex, 2=regex, 3=custom
	_             [3]byte // padding
	MatchData     [64]byte // condition data
	ActionData    [32]byte // action-specific data
	Timestamp     uint64
	TTL           uint32
	HitCount      uint32
	LastHit       uint64
}

// WriteNetworkPolicy writes a network policy to the network_policies map
func (am *AdvancedMapManager) WriteNetworkPolicy(policy NetworkPolicy) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if am.networkPoliciesMap == nil {
		return fmt.Errorf("network_policies map not loaded")
	}
	
	key := policy.PolicyID
	if err := am.networkPoliciesMap.Put(key, policy); err != nil {
		return fmt.Errorf("failed to write network policy %d: %w", policy.PolicyID, err)
	}
	
	log.Printf("[advanced_maps] Wrote network policy %d: %s:%d -> %s:%d (action=%d, priority=%d)", 
		policy.PolicyID, formatIP(policy.SrcIP), policy.SrcPort, 
		formatIP(policy.DstIP), policy.DstPort, policy.Action, policy.Priority)
	return nil
}

// WriteServiceDependency writes a service dependency to the service_deps map
func (am *AdvancedMapManager) WriteServiceDependency(dep ServiceDependency) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if am.serviceDepsMap == nil {
		return fmt.Errorf("service_deps map not loaded")
	}
	
	// Create composite key: serviceID << 32 | dependsOnID
	key := uint64(dep.ServiceID)<<32 | uint64(dep.DependsOnID)
	if err := am.serviceDepsMap.Put(key, dep); err != nil {
		return fmt.Errorf("failed to write service dependency %d->%d: %w", 
			dep.ServiceID, dep.DependsOnID, err)
	}
	
	log.Printf("[advanced_maps] Wrote service dependency: %s -> %s (health=%d)", 
		string(dep.ServiceName[:]), string(dep.DependsOnName[:]), dep.Health)
	return nil
}

// WriteProcessConnection writes a process connection to the process_connections map
func (am *AdvancedMapManager) WriteProcessConnection(conn ProcessConnection) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if am.processConnMap == nil {
		return fmt.Errorf("process_connections map not loaded")
	}
	
	// Create composite key: processID << 32 | connection hash
	connHash := am.hashConnection(conn.SrcIP, conn.DstIP, conn.SrcPort, conn.DstPort, conn.Protocol)
	key := uint64(conn.ProcessID)<<32 | uint64(connHash)
	
	if err := am.processConnMap.Put(key, conn); err != nil {
		return fmt.Errorf("failed to write process connection %d: %w", conn.ProcessID, err)
	}
	
	log.Printf("[advanced_maps] Wrote process connection: PID %d (%s) %s:%d -> %s:%d", 
		conn.ProcessID, string(conn.ProcessName[:]), 
		formatIP(conn.SrcIP), conn.SrcPort, formatIP(conn.DstIP), conn.DstPort)
	return nil
}

// WriteFlowStats writes flow statistics to the flow_stats map
func (am *AdvancedMapManager) WriteFlowStats(stats FlowStats) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if am.flowStatsMap == nil {
		return fmt.Errorf("flow_stats map not loaded")
	}
	
	// Create composite key: srcIP << 32 | dstIP
	key := uint64(stats.SrcIP)<<32 | uint64(stats.DstIP)
	if err := am.flowStatsMap.Put(key, stats); err != nil {
		return fmt.Errorf("failed to write flow stats: %w", err)
	}
	
	log.Printf("[advanced_maps] Wrote flow stats: %s -> %s (%d bytes, %d packets)", 
		formatIP(stats.SrcIP), formatIP(stats.DstIP), stats.BytesTotal, stats.PacketsTotal)
	return nil
}

// WritePolicyRule writes a policy rule to the policy_rules map
func (am *AdvancedMapManager) WritePolicyRule(rule PolicyRule) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if am.policyRulesMap == nil {
		return fmt.Errorf("policy_rules map not loaded")
	}
	
	key := rule.RuleID
	if err := am.policyRulesMap.Put(key, rule); err != nil {
		return fmt.Errorf("failed to write policy rule %d: %w", rule.RuleID, err)
	}
	
	log.Printf("[advanced_maps] Wrote policy rule %d: type=%d, action=%d, priority=%d", 
		rule.RuleID, rule.RuleType, rule.Action, rule.Priority)
	return nil
}

// GetNetworkPolicy retrieves a network policy by ID
func (am *AdvancedMapManager) GetNetworkPolicy(policyID uint32) (*NetworkPolicy, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	if am.networkPoliciesMap == nil {
		return nil, fmt.Errorf("network_policies map not loaded")
	}
	
	var policy NetworkPolicy
	if err := am.networkPoliciesMap.Lookup(policyID, &policy); err != nil {
		return nil, fmt.Errorf("failed to lookup network policy %d: %w", policyID, err)
	}
	
	return &policy, nil
}

// GetServiceDependencies retrieves all dependencies for a service
func (am *AdvancedMapManager) GetServiceDependencies(serviceID uint32) ([]ServiceDependency, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	if am.serviceDepsMap == nil {
		return nil, fmt.Errorf("service_deps map not loaded")
	}
	
	var dependencies []ServiceDependency
	
	// Iterate through map to find all dependencies for this service
	iter := am.serviceDepsMap.Iterate()
	var key uint64
	var dep ServiceDependency
	
	for iter.Next(&key, &dep) {
		// Check if this dependency belongs to our service
		if dep.ServiceID == serviceID {
			dependencies = append(dependencies, dep)
		}
	}
	
	return dependencies, nil
}

// GetProcessConnections retrieves all connections for a process
func (am *AdvancedMapManager) GetProcessConnections(processID uint32) ([]ProcessConnection, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	if am.processConnMap == nil {
		return nil, fmt.Errorf("process_connections map not loaded")
	}
	
	var connections []ProcessConnection
	
	// Iterate through map to find all connections for this process
	iter := am.processConnMap.Iterate()
	var key uint64
	var conn ProcessConnection
	
	for iter.Next(&key, &conn) {
		// Check if this connection belongs to our process
		if conn.ProcessID == processID {
			connections = append(connections, conn)
		}
	}
	
	return connections, nil
}

// ClearNetworkPolicies clears all network policies
func (am *AdvancedMapManager) ClearNetworkPolicies() error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if am.networkPoliciesMap == nil {
		return fmt.Errorf("network_policies map not loaded")
	}
	
	// Clear all entries
	iter := am.networkPoliciesMap.Iterate()
	var key uint32
	
	for iter.Next(&key, nil) {
		if err := am.networkPoliciesMap.Delete(key); err != nil {
			log.Printf("[advanced_maps] Warning: failed to delete network policy %d: %v", key, err)
		}
	}
	
	log.Printf("[advanced_maps] Cleared all network policies")
	return nil
}

// ClearServiceDependencies clears all service dependencies
func (am *AdvancedMapManager) ClearServiceDependencies() error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if am.serviceDepsMap == nil {
		return fmt.Errorf("service_deps map not loaded")
	}
	
	// Clear all entries
	iter := am.serviceDepsMap.Iterate()
	var key uint64
	
	for iter.Next(&key, nil) {
		if err := am.serviceDepsMap.Delete(key); err != nil {
			log.Printf("[advanced_maps] Warning: failed to delete service dependency %d: %v", key, err)
		}
	}
	
	log.Printf("[advanced_maps] Cleared all service dependencies")
	return nil
}

// GetMapStatistics returns statistics for all maps
func (am *AdvancedMapManager) GetMapStatistics() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	stats := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"maps": map[string]interface{}{
			"network_policies":  am.getMapEntryCount(am.networkPoliciesMap),
			"service_deps":      am.getMapEntryCount(am.serviceDepsMap),
			"process_connections": am.getMapEntryCount(am.processConnMap),
			"flow_stats":        am.getMapEntryCount(am.flowStatsMap),
			"policy_rules":      am.getMapEntryCount(am.policyRulesMap),
			"policy_edges":      am.getMapEntryCount(am.policyEdgesMap),
			"allow_lpm4":        am.getMapEntryCount(am.allowLPM4Map),
		},
	}
	
	return stats
}

// getMapEntryCount returns the number of entries in a map
func (am *AdvancedMapManager) getMapEntryCount(m *ebpf.Map) int {
	if m == nil {
		return 0
	}
	
	count := 0
	iter := m.Iterate()
	var key interface{}
	
	for iter.Next(&key, nil) {
		count++
	}
	
	return count
}

// hashConnection creates a hash for a network connection
func (am *AdvancedMapManager) hashConnection(srcIP, dstIP uint32, srcPort, dstPort uint16, protocol uint8) uint32 {
	// Simple hash function for connection identification
	hash := srcIP ^ dstIP ^ uint32(srcPort) ^ uint32(dstPort) ^ uint32(protocol)
	return hash
}

// Implement MapManagerInterface for compatibility
func (am *AdvancedMapManager) WritePolicyEdge(edgeID uint32, edge PolicyEdge) error {
	// Convert to network policy format
	policy := NetworkPolicy{
		PolicyID:  edgeID,
		SrcIP:     edge.SrcIP,
		DstIP:     edge.DstIP,
		SrcMask:   edge.SrcMask,
		DstMask:   edge.DstMask,
		SrcPort:   edge.SrcPort,
		DstPort:   edge.DstPort,
		Protocol:  edge.Protocol,
		Action:    edge.Action,
		Priority:  edge.Priority,
		Timestamp: edge.Timestamp,
	}
	
	return am.WriteNetworkPolicy(policy)
}

func (am *AdvancedMapManager) WriteAllowCIDR(cidr AllowCIDR) error {
	if am.allowLPM4Map == nil {
		return fmt.Errorf("allow_lpm4 map not loaded")
	}
	
	// Create LPM key
	key := struct {
		PrefixLen uint32
		IP        uint32
	}{
		PrefixLen: cidr.PrefixLen,
		IP:        cidr.IP,
	}
	
	// Create value
	value := struct {
		Action    uint8
		Priority  uint8
		Timestamp uint64
	}{
		Action:    cidr.Action,
		Priority:  cidr.Priority,
		Timestamp: cidr.Timestamp,
	}
	
	return am.allowLPM4Map.Put(key, value)
}

func (am *AdvancedMapManager) SetMode(mode uint32) error {
	if am.modeMap == nil {
		return fmt.Errorf("mode map not loaded")
	}
	
	key := uint32(0)
	return am.modeMap.Put(key, mode)
}

func (am *AdvancedMapManager) GetMode() (uint32, error) {
	if am.modeMap == nil {
		return 0, fmt.Errorf("mode map not loaded")
	}
	
	key := uint32(0)
	var mode uint32
	if err := am.modeMap.Lookup(key, &mode); err != nil {
		return 0, err
	}
	
	return mode, nil
}

func (am *AdvancedMapManager) ClearPolicyEdges() error {
	return am.ClearNetworkPolicies()
}

func (am *AdvancedMapManager) ClearAllowCIDRs() error {
	if am.allowLPM4Map == nil {
		return fmt.Errorf("allow_lpm4 map not loaded")
	}
	
	// Clear all entries
	iter := am.allowLPM4Map.Iterate()
	var key struct {
		PrefixLen uint32
		IP        uint32
	}
	
	for iter.Next(&key, nil) {
		if err := am.allowLPM4Map.Delete(key); err != nil {
			log.Printf("[advanced_maps] Warning: failed to delete allow CIDR: %v", err)
		}
	}
	
	log.Printf("[advanced_maps] Cleared all allow CIDRs")
	return nil
}

func (am *AdvancedMapManager) Close() error {
	// Close all maps
	maps := []*ebpf.Map{
		am.policyEdgesMap,
		am.allowLPM4Map,
		am.modeMap,
		am.statsMap,
		am.networkPoliciesMap,
		am.serviceDepsMap,
		am.processConnMap,
		am.flowStatsMap,
		am.policyRulesMap,
	}
	
	for _, m := range maps {
		if m != nil {
			m.Close()
		}
	}
	
	return nil
}

// formatIP formats an IP address for logging
func formatIP(ip uint32) string {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String()
}
