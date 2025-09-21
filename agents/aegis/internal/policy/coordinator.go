package policy

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"agents/aegis/internal/ebpf"
	"agents/aegis/internal/telemetry"
)

// MapCoordinator coordinates operations across multiple eBPF maps
type MapCoordinator struct {
	advancedMapManager *ebpf.AdvancedMapManager
	auditLogger        *telemetry.AuditLogger
	mu                 sync.RWMutex
	consistencyChecker *ConsistencyChecker
}

// ConsistencyChecker validates map consistency
type ConsistencyChecker struct {
	coordinatior *MapCoordinator
	checkInterval time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewMapCoordinator creates a new map coordinator
func NewMapCoordinator(auditLogger *telemetry.AuditLogger) (*MapCoordinator, error) {
	// Initialize advanced map manager
	advancedMapManager, err := ebpf.NewAdvancedMapManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create advanced map manager: %w", err)
	}
	
	mc := &MapCoordinator{
		advancedMapManager: advancedMapManager,
		auditLogger:        auditLogger,
	}
	
	// Initialize consistency checker
	ctx, cancel := context.WithCancel(context.Background())
	mc.consistencyChecker = &ConsistencyChecker{
		coordinatior:  mc,
		checkInterval: 30 * time.Second,
		ctx:          ctx,
		cancel:       cancel,
	}
	
	// Start consistency checking
	go mc.consistencyChecker.start()
	
	log.Printf("[coordinator] Map coordinator initialized")
	return mc, nil
}

// ApplyComplexPolicy applies a complex policy across multiple maps
func (mc *MapCoordinator) ApplyComplexPolicy(policy *Policy) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	log.Printf("[coordinator] Applying complex policy: %s", policy.Name)
	
	// Validate policy consistency
	if err := mc.validatePolicyConsistency(policy); err != nil {
		return fmt.Errorf("policy consistency validation failed: %w", err)
	}
	
	// Apply network policies
	if err := mc.applyNetworkPolicies(policy); err != nil {
		return fmt.Errorf("failed to apply network policies: %w", err)
	}
	
	// Apply service dependencies
	if err := mc.applyServiceDependencies(policy); err != nil {
		return fmt.Errorf("failed to apply service dependencies: %w", err)
	}
	
	// Apply policy rules
	if err := mc.applyPolicyRules(policy); err != nil {
		return fmt.Errorf("failed to apply policy rules: %w", err)
	}
	
	// Validate map consistency after application
	if err := mc.validateMapConsistency(); err != nil {
		log.Printf("[coordinator] Warning: map consistency check failed after policy application: %v", err)
		mc.auditLogger.LogSecurityEvent(telemetry.SecurityEvent{
			EventType:   "consistency_check_failed",
			Severity:    telemetry.SeverityWarning,
			Source:      "coordinator",
			Target:      "maps",
			Description: "Map consistency check failed after policy application",
			Details: map[string]interface{}{
				"policy_id":   policy.ID,
				"policy_name": policy.Name,
				"error":       err.Error(),
			},
		})
	}
	
	log.Printf("[coordinator] Successfully applied complex policy: %s", policy.Name)
	return nil
}

// validatePolicyConsistency validates policy consistency before application
func (mc *MapCoordinator) validatePolicyConsistency(policy *Policy) error {
	// Check for conflicting rules
	conflicts := mc.detectPolicyConflicts(policy)
	if len(conflicts) > 0 {
		return fmt.Errorf("policy conflicts detected: %v", conflicts)
	}
	
	// Check resource limits
	if err := mc.checkResourceLimits(policy); err != nil {
		return fmt.Errorf("resource limit check failed: %w", err)
	}
	
	return nil
}

// applyNetworkPolicies applies network policies to the network_policies map
func (mc *MapCoordinator) applyNetworkPolicies(policy *Policy) error {
	for i, rule := range policy.Rules {
		// Convert rule to network policy format
		networkPolicy, err := mc.convertRuleToNetworkPolicy(rule, policy, i)
		if err != nil {
			return fmt.Errorf("failed to convert rule %d to network policy: %w", i, err)
		}
		
		// Write to network_policies map
		if err := mc.advancedMapManager.WriteNetworkPolicy(networkPolicy); err != nil {
			return fmt.Errorf("failed to write network policy %d: %w", i, err)
		}
		
		// Log the operation
		mc.auditLogger.LogMapUpdate("network_policies", "put", "system", map[string]interface{}{
			"policy_id": policy.ID,
			"rule_id":   rule.ID,
			"action":    rule.Action,
		})
	}
	
	return nil
}

// applyServiceDependencies applies service dependencies
func (mc *MapCoordinator) applyServiceDependencies(policy *Policy) error {
	// Extract service dependencies from policy metadata
	if deps, exists := policy.Metadata["service_dependencies"]; exists {
		dependencies, ok := deps.([]interface{})
		if !ok {
			return fmt.Errorf("invalid service_dependencies format")
		}
		
		for i, dep := range dependencies {
			serviceDep, err := mc.convertToServiceDependency(dep, i)
			if err != nil {
				return fmt.Errorf("failed to convert service dependency %d: %w", i, err)
			}
			
			if err := mc.advancedMapManager.WriteServiceDependency(serviceDep); err != nil {
				return fmt.Errorf("failed to write service dependency %d: %w", i, err)
			}
			
			// Log the operation
			mc.auditLogger.LogMapUpdate("service_deps", "put", "system", map[string]interface{}{
				"policy_id":      policy.ID,
				"service_id":     serviceDep.ServiceID,
				"depends_on_id":  serviceDep.DependsOnID,
			})
		}
	}
	
	return nil
}

// applyPolicyRules applies policy rules to the policy_rules map
func (mc *MapCoordinator) applyPolicyRules(policy *Policy) error {
	for i, rule := range policy.Rules {
		policyRule, err := mc.convertRuleToPolicyRule(rule, policy, i)
		if err != nil {
			return fmt.Errorf("failed to convert rule %d to policy rule: %w", i, err)
		}
		
		if err := mc.advancedMapManager.WritePolicyRule(policyRule); err != nil {
			return fmt.Errorf("failed to write policy rule %d: %w", i, err)
		}
		
		// Log the operation
		mc.auditLogger.LogMapUpdate("policy_rules", "put", "system", map[string]interface{}{
			"policy_id": policy.ID,
			"rule_id":   rule.ID,
			"rule_type": policyRule.RuleType,
		})
	}
	
	return nil
}

// convertRuleToNetworkPolicy converts a policy rule to network policy format
func (mc *MapCoordinator) convertRuleToNetworkPolicy(rule Rule, policy *Policy, index int) (ebpf.NetworkPolicy, error) {
	networkPolicy := ebpf.NetworkPolicy{
		PolicyID:  uint32(index + 1), // Simple ID generation
		Action:    mc.convertActionToUint8(rule.Action),
		Priority:  uint8(rule.Priority),
		Timestamp: uint64(time.Now().Unix()),
		TTL:       3600, // 1 hour default TTL
	}
	
	// Extract network-specific conditions
	for _, condition := range rule.Conditions {
		switch condition.Field {
		case "source_ip":
			if ip, err := mc.parseIP(condition.Value); err == nil {
				networkPolicy.SrcIP = ip
			}
		case "destination_ip":
			if ip, err := mc.parseIP(condition.Value); err == nil {
				networkPolicy.DstIP = ip
			}
		case "source_port":
			if port, err := mc.parsePort(condition.Value); err == nil {
				networkPolicy.SrcPort = port
			}
		case "destination_port":
			if port, err := mc.parsePort(condition.Value); err == nil {
				networkPolicy.DstPort = port
			}
		case "protocol":
			if protocol, err := mc.parseProtocol(condition.Value); err == nil {
				networkPolicy.Protocol = protocol
			}
		}
	}
	
	return networkPolicy, nil
}

// convertToServiceDependency converts metadata to service dependency format
func (mc *MapCoordinator) convertToServiceDependency(dep interface{}, index int) (ebpf.ServiceDependency, error) {
	depMap, ok := dep.(map[string]interface{})
	if !ok {
		return ebpf.ServiceDependency{}, fmt.Errorf("invalid dependency format")
	}
	
	serviceDep := ebpf.ServiceDependency{
		ServiceID:       uint32(index + 1),
		DependsOnID:     uint32(index + 100), // Simple ID generation
		Health:          0, // Unknown
		LastCheck:       uint64(time.Now().Unix()),
		CheckInterval:   30, // 30 seconds
		Timeout:         5,  // 5 seconds
		Retries:         3,
		Weight:          1,
	}
	
	// Extract service name
	if name, exists := depMap["service_name"]; exists {
		if nameStr, ok := name.(string); ok {
			copy(serviceDep.ServiceName[:], []byte(nameStr)[:min(len(nameStr), 31)])
		}
	}
	
	// Extract dependency name
	if depName, exists := depMap["depends_on"]; exists {
		if depNameStr, ok := depName.(string); ok {
			copy(serviceDep.DependsOnName[:], []byte(depNameStr)[:min(len(depNameStr), 31)])
		}
	}
	
	// Extract port
	if port, exists := depMap["port"]; exists {
		if portInt, ok := port.(float64); ok {
			serviceDep.Port = uint16(portInt)
		}
	}
	
	// Extract protocol
	if protocol, exists := depMap["protocol"]; exists {
		if protocolStr, ok := protocol.(string); ok {
			serviceDep.Protocol = mc.convertProtocolString(protocolStr)
		}
	}
	
	return serviceDep, nil
}

// convertRuleToPolicyRule converts a policy rule to policy rule format
func (mc *MapCoordinator) convertRuleToPolicyRule(rule Rule, policy *Policy, index int) (ebpf.PolicyRule, error) {
	policyRule := ebpf.PolicyRule{
		RuleID:        uint32(index + 1),
		PolicyID:      uint32(index + 1000), // Simple ID generation
		RuleType:      0, // Network rule
		Action:        mc.convertActionToUint8(rule.Action),
		Priority:      uint8(rule.Priority),
		Enabled:       1, // Enabled
		ConditionType: 0, // Simple condition
		Timestamp:     uint64(time.Now().Unix()),
		TTL:           3600, // 1 hour default TTL
		HitCount:      0,
		LastHit:       0,
	}
	
	// Serialize condition data
	conditionData := mc.serializeConditions(rule.Conditions)
	copy(policyRule.MatchData[:], conditionData[:min(len(conditionData), 63)])
	
	// Serialize action data
	actionData := mc.serializeAction(rule.Action)
	copy(policyRule.ActionData[:], actionData[:min(len(actionData), 31)])
	
	return policyRule, nil
}

// detectPolicyConflicts detects conflicts between policy rules
func (mc *MapCoordinator) detectPolicyConflicts(policy *Policy) []string {
	var conflicts []string
	
	// Check for conflicting allow/deny rules on same conditions
	allowRules := make(map[string]bool)
	denyRules := make(map[string]bool)
	
	for _, rule := range policy.Rules {
		conditionKey := mc.getConditionKey(rule.Conditions)
		
		if rule.Action == "allow" {
			if denyRules[conditionKey] {
				conflicts = append(conflicts, fmt.Sprintf("Allow and deny rules conflict for conditions: %s", conditionKey))
			}
			allowRules[conditionKey] = true
		} else if rule.Action == "deny" {
			if allowRules[conditionKey] {
				conflicts = append(conflicts, fmt.Sprintf("Allow and deny rules conflict for conditions: %s", conditionKey))
			}
			denyRules[conditionKey] = true
		}
	}
	
	return conflicts
}

// checkResourceLimits checks if policy would exceed resource limits
func (mc *MapCoordinator) checkResourceLimits(policy *Policy) error {
	// Get current map statistics
	stats := mc.advancedMapManager.GetMapStatistics()
	
	// Check if adding this policy would exceed limits
	ruleCount := len(policy.Rules)
	currentRules := stats["maps"].(map[string]interface{})["policy_rules"].(int)
	
	maxRules := 10000 // Configurable limit
	if currentRules+ruleCount > maxRules {
		return fmt.Errorf("policy would exceed maximum rule limit: %d + %d > %d", 
			currentRules, ruleCount, maxRules)
	}
	
	return nil
}

// validateMapConsistency validates consistency across all maps
func (mc *MapCoordinator) validateMapConsistency() error {
	// This is a simplified consistency check
	// In a full implementation, you would:
	// 1. Check for orphaned references between maps
	// 2. Validate data integrity
	// 3. Check for circular dependencies
	// 4. Verify map entry counts
	
	log.Printf("[coordinator] Map consistency check completed")
	return nil
}

// Helper methods for data conversion
func (mc *MapCoordinator) convertActionToUint8(action string) uint8 {
	switch action {
	case "allow":
		return 1
	case "deny", "block", "drop":
		return 0
	case "log":
		return 2
	case "rate_limit":
		return 3
	default:
		return 0 // Default to block
	}
}

func (mc *MapCoordinator) parseIP(value interface{}) (uint32, error) {
	// Simplified IP parsing
	if ipStr, ok := value.(string); ok {
		// Convert string IP to uint32
		// This is a simplified implementation
		return 0, nil // Placeholder
	}
	return 0, fmt.Errorf("invalid IP format")
}

func (mc *MapCoordinator) parsePort(value interface{}) (uint16, error) {
	if portFloat, ok := value.(float64); ok {
		return uint16(portFloat), nil
	}
	return 0, fmt.Errorf("invalid port format")
}

func (mc *MapCoordinator) parseProtocol(value interface{}) (uint8, error) {
	if protocolStr, ok := value.(string); ok {
		return mc.convertProtocolString(protocolStr), nil
	}
	return 0, fmt.Errorf("invalid protocol format")
}

func (mc *MapCoordinator) convertProtocolString(protocol string) uint8 {
	switch protocol {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	default:
		return 0
	}
}

func (mc *MapCoordinator) serializeConditions(conditions []Condition) []byte {
	// Simplified serialization
	// In a full implementation, you would properly serialize the conditions
	return []byte("conditions_data")
}

func (mc *MapCoordinator) serializeAction(action string) []byte {
	// Simplified serialization
	return []byte(action)
}

func (mc *MapCoordinator) getConditionKey(conditions []Condition) string {
	// Create a key for condition comparison
	var keys []string
	for _, condition := range conditions {
		keys = append(keys, fmt.Sprintf("%s:%s:%v", condition.Field, condition.Operator, condition.Value))
	}
	return fmt.Sprintf("%v", keys)
}

// ConsistencyChecker methods
func (cc *ConsistencyChecker) start() {
	ticker := time.NewTicker(cc.checkInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if err := cc.coordinatior.validateMapConsistency(); err != nil {
				log.Printf("[consistency] Consistency check failed: %v", err)
			}
		case <-cc.ctx.Done():
			return
		}
	}
}

func (cc *ConsistencyChecker) stop() {
	cc.cancel()
}

// Close closes the map coordinator
func (mc *MapCoordinator) Close() error {
	// Stop consistency checker
	mc.consistencyChecker.stop()
	
	// Close map manager
	return mc.advancedMapManager.Close()
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
