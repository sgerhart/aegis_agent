package policy

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ValidationResult represents the result of policy validation
type ValidationResult struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// PolicyValidator validates policies before application
type PolicyValidator struct {
	rateLimiter *RateLimiter
}

// RateLimiter returns the rate limiter instance
func (pv *PolicyValidator) RateLimiter() *RateLimiter {
	return pv.rateLimiter
}

// NewPolicyValidator creates a new policy validator
func NewPolicyValidator() *PolicyValidator {
	return &PolicyValidator{
		rateLimiter: NewRateLimiter(10, time.Minute), // Max 10 updates per minute
	}
}

// ValidatePolicy validates a policy before application
func (pv *PolicyValidator) ValidatePolicy(policy *Policy) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Basic policy validation
	pv.validateBasicPolicy(policy, result)
	
	// Network-specific validation
	if policy.Type == "network" {
		pv.validateNetworkPolicy(policy, result)
	}
	
	// Process-specific validation
	if policy.Type == "process" {
		pv.validateProcessPolicy(policy, result)
	}
	
	// File-specific validation
	if policy.Type == "file" {
		pv.validateFilePolicy(policy, result)
	}
	
	// Syscall-specific validation
	if policy.Type == "syscall" {
		pv.validateSyscallPolicy(policy, result)
	}

	// Rule validation
	pv.validateRules(policy, result)
	
	// Conflict detection
	pv.validateConflicts(policy, result)

	result.Valid = len(result.Errors) == 0
	return result
}

// ValidatePolicyRule validates a policy rule from artifact
func (pv *PolicyValidator) ValidatePolicyRule(rule *PolicyRule) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Validate IP address
	if rule.TargetIP != "" {
		if err := pv.validateIPAddress(rule.TargetIP); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid target IP: %v", err))
		}
	}

	// Validate action
	if err := pv.validateAction(rule.Action); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid action: %v", err))
	}

	// Validate protocol
	if rule.Protocol != "" {
		if err := pv.validateProtocol(rule.Protocol); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid protocol: %v", err))
		}
	}

	// Check for dangerous configurations
	pv.checkDangerousConfigurations(rule, result)

	result.Valid = len(result.Errors) == 0
	return result
}

// validateBasicPolicy validates basic policy structure
func (pv *PolicyValidator) validateBasicPolicy(policy *Policy, result *ValidationResult) {
	// Validate ID
	if policy.ID == "" {
		result.Errors = append(result.Errors, "Policy ID cannot be empty")
	}

	// Validate name
	if policy.Name == "" {
		result.Errors = append(result.Errors, "Policy name cannot be empty")
	}

	// Validate type
	validTypes := []string{"network", "process", "file", "syscall"}
	if !contains(validTypes, policy.Type) {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid policy type: %s. Must be one of: %s", policy.Type, strings.Join(validTypes, ", ")))
	}

	// Validate priority
	if policy.Priority < 0 || policy.Priority > 1000 {
		result.Warnings = append(result.Warnings, "Policy priority should be between 0 and 1000")
	}

	// Validate rules
	if len(policy.Rules) == 0 {
		result.Warnings = append(result.Warnings, "Policy has no rules")
	}
}

// validateNetworkPolicy validates network-specific policy fields
func (pv *PolicyValidator) validateNetworkPolicy(policy *Policy, result *ValidationResult) {
	// Check if policy has network-specific rules
	hasNetworkRules := false
	for _, rule := range policy.Rules {
		for _, condition := range rule.Conditions {
			if contains([]string{"source_ip", "destination_ip", "port", "protocol"}, condition.Field) {
				hasNetworkRules = true
				break
			}
		}
		if hasNetworkRules {
			break
		}
	}

	if !hasNetworkRules {
		result.Warnings = append(result.Warnings, "Network policy has no network-specific rules")
	}
}

// validateProcessPolicy validates process-specific policy fields
func (pv *PolicyValidator) validateProcessPolicy(policy *Policy, result *ValidationResult) {
	// Check if policy has process-specific rules
	hasProcessRules := false
	for _, rule := range policy.Rules {
		for _, condition := range rule.Conditions {
			if contains([]string{"process_name", "user_id", "group_id", "capability"}, condition.Field) {
				hasProcessRules = true
				break
			}
		}
		if hasProcessRules {
			break
		}
	}

	if !hasProcessRules {
		result.Warnings = append(result.Warnings, "Process policy has no process-specific rules")
	}
}

// validateFilePolicy validates file-specific policy fields
func (pv *PolicyValidator) validateFilePolicy(policy *Policy, result *ValidationResult) {
	// Check if policy has file-specific rules
	hasFileRules := false
	for _, rule := range policy.Rules {
		for _, condition := range rule.Conditions {
			if contains([]string{"file_path", "permission", "operation"}, condition.Field) {
				hasFileRules = true
				break
			}
		}
		if hasFileRules {
			break
		}
	}

	if !hasFileRules {
		result.Warnings = append(result.Warnings, "File policy has no file-specific rules")
	}
}

// validateSyscallPolicy validates syscall-specific policy fields
func (pv *PolicyValidator) validateSyscallPolicy(policy *Policy, result *ValidationResult) {
	// Check if policy has syscall-specific rules
	hasSyscallRules := false
	for _, rule := range policy.Rules {
		for _, condition := range rule.Conditions {
			if contains([]string{"syscall", "argument", "return_value"}, condition.Field) {
				hasSyscallRules = true
				break
			}
		}
		if hasSyscallRules {
			break
		}
	}

	if !hasSyscallRules {
		result.Warnings = append(result.Warnings, "Syscall policy has no syscall-specific rules")
	}
}

// validateRules validates individual rules
func (pv *PolicyValidator) validateRules(policy *Policy, result *ValidationResult) {
	for i, rule := range policy.Rules {
		rulePrefix := fmt.Sprintf("Rule %d", i+1)
		
		// Validate rule ID
		if rule.ID == "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: Rule ID is empty", rulePrefix))
		}

		// Validate action
		if err := pv.validateAction(rule.Action); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", rulePrefix, err))
		}

		// Validate conditions
		if len(rule.Conditions) == 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: Rule has no conditions", rulePrefix))
		}

		for j, condition := range rule.Conditions {
			conditionPrefix := fmt.Sprintf("%s, Condition %d", rulePrefix, j+1)
			pv.validateCondition(condition, conditionPrefix, result)
		}
	}
}

// validateCondition validates a single condition
func (pv *PolicyValidator) validateCondition(condition Condition, prefix string, result *ValidationResult) {
	// Validate field
	if condition.Field == "" {
		result.Errors = append(result.Errors, fmt.Sprintf("%s: Field cannot be empty", prefix))
		return
	}

	// Validate operator
	validOperators := []string{"eq", "ne", "gt", "lt", "in", "not_in", "contains", "regex"}
	if !contains(validOperators, condition.Operator) {
		result.Errors = append(result.Errors, fmt.Sprintf("%s: Invalid operator '%s'. Must be one of: %s", prefix, condition.Operator, strings.Join(validOperators, ", ")))
	}

	// Validate value based on field type
	pv.validateConditionValue(condition, prefix, result)
}

// validateConditionValue validates condition values based on field type
func (pv *PolicyValidator) validateConditionValue(condition Condition, prefix string, result *ValidationResult) {
	switch condition.Field {
	case "source_ip", "destination_ip":
		if ipStr, ok := condition.Value.(string); ok {
			if err := pv.validateIPAddress(ipStr); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: Invalid IP address '%s': %v", prefix, ipStr, err))
			}
		} else if ipList, ok := condition.Value.([]interface{}); ok {
			for _, ip := range ipList {
				if ipStr, ok := ip.(string); ok {
					if err := pv.validateIPAddress(ipStr); err != nil {
						result.Errors = append(result.Errors, fmt.Sprintf("%s: Invalid IP address '%s': %v", prefix, ipStr, err))
					}
				}
			}
		}
	case "port":
		if err := pv.validatePort(condition.Value); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: Invalid port: %v", prefix, err))
		}
	case "protocol":
		if protocolStr, ok := condition.Value.(string); ok {
			if err := pv.validateProtocol(protocolStr); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: Invalid protocol '%s': %v", prefix, protocolStr, err))
			}
		}
	case "user_id", "group_id":
		if err := pv.validateID(condition.Value); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: Invalid ID: %v", prefix, err))
		}
	case "file_path":
		if pathStr, ok := condition.Value.(string); ok {
			if err := pv.validateFilePath(pathStr); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: Invalid file path '%s': %v", prefix, pathStr, err))
			}
		}
	}
}

// validateConflicts checks for policy conflicts
func (pv *PolicyValidator) validateConflicts(policy *Policy, result *ValidationResult) {
	// This is a simplified conflict detection
	// In a full implementation, you would check against existing policies
	
	// Check for conflicting allow/deny rules on same conditions
	allowRules := make(map[string]bool)
	denyRules := make(map[string]bool)
	
	for _, rule := range policy.Rules {
		conditionKey := pv.getConditionKey(rule.Conditions)
		
		if rule.Action == "allow" {
			if denyRules[conditionKey] {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Potential conflict: Allow and deny rules for same conditions"))
			}
			allowRules[conditionKey] = true
		} else if rule.Action == "deny" {
			if allowRules[conditionKey] {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Potential conflict: Allow and deny rules for same conditions"))
			}
			denyRules[conditionKey] = true
		}
	}
}

// validateIPAddress validates an IP address or CIDR
func (pv *PolicyValidator) validateIPAddress(ipStr string) error {
	// Check for dangerous IP addresses
	dangerousIPs := []string{
		"0.0.0.0",
		"127.0.0.1",
		"::1",
		"0.0.0.0/0",
		"::/0",
	}
	
	for _, dangerous := range dangerousIPs {
		if ipStr == dangerous {
			return fmt.Errorf("blocking %s would isolate the system", dangerous)
		}
	}
	
	// Parse IP or CIDR
	_, _, err := net.ParseCIDR(ipStr)
	if err != nil {
		// Try parsing as plain IP
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP address or CIDR format")
		}
	}
	
	return nil
}

// validateAction validates policy actions
func (pv *PolicyValidator) validateAction(action string) error {
	validActions := []string{"allow", "deny", "drop", "block", "log", "mark", "pass"}
	if !contains(validActions, strings.ToLower(action)) {
		return fmt.Errorf("invalid action '%s'. Must be one of: %s", action, strings.Join(validActions, ", "))
	}
	return nil
}

// validateProtocol validates network protocols
func (pv *PolicyValidator) validateProtocol(protocol string) error {
	validProtocols := []string{"tcp", "udp", "icmp", "any", "all"}
	if !contains(validProtocols, strings.ToLower(protocol)) {
		return fmt.Errorf("invalid protocol '%s'. Must be one of: %s", protocol, strings.Join(validProtocols, ", "))
	}
	return nil
}

// validatePort validates port numbers
func (pv *PolicyValidator) validatePort(value interface{}) error {
	switch v := value.(type) {
	case float64:
		port := int(v)
		if port < 0 || port > 65535 {
			return fmt.Errorf("port must be between 0 and 65535")
		}
	case int:
		if v < 0 || v > 65535 {
			return fmt.Errorf("port must be between 0 and 65535")
		}
	case []interface{}:
		for _, port := range v {
			if err := pv.validatePort(port); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid port format")
	}
	return nil
}

// validateID validates user/group IDs
func (pv *PolicyValidator) validateID(value interface{}) error {
	switch v := value.(type) {
	case float64:
		id := int(v)
		if id < 0 || id > 65535 {
			return fmt.Errorf("ID must be between 0 and 65535")
		}
	case int:
		if v < 0 || v > 65535 {
			return fmt.Errorf("ID must be between 0 and 65535")
		}
	default:
		return fmt.Errorf("invalid ID format")
	}
	return nil
}

// validateFilePath validates file paths
func (pv *PolicyValidator) validateFilePath(path string) error {
	// Check for dangerous paths
	dangerousPaths := []string{
		"/",
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/etc",
		"/sys",
		"/proc",
		"/dev",
	}
	
	for _, dangerous := range dangerousPaths {
		if path == dangerous {
			return fmt.Errorf("blocking access to '%s' could break system functionality", dangerous)
		}
	}
	
	return nil
}

// checkDangerousConfigurations checks for dangerous policy configurations
func (pv *PolicyValidator) checkDangerousConfigurations(rule *PolicyRule, result *ValidationResult) {
	// Check for blocking all traffic
	if rule.TargetIP == "0.0.0.0" || rule.TargetIP == "::" {
		result.Errors = append(result.Errors, "Blocking 0.0.0.0 or :: would isolate the system")
	}
	
	// Check for blocking localhost
	if rule.TargetIP == "127.0.0.1" || rule.TargetIP == "::1" {
		result.Warnings = append(result.Warnings, "Blocking localhost could break local services")
	}
	
	// Check for blocking DNS servers
	if rule.TargetIP == "8.8.8.8" || rule.TargetIP == "8.8.4.4" || rule.TargetIP == "1.1.1.1" {
		result.Warnings = append(result.Warnings, "Blocking common DNS servers could break name resolution")
	}
}

// getConditionKey creates a key for condition comparison
func (pv *PolicyValidator) getConditionKey(conditions []Condition) string {
	var keys []string
	for _, condition := range conditions {
		keys = append(keys, fmt.Sprintf("%s:%s:%v", condition.Field, condition.Operator, condition.Value))
	}
	return strings.Join(keys, "|")
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RateLimiter implements rate limiting for policy updates
type RateLimiter struct {
	maxRequests int
	window      time.Duration
	requests    []time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		maxRequests: maxRequests,
		window:      window,
		requests:    make([]time.Time, 0),
	}
}

// Allow checks if a request is allowed
func (rl *RateLimiter) Allow() bool {
	now := time.Now()
	
	// Remove old requests outside the window
	var validRequests []time.Time
	for _, req := range rl.requests {
		if now.Sub(req) < rl.window {
			validRequests = append(validRequests, req)
		}
	}
	rl.requests = validRequests
	
	// Check if we're under the limit
	if len(rl.requests) >= rl.maxRequests {
		return false
	}
	
	// Add current request
	rl.requests = append(rl.requests, now)
	return true
}

// PolicyRule represents a policy rule from artifact (for compatibility)
type PolicyRule struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Type        string `json:"type"`
	PolicyType  string `json:"policy_type"`
	TargetIP    string `json:"target_ip"`
	Protocol    string `json:"protocol"`
	Direction   string `json:"direction"`
	Hook        string `json:"hook"`
	Action      string `json:"action"`
}
