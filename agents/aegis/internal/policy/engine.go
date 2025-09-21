package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Engine manages segmentation policies
type Engine struct {
	policies map[string]*Policy
	mu       sync.RWMutex
}

// Policy represents a segmentation policy
type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"` // network, process, file, syscall
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	Rules       []Rule                 `json:"rules"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Rule represents a policy rule
type Rule struct {
	ID          string                 `json:"id"`
	Action      string                 `json:"action"` // allow, deny, log, mark
	Conditions  []Condition            `json:"conditions"`
	Metadata    map[string]interface{} `json:"metadata"`
	Priority    int                    `json:"priority"`
}

// Condition represents a rule condition
type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, gt, lt, in, not_in, contains, regex
	Value    interface{} `json:"value"`
}

// NetworkPolicy represents a network segmentation policy
type NetworkPolicy struct {
	*Policy
	SourceIPs      []string `json:"source_ips"`
	DestinationIPs []string `json:"destination_ips"`
	Ports          []int    `json:"ports"`
	Protocols      []string `json:"protocols"`
	Interfaces     []string `json:"interfaces"`
}

// ProcessPolicy represents a process isolation policy
type ProcessPolicy struct {
	*Policy
	ProcessNames   []string `json:"process_names"`
	UserIDs        []int    `json:"user_ids"`
	GroupIDs       []int    `json:"group_ids"`
	Capabilities   []string `json:"capabilities"`
	Namespaces     []string `json:"namespaces"`
}

// FilePolicy represents a file access control policy
type FilePolicy struct {
	*Policy
	Paths        []string `json:"paths"`
	Permissions  []string `json:"permissions"`
	Users        []string `json:"users"`
	Groups       []string `json:"groups"`
	Operations   []string `json:"operations"` // read, write, execute, delete
}

// SyscallPolicy represents a system call filtering policy
type SyscallPolicy struct {
	*Policy
	Syscalls     []string `json:"syscalls"`
	Arguments    []string `json:"arguments"`
	ReturnValues []string `json:"return_values"`
}

// NewEngine creates a new policy engine
func NewEngine() *Engine {
	return &Engine{
		policies: make(map[string]*Policy),
	}
}

// AddPolicy adds a new policy
func (e *Engine) AddPolicy(policy *Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	if policy.ID == "" {
		return fmt.Errorf("policy ID cannot be empty")
	}
	
	if _, exists := e.policies[policy.ID]; exists {
		return fmt.Errorf("policy %s already exists", policy.ID)
	}
	
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	
	e.policies[policy.ID] = policy
	
	return nil
}

// UpdatePolicy updates an existing policy
func (e *Engine) UpdatePolicy(policy *Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	if _, exists := e.policies[policy.ID]; !exists {
		return fmt.Errorf("policy %s not found", policy.ID)
	}
	
	policy.UpdatedAt = time.Now()
	e.policies[policy.ID] = policy
	
	return nil
}

// DeletePolicy deletes a policy
func (e *Engine) DeletePolicy(policyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	if _, exists := e.policies[policyID]; !exists {
		return fmt.Errorf("policy %s not found", policyID)
	}
	
	delete(e.policies, policyID)
	
	return nil
}

// GetPolicy retrieves a policy by ID
func (e *Engine) GetPolicy(policyID string) (*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	policy, exists := e.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}
	
	return policy, nil
}

// GetPolicies retrieves all policies
func (e *Engine) GetPolicies(ctx context.Context) ([]*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	var policies []*Policy
	for _, policy := range e.policies {
		policies = append(policies, policy)
	}
	
	return policies, nil
}

// GetPoliciesByType retrieves policies by type
func (e *Engine) GetPoliciesByType(policyType string) ([]*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	var policies []*Policy
	for _, policy := range e.policies {
		if policy.Type == policyType {
			policies = append(policies, policy)
		}
	}
	
	return policies, nil
}

// GetEnabledPolicies retrieves all enabled policies
func (e *Engine) GetEnabledPolicies() ([]*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	var policies []*Policy
	for _, policy := range e.policies {
		if policy.Enabled {
			policies = append(policies, policy)
		}
	}
	
	return policies, nil
}

// EnablePolicy enables a policy
func (e *Engine) EnablePolicy(policyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	policy, exists := e.policies[policyID]
	if !exists {
		return fmt.Errorf("policy %s not found", policyID)
	}
	
	policy.Enabled = true
	policy.UpdatedAt = time.Now()
	
	return nil
}

// DisablePolicy disables a policy
func (e *Engine) DisablePolicy(policyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	policy, exists := e.policies[policyID]
	if !exists {
		return fmt.Errorf("policy %s not found", policyID)
	}
	
	policy.Enabled = false
	policy.UpdatedAt = time.Now()
	
	return nil
}

// EvaluatePolicy evaluates a policy against given context
func (e *Engine) EvaluatePolicy(policyID string, context map[string]interface{}) (bool, string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	policy, exists := e.policies[policyID]
	if !exists {
		return false, "", fmt.Errorf("policy %s not found", policyID)
	}
	
	if !policy.Enabled {
		return false, "policy disabled", nil
	}
	
	// Evaluate each rule
	for _, rule := range policy.Rules {
		matches, reason, err := e.evaluateRule(rule, context)
		if err != nil {
			return false, "", fmt.Errorf("rule evaluation failed: %w", err)
		}
		
		if matches {
			return rule.Action == "allow", reason, nil
		}
	}
	
	// Default action if no rules match
	return false, "no matching rules", nil
}

// evaluateRule evaluates a single rule
func (e *Engine) evaluateRule(rule Rule, context map[string]interface{}) (bool, string, error) {
	for _, condition := range rule.Conditions {
		matches, err := e.evaluateCondition(condition, context)
		if err != nil {
			return false, "", fmt.Errorf("condition evaluation failed: %w", err)
		}
		
		if !matches {
			return false, fmt.Sprintf("condition %s not met", condition.Field), nil
		}
	}
	
	return true, "all conditions met", nil
}

// evaluateCondition evaluates a single condition
func (e *Engine) evaluateCondition(condition Condition, context map[string]interface{}) (bool, error) {
	fieldValue, exists := context[condition.Field]
	if !exists {
		return false, nil
	}
	
	switch condition.Operator {
	case "eq":
		return fieldValue == condition.Value, nil
	case "ne":
		return fieldValue != condition.Value, nil
	case "gt":
		return compareValues(fieldValue, condition.Value) > 0, nil
	case "lt":
		return compareValues(fieldValue, condition.Value) < 0, nil
	case "in":
		return containsValue(condition.Value, fieldValue), nil
	case "not_in":
		return !containsValue(condition.Value, fieldValue), nil
	case "contains":
		return containsString(fieldValue, condition.Value), nil
	case "regex":
		return matchesRegex(fieldValue, condition.Value), nil
	default:
		return false, fmt.Errorf("unknown operator: %s", condition.Operator)
	}
}

// compareValues compares two values for ordering
func compareValues(a, b interface{}) int {
	// Simple implementation - in practice, you'd handle different types
	if a == b {
		return 0
	}
	if fmt.Sprintf("%v", a) > fmt.Sprintf("%v", b) {
		return 1
	}
	return -1
}

// containsValue checks if a value is in a list
func containsValue(list, value interface{}) bool {
	// Simple implementation - in practice, you'd handle different types
	return fmt.Sprintf("%v", list) == fmt.Sprintf("%v", value)
}

// containsString checks if a string contains a substring
func containsString(str, substr interface{}) bool {
	strStr := fmt.Sprintf("%v", str)
	substrStr := fmt.Sprintf("%v", substr)
	return len(strStr) > 0 && len(substrStr) > 0 && 
		   len(strStr) >= len(substrStr) && 
		   strStr[:len(substrStr)] == substrStr
}

// matchesRegex checks if a string matches a regex pattern
func matchesRegex(str, pattern interface{}) bool {
	// Simple implementation - in practice, you'd use regexp package
	return containsString(str, pattern)
}

// ExportPolicies exports policies to JSON
func (e *Engine) ExportPolicies() ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	var policies []*Policy
	for _, policy := range e.policies {
		policies = append(policies, policy)
	}
	
	return json.MarshalIndent(policies, "", "  ")
}

// ImportPolicies imports policies from JSON
func (e *Engine) ImportPolicies(data []byte) error {
	var policies []*Policy
	if err := json.Unmarshal(data, &policies); err != nil {
		return fmt.Errorf("failed to unmarshal policies: %w", err)
	}
	
	e.mu.Lock()
	defer e.mu.Unlock()
	
	for _, policy := range policies {
		policy.CreatedAt = time.Now()
		policy.UpdatedAt = time.Now()
		e.policies[policy.ID] = policy
	}
	
	return nil
}

// GetPolicyStats returns statistics about policies
func (e *Engine) GetPolicyStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_policies":    len(e.policies),
		"enabled_policies":  0,
		"disabled_policies": 0,
		"policy_types":      make(map[string]int),
	}
	
	for _, policy := range e.policies {
		if policy.Enabled {
			stats["enabled_policies"] = stats["enabled_policies"].(int) + 1
		} else {
			stats["disabled_policies"] = stats["disabled_policies"].(int) + 1
		}
		
		typeCount := stats["policy_types"].(map[string]int)
		typeCount[policy.Type]++
	}
	
	return stats
}
