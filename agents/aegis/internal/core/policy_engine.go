package core

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

// PolicyEngine manages policy lifecycle and enforcement
type PolicyEngine struct {
	ebpfManager *EBPFManager
	telemetry   *telemetry.Logger
	
	// Policy management
	policies    map[string]*models.Policy
	pendingPolicies []*models.Policy
	mu          sync.RWMutex
	
	// State
	running     bool
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(ebpfManager *EBPFManager, telemetry *telemetry.Logger) (*PolicyEngine, error) {
	if ebpfManager == nil {
		return nil, fmt.Errorf("eBPF manager cannot be nil")
	}
	if telemetry == nil {
		return nil, fmt.Errorf("telemetry logger cannot be nil")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pe := &PolicyEngine{
		ebpfManager: ebpfManager,
		telemetry:   telemetry,
		policies:    make(map[string]*models.Policy),
		running:     false,
		ctx:         ctx,
		cancel:      cancel,
	}
	
	log.Printf("[policy_engine] Policy engine initialized")
	return pe, nil
}

// Start starts the policy engine
func (pe *PolicyEngine) Start() error {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	
	if pe.running {
		return fmt.Errorf("policy engine is already running")
	}
	
	pe.running = true
	log.Printf("[policy_engine] Policy engine started")
	
	// Start policy processing loop
	go pe.policyProcessingLoop()
	
	return nil
}

// Stop stops the policy engine
func (pe *PolicyEngine) Stop() error {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	
	if !pe.running {
		return fmt.Errorf("policy engine is not running")
	}
	
	pe.cancel()
	pe.running = false
	
	log.Printf("[policy_engine] Policy engine stopped")
	return nil
}

// policyProcessingLoop processes pending policies
func (pe *PolicyEngine) policyProcessingLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	log.Printf("[policy_engine] Policy processing loop started")
	
	for {
		select {
		case <-pe.ctx.Done():
			log.Printf("[policy_engine] Policy processing loop stopped")
			return
		case <-ticker.C:
				if err := pe.ProcessPendingPolicies(); err != nil {
				log.Printf("[policy_engine] Error processing pending policies: %v", err)
				pe.telemetry.LogError("policy_processing", err.Error(), nil)
			}
		}
	}
}

// AddPolicy adds a new policy to the engine
func (pe *PolicyEngine) AddPolicy(policy *models.Policy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	
	pe.mu.Lock()
	defer pe.mu.Unlock()
	
	// Validate policy
	if err := pe.validatePolicy(policy); err != nil {
		pe.telemetry.LogError("policy_validation", err.Error(), map[string]interface{}{
			"policy_id": policy.ID,
		})
		return fmt.Errorf("policy validation failed: %w", err)
	}
	
	// Add to pending policies for processing
	pe.pendingPolicies = append(pe.pendingPolicies, policy)
	
	log.Printf("[policy_engine] Policy %s added to pending queue", policy.ID)
	pe.telemetry.LogInfo("policy_added", fmt.Sprintf("Policy %s added", policy.ID), map[string]interface{}{
		"policy_id": policy.ID,
		"policy_type": policy.Type,
	})
	
	return nil
}

// RemovePolicy removes a policy from the engine
func (pe *PolicyEngine) RemovePolicy(policyID string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	
	policy, exists := pe.policies[policyID]
	if !exists {
		return fmt.Errorf("policy %s not found", policyID)
	}
	
	// Remove from eBPF maps
	if err := pe.ebpfManager.RemovePolicy(policyID); err != nil {
		log.Printf("[policy_engine] Warning: failed to remove policy from eBPF: %v", err)
	}
	
	// Remove from active policies
	delete(pe.policies, policyID)
	
	log.Printf("[policy_engine] Policy %s removed", policyID)
	pe.telemetry.LogInfo("policy_removed", fmt.Sprintf("Policy %s removed", policyID), map[string]interface{}{
		"policy_id": policyID,
		"policy_type": policy.Type,
	})
	
	return nil
}

// UpdatePolicy updates an existing policy
func (pe *PolicyEngine) UpdatePolicy(policy *models.Policy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	
	pe.mu.Lock()
	defer pe.mu.Unlock()
	
	// Check if policy exists
	_, exists := pe.policies[policy.ID]
	if !exists {
		return fmt.Errorf("policy %s not found", policy.ID)
	}
	
	// Validate updated policy
	if err := pe.validatePolicy(policy); err != nil {
		pe.telemetry.LogError("policy_validation", err.Error(), map[string]interface{}{
			"policy_id": policy.ID,
		})
		return fmt.Errorf("policy validation failed: %w", err)
	}
	
	// Update policy
	pe.policies[policy.ID] = policy
	
	// Update in eBPF maps
	if err := pe.ebpfManager.UpdatePolicy(policy); err != nil {
		log.Printf("[policy_engine] Warning: failed to update policy in eBPF: %v", err)
	}
	
	log.Printf("[policy_engine] Policy %s updated", policy.ID)
	pe.telemetry.LogInfo("policy_updated", fmt.Sprintf("Policy %s updated", policy.ID), map[string]interface{}{
		"policy_id": policy.ID,
		"policy_type": policy.Type,
	})
	
	return nil
}

// GetPolicy retrieves a policy by ID
func (pe *PolicyEngine) GetPolicy(policyID string) (*models.Policy, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	
	policy, exists := pe.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}
	
	// Return a copy to prevent external modifications
	policyCopy := *policy
	return &policyCopy, nil
}

// GetAllPolicies returns all active policies
func (pe *PolicyEngine) GetAllPolicies() map[string]*models.Policy {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	
	// Return a copy to prevent external modifications
	policiesCopy := make(map[string]*models.Policy)
	for id, policy := range pe.policies {
		policyCopy := *policy
		policiesCopy[id] = &policyCopy
	}
	
	return policiesCopy
}

// GetPolicyCount returns the number of active policies
func (pe *PolicyEngine) GetPolicyCount() int {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return len(pe.policies)
}

// ProcessPendingPolicies processes all pending policies
func (pe *PolicyEngine) ProcessPendingPolicies() error {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	
	if len(pe.pendingPolicies) == 0 {
		return nil
	}
	
	processed := 0
	var errors []error
	
	for _, policy := range pe.pendingPolicies {
		if err := pe.applyPolicy(policy); err != nil {
			log.Printf("[policy_engine] Failed to apply policy %s: %v", policy.ID, err)
			errors = append(errors, fmt.Errorf("policy %s: %w", policy.ID, err))
			continue
		}
		
		// Move from pending to active
		pe.policies[policy.ID] = policy
		processed++
	}
	
	// Clear processed policies
	pe.pendingPolicies = nil
	
	if len(errors) > 0 {
		pe.telemetry.LogError("policy_processing", fmt.Sprintf("Failed to process %d policies", len(errors)), map[string]interface{}{
			"errors": errors,
		})
		return fmt.Errorf("failed to process %d policies", len(errors))
	}
	
	if processed > 0 {
		log.Printf("[policy_engine] Successfully processed %d pending policies", processed)
		pe.telemetry.LogInfo("policies_processed", fmt.Sprintf("Processed %d policies", processed), map[string]interface{}{
			"count": processed,
		})
	}
	
	return nil
}

// applyPolicy applies a policy to the eBPF maps
func (pe *PolicyEngine) applyPolicy(policy *models.Policy) error {
	// Apply policy to eBPF maps
	if err := pe.ebpfManager.ApplyPolicy(policy); err != nil {
		return fmt.Errorf("failed to apply policy to eBPF: %w", err)
	}
	
	log.Printf("[policy_engine] Policy %s applied successfully", policy.ID)
	return nil
}

// validatePolicy validates a policy before application
func (pe *PolicyEngine) validatePolicy(policy *models.Policy) error {
	if policy.ID == "" {
		return fmt.Errorf("policy ID cannot be empty")
	}
	
	if policy.Name == "" {
		return fmt.Errorf("policy name cannot be empty")
	}
	
	if policy.Type == "" {
		return fmt.Errorf("policy type cannot be empty")
	}
	
	// Validate policy rules
	if len(policy.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}
	
	for i, rule := range policy.Rules {
		if err := pe.validateRule(rule, i); err != nil {
			return fmt.Errorf("rule %d validation failed: %w", i, err)
		}
	}
	
	return nil
}

// validateRule validates a policy rule
func (pe *PolicyEngine) validateRule(rule models.Rule, index int) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}
	
	if rule.Action == "" {
		return fmt.Errorf("rule action cannot be empty")
	}
	
	// Validate action values
	validActions := map[string]bool{
		"allow": true,
		"deny":  true,
		"drop":  true,
		"block": true,
		"log":   true,
	}
	
	if !validActions[rule.Action] {
		return fmt.Errorf("invalid action: %s", rule.Action)
	}
	
	// Validate conditions
	for i, condition := range rule.Conditions {
		if err := pe.validateCondition(condition, i); err != nil {
			return fmt.Errorf("condition %d validation failed: %w", i, err)
		}
	}
	
	return nil
}

// validateCondition validates a policy condition
func (pe *PolicyEngine) validateCondition(condition models.Condition, index int) error {
	if condition.Field == "" {
		return fmt.Errorf("condition field cannot be empty")
	}
	
	if condition.Operator == "" {
		return fmt.Errorf("condition operator cannot be empty")
	}
	
	// Validate operator values
	validOperators := map[string]bool{
		"eq":      true,
		"equals":  true,
		"ne":      true,
		"in":      true,
		"notin":   true,
		"cidr":    true,
	}
	
	if !validOperators[condition.Operator] {
		return fmt.Errorf("invalid operator: %s", condition.Operator)
	}
	
	return nil
}

// GetPendingPolicyCount returns the number of pending policies
func (pe *PolicyEngine) GetPendingPolicyCount() int {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return len(pe.pendingPolicies)
}

// IsRunning returns whether the policy engine is running
func (pe *PolicyEngine) IsRunning() bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.running
}
