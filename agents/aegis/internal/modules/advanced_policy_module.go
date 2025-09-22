package modules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

// AdvancedPolicyModule provides complex policy management capabilities
type AdvancedPolicyModule struct {
	*BaseModule
	policyEngine    *AdvancedPolicyEngine
	policyTemplates *PolicyTemplates
	policyValidator *PolicyValidator
	mu              sync.RWMutex
}

// AdvancedPolicyEngine manages complex policies
type AdvancedPolicyEngine struct {
	policies map[string]models.Policy
	templates map[string]PolicyTemplate
	mu       sync.RWMutex
}

// PolicyTemplates manages policy templates
type PolicyTemplates struct {
	templates map[string]PolicyTemplate
	mu        sync.RWMutex
}

// PolicyValidator validates policy configurations
type PolicyValidator struct {
	rules map[string]ValidationRule
	mu    sync.RWMutex
}

// PolicyTemplate represents a policy template
type PolicyTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Template    models.Policy          `json:"template"`
	Parameters  []TemplateParameter    `json:"parameters"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TemplateParameter represents a template parameter
type TemplateParameter struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default"`
	Description string      `json:"description"`
}

// ValidationRule represents a policy validation rule
type ValidationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Rule        func(models.Policy) error `json:"-"`
	Severity    string                 `json:"severity"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PolicyVersion represents a policy version
type PolicyVersion struct {
	Version     string                 `json:"version"`
	Policy      models.Policy          `json:"policy"`
	CreatedAt   time.Time              `json:"created_at"`
	CreatedBy   string                 `json:"created_by"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewAdvancedPolicyModule creates a new advanced policy module
func NewAdvancedPolicyModule(logger *telemetry.Logger) *AdvancedPolicyModule {
	info := ModuleInfo{
		ID:          "advanced_policy",
		Name:        "Advanced Policy Module",
		Version:     "1.0.0",
		Description: "Provides advanced policy management, templates, and validation",
		Author:      "Aegis Team",
		License:     "MIT",
		Capabilities: []string{
			"policy_templates",
			"policy_validation",
			"policy_versioning",
			"policy_inheritance",
			"policy_testing",
			"policy_rollback",
		},
		Metadata: map[string]interface{}{
			"category": "policy",
			"priority": "high",
		},
	}

	apm := &AdvancedPolicyModule{
		BaseModule:      NewBaseModule(info, logger),
		policyEngine: &AdvancedPolicyEngine{
			policies:  make(map[string]models.Policy),
			templates: make(map[string]PolicyTemplate),
		},
		policyTemplates: &PolicyTemplates{
			templates: make(map[string]PolicyTemplate),
		},
		policyValidator: &PolicyValidator{
			rules: make(map[string]ValidationRule),
		},
	}

	return apm
}

// Initialize initializes the advanced policy module
func (apm *AdvancedPolicyModule) Initialize(ctx context.Context, config ModuleConfig) error {
	if err := apm.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	// Initialize policy components
	apm.initializePolicyTemplates()
	apm.initializeValidationRules()

	apm.LogInfo("Advanced policy module initialized")
	return nil
}

// Start starts the advanced policy module
func (apm *AdvancedPolicyModule) Start(ctx context.Context) error {
	if err := apm.BaseModule.Start(ctx); err != nil {
		return err
	}

	// Start background policy management processes
	go apm.validatePolicies()
	go apm.cleanupOldVersions()

	apm.LogInfo("Advanced policy module started")
	return nil
}

// HandleMessage handles advanced policy-related messages
func (apm *AdvancedPolicyModule) HandleMessage(message interface{}) (interface{}, error) {
	switch msg := message.(type) {
	case map[string]interface{}:
		switch msg["type"] {
		case "create_policy":
			return apm.handleCreatePolicy(msg)
		case "update_policy":
			return apm.handleUpdatePolicy(msg)
		case "delete_policy":
			return apm.handleDeletePolicy(msg)
		case "get_policy":
			return apm.handleGetPolicy(msg)
		case "list_policies":
			return apm.handleListPolicies(msg)
		case "create_template":
			return apm.handleCreateTemplate(msg)
		case "get_template":
			return apm.handleGetTemplate(msg)
		case "list_templates":
			return apm.handleListTemplates(msg)
		case "validate_policy":
			return apm.handleValidatePolicy(msg)
		case "test_policy":
			return apm.handleTestPolicy(msg)
		case "rollback_policy":
			return apm.handleRollbackPolicy(msg)
		default:
			return apm.BaseModule.HandleMessage(message)
		}
	default:
		return apm.BaseModule.HandleMessage(message)
	}
}

// handleCreatePolicy handles policy creation requests
func (apm *AdvancedPolicyModule) handleCreatePolicy(msg map[string]interface{}) (interface{}, error) {
	_, ok := msg["policy"]
	if !ok {
		return nil, fmt.Errorf("policy is required")
	}
	
	// Convert to Policy struct (simplified)
	policy := models.Policy{
		ID:          fmt.Sprintf("policy_%d", time.Now().Unix()),
		Name:        "New Policy",
		Description: "Policy created via API",
		Type:        "network",
		Priority:    1,
		Enabled:     true,
		Rules:       []models.Rule{},
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	// Validate policy
	if err := apm.validatePolicy(policy); err != nil {
		return nil, fmt.Errorf("policy validation failed: %w", err)
	}
	
	apm.mu.Lock()
	apm.policyEngine.AddPolicy(policy)
	apm.mu.Unlock()
	
	return map[string]interface{}{
		"policy_id": policy.ID,
		"status":    "created",
		"timestamp": time.Now(),
	}, nil
}

// handleUpdatePolicy handles policy update requests
func (apm *AdvancedPolicyModule) handleUpdatePolicy(msg map[string]interface{}) (interface{}, error) {
	policyID, ok := msg["policy_id"].(string)
	if !ok {
		return nil, fmt.Errorf("policy_id is required")
	}
	
	apm.mu.RLock()
	policy, exists := apm.policyEngine.GetPolicy(policyID)
	apm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}
	
	// Update policy
	policy.UpdatedAt = time.Now()
	
	// Validate updated policy
	if err := apm.validatePolicy(policy); err != nil {
		return nil, fmt.Errorf("policy validation failed: %w", err)
	}
	
	apm.mu.Lock()
	apm.policyEngine.UpdatePolicy(policy)
	apm.mu.Unlock()
	
	return map[string]interface{}{
		"policy_id": policyID,
		"status":    "updated",
		"timestamp": time.Now(),
	}, nil
}

// handleDeletePolicy handles policy deletion requests
func (apm *AdvancedPolicyModule) handleDeletePolicy(msg map[string]interface{}) (interface{}, error) {
	policyID, ok := msg["policy_id"].(string)
	if !ok {
		return nil, fmt.Errorf("policy_id is required")
	}
	
	apm.mu.Lock()
	success := apm.policyEngine.DeletePolicy(policyID)
	apm.mu.Unlock()
	
	if !success {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}
	
	return map[string]interface{}{
		"policy_id": policyID,
		"status":    "deleted",
		"timestamp": time.Now(),
	}, nil
}

// handleGetPolicy handles policy retrieval requests
func (apm *AdvancedPolicyModule) handleGetPolicy(msg map[string]interface{}) (interface{}, error) {
	policyID, ok := msg["policy_id"].(string)
	if !ok {
		return nil, fmt.Errorf("policy_id is required")
	}
	
	apm.mu.RLock()
	policy, exists := apm.policyEngine.GetPolicy(policyID)
	apm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}
	
	return map[string]interface{}{
		"policy":    policy,
		"timestamp": time.Now(),
	}, nil
}

// handleListPolicies handles policy listing requests
func (apm *AdvancedPolicyModule) handleListPolicies(msg map[string]interface{}) (interface{}, error) {
	apm.mu.RLock()
	policies := apm.policyEngine.GetAllPolicies()
	apm.mu.RUnlock()
	
	return map[string]interface{}{
		"policies":  policies,
		"count":     len(policies),
		"timestamp": time.Now(),
	}, nil
}

// handleCreateTemplate handles template creation requests
func (apm *AdvancedPolicyModule) handleCreateTemplate(msg map[string]interface{}) (interface{}, error) {
	templateName, ok := msg["template_name"].(string)
	if !ok {
		return nil, fmt.Errorf("template_name is required")
	}
	
	template := PolicyTemplate{
		ID:          fmt.Sprintf("template_%d", time.Now().Unix()),
		Name:        templateName,
		Description: "Policy template created via API",
		Category:    "custom",
		Template:    models.Policy{},
		Parameters:  []TemplateParameter{},
		Metadata:    make(map[string]interface{}),
	}
	
	apm.mu.Lock()
	apm.policyTemplates.AddTemplate(template)
	apm.mu.Unlock()
	
	return map[string]interface{}{
		"template_id": template.ID,
		"status":      "created",
		"timestamp":   time.Now(),
	}, nil
}

// handleGetTemplate handles template retrieval requests
func (apm *AdvancedPolicyModule) handleGetTemplate(msg map[string]interface{}) (interface{}, error) {
	templateID, ok := msg["template_id"].(string)
	if !ok {
		return nil, fmt.Errorf("template_id is required")
	}
	
	apm.mu.RLock()
	template, exists := apm.policyTemplates.GetTemplate(templateID)
	apm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}
	
	return map[string]interface{}{
		"template":  template,
		"timestamp": time.Now(),
	}, nil
}

// handleListTemplates handles template listing requests
func (apm *AdvancedPolicyModule) handleListTemplates(msg map[string]interface{}) (interface{}, error) {
	apm.mu.RLock()
	templates := apm.policyTemplates.GetAllTemplates()
	apm.mu.RUnlock()
	
	return map[string]interface{}{
		"templates": templates,
		"count":     len(templates),
		"timestamp": time.Now(),
	}, nil
}

// handleValidatePolicy handles policy validation requests
func (apm *AdvancedPolicyModule) handleValidatePolicy(msg map[string]interface{}) (interface{}, error) {
	_, ok := msg["policy"]
	if !ok {
		return nil, fmt.Errorf("policy is required")
	}
	
	// Convert to Policy struct (simplified)
	policy := models.Policy{
		ID:          "validation_policy",
		Name:        "Policy for Validation",
		Description: "Policy being validated",
		Type:        "network",
		Priority:    1,
		Enabled:     true,
		Rules:       []models.Rule{},
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	validationResult := apm.validatePolicyWithDetails(policy)
	
	return map[string]interface{}{
		"valid":     validationResult.Valid,
		"errors":    validationResult.Errors,
		"warnings":  validationResult.Warnings,
		"timestamp": time.Now(),
	}, nil
}

// handleTestPolicy handles policy testing requests
func (apm *AdvancedPolicyModule) handleTestPolicy(msg map[string]interface{}) (interface{}, error) {
	policyID, ok := msg["policy_id"].(string)
	if !ok {
		return nil, fmt.Errorf("policy_id is required")
	}
	
	testData, ok := msg["test_data"]
	if !ok {
		return nil, fmt.Errorf("test_data is required")
	}
	
	// Simulate policy testing
	testResult := apm.testPolicy(policyID, testData)
	
	return map[string]interface{}{
		"policy_id":    policyID,
		"test_result":  testResult,
		"timestamp":    time.Now(),
	}, nil
}

// handleRollbackPolicy handles policy rollback requests
func (apm *AdvancedPolicyModule) handleRollbackPolicy(msg map[string]interface{}) (interface{}, error) {
	policyID, ok := msg["policy_id"].(string)
	if !ok {
		return nil, fmt.Errorf("policy_id is required")
	}
	
	version, ok := msg["version"].(string)
	if !ok {
		version = "previous"
	}
	
	success := apm.rollbackPolicy(policyID, version)
	
	return map[string]interface{}{
		"policy_id": policyID,
		"version":   version,
		"success":   success,
		"timestamp": time.Now(),
	}, nil
}

// validatePolicy validates a policy
func (apm *AdvancedPolicyModule) validatePolicy(policy models.Policy) error {
	apm.mu.RLock()
	rules := apm.policyValidator.GetAllRules()
	apm.mu.RUnlock()
	
	for _, rule := range rules {
		if err := rule.Rule(policy); err != nil {
			return fmt.Errorf("validation rule %s failed: %w", rule.Name, err)
		}
	}
	
	return nil
}

// validatePolicyWithDetails validates a policy with detailed results
func (apm *AdvancedPolicyModule) validatePolicyWithDetails(policy models.Policy) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}
	
	apm.mu.RLock()
	rules := apm.policyValidator.GetAllRules()
	apm.mu.RUnlock()
	
	for _, rule := range rules {
		if err := rule.Rule(policy); err != nil {
			if rule.Severity == "error" {
				result.Valid = false
				result.Errors = append(result.Errors, err.Error())
			} else {
				result.Warnings = append(result.Warnings, err.Error())
			}
		}
	}
	
	return result
}

// testPolicy tests a policy with test data
func (apm *AdvancedPolicyModule) testPolicy(policyID string, testData interface{}) map[string]interface{} {
	// Simulate policy testing
	return map[string]interface{}{
		"test_passed":     true,
		"execution_time":  "15ms",
		"rules_evaluated": 3,
		"matches_found":   1,
		"test_data":       testData,
	}
}

// rollbackPolicy rolls back a policy to a previous version
func (apm *AdvancedPolicyModule) rollbackPolicy(policyID, version string) bool {
	// Simulate policy rollback
	apm.LogInfo("Rolling back policy %s to version %s", policyID, version)
	return true
}

// validatePolicies continuously validates policies
func (apm *AdvancedPolicyModule) validatePolicies() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-apm.GetContext().Done():
			return
		case <-ticker.C:
			apm.performPolicyValidation()
		}
	}
}

// cleanupOldVersions continuously cleans up old policy versions
func (apm *AdvancedPolicyModule) cleanupOldVersions() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-apm.GetContext().Done():
			return
		case <-ticker.C:
			apm.performVersionCleanup()
		}
	}
}

// performPolicyValidation performs policy validation
func (apm *AdvancedPolicyModule) performPolicyValidation() {
	apm.mu.RLock()
	policies := apm.policyEngine.GetAllPolicies()
	apm.mu.RUnlock()
	
	validCount := 0
	for _, policy := range policies {
		if err := apm.validatePolicy(policy); err == nil {
			validCount++
		}
	}
	
	apm.SetMetric("policies_validated", len(policies))
	apm.SetMetric("policies_valid", validCount)
	apm.LogDebug("Policy validation completed: %d/%d policies valid", validCount, len(policies))
}

// performVersionCleanup performs version cleanup
func (apm *AdvancedPolicyModule) performVersionCleanup() {
	// Simulate version cleanup
	apm.SetMetric("version_cleanups", 1)
	apm.LogDebug("Version cleanup completed")
}

// initializePolicyTemplates initializes policy templates
func (apm *AdvancedPolicyModule) initializePolicyTemplates() {
	// Add default policy templates
	templates := []PolicyTemplate{
		{
			ID:          "network_segmentation",
			Name:        "Network Segmentation",
			Description: "Template for network segmentation policies",
			Category:    "network",
			Template:    models.Policy{},
			Parameters:  []TemplateParameter{},
			Metadata:    make(map[string]interface{}),
		},
		{
			ID:          "access_control",
			Name:        "Access Control",
			Description: "Template for access control policies",
			Category:    "access",
			Template:    models.Policy{},
			Parameters:  []TemplateParameter{},
			Metadata:    make(map[string]interface{}),
		},
	}
	
	for _, template := range templates {
		apm.policyTemplates.AddTemplate(template)
	}
}

// initializeValidationRules initializes validation rules
func (apm *AdvancedPolicyModule) initializeValidationRules() {
	// Add default validation rules
	rules := []ValidationRule{
		{
			ID:          "required_fields",
			Name:        "Required Fields",
			Description: "Ensures all required fields are present",
			Rule:        apm.validateRequiredFields,
			Severity:    "error",
			Metadata:    make(map[string]interface{}),
		},
		{
			ID:          "rule_validation",
			Name:        "Rule Validation",
			Description: "Validates policy rules",
			Rule:        apm.validateRules,
			Severity:    "error",
			Metadata:    make(map[string]interface{}),
		},
	}
	
	for _, rule := range rules {
		apm.policyValidator.AddRule(rule)
	}
}

// validateRequiredFields validates required fields
func (apm *AdvancedPolicyModule) validateRequiredFields(policy models.Policy) error {
	if policy.ID == "" {
		return fmt.Errorf("policy ID is required")
	}
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if len(policy.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}
	return nil
}

// validateRules validates policy rules
func (apm *AdvancedPolicyModule) validateRules(policy models.Policy) error {
	for i, rule := range policy.Rules {
		if rule.Action == "" {
			return fmt.Errorf("rule %d: action is required", i)
		}
		if len(rule.Conditions) == 0 {
			return fmt.Errorf("rule %d: at least one condition is required", i)
		}
	}
	return nil
}

// HealthCheck performs a health check
func (apm *AdvancedPolicyModule) HealthCheck() error {
	if err := apm.BaseModule.HealthCheck(); err != nil {
		return err
	}

	// Check if policy components are healthy
	apm.mu.RLock()
	policyCount := apm.policyEngine.GetPolicyCount()
	templateCount := apm.policyTemplates.GetTemplateCount()
	ruleCount := apm.policyValidator.GetRuleCount()
	apm.mu.RUnlock()

	if policyCount == 0 {
		apm.LogWarn("No policies loaded, policy management may be limited")
	}

	if templateCount == 0 {
		apm.LogWarn("No policy templates available, policy creation may be limited")
	}

	if ruleCount == 0 {
		apm.LogWarn("No validation rules configured, policy validation may be limited")
	}

	return nil
}

// GetMetrics returns advanced policy module metrics
func (apm *AdvancedPolicyModule) GetMetrics() map[string]interface{} {
	metrics := apm.BaseModule.GetMetrics()
	
	apm.mu.RLock()
	metrics["policy_count"] = apm.policyEngine.GetPolicyCount()
	metrics["template_count"] = apm.policyTemplates.GetTemplateCount()
	metrics["rule_count"] = apm.policyValidator.GetRuleCount()
	apm.mu.RUnlock()
	
	return metrics
}

// ValidationResult represents policy validation results
type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// AdvancedPolicyEngine methods

// AddPolicy adds a policy
func (ape *AdvancedPolicyEngine) AddPolicy(policy models.Policy) {
	ape.mu.Lock()
	defer ape.mu.Unlock()
	ape.policies[policy.ID] = policy
}

// UpdatePolicy updates a policy
func (ape *AdvancedPolicyEngine) UpdatePolicy(policy models.Policy) {
	ape.mu.Lock()
	defer ape.mu.Unlock()
	ape.policies[policy.ID] = policy
}

// DeletePolicy deletes a policy
func (ape *AdvancedPolicyEngine) DeletePolicy(policyID string) bool {
	ape.mu.Lock()
	defer ape.mu.Unlock()
	
	if _, exists := ape.policies[policyID]; exists {
		delete(ape.policies, policyID)
		return true
	}
	return false
}

// GetPolicy gets a policy
func (ape *AdvancedPolicyEngine) GetPolicy(policyID string) (models.Policy, bool) {
	ape.mu.RLock()
	defer ape.mu.RUnlock()
	policy, exists := ape.policies[policyID]
	return policy, exists
}

// GetAllPolicies returns all policies
func (ape *AdvancedPolicyEngine) GetAllPolicies() []models.Policy {
	ape.mu.RLock()
	defer ape.mu.RUnlock()
	
	policies := make([]models.Policy, 0, len(ape.policies))
	for _, policy := range ape.policies {
		policies = append(policies, policy)
	}
	return policies
}

// GetPolicyCount returns the number of policies
func (ape *AdvancedPolicyEngine) GetPolicyCount() int {
	ape.mu.RLock()
	defer ape.mu.RUnlock()
	return len(ape.policies)
}

// PolicyTemplates methods

// AddTemplate adds a template
func (pt *PolicyTemplates) AddTemplate(template PolicyTemplate) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.templates[template.ID] = template
}

// GetTemplate gets a template
func (pt *PolicyTemplates) GetTemplate(templateID string) (PolicyTemplate, bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	template, exists := pt.templates[templateID]
	return template, exists
}

// GetAllTemplates returns all templates
func (pt *PolicyTemplates) GetAllTemplates() []PolicyTemplate {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	
	templates := make([]PolicyTemplate, 0, len(pt.templates))
	for _, template := range pt.templates {
		templates = append(templates, template)
	}
	return templates
}

// GetTemplateCount returns the number of templates
func (pt *PolicyTemplates) GetTemplateCount() int {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return len(pt.templates)
}

// PolicyValidator methods

// AddRule adds a validation rule
func (pv *PolicyValidator) AddRule(rule ValidationRule) {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	pv.rules[rule.ID] = rule
}

// GetAllRules returns all validation rules
func (pv *PolicyValidator) GetAllRules() []ValidationRule {
	pv.mu.RLock()
	defer pv.mu.RUnlock()
	
	rules := make([]ValidationRule, 0, len(pv.rules))
	for _, rule := range pv.rules {
		rules = append(rules, rule)
	}
	return rules
}

// GetRuleCount returns the number of validation rules
func (pv *PolicyValidator) GetRuleCount() int {
	pv.mu.RLock()
	defer pv.mu.RUnlock()
	return len(pv.rules)
}
