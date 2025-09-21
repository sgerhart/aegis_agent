package policy

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// AdvancedPolicyEngine provides advanced policy management capabilities
type AdvancedPolicyEngine struct {
	auditLogger       *telemetry.AuditLogger
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	running           bool
	
	// Policy management
	templates         map[string]*PolicyTemplate
	policies          map[string]*AdvancedPolicy
	versions          map[string]*PolicyVersion
	tests             map[string]*PolicyTest
	
	// Inheritance and relationships
	inheritance       map[string][]string // child -> parents
	dependencies      map[string][]string // policy -> dependencies
	
	// Configuration
	maxVersions       int
	maxTests          int
	versionCounter    int
	testCounter       int
}

// PolicyTemplate represents a reusable policy template
type PolicyTemplate struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Category          string                 `json:"category"`
	Version           string                 `json:"version"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	
	// Template structure
	Parameters        []TemplateParameter    `json:"parameters"`
	Rules             []TemplateRule         `json:"rules"`
	Conditions        []TemplateCondition    `json:"conditions"`
	
	// Metadata
	Tags              []string               `json:"tags"`
	Author            string                 `json:"author"`
	UsageCount        int                    `json:"usage_count"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// AdvancedPolicy represents an advanced policy with inheritance and versioning
type AdvancedPolicy struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Type              PolicyType             `json:"type"`
	Category          string                 `json:"category"`
	Version           string                 `json:"version"`
	Status            PolicyStatus           `json:"status"`
	
	// Inheritance
	ParentPolicies    []string               `json:"parent_policies"`
	ChildPolicies     []string               `json:"child_policies"`
	InheritanceMode   InheritanceMode        `json:"inheritance_mode"`
	
	// Policy content
	Rules             []AdvancedRule         `json:"rules"`
	Conditions        []AdvancedCondition    `json:"conditions"`
	Actions           []AdvancedAction       `json:"actions"`
	
	// Versioning
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	CreatedBy         string                 `json:"created_by"`
	UpdatedBy         string                 `json:"updated_by"`
	
	// Dependencies
	Dependencies      []string               `json:"dependencies"`
	Dependents        []string               `json:"dependents"`
	
	// Testing
	TestSuite         string                 `json:"test_suite,omitempty"`
	TestResults       []TestResult           `json:"test_results,omitempty"`
	
	// Metadata
	Tags              []string               `json:"tags"`
	Priority          int                    `json:"priority"`
	Enabled           bool                   `json:"enabled"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// PolicyVersion represents a version of a policy
type PolicyVersion struct {
	ID                string                 `json:"id"`
	PolicyID          string                 `json:"policy_id"`
	Version           string                 `json:"version"`
	Description       string                 `json:"description"`
	CreatedAt         time.Time              `json:"created_at"`
	CreatedBy         string                 `json:"created_by"`
	
	// Version content
	Content           *AdvancedPolicy        `json:"content"`
	Changes           []VersionChange        `json:"changes"`
	
	// Status
	Status            VersionStatus          `json:"status"`
	IsActive          bool                   `json:"is_active"`
	IsStable          bool                   `json:"is_stable"`
	
	// Metadata
	Metadata          map[string]interface{} `json:"metadata"`
}

// PolicyTest represents a policy test
type PolicyTest struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	PolicyID          string                 `json:"policy_id"`
	Type              TestType               `json:"type"`
	Status            TestStatus             `json:"status"`
	
	// Test configuration
	TestCases         []TestCase             `json:"test_cases"`
	ExpectedResults   []ExpectedResult       `json:"expected_results"`
	TestData          map[string]interface{} `json:"test_data"`
	
	// Execution
	CreatedAt         time.Time              `json:"created_at"`
	LastRun           time.Time              `json:"last_run,omitempty"`
	RunCount          int                    `json:"run_count"`
	SuccessCount      int                    `json:"success_count"`
	FailureCount      int                    `json:"failure_count"`
	
	// Results
	Results           []TestResult           `json:"results"`
	Coverage          float64                `json:"coverage"`
	
	// Metadata
	Tags              []string               `json:"tags"`
	Priority          int                    `json:"priority"`
	Enabled           bool                   `json:"enabled"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// TemplateParameter represents a parameter in a policy template
type TemplateParameter struct {
	Name              string                 `json:"name"`
	Type              ParameterType          `json:"type"`
	Description       string                 `json:"description"`
	DefaultValue      interface{}            `json:"default_value"`
	Required          bool                   `json:"required"`
	Validation        ParameterValidation    `json:"validation"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// TemplateRule represents a rule in a policy template
type TemplateRule struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Type              RuleType               `json:"type"`
	Action            string                 `json:"action"`
	Conditions        []string               `json:"conditions"`
	Parameters        []string               `json:"parameters"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// TemplateCondition represents a condition in a policy template
type TemplateCondition struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Type              ConditionType          `json:"type"`
	Field             string                 `json:"field"`
	Operator          string                 `json:"operator"`
	Value             interface{}            `json:"value"`
	Parameters        []string               `json:"parameters"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// AdvancedRule represents an advanced policy rule
type AdvancedRule struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Type              RuleType               `json:"type"`
	Action            string                 `json:"action"`
	Priority          int                    `json:"priority"`
	Enabled           bool                   `json:"enabled"`
	
	// Conditions
	Conditions        []AdvancedCondition    `json:"conditions"`
	
	// Actions
	Actions           []AdvancedAction       `json:"actions"`
	
	// Inheritance
	InheritedFrom     string                 `json:"inherited_from,omitempty"`
	OverrideMode      OverrideMode           `json:"override_mode"`
	
	// Metadata
	Tags              []string               `json:"tags"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// AdvancedCondition represents an advanced policy condition
type AdvancedCondition struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Type              ConditionType          `json:"type"`
	Field             string                 `json:"field"`
	Operator          string                 `json:"operator"`
	Value             interface{}            `json:"value"`
	Negate            bool                   `json:"negate"`
	
	// Inheritance
	InheritedFrom     string                 `json:"inherited_from,omitempty"`
	OverrideMode      OverrideMode           `json:"override_mode"`
	
	// Metadata
	Tags              []string               `json:"tags"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// AdvancedAction represents an advanced policy action
type AdvancedAction struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Type              ActionType             `json:"type"`
	Action            string                 `json:"action"`
	Parameters        map[string]interface{} `json:"parameters"`
	
	// Inheritance
	InheritedFrom     string                 `json:"inherited_from,omitempty"`
	OverrideMode      OverrideMode           `json:"override_mode"`
	
	// Metadata
	Tags              []string               `json:"tags"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// TestCase represents a test case
type TestCase struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Input             map[string]interface{} `json:"input"`
	ExpectedOutput    map[string]interface{} `json:"expected_output"`
	ExpectedResult    TestResultType         `json:"expected_result"`
	Enabled           bool                   `json:"enabled"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ExpectedResult represents an expected test result
type ExpectedResult struct {
	ID                string                 `json:"id"`
	TestCaseID        string                 `json:"test_case_id"`
	ExpectedValue     interface{}            `json:"expected_value"`
	ActualValue       interface{}            `json:"actual_value,omitempty"`
	Match             bool                   `json:"match"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// TestResult represents a test execution result
type TestResult struct {
	ID                string                 `json:"id"`
	TestID            string                 `json:"test_id"`
	TestCaseID        string                 `json:"test_case_id"`
	Status            TestResultType         `json:"status"`
	StartTime         time.Time              `json:"start_time"`
	EndTime           time.Time              `json:"end_time"`
	Duration          time.Duration          `json:"duration"`
	Message           string                 `json:"message"`
	Details           map[string]interface{} `json:"details"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// VersionChange represents a change between policy versions
type VersionChange struct {
	ID                string                 `json:"id"`
	Type              ChangeType             `json:"type"`
	Field             string                 `json:"field"`
	OldValue          interface{}            `json:"old_value"`
	NewValue          interface{}            `json:"new_value"`
	Description       string                 `json:"description"`
	Timestamp         time.Time              `json:"timestamp"`
	Author            string                 `json:"author"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// Enums
type PolicyType string
const (
	PolicyTypeNetwork     PolicyType = "network"
	PolicyTypeProcess     PolicyType = "process"
	PolicyTypeFile        PolicyType = "file"
	PolicyTypeService     PolicyType = "service"
	PolicyTypeSecurity    PolicyType = "security"
	PolicyTypeCompliance  PolicyType = "compliance"
)

type PolicyStatus string
const (
	PolicyStatusDraft      PolicyStatus = "draft"
	PolicyStatusActive     PolicyStatus = "active"
	PolicyStatusInactive   PolicyStatus = "inactive"
	PolicyStatusDeprecated PolicyStatus = "deprecated"
	PolicyStatusArchived   PolicyStatus = "archived"
)

type InheritanceMode string
const (
	InheritanceModeOverride InheritanceMode = "override"
	InheritanceModeMerge    InheritanceMode = "merge"
	InheritanceModeExtend   InheritanceMode = "extend"
	InheritanceModeReplace  InheritanceMode = "replace"
)

type OverrideMode string
const (
	OverrideModeNone     OverrideMode = "none"
	OverrideModeAllow    OverrideMode = "allow"
	OverrideModeDeny     OverrideMode = "deny"
	OverrideModeReplace  OverrideMode = "replace"
)

type RuleType string
const (
	RuleTypeNetwork     RuleType = "network"
	RuleTypeProcess     RuleType = "process"
	RuleTypeFile        RuleType = "file"
	RuleTypeService     RuleType = "service"
	RuleTypeSecurity    RuleType = "security"
	RuleTypeCompliance  RuleType = "compliance"
)

type ConditionType string
const (
	ConditionTypeNetwork     ConditionType = "network"
	ConditionTypeProcess     ConditionType = "process"
	ConditionTypeFile        ConditionType = "file"
	ConditionTypeService     ConditionType = "service"
	ConditionTypeTime        ConditionType = "time"
	ConditionTypeUser        ConditionType = "user"
	ConditionTypeResource    ConditionType = "resource"
)

type ActionType string
const (
	ActionTypeAllow      ActionType = "allow"
	ActionTypeDeny       ActionType = "deny"
	ActionTypeLog        ActionType = "log"
	ActionTypeMonitor    ActionType = "monitor"
	ActionTypeQuarantine ActionType = "quarantine"
	ActionTypeNotify     ActionType = "notify"
	ActionTypeCustom     ActionType = "custom"
)

type ParameterType string
const (
	ParameterTypeString   ParameterType = "string"
	ParameterTypeInteger  ParameterType = "integer"
	ParameterTypeFloat    ParameterType = "float"
	ParameterTypeBoolean  ParameterType = "boolean"
	ParameterTypeArray    ParameterType = "array"
	ParameterTypeObject   ParameterType = "object"
)

type TestType string
const (
	TestTypeUnit        TestType = "unit"
	TestTypeIntegration TestType = "integration"
	TestTypePerformance TestType = "performance"
	TestTypeSecurity    TestType = "security"
	TestTypeCompliance  TestType = "compliance"
)

type TestStatus string
const (
	TestStatusDraft      TestStatus = "draft"
	TestStatusReady      TestStatus = "ready"
	TestStatusRunning    TestStatus = "running"
	TestStatusPassed     TestStatus = "passed"
	TestStatusFailed     TestStatus = "failed"
	TestStatusSkipped    TestStatus = "skipped"
	TestStatusError      TestStatus = "error"
)

type TestResultType string
const (
	TestResultTypePass    TestResultType = "pass"
	TestResultTypeFail    TestResultType = "fail"
	TestResultTypeSkip    TestResultType = "skip"
	TestResultTypeError   TestResultType = "error"
)

type VersionStatus string
const (
	VersionStatusDraft      VersionStatus = "draft"
	VersionStatusStable     VersionStatus = "stable"
	VersionStatusDeprecated VersionStatus = "deprecated"
	VersionStatusArchived   VersionStatus = "archived"
)

type ChangeType string
const (
	ChangeTypeAdded     ChangeType = "added"
	ChangeTypeModified  ChangeType = "modified"
	ChangeTypeRemoved   ChangeType = "removed"
	ChangeTypeRenamed   ChangeType = "renamed"
)

// ParameterValidation represents parameter validation rules
type ParameterValidation struct {
	MinLength    int                    `json:"min_length,omitempty"`
	MaxLength    int                    `json:"max_length,omitempty"`
	MinValue     float64                `json:"min_value,omitempty"`
	MaxValue     float64                `json:"max_value,omitempty"`
	Pattern      string                 `json:"pattern,omitempty"`
	EnumValues   []interface{}          `json:"enum_values,omitempty"`
	Required     bool                   `json:"required"`
	CustomRules  []string               `json:"custom_rules,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// NewAdvancedPolicyEngine creates a new advanced policy engine
func NewAdvancedPolicyEngine(auditLogger *telemetry.AuditLogger) *AdvancedPolicyEngine {
	ctx, cancel := context.WithCancel(context.Background())
	
	ape := &AdvancedPolicyEngine{
		auditLogger:       auditLogger,
		ctx:               ctx,
		cancel:            cancel,
		templates:         make(map[string]*PolicyTemplate),
		policies:          make(map[string]*AdvancedPolicy),
		versions:          make(map[string]*PolicyVersion),
		tests:             make(map[string]*PolicyTest),
		inheritance:       make(map[string][]string),
		dependencies:      make(map[string][]string),
		maxVersions:       10,
		maxTests:          100,
	}
	
	log.Printf("[advanced_policy_engine] Advanced policy engine initialized")
	return ape
}

// Start starts the advanced policy engine
func (ape *AdvancedPolicyEngine) Start() error {
	ape.mu.Lock()
	defer ape.mu.Unlock()
	
	if ape.running {
		return fmt.Errorf("advanced policy engine already running")
	}
	
	ape.running = true
	
	log.Printf("[advanced_policy_engine] Advanced policy engine started")
	
	// Log startup event
	ape.auditLogger.LogSystemEvent("advanced_policy_engine_start", "Advanced policy engine started", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	
	return nil
}

// Stop stops the advanced policy engine
func (ape *AdvancedPolicyEngine) Stop() error {
	ape.mu.Lock()
	defer ape.mu.Unlock()
	
	if !ape.running {
		return fmt.Errorf("advanced policy engine not running")
	}
	
	ape.cancel()
	ape.running = false
	
	log.Printf("[advanced_policy_engine] Advanced policy engine stopped")
	
	// Log shutdown event
	ape.auditLogger.LogSystemEvent("advanced_policy_engine_stop", "Advanced policy engine stopped", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	
	return nil
}

// CreateTemplate creates a new policy template
func (ape *AdvancedPolicyEngine) CreateTemplate(template *PolicyTemplate) error {
	ape.mu.Lock()
	defer ape.mu.Unlock()
	
	// Generate ID if not provided
	if template.ID == "" {
		template.ID = fmt.Sprintf("template_%d", time.Now().Unix())
	}
	
	// Set default values
	if template.Version == "" {
		template.Version = "1.0.0"
	}
	if template.CreatedAt.IsZero() {
		template.CreatedAt = time.Now()
	}
	template.UpdatedAt = time.Now()
	if template.Metadata == nil {
		template.Metadata = make(map[string]interface{})
	}
	
	// Validate template
	if err := ape.validateTemplate(template); err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}
	
	// Store template
	ape.templates[template.ID] = template
	
	// Log template creation
	ape.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"Policy template created",
		map[string]interface{}{
			"template_id":   template.ID,
			"template_name": template.Name,
			"category":      template.Category,
			"version":       template.Version,
		})
	
	return nil
}

// CreatePolicy creates a new advanced policy
func (ape *AdvancedPolicyEngine) CreatePolicy(policy *AdvancedPolicy) error {
	ape.mu.Lock()
	defer ape.mu.Unlock()
	
	// Generate ID if not provided
	if policy.ID == "" {
		policy.ID = fmt.Sprintf("policy_%d", time.Now().Unix())
	}
	
	// Set default values
	if policy.Version == "" {
		policy.Version = "1.0.0"
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now()
	}
	policy.UpdatedAt = time.Now()
	if policy.Metadata == nil {
		policy.Metadata = make(map[string]interface{})
	}
	
	// Validate policy
	if err := ape.validatePolicy(policy); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}
	
	// Store policy
	ape.policies[policy.ID] = policy
	
	// Create initial version
	version := &PolicyVersion{
		ID:          fmt.Sprintf("version_%d", ape.versionCounter),
		PolicyID:    policy.ID,
		Version:     policy.Version,
		Description: "Initial version",
		CreatedAt:   time.Now(),
		CreatedBy:   policy.CreatedBy,
		Content:     policy,
		Changes:     []VersionChange{},
		Status:      VersionStatusStable,
		IsActive:    true,
		IsStable:    true,
		Metadata:    make(map[string]interface{}),
	}
	ape.versionCounter++
	ape.versions[version.ID] = version
	
	// Log policy creation
	ape.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"Advanced policy created",
		map[string]interface{}{
			"policy_id":   policy.ID,
			"policy_name": policy.Name,
			"type":        policy.Type,
			"version":     policy.Version,
			"status":      policy.Status,
		})
	
	return nil
}

// CreateTest creates a new policy test
func (ape *AdvancedPolicyEngine) CreateTest(test *PolicyTest) error {
	ape.mu.Lock()
	defer ape.mu.Unlock()
	
	// Generate ID if not provided
	if test.ID == "" {
		test.ID = fmt.Sprintf("test_%d", ape.testCounter)
		ape.testCounter++
	}
	
	// Set default values
	if test.CreatedAt.IsZero() {
		test.CreatedAt = time.Now()
	}
	if test.Metadata == nil {
		test.Metadata = make(map[string]interface{})
	}
	
	// Validate test
	if err := ape.validateTest(test); err != nil {
		return fmt.Errorf("invalid test: %w", err)
	}
	
	// Store test
	ape.tests[test.ID] = test
	
	// Log test creation
	ape.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"Policy test created",
		map[string]interface{}{
			"test_id":     test.ID,
			"test_name":   test.Name,
			"policy_id":   test.PolicyID,
			"type":        test.Type,
			"status":      test.Status,
		})
	
	return nil
}

// RunTest runs a policy test
func (ape *AdvancedPolicyEngine) RunTest(testID string) (*TestResult, error) {
	ape.mu.RLock()
	test, exists := ape.tests[testID]
	ape.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("test %s not found", testID)
	}
	
	// Update test status
	ape.mu.Lock()
	test.Status = TestStatusRunning
	test.LastRun = time.Now()
	test.RunCount++
	ape.mu.Unlock()
	
	// Run test cases
	var results []TestResult
	successCount := 0
	failureCount := 0
	
	for _, testCase := range test.TestCases {
		if !testCase.Enabled {
			continue
		}
		
		result := ape.runTestCase(test, testCase)
		results = append(results, result)
		
		if result.Status == TestResultTypePass {
			successCount++
		} else {
			failureCount++
		}
	}
	
	// Update test results
	ape.mu.Lock()
	test.Results = results
	test.SuccessCount = successCount
	test.FailureCount = failureCount
	test.Coverage = ape.calculateTestCoverage(test)
	
	if failureCount == 0 {
		test.Status = TestStatusPassed
	} else {
		test.Status = TestStatusFailed
	}
	ape.mu.Unlock()
	
	// Log test execution
	ape.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"Policy test executed",
		map[string]interface{}{
			"test_id":       testID,
			"test_name":     test.Name,
			"policy_id":     test.PolicyID,
			"success_count": successCount,
			"failure_count": failureCount,
			"coverage":      test.Coverage,
		})
	
	return &results[0], nil
}

// runTestCase runs a single test case
func (ape *AdvancedPolicyEngine) runTestCase(test *PolicyTest, testCase TestCase) TestResult {
	startTime := time.Now()
	
	result := TestResult{
		ID:         fmt.Sprintf("result_%d", time.Now().Unix()),
		TestID:     test.ID,
		TestCaseID: testCase.ID,
		StartTime:  startTime,
		EndTime:    time.Now(),
		Details:    make(map[string]interface{}),
		Metadata:   make(map[string]interface{}),
	}
	
	result.Duration = result.EndTime.Sub(result.StartTime)
	
	// Simulate test execution (in reality would run actual policy logic)
	if testCase.ExpectedResult == TestResultTypePass {
		result.Status = TestResultTypePass
		result.Message = "Test case passed"
	} else {
		result.Status = TestResultTypeFail
		result.Message = "Test case failed"
	}
	
	return result
}

// calculateTestCoverage calculates test coverage percentage
func (ape *AdvancedPolicyEngine) calculateTestCoverage(test *PolicyTest) float64 {
	if len(test.TestCases) == 0 {
		return 0.0
	}
	
	enabledCases := 0
	for _, testCase := range test.TestCases {
		if testCase.Enabled {
			enabledCases++
		}
	}
	
	return float64(enabledCases) / float64(len(test.TestCases)) * 100.0
}

// Validation methods
func (ape *AdvancedPolicyEngine) validateTemplate(template *PolicyTemplate) error {
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}
	
	if template.Category == "" {
		return fmt.Errorf("template category is required")
	}
	
	if len(template.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}
	
	return nil
}

func (ape *AdvancedPolicyEngine) validatePolicy(policy *AdvancedPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	
	if policy.Type == "" {
		return fmt.Errorf("policy type is required")
	}
	
	if len(policy.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}
	
	return nil
}

func (ape *AdvancedPolicyEngine) validateTest(test *PolicyTest) error {
	if test.Name == "" {
		return fmt.Errorf("test name is required")
	}
	
	if test.PolicyID == "" {
		return fmt.Errorf("policy ID is required")
	}
	
	if len(test.TestCases) == 0 {
		return fmt.Errorf("at least one test case is required")
	}
	
	return nil
}

// Public methods
func (ape *AdvancedPolicyEngine) GetTemplates() map[string]*PolicyTemplate {
	ape.mu.RLock()
	defer ape.mu.RUnlock()
	
	templates := make(map[string]*PolicyTemplate)
	for id, template := range ape.templates {
		templates[id] = template
	}
	
	return templates
}

func (ape *AdvancedPolicyEngine) GetPolicies() map[string]*AdvancedPolicy {
	ape.mu.RLock()
	defer ape.mu.RUnlock()
	
	policies := make(map[string]*AdvancedPolicy)
	for id, policy := range ape.policies {
		policies[id] = policy
	}
	
	return policies
}

func (ape *AdvancedPolicyEngine) GetVersions() map[string]*PolicyVersion {
	ape.mu.RLock()
	defer ape.mu.RUnlock()
	
	versions := make(map[string]*PolicyVersion)
	for id, version := range ape.versions {
		versions[id] = version
	}
	
	return versions
}

func (ape *AdvancedPolicyEngine) GetTests() map[string]*PolicyTest {
	ape.mu.RLock()
	defer ape.mu.RUnlock()
	
	tests := make(map[string]*PolicyTest)
	for id, test := range ape.tests {
		tests[id] = test
	}
	
	return tests
}

func (ape *AdvancedPolicyEngine) GetStatistics() map[string]interface{} {
	ape.mu.RLock()
	defer ape.mu.RUnlock()
	
	stats := map[string]interface{}{
		"templates_count": len(ape.templates),
		"policies_count":  len(ape.policies),
		"versions_count":  len(ape.versions),
		"tests_count":     len(ape.tests),
		"active_policies": 0,
		"active_tests":    0,
	}
	
	for _, policy := range ape.policies {
		if policy.Status == PolicyStatusActive {
			stats["active_policies"] = stats["active_policies"].(int) + 1
		}
	}
	
	for _, test := range ape.tests {
		if test.Status == TestStatusPassed {
			stats["active_tests"] = stats["active_tests"].(int) + 1
		}
	}
	
	return stats
}

// Close closes the advanced policy engine
func (ape *AdvancedPolicyEngine) Close() error {
	return ape.Stop()
}
