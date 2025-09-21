package policy

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"agents/aegis/internal/observability"
	"agents/aegis/internal/telemetry"
)

// ProcessPolicyManager manages process-level policies
type ProcessPolicyManager struct {
	processMonitor    *observability.ProcessMonitor
	auditLogger       *telemetry.AuditLogger
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	running           bool
	
	// Policy storage
	networkPolicies   map[string]*ProcessNetworkPolicy
	filePolicies      map[string]*ProcessFilePolicy
	executionPolicies map[string]*ProcessExecutionPolicy
	ipcPolicies       map[string]*ProcessIPCPolicy
	
	// Policy enforcement
	enforcementEngine *ProcessEnforcementEngine
	policyCounter     int
}

// ProcessNetworkPolicy defines network access policies for processes
type ProcessNetworkPolicy struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	ProcessPatterns   []ProcessPattern       `json:"process_patterns"`
	NetworkRules      []NetworkRule          `json:"network_rules"`
	Priority          int                    `json:"priority"`
	Enabled           bool                   `json:"enabled"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ProcessFilePolicy defines file access policies for processes
type ProcessFilePolicy struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	ProcessPatterns   []ProcessPattern       `json:"process_patterns"`
	FileRules         []FileRule             `json:"file_rules"`
	Priority          int                    `json:"priority"`
	Enabled           bool                   `json:"enabled"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ProcessExecutionPolicy defines execution policies for processes
type ProcessExecutionPolicy struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	ProcessPatterns   []ProcessPattern       `json:"process_patterns"`
	ExecutionRules    []ExecutionRule        `json:"execution_rules"`
	Priority          int                    `json:"priority"`
	Enabled           bool                   `json:"enabled"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ProcessIPCPolicy defines inter-process communication policies
type ProcessIPCPolicy struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	ProcessPatterns   []ProcessPattern       `json:"process_patterns"`
	IPCRules          []IPCRule              `json:"ipc_rules"`
	Priority          int                    `json:"priority"`
	Enabled           bool                   `json:"enabled"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ProcessPattern defines patterns to match processes
type ProcessPattern struct {
	Type        PatternType             `json:"type"`
	Value       string                  `json:"value"`
	Operator    PatternOperator         `json:"operator"`
	Metadata    map[string]interface{}  `json:"metadata"`
}

// NetworkRule defines network access rules
type NetworkRule struct {
	ID              string                 `json:"id"`
	Action          RuleAction             `json:"action"`
	Protocol        string                 `json:"protocol"`
	SourceAddress   string                 `json:"source_address"`
	DestinationAddress string              `json:"destination_address"`
	SourcePort      int                    `json:"source_port"`
	DestinationPort int                    `json:"destination_port"`
	Direction       NetworkDirection       `json:"direction"`
	Priority        int                    `json:"priority"`
	Enabled         bool                   `json:"enabled"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// FileRule defines file access rules
type FileRule struct {
	ID              string                 `json:"id"`
	Action          RuleAction             `json:"action"`
	Path            string                 `json:"path"`
	AccessMode      FileAccessMode         `json:"access_mode"`
	Owner           string                 `json:"owner"`
	Group           string                 `json:"group"`
	Permissions     string                 `json:"permissions"`
	Priority        int                    `json:"priority"`
	Enabled         bool                   `json:"enabled"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ExecutionRule defines process execution rules
type ExecutionRule struct {
	ID              string                 `json:"id"`
	Action          RuleAction             `json:"action"`
	Executable      string                 `json:"executable"`
	Arguments       []string               `json:"arguments"`
	WorkingDirectory string                `json:"working_directory"`
	User            string                 `json:"user"`
	Group           string                 `json:"group"`
	Environment     map[string]string      `json:"environment"`
	Priority        int                    `json:"priority"`
	Enabled         bool                   `json:"enabled"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// IPCRule defines inter-process communication rules
type IPCRule struct {
	ID              string                 `json:"id"`
	Action          RuleAction             `json:"action"`
	IPCMethod       IPCMethod              `json:"ipc_method"`
	SourceProcess   string                 `json:"source_process"`
	TargetProcess   string                 `json:"target_process"`
	MessageType     string                 `json:"message_type"`
	Priority        int                    `json:"priority"`
	Enabled         bool                   `json:"enabled"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ProcessEnforcementEngine handles policy enforcement
type ProcessEnforcementEngine struct {
	processPolicyManager *ProcessPolicyManager
	auditLogger          *telemetry.AuditLogger
	mu                   sync.RWMutex
	running              bool
}

// Enums
type PatternType string
const (
	PatternTypeProcessName    PatternType = "process_name"
	PatternTypeExecutable     PatternType = "executable"
	PatternTypeUser           PatternType = "user"
	PatternTypeGroup          PatternType = "group"
	PatternTypeNamespace      PatternType = "namespace"
	PatternTypeCommandLine    PatternType = "command_line"
	PatternTypeEnvironment    PatternType = "environment"
)

type PatternOperator string
const (
	OperatorEquals        PatternOperator = "equals"
	OperatorContains      PatternOperator = "contains"
	OperatorStartsWith    PatternOperator = "starts_with"
	OperatorEndsWith      PatternOperator = "ends_with"
	OperatorRegex         PatternOperator = "regex"
	OperatorIn            PatternOperator = "in"
	OperatorNotEquals     PatternOperator = "not_equals"
	OperatorNotContains   PatternOperator = "not_contains"
)

type RuleAction string
const (
	ActionAllow        RuleAction = "allow"
	ActionDeny         RuleAction = "deny"
	ActionLog          RuleAction = "log"
	ActionRestrict     RuleAction = "restrict"
	ActionMonitor      RuleAction = "monitor"
	ActionQuarantine   RuleAction = "quarantine"
)

type NetworkDirection string
const (
	DirectionInbound   NetworkDirection = "inbound"
	DirectionOutbound  NetworkDirection = "outbound"
	DirectionBidirectional NetworkDirection = "bidirectional"
)

type FileAccessMode string
const (
	AccessModeRead      FileAccessMode = "read"
	AccessModeWrite     FileAccessMode = "write"
	AccessModeExecute   FileAccessMode = "execute"
	AccessModeReadWrite FileAccessMode = "read_write"
	AccessModeAll       FileAccessMode = "all"
)

type IPCMethod string
const (
	IPCMethodPipe       IPCMethod = "pipe"
	IPCMethodSocket     IPCMethod = "socket"
	IPCMethodSharedMemory IPCMethod = "shared_memory"
	IPCMethodMessageQueue IPCMethod = "message_queue"
	IPCMethodSemaphore  IPCMethod = "semaphore"
	IPCMethodSignal     IPCMethod = "signal"
)

// NewProcessPolicyManager creates a new process policy manager
func NewProcessPolicyManager(processMonitor *observability.ProcessMonitor, auditLogger *telemetry.AuditLogger) *ProcessPolicyManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	ppm := &ProcessPolicyManager{
		processMonitor:     processMonitor,
		auditLogger:        auditLogger,
		ctx:                ctx,
		cancel:             cancel,
		networkPolicies:    make(map[string]*ProcessNetworkPolicy),
		filePolicies:       make(map[string]*ProcessFilePolicy),
		executionPolicies:  make(map[string]*ProcessExecutionPolicy),
		ipcPolicies:        make(map[string]*ProcessIPCPolicy),
	}
	
	// Initialize enforcement engine
	ppm.enforcementEngine = &ProcessEnforcementEngine{
		processPolicyManager: ppm,
		auditLogger:          auditLogger,
	}
	
	log.Printf("[process_policy_manager] Process policy manager initialized")
	return ppm
}

// Start starts the process policy manager
func (ppm *ProcessPolicyManager) Start() error {
	ppm.mu.Lock()
	defer ppm.mu.Unlock()
	
	if ppm.running {
		return fmt.Errorf("process policy manager already running")
	}
	
	ppm.running = true
	
	// Start enforcement engine
	go ppm.enforcementEngine.start()
	
	log.Printf("[process_policy_manager] Process policy manager started")
	
	// Log startup event
	ppm.auditLogger.LogSystemEvent("process_policy_manager_start", "Process policy manager started", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	
	return nil
}

// Stop stops the process policy manager
func (ppm *ProcessPolicyManager) Stop() error {
	ppm.mu.Lock()
	defer ppm.mu.Unlock()
	
	if !ppm.running {
		return fmt.Errorf("process policy manager not running")
	}
	
	ppm.cancel()
	ppm.running = false
	
	log.Printf("[process_policy_manager] Process policy manager stopped")
	
	// Log shutdown event
	ppm.auditLogger.LogSystemEvent("process_policy_manager_stop", "Process policy manager stopped", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	
	return nil
}

// AddNetworkPolicy adds a network policy for processes
func (ppm *ProcessPolicyManager) AddNetworkPolicy(policy *ProcessNetworkPolicy) error {
	ppm.mu.Lock()
	defer ppm.mu.Unlock()
	
	// Generate ID if not provided
	if policy.ID == "" {
		policy.ID = fmt.Sprintf("network_policy_%d", ppm.policyCounter)
		ppm.policyCounter++
	}
	
	// Set timestamps
	now := time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	
	// Validate policy
	if err := ppm.validateNetworkPolicy(policy); err != nil {
		return fmt.Errorf("invalid network policy: %w", err)
	}
	
	// Store policy
	ppm.networkPolicies[policy.ID] = policy
	
	// Log policy addition
	ppm.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"Process network policy added",
		map[string]interface{}{
			"policy_id":   policy.ID,
			"policy_name": policy.Name,
			"rules_count": len(policy.NetworkRules),
			"enabled":     policy.Enabled,
		})
	
	return nil
}

// AddFilePolicy adds a file access policy for processes
func (ppm *ProcessPolicyManager) AddFilePolicy(policy *ProcessFilePolicy) error {
	ppm.mu.Lock()
	defer ppm.mu.Unlock()
	
	// Generate ID if not provided
	if policy.ID == "" {
		policy.ID = fmt.Sprintf("file_policy_%d", ppm.policyCounter)
		ppm.policyCounter++
	}
	
	// Set timestamps
	now := time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	
	// Validate policy
	if err := ppm.validateFilePolicy(policy); err != nil {
		return fmt.Errorf("invalid file policy: %w", err)
	}
	
	// Store policy
	ppm.filePolicies[policy.ID] = policy
	
	// Log policy addition
	ppm.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"Process file policy added",
		map[string]interface{}{
			"policy_id":   policy.ID,
			"policy_name": policy.Name,
			"rules_count": len(policy.FileRules),
			"enabled":     policy.Enabled,
		})
	
	return nil
}

// AddExecutionPolicy adds an execution policy for processes
func (ppm *ProcessPolicyManager) AddExecutionPolicy(policy *ProcessExecutionPolicy) error {
	ppm.mu.Lock()
	defer ppm.mu.Unlock()
	
	// Generate ID if not provided
	if policy.ID == "" {
		policy.ID = fmt.Sprintf("execution_policy_%d", ppm.policyCounter)
		ppm.policyCounter++
	}
	
	// Set timestamps
	now := time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	
	// Validate policy
	if err := ppm.validateExecutionPolicy(policy); err != nil {
		return fmt.Errorf("invalid execution policy: %w", err)
	}
	
	// Store policy
	ppm.executionPolicies[policy.ID] = policy
	
	// Log policy addition
	ppm.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"Process execution policy added",
		map[string]interface{}{
			"policy_id":   policy.ID,
			"policy_name": policy.Name,
			"rules_count": len(policy.ExecutionRules),
			"enabled":     policy.Enabled,
		})
	
	return nil
}

// AddIPCPolicy adds an IPC policy for processes
func (ppm *ProcessPolicyManager) AddIPCPolicy(policy *ProcessIPCPolicy) error {
	ppm.mu.Lock()
	defer ppm.mu.Unlock()
	
	// Generate ID if not provided
	if policy.ID == "" {
		policy.ID = fmt.Sprintf("ipc_policy_%d", ppm.policyCounter)
		ppm.policyCounter++
	}
	
	// Set timestamps
	now := time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	
	// Validate policy
	if err := ppm.validateIPCPolicy(policy); err != nil {
		return fmt.Errorf("invalid IPC policy: %w", err)
	}
	
	// Store policy
	ppm.ipcPolicies[policy.ID] = policy
	
	// Log policy addition
	ppm.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"Process IPC policy added",
		map[string]interface{}{
			"policy_id":   policy.ID,
			"policy_name": policy.Name,
			"rules_count": len(policy.IPCRules),
			"enabled":     policy.Enabled,
		})
	
	return nil
}

// Validate policies
func (ppm *ProcessPolicyManager) validateNetworkPolicy(policy *ProcessNetworkPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	
	if len(policy.ProcessPatterns) == 0 {
		return fmt.Errorf("at least one process pattern is required")
	}
	
	if len(policy.NetworkRules) == 0 {
		return fmt.Errorf("at least one network rule is required")
	}
	
	// Validate process patterns
	for i, pattern := range policy.ProcessPatterns {
		if err := ppm.validateProcessPattern(&pattern); err != nil {
			return fmt.Errorf("invalid process pattern %d: %w", i, err)
		}
	}
	
	// Validate network rules
	for i, rule := range policy.NetworkRules {
		if err := ppm.validateNetworkRule(&rule); err != nil {
			return fmt.Errorf("invalid network rule %d: %w", i, err)
		}
	}
	
	return nil
}

func (ppm *ProcessPolicyManager) validateFilePolicy(policy *ProcessFilePolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	
	if len(policy.ProcessPatterns) == 0 {
		return fmt.Errorf("at least one process pattern is required")
	}
	
	if len(policy.FileRules) == 0 {
		return fmt.Errorf("at least one file rule is required")
	}
	
	// Validate process patterns
	for i, pattern := range policy.ProcessPatterns {
		if err := ppm.validateProcessPattern(&pattern); err != nil {
			return fmt.Errorf("invalid process pattern %d: %w", i, err)
		}
	}
	
	// Validate file rules
	for i, rule := range policy.FileRules {
		if err := ppm.validateFileRule(&rule); err != nil {
			return fmt.Errorf("invalid file rule %d: %w", i, err)
		}
	}
	
	return nil
}

func (ppm *ProcessPolicyManager) validateExecutionPolicy(policy *ProcessExecutionPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	
	if len(policy.ProcessPatterns) == 0 {
		return fmt.Errorf("at least one process pattern is required")
	}
	
	if len(policy.ExecutionRules) == 0 {
		return fmt.Errorf("at least one execution rule is required")
	}
	
	// Validate process patterns
	for i, pattern := range policy.ProcessPatterns {
		if err := ppm.validateProcessPattern(&pattern); err != nil {
			return fmt.Errorf("invalid process pattern %d: %w", i, err)
		}
	}
	
	// Validate execution rules
	for i, rule := range policy.ExecutionRules {
		if err := ppm.validateExecutionRule(&rule); err != nil {
			return fmt.Errorf("invalid execution rule %d: %w", i, err)
		}
	}
	
	return nil
}

func (ppm *ProcessPolicyManager) validateIPCPolicy(policy *ProcessIPCPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	
	if len(policy.ProcessPatterns) == 0 {
		return fmt.Errorf("at least one process pattern is required")
	}
	
	if len(policy.IPCRules) == 0 {
		return fmt.Errorf("at least one IPC rule is required")
	}
	
	// Validate process patterns
	for i, pattern := range policy.ProcessPatterns {
		if err := ppm.validateProcessPattern(&pattern); err != nil {
			return fmt.Errorf("invalid process pattern %d: %w", i, err)
		}
	}
	
	// Validate IPC rules
	for i, rule := range policy.IPCRules {
		if err := ppm.validateIPCRule(&rule); err != nil {
			return fmt.Errorf("invalid IPC rule %d: %w", i, err)
		}
	}
	
	return nil
}

func (ppm *ProcessPolicyManager) validateProcessPattern(pattern *ProcessPattern) error {
	if pattern.Type == "" {
		return fmt.Errorf("pattern type is required")
	}
	
	if pattern.Value == "" {
		return fmt.Errorf("pattern value is required")
	}
	
	if pattern.Operator == "" {
		return fmt.Errorf("pattern operator is required")
	}
	
	// Validate regex patterns
	if pattern.Operator == OperatorRegex {
		if _, err := regexp.Compile(pattern.Value); err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	}
	
	return nil
}

func (ppm *ProcessPolicyManager) validateNetworkRule(rule *NetworkRule) error {
	if rule.Action == "" {
		return fmt.Errorf("rule action is required")
	}
	
	if rule.Protocol == "" {
		return fmt.Errorf("rule protocol is required")
	}
	
	if rule.Direction == "" {
		return fmt.Errorf("rule direction is required")
	}
	
	return nil
}

func (ppm *ProcessPolicyManager) validateFileRule(rule *FileRule) error {
	if rule.Action == "" {
		return fmt.Errorf("rule action is required")
	}
	
	if rule.Path == "" {
		return fmt.Errorf("rule path is required")
	}
	
	if rule.AccessMode == "" {
		return fmt.Errorf("rule access mode is required")
	}
	
	return nil
}

func (ppm *ProcessPolicyManager) validateExecutionRule(rule *ExecutionRule) error {
	if rule.Action == "" {
		return fmt.Errorf("rule action is required")
	}
	
	if rule.Executable == "" {
		return fmt.Errorf("rule executable is required")
	}
	
	return nil
}

func (ppm *ProcessPolicyManager) validateIPCRule(rule *IPCRule) error {
	if rule.Action == "" {
		return fmt.Errorf("rule action is required")
	}
	
	if rule.IPCMethod == "" {
		return fmt.Errorf("rule IPC method is required")
	}
	
	return nil
}

// ProcessEnforcementEngine methods
func (pee *ProcessEnforcementEngine) start() {
	// Start policy enforcement monitoring
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			pee.enforcePolicies()
		case <-pee.processPolicyManager.ctx.Done():
			return
		}
	}
}

func (pee *ProcessEnforcementEngine) enforcePolicies() {
	// Get all processes
	processes, err := pee.processPolicyManager.processMonitor.GetAllProcesses()
	if err != nil {
		log.Printf("[process_enforcement] Failed to get processes: %v", err)
		return
	}
	
	// Enforce network policies
	pee.enforceNetworkPolicies(processes)
	
	// Enforce file policies
	pee.enforceFilePolicies(processes)
	
	// Enforce execution policies
	pee.enforceExecutionPolicies(processes)
	
	// Enforce IPC policies
	pee.enforceIPCPolicies(processes)
}

func (pee *ProcessEnforcementEngine) enforceNetworkPolicies(processes []observability.ProcessInfo) {
	pee.processPolicyManager.mu.RLock()
	defer pee.processPolicyManager.mu.RUnlock()
	
	for _, process := range processes {
		for _, policy := range pee.processPolicyManager.networkPolicies {
			if !policy.Enabled {
				continue
			}
			
			if pee.processMatchesPatterns(process, policy.ProcessPatterns) {
				pee.enforceNetworkPolicyForProcess(process, policy)
			}
		}
	}
}

func (pee *ProcessEnforcementEngine) enforceFilePolicies(processes []observability.ProcessInfo) {
	pee.processPolicyManager.mu.RLock()
	defer pee.processPolicyManager.mu.RUnlock()
	
	for _, process := range processes {
		for _, policy := range pee.processPolicyManager.filePolicies {
			if !policy.Enabled {
				continue
			}
			
			if pee.processMatchesPatterns(process, policy.ProcessPatterns) {
				pee.enforceFilePolicyForProcess(process, policy)
			}
		}
	}
}

func (pee *ProcessEnforcementEngine) enforceExecutionPolicies(processes []observability.ProcessInfo) {
	pee.processPolicyManager.mu.RLock()
	defer pee.processPolicyManager.mu.RUnlock()
	
	for _, process := range processes {
		for _, policy := range pee.processPolicyManager.executionPolicies {
			if !policy.Enabled {
				continue
			}
			
			if pee.processMatchesPatterns(process, policy.ProcessPatterns) {
				pee.enforceExecutionPolicyForProcess(process, policy)
			}
		}
	}
}

func (pee *ProcessEnforcementEngine) enforceIPCPolicies(processes []observability.ProcessInfo) {
	pee.processPolicyManager.mu.RLock()
	defer pee.processPolicyManager.mu.RUnlock()
	
	for _, process := range processes {
		for _, policy := range pee.processPolicyManager.ipcPolicies {
			if !policy.Enabled {
				continue
			}
			
			if pee.processMatchesPatterns(process, policy.ProcessPatterns) {
				pee.enforceIPCPolicyForProcess(process, policy)
			}
		}
	}
}

func (pee *ProcessEnforcementEngine) processMatchesPatterns(process observability.ProcessInfo, patterns []ProcessPattern) bool {
	for _, pattern := range patterns {
		if !pee.processMatchesPattern(process, pattern) {
			return false
		}
	}
	return true
}

func (pee *ProcessEnforcementEngine) processMatchesPattern(process observability.ProcessInfo, pattern ProcessPattern) bool {
	processName := string(process.Comm[:])
	
	switch pattern.Type {
	case PatternTypeProcessName:
		return pee.matchString(processName, pattern.Value, pattern.Operator)
	case PatternTypeExecutable:
		// Simplified - would need to get actual executable path
		return pee.matchString(processName, pattern.Value, pattern.Operator)
	case PatternTypeUser:
		userStr := fmt.Sprintf("%d", process.UID)
		return pee.matchString(userStr, pattern.Value, pattern.Operator)
	case PatternTypeGroup:
		groupStr := fmt.Sprintf("%d", process.GID)
		return pee.matchString(groupStr, pattern.Value, pattern.Operator)
	case PatternTypeNamespace:
		nsStr := fmt.Sprintf("%d", process.NamespaceID)
		return pee.matchString(nsStr, pattern.Value, pattern.Operator)
	default:
		return false
	}
}

func (pee *ProcessEnforcementEngine) matchString(value, pattern string, operator PatternOperator) bool {
	switch operator {
	case OperatorEquals:
		return value == pattern
	case OperatorContains:
		return strings.Contains(value, pattern)
	case OperatorStartsWith:
		return strings.HasPrefix(value, pattern)
	case OperatorEndsWith:
		return strings.HasSuffix(value, pattern)
	case OperatorRegex:
		matched, _ := regexp.MatchString(pattern, value)
		return matched
	case OperatorNotEquals:
		return value != pattern
	case OperatorNotContains:
		return !strings.Contains(value, pattern)
	default:
		return false
	}
}

func (pee *ProcessEnforcementEngine) enforceNetworkPolicyForProcess(process observability.ProcessInfo, policy *ProcessNetworkPolicy) {
	// Get process network connections
	connections, err := pee.processPolicyManager.processMonitor.GetProcessNetworkConnections(process.PID)
	if err != nil {
		return
	}
	
	// Apply network rules to connections
	for _, connection := range connections {
		for _, rule := range policy.NetworkRules {
			if pee.connectionMatchesRule(connection, rule) {
				pee.applyNetworkRule(process, connection, rule)
			}
		}
	}
}

func (pee *ProcessEnforcementEngine) enforceFilePolicyForProcess(process observability.ProcessInfo, policy *ProcessFilePolicy) {
	// Get process file access
	fileAccess, err := pee.processPolicyManager.processMonitor.GetProcessFileAccess(process.PID)
	if err != nil {
		return
	}
	
	// Apply file rules to file access
	for _, access := range fileAccess {
		for _, rule := range policy.FileRules {
			if pee.fileAccessMatchesRule(access, rule) {
				pee.applyFileRule(process, access, rule)
			}
		}
	}
}

func (pee *ProcessEnforcementEngine) enforceExecutionPolicyForProcess(process observability.ProcessInfo, policy *ProcessExecutionPolicy) {
	// Apply execution rules to process
	for _, rule := range policy.ExecutionRules {
		if pee.executionMatchesRule(process, rule) {
			pee.applyExecutionRule(process, rule)
		}
	}
}

func (pee *ProcessEnforcementEngine) enforceIPCPolicyForProcess(process observability.ProcessInfo, policy *ProcessIPCPolicy) {
	// Apply IPC rules to process
	for _, rule := range policy.IPCRules {
		if pee.ipcMatchesRule(process, rule) {
			pee.applyIPCRule(process, rule)
		}
	}
}

// Rule matching methods
func (pee *ProcessEnforcementEngine) connectionMatchesRule(connection observability.ProcessNetworkConn, rule *NetworkRule) bool {
	// Simplified matching - in reality would check all rule fields
	return true // Placeholder
}

func (pee *ProcessEnforcementEngine) fileAccessMatchesRule(access observability.ProcessFileAccess, rule *FileRule) bool {
	// Check if file path matches rule path pattern
	filePath := string(access.FilePath[:])
	return strings.Contains(filePath, rule.Path)
}

func (pee *ProcessEnforcementEngine) executionMatchesRule(process observability.ProcessInfo, rule *ExecutionRule) bool {
	// Check if process executable matches rule
	processName := string(process.Comm[:])
	return strings.Contains(processName, rule.Executable)
}

func (pee *ProcessEnforcementEngine) ipcMatchesRule(process observability.ProcessInfo, rule *IPCRule) bool {
	// Simplified IPC matching
	return true // Placeholder
}

// Rule application methods
func (pee *ProcessEnforcementEngine) applyNetworkRule(process observability.ProcessInfo, connection observability.ProcessNetworkConn, rule *NetworkRule) {
	// Log network rule application
	pee.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"Network rule applied to process",
		map[string]interface{}{
			"process_id":   process.PID,
			"process_name": string(process.Comm[:]),
			"rule_action":  rule.Action,
			"protocol":     rule.Protocol,
			"direction":    rule.Direction,
		})
	
	// Apply rule action (simplified)
	switch rule.Action {
	case ActionAllow:
		// Allow connection
	case ActionDeny:
		// Block connection
	case ActionLog:
		// Log connection
	case ActionRestrict:
		// Restrict connection
	case ActionMonitor:
		// Monitor connection
	case ActionQuarantine:
		// Quarantine process
	}
}

func (pee *ProcessEnforcementEngine) applyFileRule(process observability.ProcessInfo, access observability.ProcessFileAccess, rule *FileRule) {
	// Log file rule application
	pee.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"File rule applied to process",
		map[string]interface{}{
			"process_id":   process.PID,
			"process_name": string(process.Comm[:]),
			"rule_action":  rule.Action,
			"file_path":    string(access.FilePath[:]),
			"access_mode":  rule.AccessMode,
		})
	
	// Apply rule action (simplified)
	switch rule.Action {
	case ActionAllow:
		// Allow file access
	case ActionDeny:
		// Block file access
	case ActionLog:
		// Log file access
	case ActionRestrict:
		// Restrict file access
	case ActionMonitor:
		// Monitor file access
	case ActionQuarantine:
		// Quarantine process
	}
}

func (pee *ProcessEnforcementEngine) applyExecutionRule(process observability.ProcessInfo, rule *ExecutionRule) {
	// Log execution rule application
	pee.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"Execution rule applied to process",
		map[string]interface{}{
			"process_id":   process.PID,
			"process_name": string(process.Comm[:]),
			"rule_action":  rule.Action,
			"executable":   rule.Executable,
		})
	
	// Apply rule action (simplified)
	switch rule.Action {
	case ActionAllow:
		// Allow execution
	case ActionDeny:
		// Block execution
	case ActionLog:
		// Log execution
	case ActionRestrict:
		// Restrict execution
	case ActionMonitor:
		// Monitor execution
	case ActionQuarantine:
		// Quarantine process
	}
}

func (pee *ProcessEnforcementEngine) applyIPCRule(process observability.ProcessInfo, rule *IPCRule) {
	// Log IPC rule application
	pee.auditLogger.LogCustomEvent(telemetry.EventTypePolicyEvent, telemetry.SeverityInfo,
		"IPC rule applied to process",
		map[string]interface{}{
			"process_id":   process.PID,
			"process_name": string(process.Comm[:]),
			"rule_action":  rule.Action,
			"ipc_method":   rule.IPCMethod,
		})
	
	// Apply rule action (simplified)
	switch rule.Action {
	case ActionAllow:
		// Allow IPC
	case ActionDeny:
		// Block IPC
	case ActionLog:
		// Log IPC
	case ActionRestrict:
		// Restrict IPC
	case ActionMonitor:
		// Monitor IPC
	case ActionQuarantine:
		// Quarantine process
	}
}

// Public methods for accessing policies
func (ppm *ProcessPolicyManager) GetNetworkPolicies() map[string]*ProcessNetworkPolicy {
	ppm.mu.RLock()
	defer ppm.mu.RUnlock()
	
	policies := make(map[string]*ProcessNetworkPolicy)
	for id, policy := range ppm.networkPolicies {
		policies[id] = policy
	}
	
	return policies
}

func (ppm *ProcessPolicyManager) GetFilePolicies() map[string]*ProcessFilePolicy {
	ppm.mu.RLock()
	defer ppm.mu.RUnlock()
	
	policies := make(map[string]*ProcessFilePolicy)
	for id, policy := range ppm.filePolicies {
		policies[id] = policy
	}
	
	return policies
}

func (ppm *ProcessPolicyManager) GetExecutionPolicies() map[string]*ProcessExecutionPolicy {
	ppm.mu.RLock()
	defer ppm.mu.RUnlock()
	
	policies := make(map[string]*ProcessExecutionPolicy)
	for id, policy := range ppm.executionPolicies {
		policies[id] = policy
	}
	
	return policies
}

func (ppm *ProcessPolicyManager) GetIPCPolicies() map[string]*ProcessIPCPolicy {
	ppm.mu.RLock()
	defer ppm.mu.RUnlock()
	
	policies := make(map[string]*ProcessIPCPolicy)
	for id, policy := range ppm.ipcPolicies {
		policies[id] = policy
	}
	
	return policies
}

func (ppm *ProcessPolicyManager) GetPolicyStatistics() map[string]interface{} {
	ppm.mu.RLock()
	defer ppm.mu.RUnlock()
	
	stats := map[string]interface{}{
		"network_policies":   len(ppm.networkPolicies),
		"file_policies":      len(ppm.filePolicies),
		"execution_policies": len(ppm.executionPolicies),
		"ipc_policies":       len(ppm.ipcPolicies),
		"total_policies":     len(ppm.networkPolicies) + len(ppm.filePolicies) + len(ppm.executionPolicies) + len(ppm.ipcPolicies),
	}
	
	return stats
}

// Close closes the process policy manager
func (ppm *ProcessPolicyManager) Close() error {
	return ppm.Stop()
}
