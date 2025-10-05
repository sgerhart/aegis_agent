package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

// StateManager manages persistent local state for security continuity
type StateManager struct {
	stateDir     string
	telemetry    *telemetry.Logger
	mu           sync.RWMutex
	
	// Persistent state
	agentState   *AgentState
	policyState  *PolicyState
	hostState    *HostState
	lastSnapshot time.Time
}

// AgentState represents the agent's persistent state
type AgentState struct {
	AgentID        string                 `json:"agent_id"`
	LastStartup    time.Time              `json:"last_startup"`
	LastShutdown   time.Time              `json:"last_shutdown"`
	Uptime         time.Duration          `json:"uptime"`
	RestartCount   int                    `json:"restart_count"`
	LastBackendSync time.Time             `json:"last_backend_sync"`
	Capabilities   map[string]interface{} `json:"capabilities"`
	Version        string                 `json:"version"`
}

// PolicyState represents the policy state
type PolicyState struct {
	ActivePolicies    map[string]*models.Policy `json:"active_policies"`
	PolicyVersion     string                    `json:"policy_version"`
	LastPolicyUpdate  time.Time                 `json:"last_policy_update"`
	EnforcementMode   string                    `json:"enforcement_mode"`
	ViolationCount    int                       `json:"violation_count"`
	LastViolation     time.Time                 `json:"last_violation"`
}

// HostState represents the host's security state
type HostState struct {
	HostID           string                 `json:"host_id"`
	LastScan         time.Time              `json:"last_scan"`
	ProcessCount     int                    `json:"process_count"`
	NetworkConnections int                  `json:"network_connections"`
	FileSystemState  map[string]interface{} `json:"filesystem_state"`
	SecurityEvents   []SecurityEvent        `json:"security_events"`
	ThreatsDetected  []ThreatDetection      `json:"threats_detected"`
	ComplianceStatus string                 `json:"compliance_status"`
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatDetection represents a threat detection
type ThreatDetection struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	IOC         string                 `json:"ioc"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewStateManager creates a new state manager
func NewStateManager(stateDir string, telemetry *telemetry.Logger) (*StateManager, error) {
	if stateDir == "" {
		stateDir = "/var/lib/aegis/state"
	}
	
	sm := &StateManager{
		stateDir:  stateDir,
		telemetry: telemetry,
		agentState: &AgentState{
			Capabilities: make(map[string]interface{}),
		},
		policyState: &PolicyState{
			ActivePolicies: make(map[string]*models.Policy),
		},
		hostState: &HostState{
			FileSystemState: make(map[string]interface{}),
			SecurityEvents:  make([]SecurityEvent, 0),
			ThreatsDetected: make([]ThreatDetection, 0),
		},
	}
	
	// Ensure state directory exists
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}
	
	// Load existing state
	if err := sm.loadState(); err != nil {
		telemetry.LogWarn("state_manager", fmt.Sprintf("Failed to load existing state: %v", err), nil)
		// Continue with default state
	}
	
	telemetry.LogInfo("state_manager", "State manager initialized", map[string]interface{}{
		"state_dir": stateDir,
	})
	
	return sm, nil
}

// InitializeAgentState initializes the agent state on startup
func (sm *StateManager) InitializeAgentState(agentID, version string, capabilities map[string]interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// Update agent state
	sm.agentState.AgentID = agentID
	sm.agentState.Version = version
	sm.agentState.Capabilities = capabilities
	sm.agentState.LastStartup = time.Now()
	sm.agentState.RestartCount++
	
	// Calculate uptime if we have a previous shutdown time
	if !sm.agentState.LastShutdown.IsZero() {
		sm.agentState.Uptime = time.Since(sm.agentState.LastShutdown)
	}
	
	sm.telemetry.LogInfo("state_manager", "Agent state initialized", map[string]interface{}{
		"agent_id":      agentID,
		"version":       version,
		"restart_count": sm.agentState.RestartCount,
	})
	
	return sm.saveState()
}

// UpdatePolicyState updates the policy state
func (sm *StateManager) UpdatePolicyState(policies map[string]*models.Policy, version string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.policyState.ActivePolicies = policies
	sm.policyState.PolicyVersion = version
	sm.policyState.LastPolicyUpdate = time.Now()
	
	sm.telemetry.LogInfo("state_manager", "Policy state updated", map[string]interface{}{
		"policy_count": len(policies),
		"version":      version,
	})
	
	return sm.saveState()
}

// UpdateHostState updates the host state
func (sm *StateManager) UpdateHostState(hostID string, processCount, networkConnections int) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.hostState.HostID = hostID
	sm.hostState.ProcessCount = processCount
	sm.hostState.NetworkConnections = networkConnections
	sm.hostState.LastScan = time.Now()
	
	return sm.saveState()
}

// AddSecurityEvent adds a security event
func (sm *StateManager) AddSecurityEvent(event SecurityEvent) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.hostState.SecurityEvents = append(sm.hostState.SecurityEvents, event)
	
	// Keep only last 1000 events
	if len(sm.hostState.SecurityEvents) > 1000 {
		sm.hostState.SecurityEvents = sm.hostState.SecurityEvents[len(sm.hostState.SecurityEvents)-1000:]
	}
	
	sm.telemetry.LogInfo("state_manager", "Security event added", map[string]interface{}{
		"event_id":   event.ID,
		"event_type": event.Type,
		"severity":   event.Severity,
	})
	
	return sm.saveState()
}

// AddThreatDetection adds a threat detection
func (sm *StateManager) AddThreatDetection(threat ThreatDetection) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.hostState.ThreatsDetected = append(sm.hostState.ThreatsDetected, threat)
	
	// Keep only last 500 threats
	if len(sm.hostState.ThreatsDetected) > 500 {
		sm.hostState.ThreatsDetected = sm.hostState.ThreatsDetected[len(sm.hostState.ThreatsDetected)-500:]
	}
	
	sm.telemetry.LogInfo("state_manager", "Threat detection added", map[string]interface{}{
		"threat_id":   threat.ID,
		"threat_type": threat.Type,
		"severity":    threat.Severity,
		"ioc":         threat.IOC,
	})
	
	return sm.saveState()
}

// GetAgentState returns the current agent state
func (sm *StateManager) GetAgentState() *AgentState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	// Return a copy
	state := *sm.agentState
	return &state
}

// GetPolicyState returns the current policy state
func (sm *StateManager) GetPolicyState() *PolicyState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	// Return a copy
	state := *sm.policyState
	return &state
}

// GetHostState returns the current host state
func (sm *StateManager) GetHostState() *HostState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	// Return a copy
	state := *sm.hostState
	return &state
}

// SaveState saves the current state to disk
func (sm *StateManager) SaveState() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	return sm.saveState()
}

// saveState saves the current state to disk (internal method)
func (sm *StateManager) saveState() error {
	state := struct {
		AgentState  *AgentState  `json:"agent_state"`
		PolicyState *PolicyState `json:"policy_state"`
		HostState   *HostState   `json:"host_state"`
		LastSaved   time.Time    `json:"last_saved"`
	}{
		AgentState:  sm.agentState,
		PolicyState: sm.policyState,
		HostState:   sm.hostState,
		LastSaved:   time.Now(),
	}
	
	// Save to temporary file first, then rename (atomic operation)
	tempFile := filepath.Join(sm.stateDir, "state.tmp")
	finalFile := filepath.Join(sm.stateDir, "state.json")
	
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}
	
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename state file: %w", err)
	}
	
	sm.lastSnapshot = time.Now()
	return nil
}

// loadState loads the state from disk
func (sm *StateManager) loadState() error {
	stateFile := filepath.Join(sm.stateDir, "state.json")
	
	data, err := os.ReadFile(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			// No existing state, start fresh
			return nil
		}
		return fmt.Errorf("failed to read state file: %w", err)
	}
	
	var state struct {
		AgentState  *AgentState  `json:"agent_state"`
		PolicyState *PolicyState `json:"policy_state"`
		HostState   *HostState   `json:"host_state"`
		LastSaved   time.Time    `json:"last_saved"`
	}
	
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("failed to unmarshal state: %w", err)
	}
	
	// Validate and set state
	if state.AgentState != nil {
		sm.agentState = state.AgentState
	}
	if state.PolicyState != nil {
		sm.policyState = state.PolicyState
	}
	if state.HostState != nil {
		sm.hostState = state.HostState
	}
	
	sm.telemetry.LogInfo("state_manager", "State loaded from disk", map[string]interface{}{
		"last_saved": state.LastSaved,
		"agent_id":   sm.agentState.AgentID,
	})
	
	return nil
}

// Shutdown gracefully shuts down the state manager
func (sm *StateManager) Shutdown() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.agentState.LastShutdown = time.Now()
	
	if err := sm.saveState(); err != nil {
		sm.telemetry.LogError("state_manager", fmt.Sprintf("Failed to save state on shutdown: %v", err), nil)
		return err
	}
	
	sm.telemetry.LogInfo("state_manager", "State manager shutdown complete", nil)
	return nil
}

// GetStateSummary returns a summary of the current state
func (sm *StateManager) GetStateSummary() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	return map[string]interface{}{
		"agent": map[string]interface{}{
			"id":            sm.agentState.AgentID,
			"version":       sm.agentState.Version,
			"restart_count": sm.agentState.RestartCount,
			"last_startup":  sm.agentState.LastStartup,
		},
		"policies": map[string]interface{}{
			"active_count":    len(sm.policyState.ActivePolicies),
			"version":         sm.policyState.PolicyVersion,
			"last_update":     sm.policyState.LastPolicyUpdate,
			"violation_count": sm.policyState.ViolationCount,
		},
		"host": map[string]interface{}{
			"id":                  sm.hostState.HostID,
			"process_count":       sm.hostState.ProcessCount,
			"network_connections": sm.hostState.NetworkConnections,
			"last_scan":          sm.hostState.LastScan,
			"security_events":    len(sm.hostState.SecurityEvents),
			"threats_detected":   len(sm.hostState.ThreatsDetected),
		},
		"last_saved": sm.lastSnapshot,
	}
}
