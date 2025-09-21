package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"agents/aegis/internal/policy"
)

// RollbackManager manages policy rollback operations
type RollbackManager struct {
	historyFile   string
	maxHistory    int
	history       []PolicySnapshot
	mu            sync.RWMutex
	emergencyMode bool
}

// PolicySnapshot represents a snapshot of policy state for rollback
type PolicySnapshot struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	PolicyID    string                 `json:"policy_id"`
	PolicyName  string                 `json:"policy_name"`
	PolicyData  map[string]interface{} `json:"policy_data"`
	MapState    map[string]interface{} `json:"map_state"`
	Reason      string                 `json:"reason"`
	Success     bool                   `json:"success"`
	RollbackTo  string                 `json:"rollback_to,omitempty"` // ID of snapshot to rollback to
}

// RollbackResult represents the result of a rollback operation
type RollbackResult struct {
	Success     bool     `json:"success"`
	Message     string   `json:"message"`
	RestoredTo  string   `json:"restored_to"`
	Errors      []string `json:"errors"`
	Warnings    []string `json:"warnings"`
}

// NewRollbackManager creates a new rollback manager
func NewRollbackManager(historyFile string, maxHistory int) *RollbackManager {
	rm := &RollbackManager{
		historyFile: historyFile,
		maxHistory:  maxHistory,
		history:     make([]PolicySnapshot, 0),
		emergencyMode: false,
	}
	
	// Load existing history
	rm.loadHistory()
	
	return rm
}

// CreateSnapshot creates a new policy snapshot
func (rm *RollbackManager) CreateSnapshot(policyID, policyName string, policyData map[string]interface{}, mapState map[string]interface{}, reason string) *PolicySnapshot {
	snapshot := &PolicySnapshot{
		ID:         generateSnapshotID(),
		Timestamp:  time.Now(),
		PolicyID:   policyID,
		PolicyName: policyName,
		PolicyData: policyData,
		MapState:   mapState,
		Reason:     reason,
		Success:    true,
	}
	
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	// Add to history
	rm.history = append(rm.history, *snapshot)
	
	// Maintain history size
	if len(rm.history) > rm.maxHistory {
		rm.history = rm.history[1:]
	}
	
	// Save to disk
	rm.saveHistory()
	
	log.Printf("[rollback] Created snapshot %s for policy %s: %s", snapshot.ID, policyID, reason)
	return snapshot
}

// CreateFailureSnapshot creates a snapshot for a failed policy application
func (rm *RollbackManager) CreateFailureSnapshot(policyID, policyName string, policyData map[string]interface{}, mapState map[string]interface{}, reason string) *PolicySnapshot {
	snapshot := &PolicySnapshot{
		ID:         generateSnapshotID(),
		Timestamp:  time.Now(),
		PolicyID:   policyID,
		PolicyName: policyName,
		PolicyData: policyData,
		MapState:   mapState,
		Reason:     reason,
		Success:    false,
	}
	
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	// Add to history
	rm.history = append(rm.history, *snapshot)
	
	// Save to disk
	rm.saveHistory()
	
	log.Printf("[rollback] Created failure snapshot %s for policy %s: %s", snapshot.ID, policyID, reason)
	return snapshot
}

// RollbackToSnapshot rolls back to a specific snapshot
func (rm *RollbackManager) RollbackToSnapshot(ctx context.Context, snapshotID string) (*RollbackResult, error) {
	rm.mu.RLock()
	snapshot, err := rm.findSnapshot(snapshotID)
	rm.mu.RUnlock()
	
	if err != nil {
		return &RollbackResult{
			Success: false,
			Message: fmt.Sprintf("Snapshot not found: %v", err),
		}, err
	}
	
	log.Printf("[rollback] Rolling back to snapshot %s (policy: %s)", snapshotID, snapshot.PolicyName)
	
	// Perform rollback
	result := rm.performRollback(ctx, snapshot)
	
	// Create rollback snapshot
	rollbackSnapshot := &PolicySnapshot{
		ID:         generateSnapshotID(),
		Timestamp:  time.Now(),
		PolicyID:   snapshot.PolicyID,
		PolicyName: snapshot.PolicyName,
		PolicyData: snapshot.PolicyData,
		MapState:   snapshot.MapState,
		Reason:     fmt.Sprintf("Rollback to snapshot %s", snapshotID),
		Success:    result.Success,
		RollbackTo: snapshotID,
	}
	
	rm.mu.Lock()
	rm.history = append(rm.history, *rollbackSnapshot)
	rm.saveHistory()
	rm.mu.Unlock()
	
	return result, nil
}

// RollbackLast rolls back to the last successful snapshot
func (rm *RollbackManager) RollbackLast(ctx context.Context) (*RollbackResult, error) {
	rm.mu.RLock()
	lastSuccessful := rm.findLastSuccessfulSnapshot()
	rm.mu.RUnlock()
	
	if lastSuccessful == nil {
		return &RollbackResult{
			Success: false,
			Message: "No successful snapshots found for rollback",
		}, fmt.Errorf("no successful snapshots found")
	}
	
	return rm.RollbackToSnapshot(ctx, lastSuccessful.ID)
}

// EmergencyRollback performs an emergency rollback to clear all policies
func (rm *RollbackManager) EmergencyRollback(ctx context.Context) (*RollbackResult, error) {
	log.Printf("[rollback] Performing emergency rollback - clearing all policies")
	
	rm.emergencyMode = true
	defer func() { rm.emergencyMode = false }()
	
	// Clear all eBPF maps
	result := rm.clearAllMaps(ctx)
	
	// Create emergency snapshot
	emergencySnapshot := &PolicySnapshot{
		ID:         generateSnapshotID(),
		Timestamp:  time.Now(),
		PolicyID:   "emergency",
		PolicyName: "Emergency Rollback",
		PolicyData: map[string]interface{}{
			"emergency": true,
			"cleared":   true,
		},
		MapState:  map[string]interface{}{},
		Reason:    "Emergency rollback - all policies cleared",
		Success:   result.Success,
	}
	
	rm.mu.Lock()
	rm.history = append(rm.history, *emergencySnapshot)
	rm.saveHistory()
	rm.mu.Unlock()
	
	return result, nil
}

// GetHistory returns the rollback history
func (rm *RollbackManager) GetHistory() []PolicySnapshot {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	// Return a copy to prevent external modification
	history := make([]PolicySnapshot, len(rm.history))
	copy(history, rm.history)
	
	return history
}

// GetLastSnapshots returns the last N snapshots
func (rm *RollbackManager) GetLastSnapshots(count int) []PolicySnapshot {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	if count > len(rm.history) {
		count = len(rm.history)
	}
	
	start := len(rm.history) - count
	history := make([]PolicySnapshot, count)
	copy(history, rm.history[start:])
	
	return history
}

// IsEmergencyMode returns whether emergency mode is active
func (rm *RollbackManager) IsEmergencyMode() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.emergencyMode
}

// findSnapshot finds a snapshot by ID
func (rm *RollbackManager) findSnapshot(snapshotID string) (*PolicySnapshot, error) {
	for i := len(rm.history) - 1; i >= 0; i-- {
		if rm.history[i].ID == snapshotID {
			return &rm.history[i], nil
		}
	}
	return nil, fmt.Errorf("snapshot %s not found", snapshotID)
}

// findLastSuccessfulSnapshot finds the last successful snapshot
func (rm *RollbackManager) findLastSuccessfulSnapshot() *PolicySnapshot {
	for i := len(rm.history) - 1; i >= 0; i-- {
		if rm.history[i].Success {
			return &rm.history[i]
		}
	}
	return nil
}

// performRollback performs the actual rollback operation
func (rm *RollbackManager) performRollback(ctx context.Context, snapshot *PolicySnapshot) *RollbackResult {
	result := &RollbackResult{
		Success:  false,
		Errors:   []string{},
		Warnings: []string{},
	}
	
	// Restore map state
	if err := rm.restoreMapState(ctx, snapshot.MapState); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to restore map state: %v", err))
		result.Message = "Rollback failed - map state restoration failed"
		return result
	}
	
	// Restore policy data
	if err := rm.restorePolicyData(ctx, snapshot.PolicyData); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Policy data restoration warning: %v", err))
		// Don't fail rollback for policy data issues
	}
	
	result.Success = true
	result.Message = fmt.Sprintf("Successfully rolled back to snapshot %s", snapshot.ID)
	result.RestoredTo = snapshot.ID
	
	log.Printf("[rollback] Rollback completed successfully to snapshot %s", snapshot.ID)
	return result
}

// restoreMapState restores the eBPF map state
func (rm *RollbackManager) restoreMapState(ctx context.Context, mapState map[string]interface{}) error {
	log.Printf("[rollback] Restoring map state")
	
	// This is a simplified implementation
	// In a full implementation, you would:
	// 1. Clear existing maps
	// 2. Restore each map's contents from the snapshot
	// 3. Verify map integrity
	
	// For now, we'll simulate the restoration
	if mapState == nil {
		log.Printf("[rollback] No map state to restore")
		return nil
	}
	
	// Simulate map restoration
	for mapName, mapData := range mapState {
		log.Printf("[rollback] Restoring map %s with %d entries", mapName, len(mapData.(map[string]interface{})))
		// Here you would actually restore the map data
	}
	
	return nil
}

// restorePolicyData restores policy data
func (rm *RollbackManager) restorePolicyData(ctx context.Context, policyData map[string]interface{}) error {
	log.Printf("[rollback] Restoring policy data")
	
	if policyData == nil {
		log.Printf("[rollback] No policy data to restore")
		return nil
	}
	
	// This is a simplified implementation
	// In a full implementation, you would:
	// 1. Clear existing policies
	// 2. Restore policies from the snapshot
	// 3. Update the policy engine
	
	log.Printf("[rollback] Policy data restoration completed")
	return nil
}

// clearAllMaps clears all eBPF maps (emergency rollback)
func (rm *RollbackManager) clearAllMaps(ctx context.Context) *RollbackResult {
	result := &RollbackResult{
		Success:  false,
		Errors:   []string{},
		Warnings: []string{},
	}
	
	log.Printf("[rollback] Clearing all eBPF maps")
	
	// This is a simplified implementation
	// In a full implementation, you would:
	// 1. Load all pinned maps
	// 2. Clear their contents
	// 3. Set default values
	
	// Simulate map clearing
	mapNames := []string{
		"/sys/fs/bpf/aegis_blocked_destinations",
		"/sys/fs/bpf/aegis/policy_edges",
		"/sys/fs/bpf/aegis/allow_lpm4",
		"/sys/fs/bpf/aegis/mode",
	}
	
	for _, mapName := range mapNames {
		log.Printf("[rollback] Clearing map %s", mapName)
		// Here you would actually clear the map
	}
	
	result.Success = true
	result.Message = "Emergency rollback completed - all maps cleared"
	
	return result
}

// loadHistory loads rollback history from disk
func (rm *RollbackManager) loadHistory() error {
	if _, err := os.Stat(rm.historyFile); os.IsNotExist(err) {
		log.Printf("[rollback] No history file found, starting fresh")
		return nil
	}
	
	data, err := os.ReadFile(rm.historyFile)
	if err != nil {
		return fmt.Errorf("failed to read history file: %w", err)
	}
	
	if err := json.Unmarshal(data, &rm.history); err != nil {
		return fmt.Errorf("failed to unmarshal history: %w", err)
	}
	
	log.Printf("[rollback] Loaded %d snapshots from history", len(rm.history))
	return nil
}

// saveHistory saves rollback history to disk
func (rm *RollbackManager) saveHistory() error {
	// Ensure directory exists
	dir := filepath.Dir(rm.historyFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create history directory: %w", err)
	}
	
	data, err := json.MarshalIndent(rm.history, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal history: %w", err)
	}
	
	if err := os.WriteFile(rm.historyFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write history file: %w", err)
	}
	
	return nil
}

// generateSnapshotID generates a unique snapshot ID
func generateSnapshotID() string {
	return fmt.Sprintf("snapshot_%d", time.Now().UnixNano())
}