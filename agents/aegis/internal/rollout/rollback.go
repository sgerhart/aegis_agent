package rollout

import (
	"fmt"
	"time"

	"agents/aegis/internal/telemetry"
)

// RollbackManager handles safe rollback of policy assignments
type RollbackManager struct {
	eventEmitter *telemetry.EventEmitter
	snapshots    map[string]*PolicySnapshot
}

// PolicySnapshot represents a snapshot of policy state for rollback
type PolicySnapshot struct {
	ID           string                 `json:"id"`
	AssignmentID string                 `json:"assignment_id"`
	CreatedAt    time.Time              `json:"created_at"`
	State        map[string]any         `json:"state"`
	Metadata     map[string]any         `json:"metadata"`
}

// RollbackResult represents the result of a rollback operation
type RollbackResult struct {
	Success     bool              `json:"success"`
	RollbackID  string            `json:"rollback_id"`
	Changes     []string          `json:"changes"`
	Warnings    []string          `json:"warnings"`
	Errors      []string          `json:"errors"`
	Duration    time.Duration     `json:"duration"`
	Metadata    map[string]any    `json:"metadata"`
}

// NewRollbackManager creates a new rollback manager
func NewRollbackManager(eventEmitter *telemetry.EventEmitter) *RollbackManager {
	return &RollbackManager{
		eventEmitter: eventEmitter,
		snapshots:    make(map[string]*PolicySnapshot),
	}
}

// CreateSnapshot creates a snapshot of the current policy state
func (rm *RollbackManager) CreateSnapshot(assignmentID string, state map[string]any) *PolicySnapshot {
	snapshot := &PolicySnapshot{
		ID:           generateRollbackID(),
		AssignmentID: assignmentID,
		CreatedAt:    time.Now(),
		State:        state,
		Metadata:     make(map[string]any),
	}
	
	rm.snapshots[snapshot.ID] = snapshot
	
	// Emit snapshot created event
	rm.eventEmitter.EmitCounter("rollback_snapshot_created", 1, "count", map[string]string{
		"assignment_id": assignmentID,
		"rollback_id":   snapshot.ID,
	})
	
	return snapshot
}

// RollbackToSnapshot rolls back to a specific snapshot
func (rm *RollbackManager) RollbackToSnapshot(rollbackID string) *RollbackResult {
	start := time.Now()
	result := &RollbackResult{
		RollbackID: rollbackID,
		Changes:    []string{},
		Warnings:   []string{},
		Errors:     []string{},
		Metadata:   make(map[string]any),
	}
	
	// Get snapshot
	snapshot, exists := rm.snapshots[rollbackID]
	if !exists {
		result.Errors = append(result.Errors, fmt.Sprintf("Snapshot not found: %s", rollbackID))
		result.Success = false
		result.Duration = time.Since(start)
		
		rm.eventEmitter.EmitRollbackFailed(rollbackID, "", "snapshot not found", "Snapshot not found", time.Since(start))
		return result
	}
	
	// Check if snapshot is too old (max 24 hours)
	if time.Since(snapshot.CreatedAt) > 24*time.Hour {
		result.Warnings = append(result.Warnings, "Snapshot is older than 24 hours")
	}
	
	// Perform rollback
	changes, err := rm.performRollback(snapshot)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Rollback failed: %v", err))
		result.Success = false
		result.Duration = time.Since(start)
		
		rm.eventEmitter.EmitRollbackFailed(rollbackID, snapshot.AssignmentID, "rollback failed", err.Error(), time.Since(start))
		return result
	}
	
	result.Changes = changes
	result.Success = true
	result.Duration = time.Since(start)
	
	// Add metadata
	result.Metadata["assignment_id"] = snapshot.AssignmentID
	result.Metadata["snapshot_created_at"] = snapshot.CreatedAt
	result.Metadata["rollback_duration"] = result.Duration.Milliseconds()
	
	// Emit success event
	rm.eventEmitter.EmitRollbackOK(rollbackID, snapshot.AssignmentID, "manual rollback", changes, time.Since(start))
	
	return result
}

// RollbackAssignment rolls back a specific assignment
func (rm *RollbackManager) RollbackAssignment(assignmentID string) *RollbackResult {
	start := time.Now()
	result := &RollbackResult{
		Changes:  []string{},
		Warnings: []string{},
		Errors:   []string{},
		Metadata: make(map[string]any),
	}
	
	// Find the most recent snapshot for this assignment
	var latestSnapshot *PolicySnapshot
	for _, snapshot := range rm.snapshots {
		if snapshot.AssignmentID == assignmentID {
			if latestSnapshot == nil || snapshot.CreatedAt.After(latestSnapshot.CreatedAt) {
				latestSnapshot = snapshot
			}
		}
	}
	
	if latestSnapshot == nil {
		result.Errors = append(result.Errors, fmt.Sprintf("No snapshot found for assignment: %s", assignmentID))
		result.Success = false
		result.Duration = time.Since(start)
		
		rm.eventEmitter.EmitRollbackFailed("", assignmentID, "no snapshot", "No snapshot found", time.Since(start))
		return result
	}
	
	// Use the found snapshot
	result.RollbackID = latestSnapshot.ID
	return rm.RollbackToSnapshot(latestSnapshot.ID)
}

// performRollback performs the actual rollback operation
func (rm *RollbackManager) performRollback(snapshot *PolicySnapshot) ([]string, error) {
	var changes []string
	
	// Simulate eBPF program removal
	changes = append(changes, fmt.Sprintf("Removed eBPF program for assignment: %s", snapshot.AssignmentID))
	
	// Simulate map cleanup
	changes = append(changes, fmt.Sprintf("Cleaned up policy maps for assignment: %s", snapshot.AssignmentID))
	
	// Simulate TC detachment
	changes = append(changes, "Detached TC classifier from network interfaces")
	
	// Simulate cgroup detachment
	changes = append(changes, "Detached cgroup eBPF programs")
	
	// Restore previous state
	if prevState, ok := snapshot.State["previous_state"]; ok {
		changes = append(changes, fmt.Sprintf("Restored previous state: %v", prevState))
	}
	
	return changes, nil
}

// ListSnapshots returns all available snapshots
func (rm *RollbackManager) ListSnapshots() []*PolicySnapshot {
	var snapshots []*PolicySnapshot
	for _, snapshot := range rm.snapshots {
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

// GetSnapshot returns a specific snapshot by ID
func (rm *RollbackManager) GetSnapshot(rollbackID string) (*PolicySnapshot, error) {
	snapshot, exists := rm.snapshots[rollbackID]
	if !exists {
		return nil, fmt.Errorf("snapshot not found: %s", rollbackID)
	}
	return snapshot, nil
}

// DeleteSnapshot deletes a snapshot
func (rm *RollbackManager) DeleteSnapshot(rollbackID string) error {
	if _, exists := rm.snapshots[rollbackID]; !exists {
		return fmt.Errorf("snapshot not found: %s", rollbackID)
	}
	
	delete(rm.snapshots, rollbackID)
	
	// Emit snapshot deleted event
	rm.eventEmitter.EmitCounter("rollback_snapshot_deleted", 1, "count", map[string]string{
		"rollback_id": rollbackID,
	})
	
	return nil
}

// CleanupOldSnapshots removes snapshots older than the specified duration
func (rm *RollbackManager) CleanupOldSnapshots(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	count := 0
	
	for id, snapshot := range rm.snapshots {
		if snapshot.CreatedAt.Before(cutoff) {
			delete(rm.snapshots, id)
			count++
		}
	}
	
	if count > 0 {
		rm.eventEmitter.EmitCounter("rollback_snapshots_cleaned", float64(count), "count", map[string]string{
			"max_age_hours": fmt.Sprintf("%.1f", maxAge.Hours()),
		})
	}
	
	return count
}

// GetRollbackSummary returns a summary of rollback operations
func (rm *RollbackManager) GetRollbackSummary() map[string]any {
	summary := map[string]any{
		"total_snapshots": len(rm.snapshots),
		"oldest_snapshot": nil,
		"newest_snapshot": nil,
	}
	
	if len(rm.snapshots) == 0 {
		return summary
	}
	
	var oldest, newest *PolicySnapshot
	for _, snapshot := range rm.snapshots {
		if oldest == nil || snapshot.CreatedAt.Before(oldest.CreatedAt) {
			oldest = snapshot
		}
		if newest == nil || snapshot.CreatedAt.After(newest.CreatedAt) {
			newest = snapshot
		}
	}
	
	if oldest != nil {
		summary["oldest_snapshot"] = map[string]any{
			"id":         oldest.ID,
			"created_at": oldest.CreatedAt,
		}
	}
	
	if newest != nil {
		summary["newest_snapshot"] = map[string]any{
			"id":         newest.ID,
			"created_at": newest.CreatedAt,
		}
	}
	
	return summary
}

// generateRollbackID generates a unique rollback ID
func generateRollbackID() string {
	return fmt.Sprintf("rollback-%d-%s", time.Now().Unix(), randomString(8))
}

// randomString generates a random string of specified length
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
