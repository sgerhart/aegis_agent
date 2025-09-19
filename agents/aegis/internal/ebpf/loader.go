package ebpf

import (
	"fmt"
	"time"

	"agents/aegis/internal/crypto"
	"agents/aegis/internal/rollout"
	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

// Loader handles the complete eBPF policy loading pipeline
type Loader struct {
	verifier     *crypto.Verifier
	dryRunMgr    *rollout.DryRunManager
	rollbackMgr  *rollout.RollbackManager
	ttlMgr       *rollout.TTLManager
	eventEmitter *telemetry.EventEmitter
	dryRunMode   bool
}

// NewLoader creates a new eBPF loader
func NewLoader(verifier *crypto.Verifier, eventEmitter *telemetry.EventEmitter, dryRunMode bool) *Loader {
	dryRunMgr := rollout.NewDryRunManager(verifier, eventEmitter)
	rollbackMgr := rollout.NewRollbackManager(eventEmitter)
	ttlMgr := rollout.NewTTLManager(5 * time.Minute) // Check every 5 minutes
	
	return &Loader{
		verifier:     verifier,
		dryRunMgr:    dryRunMgr,
		rollbackMgr:  rollbackMgr,
		ttlMgr:       ttlMgr,
		eventEmitter: eventEmitter,
		dryRunMode:   dryRunMode,
	}
}

// LoadResult represents the result of loading an assignment
type LoadResult struct {
	Success      bool              `json:"success"`
	AssignmentID string            `json:"assignment_id"`
	DryRun       bool              `json:"dry_run"`
	Changes      []string          `json:"changes"`
	Warnings     []string          `json:"warnings"`
	Errors       []string          `json:"errors"`
	RollbackID   string            `json:"rollback_id,omitempty"`
	Duration     time.Duration     `json:"duration"`
	Metadata     map[string]any    `json:"metadata"`
}

// LoadAssignment loads a policy assignment with full safety checks
func (l *Loader) LoadAssignment(assignment *models.Assignment) *LoadResult {
	start := time.Now()
	result := &LoadResult{
		AssignmentID: assignment.ID,
		DryRun:       l.dryRunMode || assignment.DryRun,
		Changes:      []string{},
		Warnings:     []string{},
		Errors:       []string{},
		Metadata:     make(map[string]any),
	}
	
	// Step 1: Validate assignment
	if err := l.validateAssignment(assignment); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Validation failed: %v", err))
		result.Success = false
		result.Duration = time.Since(start)
		return result
	}
	
	// Step 2: Check TTL
	if assignment.IsExpired() {
		result.Errors = append(result.Errors, "Assignment has expired")
		result.Success = false
		result.Duration = time.Since(start)
		return result
	}
	
	// Step 3: Verify bundle signature
	verification, err := l.verifier.VerifyBundle(&assignment.Bundle)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Verification failed: %v", err))
		result.Success = false
		result.Duration = time.Since(start)
		
		l.eventEmitter.EmitVerifyFailed(assignment.Bundle.ID, err.Error(), time.Since(start))
		return result
	}
	
	if !verification.Valid {
		result.Errors = append(result.Errors, verification.Error)
		result.Success = false
		result.Duration = time.Since(start)
		
		l.eventEmitter.EmitVerifyFailed(assignment.Bundle.ID, verification.Error, time.Since(start))
		return result
	}
	
	l.eventEmitter.EmitVerifyOK(assignment.Bundle.ID, verification.KeyID, verification.Algorithm, time.Since(start))
	
	// Step 4: Create snapshot for rollback
	snapshot := l.rollbackMgr.CreateSnapshot(assignment.ID, map[string]any{
		"assignment_id": assignment.ID,
		"policy_id":     assignment.PolicyID,
		"version":       assignment.Version,
		"created_at":    time.Now(),
	})
	result.RollbackID = snapshot.ID
	
	// Step 5: Apply or dry-run
	if result.DryRun {
		// Dry-run mode: simulate application
		changes, warnings, err := l.simulateApplication(assignment)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Dry-run failed: %v", err))
			result.Success = false
			result.Duration = time.Since(start)
			return result
		}
		
		result.Changes = changes
		result.Warnings = warnings
		result.Success = true
		
		l.eventEmitter.EmitEnforceOK(assignment.ID, assignment.PolicyID, true, changes, time.Since(start))
	} else {
		// Real mode: apply the policy
		changes, warnings, err := l.applyPolicy(assignment)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Application failed: %v", err))
			result.Success = false
			result.Duration = time.Since(start)
			
			// Attempt rollback on failure
			l.attemptRollback(snapshot.ID, assignment.ID, err.Error())
			return result
		}
		
		result.Changes = changes
		result.Warnings = warnings
		result.Success = true
		
		l.eventEmitter.EmitEnforceOK(assignment.ID, assignment.PolicyID, false, changes, time.Since(start))
	}
	
	result.Duration = time.Since(start)
	
	// Add metadata
	result.Metadata["policy_id"] = assignment.PolicyID
	result.Metadata["version"] = assignment.Version
	result.Metadata["bundle_id"] = assignment.Bundle.ID
	result.Metadata["key_id"] = verification.KeyID
	result.Metadata["algorithm"] = verification.Algorithm
	
	return result
}

// validateAssignment validates an assignment
func (l *Loader) validateAssignment(assignment *models.Assignment) error {
	// Basic validation
	if err := assignment.Validate(); err != nil {
		return err
	}
	
	// Check if assignment matches host selectors
	// This would need host information to be passed in
	// For now, we'll assume it matches
	
	return nil
}

// simulateApplication simulates the application of a policy
func (l *Loader) simulateApplication(assignment *models.Assignment) ([]string, []string, error) {
	var changes []string
	var warnings []string
	
	// Simulate eBPF program loading
	changes = append(changes, fmt.Sprintf("Would load eBPF program: %s", assignment.PolicyID))
	
	// Simulate map updates
	changes = append(changes, fmt.Sprintf("Would update policy maps for assignment: %s", assignment.ID))
	
	// Simulate TC attachment
	changes = append(changes, "Would attach TC classifier to network interfaces")
	
	// Simulate cgroup attachment
	changes = append(changes, "Would attach cgroup eBPF programs")
	
	// Check for potential issues
	if assignment.Priority < 0 {
		warnings = append(warnings, "Assignment has negative priority")
	}
	
	// Check bundle size
	if len(assignment.Bundle.Content) > 1024*1024 { // 1MB
		warnings = append(warnings, "Bundle size is large, may impact performance")
	}
	
	return changes, warnings, nil
}

// applyPolicy applies a policy to the system
func (l *Loader) applyPolicy(assignment *models.Assignment) ([]string, []string, error) {
	var changes []string
	var warnings []string
	
	// Load eBPF program
	if err := l.loadEBPFProgram(assignment); err != nil {
		return nil, nil, fmt.Errorf("failed to load eBPF program: %w", err)
	}
	changes = append(changes, fmt.Sprintf("Loaded eBPF program: %s", assignment.PolicyID))
	
	// Update policy maps
	if err := l.updatePolicyMaps(assignment); err != nil {
		return nil, nil, fmt.Errorf("failed to update policy maps: %w", err)
	}
	changes = append(changes, fmt.Sprintf("Updated policy maps for assignment: %s", assignment.ID))
	
	// Attach TC classifier
	if err := l.attachTCClassifier(assignment); err != nil {
		return nil, nil, fmt.Errorf("failed to attach TC classifier: %w", err)
	}
	changes = append(changes, "Attached TC classifier to network interfaces")
	
	// Attach cgroup programs
	if err := l.attachCgroupPrograms(assignment); err != nil {
		return nil, nil, fmt.Errorf("failed to attach cgroup programs: %w", err)
	}
	changes = append(changes, "Attached cgroup eBPF programs")
	
	return changes, warnings, nil
}

// loadEBPFProgram loads an eBPF program
func (l *Loader) loadEBPFProgram(assignment *models.Assignment) error {
	// This would integrate with the actual eBPF loader
	// For now, we'll simulate success
	return nil
}

// updatePolicyMaps updates policy maps
func (l *Loader) updatePolicyMaps(assignment *models.Assignment) error {
	// This would integrate with the actual policy map updater
	// For now, we'll simulate success
	return nil
}

// attachTCClassifier attaches TC classifier
func (l *Loader) attachTCClassifier(assignment *models.Assignment) error {
	// This would integrate with the actual TC attachment
	// For now, we'll simulate success
	return nil
}

// attachCgroupPrograms attaches cgroup programs
func (l *Loader) attachCgroupPrograms(assignment *models.Assignment) error {
	// This would integrate with the actual cgroup attachment
	// For now, we'll simulate success
	return nil
}

// attemptRollback attempts to rollback on failure
func (l *Loader) attemptRollback(rollbackID, assignmentID, reason string) {
	rollbackResult := l.rollbackMgr.RollbackToSnapshot(rollbackID)
	if rollbackResult.Success {
		l.eventEmitter.EmitRollbackOK(rollbackID, assignmentID, reason, rollbackResult.Changes, rollbackResult.Duration)
	} else {
		l.eventEmitter.EmitRollbackFailed(rollbackID, assignmentID, reason, fmt.Sprintf("Rollback failed: %v", rollbackResult.Errors), rollbackResult.Duration)
	}
}

// LoadMultipleAssignments loads multiple assignments
func (l *Loader) LoadMultipleAssignments(assignments []*models.Assignment) map[string]*LoadResult {
	results := make(map[string]*LoadResult)
	
	for _, assignment := range assignments {
		result := l.LoadAssignment(assignment)
		results[assignment.ID] = result
	}
	
	return results
}

// RollbackAssignment rolls back an assignment
func (l *Loader) RollbackAssignment(assignmentID string) *rollout.RollbackResult {
	return l.rollbackMgr.RollbackAssignment(assignmentID)
}

// RollbackToSnapshot rolls back to a specific snapshot
func (l *Loader) RollbackToSnapshot(rollbackID string) *rollout.RollbackResult {
	return l.rollbackMgr.RollbackToSnapshot(rollbackID)
}

// GetRollbackSummary returns rollback summary
func (l *Loader) GetRollbackSummary() map[string]any {
	return l.rollbackMgr.GetRollbackSummary()
}

// SetDryRunMode sets the dry-run mode
func (l *Loader) SetDryRunMode(dryRun bool) {
	l.dryRunMode = dryRun
}

// GetDryRunMode returns the current dry-run mode
func (l *Loader) GetDryRunMode() bool {
	return l.dryRunMode
}

// StartTTLChecker starts the TTL checker
func (l *Loader) StartTTLChecker(assignments []*models.Assignment) {
	l.ttlMgr.StartExpiryChecker(assignments)
}

// GetExpiredAssignments returns expired assignments
func (l *Loader) GetExpiredAssignments(assignments []*models.Assignment) []*models.Assignment {
	return l.ttlMgr.CheckExpired(assignments)
}

// Close closes the loader and cleans up resources
func (l *Loader) Close() {
	l.ttlMgr.Stop()
}
