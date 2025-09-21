package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PolicyHistoryManager manages policy change history
type PolicyHistoryManager struct {
	historyFile string
	maxEntries  int
	history     []PolicyHistoryEntry
	mu          sync.RWMutex
}

// PolicyHistoryEntry represents a single policy change in history
type PolicyHistoryEntry struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Action      string                 `json:"action"` // create, update, delete, apply, rollback
	PolicyID    string                 `json:"policy_id"`
	PolicyName  string                 `json:"policy_name"`
	PolicyType  string                 `json:"policy_type"`
	Changes     map[string]interface{} `json:"changes"`
	Reason      string                 `json:"reason"`
	User        string                 `json:"user"`
	Source      string                 `json:"source"` // manual, artifact, api, rollback
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Impact      *PolicyImpact          `json:"impact,omitempty"`
}

// PolicyImpact represents the impact of a policy change
type PolicyImpact struct {
	AffectedProcesses []string `json:"affected_processes"`
	AffectedServices  []string `json:"affected_services"`
	NetworkChanges    []string `json:"network_changes"`
	RiskLevel         string   `json:"risk_level"` // low, medium, high, critical
	EstimatedDowntime string   `json:"estimated_downtime"`
}

// HistoryQuery represents a query for policy history
type HistoryQuery struct {
	PolicyID  string    `json:"policy_id,omitempty"`
	Action    string    `json:"action,omitempty"`
	Source    string    `json:"source,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Success   *bool     `json:"success,omitempty"`
	Limit     int       `json:"limit,omitempty"`
}

// NewPolicyHistoryManager creates a new policy history manager
func NewPolicyHistoryManager(historyFile string, maxEntries int) *PolicyHistoryManager {
	phm := &PolicyHistoryManager{
		historyFile: historyFile,
		maxEntries:  maxEntries,
		history:     make([]PolicyHistoryEntry, 0),
	}
	
	// Load existing history
	phm.loadHistory()
	
	return phm
}

// RecordPolicyChange records a policy change in history
func (phm *PolicyHistoryManager) RecordPolicyChange(action, policyID, policyName, policyType, reason, user, source string, changes map[string]interface{}, success bool, err error) *PolicyHistoryEntry {
	entry := &PolicyHistoryEntry{
		ID:         generateHistoryID(),
		Timestamp:  time.Now(),
		Action:     action,
		PolicyID:   policyID,
		PolicyName: policyName,
		PolicyType: policyType,
		Changes:    changes,
		Reason:     reason,
		User:       user,
		Source:     source,
		Success:    success,
	}
	
	if err != nil {
		entry.Error = err.Error()
	}
	
	phm.mu.Lock()
	defer phm.mu.Unlock()
	
	// Add to history
	phm.history = append(phm.history, *entry)
	
	// Maintain history size
	if len(phm.history) > phm.maxEntries {
		phm.history = phm.history[1:]
	}
	
	// Save to disk
	phm.saveHistory()
	
	log.Printf("[history] Recorded %s action for policy %s (%s): %s", action, policyID, policyName, reason)
	return entry
}

// RecordPolicyApplication records a policy application
func (phm *PolicyHistoryManager) RecordPolicyApplication(policy *Policy, source string, success bool, err error) *PolicyHistoryEntry {
	changes := map[string]interface{}{
		"policy_data": policy,
		"enabled":     policy.Enabled,
		"rules_count": len(policy.Rules),
	}
	
	return phm.RecordPolicyChange("apply", policy.ID, policy.Name, policy.Type, "Policy applied", "system", source, changes, success, err)
}

// RecordPolicyRollback records a policy rollback
func (phm *PolicyHistoryManager) RecordPolicyRollback(policyID, policyName, rollbackTo string, success bool, err error) *PolicyHistoryEntry {
	changes := map[string]interface{}{
		"rollback_to": rollbackTo,
		"timestamp":   time.Now(),
	}
	
	return phm.RecordPolicyChange("rollback", policyID, policyName, "", fmt.Sprintf("Rolled back to %s", rollbackTo), "system", "rollback", changes, success, err)
}

// RecordPolicyImpact records the impact of a policy change
func (phm *PolicyHistoryManager) RecordPolicyImpact(entryID string, impact *PolicyImpact) error {
	phm.mu.Lock()
	defer phm.mu.Unlock()
	
	for i := range phm.history {
		if phm.history[i].ID == entryID {
			phm.history[i].Impact = impact
			phm.saveHistory()
			log.Printf("[history] Recorded impact for entry %s: risk=%s", entryID, impact.RiskLevel)
			return nil
		}
	}
	
	return fmt.Errorf("history entry %s not found", entryID)
}

// GetHistory returns policy history based on query
func (phm *PolicyHistoryManager) GetHistory(query *HistoryQuery) []PolicyHistoryEntry {
	phm.mu.RLock()
	defer phm.mu.RUnlock()
	
	var results []PolicyHistoryEntry
	
	for _, entry := range phm.history {
		if phm.matchesQuery(entry, query) {
			results = append(results, entry)
		}
	}
	
	// Apply limit
	if query != nil && query.Limit > 0 && len(results) > query.Limit {
		results = results[:query.Limit]
	}
	
	return results
}

// GetPolicyHistory returns history for a specific policy
func (phm *PolicyHistoryManager) GetPolicyHistory(policyID string, limit int) []PolicyHistoryEntry {
	query := &HistoryQuery{
		PolicyID: policyID,
		Limit:    limit,
	}
	return phm.GetHistory(query)
}

// GetRecentHistory returns recent policy changes
func (phm *PolicyHistoryManager) GetRecentHistory(limit int) []PolicyHistoryEntry {
	phm.mu.RLock()
	defer phm.mu.RUnlock()
	
	if limit > len(phm.history) {
		limit = len(phm.history)
	}
	
	start := len(phm.history) - limit
	results := make([]PolicyHistoryEntry, limit)
	copy(results, phm.history[start:])
	
	return results
}

// GetFailedChanges returns failed policy changes
func (phm *PolicyHistoryManager) GetFailedChanges(limit int) []PolicyHistoryEntry {
	query := &HistoryQuery{
		Success: &[]bool{false}[0], // false
		Limit:   limit,
	}
	return phm.GetHistory(query)
}

// GetChangesBySource returns changes by source
func (phm *PolicyHistoryManager) GetChangesBySource(source string, limit int) []PolicyHistoryEntry {
	query := &HistoryQuery{
		Source: source,
		Limit:  limit,
	}
	return phm.GetHistory(query)
}

// GetChangesInTimeRange returns changes within a time range
func (phm *PolicyHistoryManager) GetChangesInTimeRange(start, end time.Time) []PolicyHistoryEntry {
	query := &HistoryQuery{
		StartTime: start,
		EndTime:   end,
	}
	return phm.GetHistory(query)
}

// GetStatistics returns policy change statistics
func (phm *PolicyHistoryManager) GetStatistics() map[string]interface{} {
	phm.mu.RLock()
	defer phm.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_changes":     len(phm.history),
		"successful_changes": 0,
		"failed_changes":     0,
		"changes_by_action":  make(map[string]int),
		"changes_by_source":  make(map[string]int),
		"changes_by_type":    make(map[string]int),
		"risk_distribution":  make(map[string]int),
		"recent_activity":    0,
	}
	
	// Count recent activity (last 24 hours)
	recentThreshold := time.Now().Add(-24 * time.Hour)
	
	for _, entry := range phm.history {
		// Count successes/failures
		if entry.Success {
			stats["successful_changes"] = stats["successful_changes"].(int) + 1
		} else {
			stats["failed_changes"] = stats["failed_changes"].(int) + 1
		}
		
		// Count by action
		actionCount := stats["changes_by_action"].(map[string]int)
		actionCount[entry.Action]++
		
		// Count by source
		sourceCount := stats["changes_by_source"].(map[string]int)
		sourceCount[entry.Source]++
		
		// Count by type
		typeCount := stats["changes_by_type"].(map[string]int)
		typeCount[entry.PolicyType]++
		
		// Count risk distribution
		if entry.Impact != nil {
			riskCount := stats["risk_distribution"].(map[string]int)
			riskCount[entry.Impact.RiskLevel]++
		}
		
		// Count recent activity
		if entry.Timestamp.After(recentThreshold) {
			stats["recent_activity"] = stats["recent_activity"].(int) + 1
		}
	}
	
	return stats
}

// ExportHistory exports history to JSON
func (phm *PolicyHistoryManager) ExportHistory(query *HistoryQuery) ([]byte, error) {
	history := phm.GetHistory(query)
	return json.MarshalIndent(history, "", "  ")
}

// ImportHistory imports history from JSON
func (phm *PolicyHistoryManager) ImportHistory(data []byte) error {
	var entries []PolicyHistoryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to unmarshal history: %w", err)
	}
	
	phm.mu.Lock()
	defer phm.mu.Unlock()
	
	// Add imported entries
	phm.history = append(phm.history, entries...)
	
	// Maintain size limit
	if len(phm.history) > phm.maxEntries {
		phm.history = phm.history[len(phm.history)-phm.maxEntries:]
	}
	
	// Save to disk
	return phm.saveHistory()
}

// ClearHistory clears all history
func (phm *PolicyHistoryManager) ClearHistory() error {
	phm.mu.Lock()
	defer phm.mu.Unlock()
	
	phm.history = make([]PolicyHistoryEntry, 0)
	return phm.saveHistory()
}

// matchesQuery checks if an entry matches the query criteria
func (phm *PolicyHistoryManager) matchesQuery(entry PolicyHistoryEntry, query *HistoryQuery) bool {
	if query == nil {
		return true
	}
	
	if query.PolicyID != "" && entry.PolicyID != query.PolicyID {
		return false
	}
	
	if query.Action != "" && entry.Action != query.Action {
		return false
	}
	
	if query.Source != "" && entry.Source != query.Source {
		return false
	}
	
	if !query.StartTime.IsZero() && entry.Timestamp.Before(query.StartTime) {
		return false
	}
	
	if !query.EndTime.IsZero() && entry.Timestamp.After(query.EndTime) {
		return false
	}
	
	if query.Success != nil && entry.Success != *query.Success {
		return false
	}
	
	return true
}

// loadHistory loads policy history from disk
func (phm *PolicyHistoryManager) loadHistory() error {
	if _, err := os.Stat(phm.historyFile); os.IsNotExist(err) {
		log.Printf("[history] No history file found, starting fresh")
		return nil
	}
	
	data, err := os.ReadFile(phm.historyFile)
	if err != nil {
		return fmt.Errorf("failed to read history file: %w", err)
	}
	
	if err := json.Unmarshal(data, &phm.history); err != nil {
		return fmt.Errorf("failed to unmarshal history: %w", err)
	}
	
	log.Printf("[history] Loaded %d history entries", len(phm.history))
	return nil
}

// saveHistory saves policy history to disk
func (phm *PolicyHistoryManager) saveHistory() error {
	// Ensure directory exists
	dir := filepath.Dir(phm.historyFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create history directory: %w", err)
	}
	
	data, err := json.MarshalIndent(phm.history, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal history: %w", err)
	}
	
	if err := os.WriteFile(phm.historyFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write history file: %w", err)
	}
	
	return nil
}

// generateHistoryID generates a unique history entry ID
func generateHistoryID() string {
	return fmt.Sprintf("history_%d", time.Now().UnixNano())
}
