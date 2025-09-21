package telemetry

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

// AuditLogger handles comprehensive audit logging for policy changes and security events
type AuditLogger struct {
	logFile    string
	maxEntries int
	entries    []AuditEntry
	mu         sync.RWMutex
	eventChan  chan AuditEvent
	ctx        context.Context
	cancel     context.CancelFunc
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Level       string                 `json:"level"` // INFO, WARN, ERROR, CRITICAL
	Category    string                 `json:"category"` // policy_change, security_event, map_update, system_event
	Event       string                 `json:"event"`
	User        string                 `json:"user"`
	Source      string                 `json:"source"` // artifact, api, manual, system
	PolicyID    string                 `json:"policy_id,omitempty"`
	PolicyName  string                 `json:"policy_name,omitempty"`
	Details     map[string]interface{} `json:"details"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	RiskLevel   string                 `json:"risk_level,omitempty"` // low, medium, high, critical
	Compliance  []string               `json:"compliance,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
}

// AuditEvent represents an audit event to be logged
type AuditEvent struct {
	Level       string                 `json:"level"`
	Category    string                 `json:"category"`
	Event       string                 `json:"event"`
	User        string                 `json:"user"`
	Source      string                 `json:"source"`
	PolicyID    string                 `json:"policy_id,omitempty"`
	PolicyName  string                 `json:"policy_name,omitempty"`
	Details     map[string]interface{} `json:"details"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	RiskLevel   string                 `json:"risk_level,omitempty"`
	Compliance  []string               `json:"compliance,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	Type        string                 `json:"type"` // policy_injection, unauthorized_access, rate_limit_exceeded, suspicious_activity
	Severity    string                 `json:"severity"` // low, medium, high, critical
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Details     map[string]interface{} `json:"details"`
	Mitigation  string                 `json:"mitigation,omitempty"`
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logFile string, maxEntries int) *AuditLogger {
	ctx, cancel := context.WithCancel(context.Background())
	
	al := &AuditLogger{
		logFile:    logFile,
		maxEntries: maxEntries,
		entries:    make([]AuditEntry, 0),
		eventChan:  make(chan AuditEvent, 1000), // Buffer for 1000 events
		ctx:        ctx,
		cancel:     cancel,
	}
	
	// Load existing audit log
	al.loadAuditLog()
	
	// Start background processor
	go al.processEvents()
	
	return al
}

// LogPolicyChange logs a policy change event
func (al *AuditLogger) LogPolicyChange(action, policyID, policyName, user, source string, details map[string]interface{}) {
	event := AuditEvent{
		Level:      "INFO",
		Category:   "policy_change",
		Event:      fmt.Sprintf("Policy %s: %s", action, policyName),
		User:       user,
		Source:     source,
		PolicyID:   policyID,
		PolicyName: policyName,
		Details:    details,
		RiskLevel:  al.assessRiskLevel(action, details),
		Compliance: []string{"SOX", "PCI-DSS", "HIPAA"},
		Tags:       []string{"policy", action},
	}
	
	al.logEvent(event)
}

// LogMapUpdate logs an eBPF map update event
func (al *AuditLogger) LogMapUpdate(mapName, operation, user string, details map[string]interface{}) {
	event := AuditEvent{
		Level:     "INFO",
		Category:  "map_update",
		Event:     fmt.Sprintf("Map %s %s", mapName, operation),
		User:      user,
		Source:    "system",
		Details:   details,
		RiskLevel: "medium", // Map updates are inherently risky
		Tags:      []string{"map", operation, mapName},
	}
	
	al.logEvent(event)
}

// LogSecurityEvent logs a security event
func (al *AuditLogger) LogSecurityEvent(securityEvent SecurityEvent) {
	event := AuditEvent{
		Level:      al.severityToLevel(securityEvent.Severity),
		Category:   "security_event",
		Event:      securityEvent.Description,
		User:       "system",
		Source:     securityEvent.Source,
		Details:    securityEvent.Details,
		RiskLevel:  securityEvent.Severity,
		Compliance: []string{"SOX", "PCI-DSS", "HIPAA"},
		Tags:       []string{"security", securityEvent.Type},
	}
	
	al.logEvent(event)
	
	// Log to console for immediate visibility
	log.Printf("[SECURITY] %s: %s - %s", securityEvent.Severity, securityEvent.Type, securityEvent.Description)
}

// LogSystemEvent logs a system event
func (al *AuditLogger) LogSystemEvent(eventType, description string, details map[string]interface{}) {
	event := AuditEvent{
		Level:     "INFO",
		Category:  "system_event",
		Event:     description,
		User:      "system",
		Source:    "system",
		Details:   details,
		RiskLevel: "low",
		Tags:      []string{"system", eventType},
	}
	
	al.logEvent(event)
}

// LogPolicyImpact logs policy impact analysis
func (al *AuditLogger) LogPolicyImpact(policyID, policyName string, impact map[string]interface{}) {
	event := AuditEvent{
		Level:      "INFO",
		Category:   "policy_change",
		Event:      fmt.Sprintf("Policy impact analysis: %s", policyName),
		User:       "system",
		Source:     "system",
		PolicyID:   policyID,
		PolicyName: policyName,
		Details:    impact,
		RiskLevel:  al.assessImpactRisk(impact),
		Tags:       []string{"policy", "impact", "analysis"},
	}
	
	al.logEvent(event)
}

// LogValidationFailure logs policy validation failures
func (al *AuditLogger) LogValidationFailure(policyID, policyName, reason string, details map[string]interface{}) {
	event := AuditEvent{
		Level:      "WARN",
		Category:   "security_event",
		Event:      fmt.Sprintf("Policy validation failed: %s", reason),
		User:       "system",
		Source:     "artifact",
		PolicyID:   policyID,
		PolicyName: policyName,
		Details:    details,
		RiskLevel:  "high", // Validation failures are high risk
		Tags:       []string{"validation", "failure", "security"},
	}
	
	al.logEvent(event)
}

// LogRollbackEvent logs rollback events
func (al *AuditLogger) LogRollbackEvent(action, policyID, policyName, reason string, success bool, details map[string]interface{}) {
	level := "INFO"
	if !success {
		level = "ERROR"
	}
	
	event := AuditEvent{
		Level:      level,
		Category:   "policy_change",
		Event:      fmt.Sprintf("Rollback %s: %s", action, policyName),
		User:       "system",
		Source:     "system",
		PolicyID:   policyID,
		PolicyName: policyName,
		Details:    details,
		RiskLevel:  "high", // Rollbacks are high risk operations
		Tags:       []string{"rollback", action},
	}
	
	al.logEvent(event)
}

// GetAuditEntries returns audit entries based on criteria
func (al *AuditLogger) GetAuditEntries(category, level string, limit int) []AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()
	
	var results []AuditEntry
	count := 0
	
	// Search from newest to oldest
	for i := len(al.entries) - 1; i >= 0 && count < limit; i-- {
		entry := al.entries[i]
		
		if category != "" && entry.Category != category {
			continue
		}
		
		if level != "" && entry.Level != level {
			continue
		}
		
		results = append(results, entry)
		count++
	}
	
	// Reverse to get chronological order
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}
	
	return results
}

// GetSecurityEvents returns security events
func (al *AuditLogger) GetSecurityEvents(severity string, limit int) []AuditEntry {
	return al.GetAuditEntries("security_event", al.severityToLevel(severity), limit)
}

// GetPolicyChanges returns policy change events
func (al *AuditLogger) GetPolicyChanges(policyID string, limit int) []AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()
	
	var results []AuditEntry
	count := 0
	
	for i := len(al.entries) - 1; i >= 0 && count < limit; i-- {
		entry := al.entries[i]
		
		if entry.Category == "policy_change" && (policyID == "" || entry.PolicyID == policyID) {
			results = append(results, entry)
			count++
		}
	}
	
	// Reverse to get chronological order
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}
	
	return results
}

// GetAuditStatistics returns audit log statistics
func (al *AuditLogger) GetAuditStatistics() map[string]interface{} {
	al.mu.RLock()
	defer al.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_entries":       len(al.entries),
		"entries_by_level":    make(map[string]int),
		"entries_by_category": make(map[string]int),
		"entries_by_risk":     make(map[string]int),
		"recent_activity":     0,
		"security_events":     0,
	}
	
	recentThreshold := time.Now().Add(-24 * time.Hour)
	
	for _, entry := range al.entries {
		// Count by level
		levelCount := stats["entries_by_level"].(map[string]int)
		levelCount[entry.Level]++
		
		// Count by category
		categoryCount := stats["entries_by_category"].(map[string]int)
		categoryCount[entry.Category]++
		
		// Count by risk level
		riskCount := stats["entries_by_risk"].(map[string]int)
		riskCount[entry.RiskLevel]++
		
		// Count recent activity
		if entry.Timestamp.After(recentThreshold) {
			stats["recent_activity"] = stats["recent_activity"].(int) + 1
		}
		
		// Count security events
		if entry.Category == "security_event" {
			stats["security_events"] = stats["security_events"].(int) + 1
		}
	}
	
	return stats
}

// ExportAuditLog exports audit log to JSON
func (al *AuditLogger) ExportAuditLog(category, level string, limit int) ([]byte, error) {
	entries := al.GetAuditEntries(category, level, limit)
	return json.MarshalIndent(entries, "", "  ")
}

// Close closes the audit logger
func (al *AuditLogger) Close() {
	al.cancel()
	close(al.eventChan)
}

// logEvent logs an audit event
func (al *AuditLogger) logEvent(event AuditEvent) {
	select {
	case al.eventChan <- event:
		// Event queued successfully
	default:
		// Channel is full, log to console as fallback
		log.Printf("[AUDIT] Channel full, logging to console: %s", event.Event)
	}
}

// processEvents processes audit events in the background
func (al *AuditLogger) processEvents() {
	for {
		select {
		case event := <-al.eventChan:
			al.processEvent(event)
		case <-al.ctx.Done():
			return
		}
	}
}

// processEvent processes a single audit event
func (al *AuditLogger) processEvent(event AuditEvent) {
	entry := AuditEntry{
		ID:         generateAuditID(),
		Timestamp:  time.Now(),
		Level:      event.Level,
		Category:   event.Category,
		Event:      event.Event,
		User:       event.User,
		Source:     event.Source,
		PolicyID:   event.PolicyID,
		PolicyName: event.PolicyName,
		Details:    event.Details,
		IPAddress:  event.IPAddress,
		UserAgent:  event.UserAgent,
		SessionID:  event.SessionID,
		RiskLevel:  event.RiskLevel,
		Compliance: event.Compliance,
		Tags:       event.Tags,
	}
	
	al.mu.Lock()
	defer al.mu.Unlock()
	
	// Add to entries
	al.entries = append(al.entries, entry)
	
	// Maintain size limit
	if len(al.entries) > al.maxEntries {
		al.entries = al.entries[1:]
	}
	
	// Save to disk
	al.saveAuditLog()
	
	// Log to console for immediate visibility
	log.Printf("[AUDIT] %s %s: %s", entry.Level, entry.Category, entry.Event)
}

// assessRiskLevel assesses the risk level of a policy action
func (al *AuditLogger) assessRiskLevel(action string, details map[string]interface{}) string {
	switch action {
	case "delete", "rollback":
		return "high"
	case "update", "modify":
		return "medium"
	case "create", "apply":
		return "low"
	default:
		return "medium"
	}
}

// assessImpactRisk assesses the risk level of policy impact
func (al *AuditLogger) assessImpactRisk(impact map[string]interface{}) string {
	// Check for high-risk indicators
	if affected, ok := impact["affected_processes"]; ok {
		if processes, ok := affected.([]interface{}); ok && len(processes) > 10 {
			return "high"
		}
	}
	
	if services, ok := impact["affected_services"]; ok {
		if svcs, ok := services.([]interface{}); ok && len(svcs) > 5 {
			return "high"
		}
	}
	
	return "medium"
}

// severityToLevel converts security severity to audit level
func (al *AuditLogger) severityToLevel(severity string) string {
	switch severity {
	case "critical":
		return "ERROR"
	case "high":
		return "ERROR"
	case "medium":
		return "WARN"
	case "low":
		return "INFO"
	default:
		return "INFO"
	}
}

// loadAuditLog loads audit log from disk
func (al *AuditLogger) loadAuditLog() error {
	if _, err := os.Stat(al.logFile); os.IsNotExist(err) {
		log.Printf("[audit] No audit log file found, starting fresh")
		return nil
	}
	
	data, err := os.ReadFile(al.logFile)
	if err != nil {
		return fmt.Errorf("failed to read audit log file: %w", err)
	}
	
	if err := json.Unmarshal(data, &al.entries); err != nil {
		return fmt.Errorf("failed to unmarshal audit log: %w", err)
	}
	
	log.Printf("[audit] Loaded %d audit entries", len(al.entries))
	return nil
}

// saveAuditLog saves audit log to disk
func (al *AuditLogger) saveAuditLog() error {
	// Ensure directory exists
	dir := filepath.Dir(al.logFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create audit log directory: %w", err)
	}
	
	data, err := json.MarshalIndent(al.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal audit log: %w", err)
	}
	
	if err := os.WriteFile(al.logFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write audit log file: %w", err)
	}
	
	return nil
}

// generateAuditID generates a unique audit entry ID
func generateAuditID() string {
	return fmt.Sprintf("audit_%d", time.Now().UnixNano())
}
