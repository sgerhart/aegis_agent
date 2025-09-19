package telemetry

import (
	"encoding/json"
	"time"
)

// EventType represents the type of telemetry event
type EventType string

const (
	EventTypeVerifyOK       EventType = "verify_ok"
	EventTypeVerifyFailed   EventType = "verify_failed"
	EventTypeEnforceOK      EventType = "enforce_ok"
	EventTypeEnforceFailed  EventType = "enforce_failed"
	EventTypeRollbackOK     EventType = "rollback_ok"
	EventTypeRollbackFailed EventType = "rollback_failed"
	EventTypeCounter        EventType = "counter"
	EventTypeAssignment     EventType = "assignment"
	EventTypeError          EventType = "error"
	EventTypeWarning        EventType = "warning"
)

// Event represents a structured telemetry event
type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	HostID    string                 `json:"host_id"`
	AgentID   string                 `json:"agent_id,omitempty"`
	Message   string                 `json:"message,omitempty"`
	Data      map[string]any         `json:"data,omitempty"`
	Metadata  map[string]any         `json:"metadata,omitempty"`
}

// VerifyEvent represents a verification event
type VerifyEvent struct {
	Event
	BundleID     string `json:"bundle_id"`
	KeyID        string `json:"key_id,omitempty"`
	Algorithm    string `json:"algorithm,omitempty"`
	Duration     int64  `json:"duration_ms"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// EnforceEvent represents an enforcement event
type EnforceEvent struct {
	Event
	AssignmentID string   `json:"assignment_id"`
	PolicyID     string   `json:"policy_id"`
	DryRun       bool     `json:"dry_run"`
	Changes      []string `json:"changes,omitempty"`
	Duration     int64    `json:"duration_ms"`
	ErrorMessage string   `json:"error_message,omitempty"`
}

// RollbackEvent represents a rollback event
type RollbackEvent struct {
	Event
	RollbackID   string   `json:"rollback_id"`
	AssignmentID string   `json:"assignment_id,omitempty"`
	Reason       string   `json:"reason"`
	Changes      []string `json:"changes,omitempty"`
	Duration     int64    `json:"duration_ms"`
	ErrorMessage string   `json:"error_message,omitempty"`
}

// CounterEvent represents a counter/metric event
type CounterEvent struct {
	Event
	MetricName string  `json:"metric_name"`
	Value      float64 `json:"value"`
	Unit       string  `json:"unit,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// AssignmentEvent represents an assignment-related event
type AssignmentEvent struct {
	Event
	AssignmentID string `json:"assignment_id"`
	Action      string `json:"action"` // "received", "applied", "expired", "failed"
	PolicyID    string `json:"policy_id"`
	Version     string `json:"version"`
	TTL         int64  `json:"ttl_seconds,omitempty"`
}

// EventEmitter handles telemetry event emission
type EventEmitter struct {
	hostID  string
	agentID string
	events  chan Event
}

// NewEventEmitter creates a new event emitter
func NewEventEmitter(hostID, agentID string) *EventEmitter {
	return &EventEmitter{
		hostID:  hostID,
		agentID: agentID,
		events:  make(chan Event, 1000), // Buffered channel
	}
}

// EmitVerifyOK emits a successful verification event
func (ee *EventEmitter) EmitVerifyOK(bundleID, keyID, algorithm string, duration time.Duration) {
	event := VerifyEvent{
		Event: Event{
			ID:        generateEventID(),
			Type:      EventTypeVerifyOK,
			Timestamp: time.Now(),
			HostID:    ee.hostID,
			AgentID:   ee.agentID,
			Message:   "Bundle verification successful",
		},
		BundleID:  bundleID,
		KeyID:     keyID,
		Algorithm: algorithm,
		Duration:  duration.Milliseconds(),
	}
	
	select {
	case ee.events <- event.Event:
	default:
		// Channel full, drop event
	}
}

// EmitVerifyFailed emits a failed verification event
func (ee *EventEmitter) EmitVerifyFailed(bundleID, errorMessage string, duration time.Duration) {
	event := VerifyEvent{
		Event: Event{
			ID:        generateEventID(),
			Type:      EventTypeVerifyFailed,
			Timestamp: time.Now(),
			HostID:    ee.hostID,
			AgentID:   ee.agentID,
			Message:   "Bundle verification failed",
		},
		BundleID:     bundleID,
		Duration:     duration.Milliseconds(),
		ErrorMessage: errorMessage,
	}
	
	select {
	case ee.events <- event.Event:
	default:
		// Channel full, drop event
	}
}

// EmitEnforceOK emits a successful enforcement event
func (ee *EventEmitter) EmitEnforceOK(assignmentID, policyID string, dryRun bool, changes []string, duration time.Duration) {
	event := EnforceEvent{
		Event: Event{
			ID:        generateEventID(),
			Type:      EventTypeEnforceOK,
			Timestamp: time.Now(),
			HostID:    ee.hostID,
			AgentID:   ee.agentID,
			Message:   "Policy enforcement successful",
		},
		AssignmentID: assignmentID,
		PolicyID:     policyID,
		DryRun:       dryRun,
		Changes:      changes,
		Duration:     duration.Milliseconds(),
	}
	
	select {
	case ee.events <- event.Event:
	default:
		// Channel full, drop event
	}
}

// EmitEnforceFailed emits a failed enforcement event
func (ee *EventEmitter) EmitEnforceFailed(assignmentID, policyID string, dryRun bool, errorMessage string, duration time.Duration) {
	event := EnforceEvent{
		Event: Event{
			ID:        generateEventID(),
			Type:      EventTypeEnforceFailed,
			Timestamp: time.Now(),
			HostID:    ee.hostID,
			AgentID:   ee.agentID,
			Message:   "Policy enforcement failed",
		},
		AssignmentID: assignmentID,
		PolicyID:     policyID,
		DryRun:       dryRun,
		Duration:     duration.Milliseconds(),
		ErrorMessage: errorMessage,
	}
	
	select {
	case ee.events <- event.Event:
	default:
		// Channel full, drop event
	}
}

// EmitRollbackOK emits a successful rollback event
func (ee *EventEmitter) EmitRollbackOK(rollbackID, assignmentID, reason string, changes []string, duration time.Duration) {
	event := RollbackEvent{
		Event: Event{
			ID:        generateEventID(),
			Type:      EventTypeRollbackOK,
			Timestamp: time.Now(),
			HostID:    ee.hostID,
			AgentID:   ee.agentID,
			Message:   "Rollback successful",
		},
		RollbackID:   rollbackID,
		AssignmentID: assignmentID,
		Reason:       reason,
		Changes:      changes,
		Duration:     duration.Milliseconds(),
	}
	
	select {
	case ee.events <- event.Event:
	default:
		// Channel full, drop event
	}
}

// EmitRollbackFailed emits a failed rollback event
func (ee *EventEmitter) EmitRollbackFailed(rollbackID, assignmentID, reason, errorMessage string, duration time.Duration) {
	event := RollbackEvent{
		Event: Event{
			ID:        generateEventID(),
			Type:      EventTypeRollbackFailed,
			Timestamp: time.Now(),
			HostID:    ee.hostID,
			AgentID:   ee.agentID,
			Message:   "Rollback failed",
		},
		RollbackID:   rollbackID,
		AssignmentID: assignmentID,
		Reason:       reason,
		Duration:     duration.Milliseconds(),
		ErrorMessage: errorMessage,
	}
	
	select {
	case ee.events <- event.Event:
	default:
		// Channel full, drop event
	}
}

// EmitCounter emits a counter/metric event
func (ee *EventEmitter) EmitCounter(metricName string, value float64, unit string, tags map[string]string) {
	event := CounterEvent{
		Event: Event{
			ID:        generateEventID(),
			Type:      EventTypeCounter,
			Timestamp: time.Now(),
			HostID:    ee.hostID,
			AgentID:   ee.agentID,
		},
		MetricName: metricName,
		Value:      value,
		Unit:       unit,
		Tags:       tags,
	}
	
	select {
	case ee.events <- event.Event:
	default:
		// Channel full, drop event
	}
}

// EmitAssignment emits an assignment-related event
func (ee *EventEmitter) EmitAssignment(assignmentID, action, policyID, version string, ttl int64) {
	event := AssignmentEvent{
		Event: Event{
			ID:        generateEventID(),
			Type:      EventTypeAssignment,
			Timestamp: time.Now(),
			HostID:    ee.hostID,
			AgentID:   ee.agentID,
		},
		AssignmentID: assignmentID,
		Action:      action,
		PolicyID:    policyID,
		Version:     version,
		TTL:         ttl,
	}
	
	select {
	case ee.events <- event.Event:
	default:
		// Channel full, drop event
	}
}

// EmitError emits an error event
func (ee *EventEmitter) EmitError(message string, data map[string]any) {
	event := Event{
		ID:        generateEventID(),
		Type:      EventTypeError,
		Timestamp: time.Now(),
		HostID:    ee.hostID,
		AgentID:   ee.agentID,
		Message:   message,
		Data:      data,
	}
	
	select {
	case ee.events <- event:
	default:
		// Channel full, drop event
	}
}

// EmitWarning emits a warning event
func (ee *EventEmitter) EmitWarning(message string, data map[string]any) {
	event := Event{
		ID:        generateEventID(),
		Type:      EventTypeWarning,
		Timestamp: time.Now(),
		HostID:    ee.hostID,
		AgentID:   ee.agentID,
		Message:   message,
		Data:      data,
	}
	
	select {
	case ee.events <- event:
	default:
		// Channel full, drop event
	}
}

// GetEvents returns the event channel
func (ee *EventEmitter) GetEvents() <-chan Event {
	return ee.events
}

// Close closes the event emitter
func (ee *EventEmitter) Close() {
	close(ee.events)
}

// ToJSON converts an event to JSON
func (e *Event) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
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
