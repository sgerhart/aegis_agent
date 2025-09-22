package telemetry

import (
	"fmt"
	"time"
)

// Event represents a telemetry event
type Event struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Message   string                 `json:"message"`
	Timestamp int64                  `json:"timestamp"`
	Level     string                 `json:"level"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// EventType represents the type of event
type EventType string

const (
	EventTypePolicyApplied    EventType = "policy_applied"
	EventTypePolicyRemoved    EventType = "policy_removed"
	EventTypePolicyFailed     EventType = "policy_failed"
	EventTypeEnforcementStart EventType = "enforcement_start"
	EventTypeEnforcementStop  EventType = "enforcement_stop"
	EventTypeError           EventType = "error"
	EventTypeInfo            EventType = "info"
	EventTypeWarning         EventType = "warning"
)

// NewEvent creates a new telemetry event
func NewEvent(eventType EventType, message string, metadata map[string]interface{}) *Event {
	return &Event{
		ID:        generateEventID(),
		Type:      string(eventType),
		Message:   message,
		Timestamp: time.Now().Unix(),
		Level:     getEventLevel(eventType),
		Metadata:  metadata,
	}
}

// generateEventID generates a unique event ID
func generateEventID() string {
	// Simple ID generation - in production, use proper UUID
	return fmt.Sprintf("event_%d", time.Now().UnixNano())
}

// getEventLevel returns the log level for an event type
func getEventLevel(eventType EventType) string {
	switch eventType {
	case EventTypeError, EventTypePolicyFailed:
		return "error"
	case EventTypeWarning:
		return "warn"
	case EventTypeInfo, EventTypePolicyApplied, EventTypePolicyRemoved, EventTypeEnforcementStart, EventTypeEnforcementStop:
		return "info"
	default:
		return "info"
	}
}