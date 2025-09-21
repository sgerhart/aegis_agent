package telemetry

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// EventType represents the type of telemetry event
type EventType string

const (
	EventTypePolicyChange  EventType = "policy_change"
	EventTypeMapUpdate     EventType = "map_update"
	EventTypeSecurityEvent EventType = "security_event"
)

// EventSeverity represents the severity of an event
type EventSeverity string

const (
	SeverityInfo     EventSeverity = "info"
	SeverityWarning  EventSeverity = "warning"
	SeverityError    EventSeverity = "error"
	SeverityCritical EventSeverity = "critical"
)

// TelemetryEvent represents a structured telemetry event
type TelemetryEvent struct {
	ID          string                 `json:"id"`
	Type        EventType              `json:"type"`
	Severity    EventSeverity          `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	HostID      string                 `json:"host_id"`
	AgentUID    string                 `json:"agent_uid"`
	Event       string                 `json:"event"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	User        string                 `json:"user"`
	PolicyID    string                 `json:"policy_id,omitempty"`
	PolicyName  string                 `json:"policy_name,omitempty"`
	Details     map[string]interface{} `json:"details"`
	Tags        []string               `json:"tags,omitempty"`
}

// EventEmitter interface for emitting telemetry events
type EventEmitter interface {
	EmitCustomEvent(eventType EventType, severity EventSeverity, event string, details map[string]interface{})
}

// ConsoleEventEmitter emits events to console/log
type ConsoleEventEmitter struct {
	hostID   string
	agentUID string
}

// NewConsoleEventEmitter creates a new console event emitter
func NewConsoleEventEmitter(hostID, agentUID string) *ConsoleEventEmitter {
	return &ConsoleEventEmitter{
		hostID:   hostID,
		agentUID: agentUID,
	}
}

// EmitCustomEvent emits a custom telemetry event
func (cee *ConsoleEventEmitter) EmitCustomEvent(eventType EventType, severity EventSeverity, event string, details map[string]interface{}) {
	telemetryEvent := TelemetryEvent{
		ID:          generateEventID(),
		Type:        eventType,
		Severity:    severity,
		Timestamp:   time.Now(),
		HostID:      cee.hostID,
		AgentUID:    cee.agentUID,
		Event:       event,
		Description: event,
		Source:      "custom",
		User:        "system",
		Details:     details,
		Tags:        []string{"custom", string(eventType)},
	}
	
	cee.logEvent(telemetryEvent)
}

// logEvent logs a telemetry event
func (cee *ConsoleEventEmitter) logEvent(event TelemetryEvent) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		log.Printf("[TELEMETRY] Failed to marshal event: %v", err)
		return
	}
	
	switch event.Severity {
	case SeverityCritical:
		log.Printf("[TELEMETRY-CRITICAL] %s", string(eventJSON))
	case SeverityError:
		log.Printf("[TELEMETRY-ERROR] %s", string(eventJSON))
	case SeverityWarning:
		log.Printf("[TELEMETRY-WARN] %s", string(eventJSON))
	default:
		log.Printf("[TELEMETRY-INFO] %s", string(eventJSON))
	}
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}