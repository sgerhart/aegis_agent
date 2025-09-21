package telemetry

import (
	"encoding/json"
	"log"
	"time"
)

// ConsoleEmitter is a simple implementation that logs events to the console
type ConsoleEmitter struct {
	HostID  string
	AgentID string
}

// NewConsoleEmitter creates a new ConsoleEmitter
func NewConsoleEmitter(hostID string) *ConsoleEmitter {
	return &ConsoleEmitter{
		HostID:  hostID,
		AgentID: "agent-unknown",
	}
}

// Emit logs the event to the console in JSON format
func (e *ConsoleEmitter) Emit(event Event) {
	event.Timestamp = time.Now().UTC()
	event.HostID = e.HostID
	event.AgentID = e.AgentID
	
	b, err := json.Marshal(event)
	if err != nil {
		log.Printf("[telemetry] failed to marshal event: %v", err)
		return
	}
	
	log.Printf("[telemetry] %s", string(b))
}

// EmitVerifyOK emits a verification success event
func (e *ConsoleEmitter) EmitVerifyOK(bundleID, keyID, algorithm string, duration time.Duration) {
	event := Event{
		Type: EventTypeVerifyOK,
		Data: map[string]any{
			"bundle_id":  bundleID,
			"key_id":     keyID,
			"algorithm":  algorithm,
			"duration_ms": duration.Milliseconds(),
		},
		Message: "Bundle verification successful",
	}
	e.Emit(event)
}

// EmitVerifyFailed emits a verification failure event
func (e *ConsoleEmitter) EmitVerifyFailed(bundleID, errorMessage string, duration time.Duration) {
	event := Event{
		Type: EventTypeVerifyFailed,
		Data: map[string]any{
			"bundle_id":     bundleID,
			"error_message": errorMessage,
			"duration_ms":   duration.Milliseconds(),
		},
		Message: "Bundle verification failed",
	}
	e.Emit(event)
}

// EmitEnforceOK emits an enforcement success event
func (e *ConsoleEmitter) EmitEnforceOK(assignmentID, policyID string, dryRun bool, changes []string, duration time.Duration) {
	event := Event{
		Type: EventTypeEnforceOK,
		Data: map[string]any{
			"assignment_id": assignmentID,
			"policy_id":     policyID,
			"dry_run":       dryRun,
			"changes":       changes,
			"duration_ms":   duration.Milliseconds(),
		},
		Message: "Policy enforcement successful",
	}
	e.Emit(event)
}

// EmitEnforceFailed emits an enforcement failure event
func (e *ConsoleEmitter) EmitEnforceFailed(assignmentID, policyID string, dryRun bool, errorMessage string, duration time.Duration) {
	event := Event{
		Type: EventTypeEnforceFailed,
		Data: map[string]any{
			"assignment_id": assignmentID,
			"policy_id":     policyID,
			"dry_run":       dryRun,
			"error_message": errorMessage,
			"duration_ms":   duration.Milliseconds(),
		},
		Message: "Policy enforcement failed",
	}
	e.Emit(event)
}

// EmitRollbackOK emits a rollback success event
func (e *ConsoleEmitter) EmitRollbackOK(rollbackID, assignmentID, reason string, changes []string, duration time.Duration) {
	event := Event{
		Type: EventTypeRollbackOK,
		Data: map[string]any{
			"rollback_id":   rollbackID,
			"assignment_id": assignmentID,
			"reason":        reason,
			"changes":       changes,
			"duration_ms":   duration.Milliseconds(),
		},
		Message: "Rollback successful",
	}
	e.Emit(event)
}

// EmitRollbackFailed emits a rollback failure event
func (e *ConsoleEmitter) EmitRollbackFailed(rollbackID, assignmentID, reason, errorMessage string, duration time.Duration) {
	event := Event{
		Type: EventTypeRollbackFailed,
		Data: map[string]any{
			"rollback_id":   rollbackID,
			"assignment_id": assignmentID,
			"reason":        reason,
			"error_message": errorMessage,
			"duration_ms":   duration.Milliseconds(),
		},
		Message: "Rollback failed",
	}
	e.Emit(event)
}

// EmitCounter emits a counter event
func (e *ConsoleEmitter) EmitCounter(metricName string, value float64, unit string, tags map[string]string) {
	event := Event{
		Type: EventTypeCounter,
		Data: map[string]any{
			"metric_name": metricName,
			"value":       value,
			"unit":        unit,
			"tags":        tags,
		},
		Message: "Counter event",
	}
	e.Emit(event)
}

// EmitAssignment emits an assignment event
func (e *ConsoleEmitter) EmitAssignment(assignmentID, action, policyID, version string, ttl int64) {
	event := Event{
		Type: EventTypeAssignment,
		Data: map[string]any{
			"assignment_id": assignmentID,
			"action":        action,
			"policy_id":     policyID,
			"version":       version,
			"ttl_seconds":   ttl,
		},
		Message: "Assignment event",
	}
	e.Emit(event)
}

// EmitError emits an error event
func (e *ConsoleEmitter) EmitError(message string, data map[string]any) {
	event := Event{
		Type:    EventTypeError,
		Data:    data,
		Message: message,
	}
	e.Emit(event)
}

// EmitWarning emits a warning event
func (e *ConsoleEmitter) EmitWarning(message string, data map[string]any) {
	event := Event{
		Type:    EventTypeWarning,
		Data:    data,
		Message: message,
	}
	e.Emit(event)
}

// EmitBackendComm emits a backend communication event (compatibility with EventEmitter)
func (e *ConsoleEmitter) EmitBackendComm(endpoint, method, action string, statusCode int, duration time.Duration, dataSize int64, errorMsg string) {
	event := Event{
		Type: EventTypeBackendComm,
		Data: map[string]any{
			"endpoint":      endpoint,
			"method":        method,
			"action":        action,
			"status_code":   statusCode,
			"duration_ms":   duration.Milliseconds(),
			"data_size":     dataSize,
			"error_message": errorMsg,
		},
		Message: "Backend communication: " + action,
	}
	e.Emit(event)
}

