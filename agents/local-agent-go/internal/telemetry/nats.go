package telemetry

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

type Telemetry struct {
	nc     *nats.Conn
	hostID string
}

// EventType represents the type of telemetry event
type EventType string

const (
	EventLoaded     EventType = "loaded"
	EventUnloaded   EventType = "unloaded"
	EventError      EventType = "error"
	EventRolledBack EventType = "rolled_back"
)

// TelemetryEvent represents a telemetry event
type TelemetryEvent struct {
	HostID       string    `json:"host_id"`
	ArtifactID   string    `json:"artifact_id"`
	Status       EventType `json:"status"`
	Drops        int       `json:"drops"`
	Errors       int       `json:"errors"`
	CPUPct       float64   `json:"cpu_pct"`
	VerifierMsg  *string   `json:"verifier_msg,omitempty"`
	ErrorMessage *string   `json:"error_message,omitempty"`
	Timestamp    string    `json:"ts"`
}

func New(natsURL, hostID string) *Telemetry {
	nc, _ := nats.Connect(natsURL)
	return &Telemetry{nc: nc, hostID: hostID}
}

// EmitLoaded emits a loaded event
func (t *Telemetry) EmitLoaded(artifactID string) error {
	return t.emitEvent(TelemetryEvent{
		HostID:     t.hostID,
		ArtifactID: artifactID,
		Status:     EventLoaded,
		Drops:      0,
		Errors:     0,
		CPUPct:     0.0,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	})
}

// EmitUnloaded emits an unloaded event
func (t *Telemetry) EmitUnloaded(artifactID string) error {
	return t.emitEvent(TelemetryEvent{
		HostID:     t.hostID,
		ArtifactID: artifactID,
		Status:     EventUnloaded,
		Drops:      0,
		Errors:     0,
		CPUPct:     0.0,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	})
}

// EmitError emits an error event
func (t *Telemetry) EmitError(artifactID string, errorMsg string) error {
	return t.emitEvent(TelemetryEvent{
		HostID:       t.hostID,
		ArtifactID:   artifactID,
		Status:       EventError,
		Drops:        0,
		Errors:       1,
		CPUPct:       0.0,
		ErrorMessage: &errorMsg,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	})
}

// EmitRolledBack emits a rolled back event
func (t *Telemetry) EmitRolledBack(artifactID string, reason string) error {
	return t.emitEvent(TelemetryEvent{
		HostID:       t.hostID,
		ArtifactID:   artifactID,
		Status:       EventRolledBack,
		Drops:        0,
		Errors:       0,
		CPUPct:       0.0,
		ErrorMessage: &reason,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	})
}

// EmitMetrics emits metrics for a loaded artifact
func (t *Telemetry) EmitMetrics(artifactID string, drops, errors int, cpuPct float64) error {
	return t.emitEvent(TelemetryEvent{
		HostID:     t.hostID,
		ArtifactID: artifactID,
		Status:     EventLoaded,
		Drops:      drops,
		Errors:     errors,
		CPUPct:     cpuPct,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	})
}

// emitEvent sends a telemetry event to NATS
func (t *Telemetry) emitEvent(event TelemetryEvent) error {
	if t.nc == nil {
		return fmt.Errorf("nats not connected")
	}
	
	b, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	
	return t.nc.Publish("agent.telemetry", b)
}

// Close closes the NATS connection
func (t *Telemetry) Close() error {
	if t.nc != nil {
		t.nc.Close()
	}
	return nil
}
