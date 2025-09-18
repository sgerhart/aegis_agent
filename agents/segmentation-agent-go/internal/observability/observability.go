package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

// Observability handles metrics collection and publishing
type Observability struct {
	nc     *nats.Conn
	hostID string
}

// MetricType represents the type of metric
type MetricType string

const (
	MetricCounter MetricType = "counter"
	MetricGauge   MetricType = "gauge"
	MetricHistogram MetricType = "histogram"
	MetricSummary  MetricType = "summary"
)

// Metric represents a single metric
type Metric struct {
	Name        string                 `json:"name"`
	Type        MetricType             `json:"type"`
	Value       float64                `json:"value"`
	Labels      map[string]string      `json:"labels"`
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PolicyUpdateEvent represents a policy update event
type PolicyUpdateEvent struct {
	HostID      string                 `json:"host_id"`
	PolicyID    string                 `json:"policy_id"`
	Action      string                 `json:"action"` // created, updated, deleted, enabled, disabled
	PolicyType  string                 `json:"policy_type"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SegmentationEvent represents a segmentation event
type SegmentationEvent struct {
	HostID      string                 `json:"host_id"`
	EventType   string                 `json:"event_type"` // packet_dropped, packet_allowed, connection_blocked, etc.
	PolicyID    string                 `json:"policy_id"`
	SourceIP    string                 `json:"source_ip"`
	DestIP      string                 `json:"dest_ip"`
	SourcePort  int                    `json:"source_port"`
	DestPort    int                    `json:"dest_port"`
	Protocol    string                 `json:"protocol"`
	Interface   string                 `json:"interface"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SystemEvent represents a system-level event
type SystemEvent struct {
	HostID      string                 `json:"host_id"`
	EventType   string                 `json:"event_type"` // program_loaded, program_unloaded, map_updated, etc.
	Component   string                 `json:"component"`
	Message     string                 `json:"message"`
	Level       string                 `json:"level"` // info, warn, error, debug
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// New creates a new observability instance
func New(natsURL, hostID string) *Observability {
	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Printf("Failed to connect to NATS: %v", err)
		return &Observability{hostID: hostID}
	}
	
	return &Observability{
		nc:     nc,
		hostID: hostID,
	}
}

// PublishMetrics publishes metrics to NATS
func (o *Observability) PublishMetrics(metrics map[string]interface{}) error {
	if o.nc == nil {
		return fmt.Errorf("NATS not connected")
	}
	
	// Convert metrics to Metric objects
	var metricList []Metric
	for name, value := range metrics {
		metric := Metric{
			Name:      name,
			Type:      MetricCounter,
			Value:     convertToFloat64(value),
			Labels:    map[string]string{"host_id": o.hostID},
			Timestamp: time.Now(),
		}
		metricList = append(metricList, metric)
	}
	
	// Publish metrics
	data, err := json.Marshal(metricList)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}
	
	subject := fmt.Sprintf("segmentation.metrics.%s", o.hostID)
	return o.nc.Publish(subject, data)
}

// PublishPolicyUpdate publishes a policy update event
func (o *Observability) PublishPolicyUpdate(policies []interface{}) error {
	if o.nc == nil {
		return fmt.Errorf("NATS not connected")
	}
	
	// Create policy update events
	var events []PolicyUpdateEvent
	for _, policy := range policies {
		// Convert policy to PolicyUpdateEvent
		event := PolicyUpdateEvent{
			HostID:     o.hostID,
			Action:     "updated",
			Timestamp:  time.Now(),
			Metadata:   make(map[string]interface{}),
		}
		events = append(events, event)
	}
	
	// Publish events
	data, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("failed to marshal policy update events: %w", err)
	}
	
	subject := fmt.Sprintf("segmentation.policy_updates.%s", o.hostID)
	return o.nc.Publish(subject, data)
}

// PublishSegmentationEvent publishes a segmentation event
func (o *Observability) PublishSegmentationEvent(event SegmentationEvent) error {
	if o.nc == nil {
		return fmt.Errorf("NATS not connected")
	}
	
	event.HostID = o.hostID
	event.Timestamp = time.Now()
	
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal segmentation event: %w", err)
	}
	
	subject := fmt.Sprintf("segmentation.events.%s", o.hostID)
	return o.nc.Publish(subject, data)
}

// PublishSystemEvent publishes a system event
func (o *Observability) PublishSystemEvent(event SystemEvent) error {
	if o.nc == nil {
		return fmt.Errorf("NATS not connected")
	}
	
	event.HostID = o.hostID
	event.Timestamp = time.Now()
	
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal system event: %w", err)
	}
	
	subject := fmt.Sprintf("segmentation.system.%s", o.hostID)
	return o.nc.Publish(subject, data)
}

// PublishCounter publishes a counter metric
func (o *Observability) PublishCounter(name string, value float64, labels map[string]string) error {
	metric := Metric{
		Name:      name,
		Type:      MetricCounter,
		Value:     value,
		Labels:    labels,
		Timestamp: time.Now(),
	}
	
	return o.publishMetric(metric)
}

// PublishGauge publishes a gauge metric
func (o *Observability) PublishGauge(name string, value float64, labels map[string]string) error {
	metric := Metric{
		Name:      name,
		Type:      MetricGauge,
		Value:     value,
		Labels:    labels,
		Timestamp: time.Now(),
	}
	
	return o.publishMetric(metric)
}

// PublishHistogram publishes a histogram metric
func (o *Observability) PublishHistogram(name string, value float64, labels map[string]string) error {
	metric := Metric{
		Name:      name,
		Type:      MetricHistogram,
		Value:     value,
		Labels:    labels,
		Timestamp: time.Now(),
	}
	
	return o.publishMetric(metric)
}

// publishMetric publishes a single metric
func (o *Observability) publishMetric(metric Metric) error {
	if o.nc == nil {
		return fmt.Errorf("NATS not connected")
	}
	
	// Add host_id label if not present
	if metric.Labels == nil {
		metric.Labels = make(map[string]string)
	}
	metric.Labels["host_id"] = o.hostID
	
	data, err := json.Marshal(metric)
	if err != nil {
		return fmt.Errorf("failed to marshal metric: %w", err)
	}
	
	subject := fmt.Sprintf("segmentation.metrics.%s.%s", o.hostID, metric.Name)
	return o.nc.Publish(subject, data)
}

// PublishPacketDrop publishes a packet drop event
func (o *Observability) PublishPacketDrop(policyID, sourceIP, destIP string, sourcePort, destPort int, protocol, iface string) error {
	event := SegmentationEvent{
		EventType:  "packet_dropped",
		PolicyID:   policyID,
		SourceIP:   sourceIP,
		DestIP:     destIP,
		SourcePort: sourcePort,
		DestPort:   destPort,
		Protocol:   protocol,
		Interface:  iface,
	}
	
	return o.PublishSegmentationEvent(event)
}

// PublishPacketAllow publishes a packet allow event
func (o *Observability) PublishPacketAllow(policyID, sourceIP, destIP string, sourcePort, destPort int, protocol, iface string) error {
	event := SegmentationEvent{
		EventType:  "packet_allowed",
		PolicyID:   policyID,
		SourceIP:   sourceIP,
		DestIP:     destIP,
		SourcePort: sourcePort,
		DestPort:   destPort,
		Protocol:   protocol,
		Interface:  iface,
	}
	
	return o.PublishSegmentationEvent(event)
}

// PublishConnectionBlock publishes a connection block event
func (o *Observability) PublishConnectionBlock(policyID, sourceIP, destIP string, sourcePort, destPort int, protocol string) error {
	event := SegmentationEvent{
		EventType:  "connection_blocked",
		PolicyID:   policyID,
		SourceIP:   sourceIP,
		DestIP:     destIP,
		SourcePort: sourcePort,
		DestPort:   destPort,
		Protocol:   protocol,
	}
	
	return o.PublishSegmentationEvent(event)
}

// PublishProgramLoad publishes a program load event
func (o *Observability) PublishProgramLoad(programName, programType string) error {
	event := SystemEvent{
		EventType: "program_loaded",
		Component: "ebpf_loader",
		Message:   fmt.Sprintf("Program %s (%s) loaded successfully", programName, programType),
		Level:     "info",
		Metadata: map[string]interface{}{
			"program_name": programName,
			"program_type": programType,
		},
	}
	
	return o.PublishSystemEvent(event)
}

// PublishProgramUnload publishes a program unload event
func (o *Observability) PublishProgramUnload(programName, programType string) error {
	event := SystemEvent{
		EventType: "program_unloaded",
		Component: "ebpf_loader",
		Message:   fmt.Sprintf("Program %s (%s) unloaded", programName, programType),
		Level:     "info",
		Metadata: map[string]interface{}{
			"program_name": programName,
			"program_type": programType,
		},
	}
	
	return o.PublishSystemEvent(event)
}

// PublishMapUpdate publishes a map update event
func (o *Observability) PublishMapUpdate(mapName, mapType string, keyCount int) error {
	event := SystemEvent{
		EventType: "map_updated",
		Component: "ebpf_loader",
		Message:   fmt.Sprintf("Map %s (%s) updated with %d entries", mapName, mapType, keyCount),
		Level:     "info",
		Metadata: map[string]interface{}{
			"map_name":   mapName,
			"map_type":   mapType,
			"key_count":  keyCount,
		},
	}
	
	return o.PublishSystemEvent(event)
}

// PublishError publishes an error event
func (o *Observability) PublishError(component, message string, err error) error {
	event := SystemEvent{
		EventType: "error",
		Component: component,
		Message:   message,
		Level:     "error",
		Metadata: map[string]interface{}{
			"error": err.Error(),
		},
	}
	
	return o.PublishSystemEvent(event)
}

// PublishWarning publishes a warning event
func (o *Observability) PublishWarning(component, message string) error {
	event := SystemEvent{
		EventType: "warning",
		Component: component,
		Message:   message,
		Level:     "warn",
	}
	
	return o.PublishSystemEvent(event)
}

// PublishInfo publishes an info event
func (o *Observability) PublishInfo(component, message string) error {
	event := SystemEvent{
		EventType: "info",
		Component: component,
		Message:   message,
		Level:     "info",
	}
	
	return o.PublishSystemEvent(event)
}

// Close closes the NATS connection
func (o *Observability) Close() error {
	if o.nc != nil {
		o.nc.Close()
	}
	return nil
}

// convertToFloat64 converts various types to float64
func convertToFloat64(value interface{}) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	default:
		return 0.0
	}
}
