package modules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// TelemetryModule provides enhanced telemetry capabilities
type TelemetryModule struct {
	*BaseModule
	collectors    map[string]interface{}
	metricsBuffer []telemetry.Event
	bufferSize    int
	flushInterval time.Duration
	mu            sync.RWMutex
}

// NewTelemetryModule creates a new telemetry module
func NewTelemetryModule(logger *telemetry.Logger) *TelemetryModule {
	info := ModuleInfo{
		ID:          "telemetry",
		Name:        "Enhanced Telemetry Module",
		Version:     "1.0.0",
		Description: "Provides enhanced telemetry and metrics collection",
		Author:      "Aegis Team",
		License:     "MIT",
		Capabilities: []string{
			"metrics_collection",
			"event_buffering",
			"performance_monitoring",
			"system_telemetry",
		},
		Metadata: map[string]interface{}{
			"category": "observability",
			"priority": "high",
		},
	}

	tm := &TelemetryModule{
		BaseModule:    NewBaseModule(info, logger),
		collectors:    make(map[string]interface{}),
		metricsBuffer: make([]telemetry.Event, 0),
		bufferSize:    1000,
		flushInterval: 30 * time.Second,
	}

	// Register factory function
	telemetryFactory := func(config ModuleConfig) (ModuleInterface, error) {
		return tm, nil
	}

	// This would typically be registered with a global factory
	_ = telemetryFactory

	return tm
}

// Initialize initializes the telemetry module
func (tm *TelemetryModule) Initialize(ctx context.Context, config ModuleConfig) error {
	if err := tm.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	// Configure buffer size from settings
	if bufferSize, ok := config.Settings["buffer_size"].(float64); ok {
		tm.bufferSize = int(bufferSize)
	}

	// Configure flush interval from settings
	if flushInterval, ok := config.Settings["flush_interval"].(string); ok {
		if duration, err := time.ParseDuration(flushInterval); err == nil {
			tm.flushInterval = duration
		}
	}

	tm.LogInfo("Telemetry module initialized with buffer size %d and flush interval %v", 
		tm.bufferSize, tm.flushInterval)

	return nil
}

// Start starts the telemetry module
func (tm *TelemetryModule) Start(ctx context.Context) error {
	if err := tm.BaseModule.Start(ctx); err != nil {
		return err
	}

	// Start background goroutines
	go tm.flushMetrics()
	go tm.collectSystemMetrics()

	tm.LogInfo("Telemetry module started")
	return nil
}

// Stop stops the telemetry module
func (tm *TelemetryModule) Stop(ctx context.Context) error {
	// Flush remaining metrics
	tm.flushMetricsBuffer()

	return tm.BaseModule.Stop(ctx)
}

// HandleMessage handles telemetry-related messages
func (tm *TelemetryModule) HandleMessage(message interface{}) (interface{}, error) {
	switch msg := message.(type) {
	case map[string]interface{}:
		switch msg["type"] {
		case "collect_metric":
			return tm.handleCollectMetric(msg)
		case "get_metrics":
			return tm.handleGetMetrics(msg)
		case "flush_metrics":
			return tm.handleFlushMetrics(msg)
		default:
			return tm.BaseModule.HandleMessage(message)
		}
	default:
		return tm.BaseModule.HandleMessage(message)
	}
}

// handleCollectMetric handles metric collection requests
func (tm *TelemetryModule) handleCollectMetric(msg map[string]interface{}) (interface{}, error) {
	metricName, ok := msg["name"].(string)
	if !ok {
		return nil, fmt.Errorf("metric name is required")
	}

	metricValue, ok := msg["value"]
	if !ok {
		return nil, fmt.Errorf("metric value is required")
	}

	tags := make(map[string]string)
	if tagsData, ok := msg["tags"].(map[string]interface{}); ok {
		for k, v := range tagsData {
			if str, ok := v.(string); ok {
				tags[k] = str
			}
		}
	}

	// Collect the metric
	tm.collectMetric(metricName, metricValue, tags)

	return map[string]interface{}{
		"status": "collected",
		"metric": metricName,
	}, nil
}

// handleGetMetrics handles metrics retrieval requests
func (tm *TelemetryModule) handleGetMetrics(msg map[string]interface{}) (interface{}, error) {
	metrics := tm.GetMetrics()
	
	// Add buffered metrics
	tm.mu.RLock()
	bufferedCount := len(tm.metricsBuffer)
	tm.mu.RUnlock()
	
	metrics["buffered_metrics_count"] = bufferedCount
	
	return metrics, nil
}

// handleFlushMetrics handles metrics flush requests
func (tm *TelemetryModule) handleFlushMetrics(msg map[string]interface{}) (interface{}, error) {
	count := tm.flushMetricsBuffer()
	
	return map[string]interface{}{
		"status": "flushed",
		"count":  count,
	}, nil
}

// collectMetric collects a metric
func (tm *TelemetryModule) collectMetric(name string, value interface{}, tags map[string]string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Add to buffer
	event := telemetry.Event{
		Type:      "metric",
		Message:   name,
		Timestamp: time.Now().Unix(),
		Metadata: map[string]interface{}{
			"value": value,
			"tags":  tags,
		},
	}

	tm.metricsBuffer = append(tm.metricsBuffer, event)

	// Flush if buffer is full
	if len(tm.metricsBuffer) >= tm.bufferSize {
		go tm.flushMetricsBuffer()
	}

	// Update module metrics
	tm.SetMetric("metrics_collected", len(tm.metricsBuffer))
}

// flushMetrics periodically flushes metrics
func (tm *TelemetryModule) flushMetrics() {
	ticker := time.NewTicker(tm.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tm.GetContext().Done():
			return
		case <-ticker.C:
			tm.flushMetricsBuffer()
		}
	}
}

// flushMetricsBuffer flushes the metrics buffer
func (tm *TelemetryModule) flushMetricsBuffer() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	count := len(tm.metricsBuffer)
	if count == 0 {
		return 0
	}

	// In a real implementation, this would send metrics to a backend
	tm.LogDebug("Flushing %d metrics", count)
	
	// Clear the buffer
	tm.metricsBuffer = make([]telemetry.Event, 0)
	
	// Update metrics
	tm.SetMetric("metrics_flushed", count)
	tm.SetMetric("last_flush_time", time.Now().Unix())

	return count
}

// collectSystemMetrics collects system metrics
func (tm *TelemetryModule) collectSystemMetrics() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tm.GetContext().Done():
			return
		case <-ticker.C:
			// Collect basic system metrics
			tm.collectMetric("system.uptime", tm.GetUptime().Seconds(), map[string]string{
				"module": tm.GetInfo().ID,
			})
			
			tm.collectMetric("system.memory", tm.getMemoryUsage(), map[string]string{
				"module": tm.GetInfo().ID,
			})
		}
	}
}

// getMemoryUsage gets memory usage (simplified)
func (tm *TelemetryModule) getMemoryUsage() float64 {
	// This is a simplified implementation
	// In a real system, you would use runtime.MemStats
	return 1024.0 // MB
}

// HealthCheck performs a health check
func (tm *TelemetryModule) HealthCheck() error {
	if err := tm.BaseModule.HealthCheck(); err != nil {
		return err
	}

	// Check buffer health
	tm.mu.RLock()
	bufferSize := len(tm.metricsBuffer)
	tm.mu.RUnlock()

	if bufferSize > tm.bufferSize*2 {
		return fmt.Errorf("metrics buffer is too large: %d", bufferSize)
	}

	return nil
}

// GetMetrics returns telemetry module metrics
func (tm *TelemetryModule) GetMetrics() map[string]interface{} {
	metrics := tm.BaseModule.GetMetrics()
	
	tm.mu.RLock()
	metrics["buffered_metrics"] = len(tm.metricsBuffer)
	metrics["buffer_size"] = tm.bufferSize
	metrics["flush_interval"] = tm.flushInterval.Seconds()
	tm.mu.RUnlock()
	
	return metrics
}
