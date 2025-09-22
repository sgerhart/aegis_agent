package modules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// ObservabilityModule provides advanced monitoring and anomaly detection
type ObservabilityModule struct {
	*BaseModule
	metricsCollector *MetricsCollector
	anomalyDetector  *AnomalyDetector
	alertManager     *AlertManager
	mu               sync.RWMutex
}

// MetricsCollector collects and processes metrics
type MetricsCollector struct {
	metrics map[string]interface{}
	mu      sync.RWMutex
}

// AnomalyDetector detects anomalies in system behavior
type AnomalyDetector struct {
	baselines map[string]float64
	mu        sync.RWMutex
}

// AlertManager manages alerts and notifications
type AlertManager struct {
	alerts map[string]Alert
	mu     sync.RWMutex
}

// Alert represents an alert
type Alert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Message     string                 `json:"message"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
	Resolved    bool                   `json:"resolved"`
}

// NewObservabilityModule creates a new observability module
func NewObservabilityModule(logger *telemetry.Logger) *ObservabilityModule {
	info := ModuleInfo{
		ID:          "observability",
		Name:        "Advanced Observability Module",
		Version:     "1.0.0",
		Description: "Provides advanced monitoring, anomaly detection, and alerting",
		Author:      "Aegis Team",
		License:     "MIT",
		Capabilities: []string{
			"metrics_collection",
			"anomaly_detection",
			"alerting",
			"performance_monitoring",
			"log_analysis",
			"trend_analysis",
		},
		Metadata: map[string]interface{}{
			"category": "observability",
			"priority": "high",
		},
	}

	om := &ObservabilityModule{
		BaseModule:      NewBaseModule(info, logger),
		metricsCollector: &MetricsCollector{
			metrics: make(map[string]interface{}),
		},
		anomalyDetector: &AnomalyDetector{
			baselines: make(map[string]float64),
		},
		alertManager: &AlertManager{
			alerts: make(map[string]Alert),
		},
	}

	return om
}

// Initialize initializes the observability module
func (om *ObservabilityModule) Initialize(ctx context.Context, config ModuleConfig) error {
	if err := om.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	// Initialize baselines
	om.initializeBaselines()

	om.LogInfo("Observability module initialized")
	return nil
}

// Start starts the observability module
func (om *ObservabilityModule) Start(ctx context.Context) error {
	if err := om.BaseModule.Start(ctx); err != nil {
		return err
	}

	// Start background monitoring processes
	go om.collectMetrics()
	go om.detectAnomalies()
	go om.processAlerts()

	om.LogInfo("Observability module started")
	return nil
}

// HandleMessage handles observability-related messages
func (om *ObservabilityModule) HandleMessage(message interface{}) (interface{}, error) {
	switch msg := message.(type) {
	case map[string]interface{}:
		switch msg["type"] {
		case "get_metrics":
			return om.handleGetMetrics(msg)
		case "get_alerts":
			return om.handleGetAlerts(msg)
		case "create_alert":
			return om.handleCreateAlert(msg)
		case "resolve_alert":
			return om.handleResolveAlert(msg)
		case "get_anomalies":
			return om.handleGetAnomalies(msg)
		case "update_baseline":
			return om.handleUpdateBaseline(msg)
		default:
			return om.BaseModule.HandleMessage(message)
		}
	default:
		return om.BaseModule.HandleMessage(message)
	}
}

// handleGetMetrics handles metrics retrieval requests
func (om *ObservabilityModule) handleGetMetrics(msg map[string]interface{}) (interface{}, error) {
	om.mu.RLock()
	metrics := om.metricsCollector.GetAllMetrics()
	om.mu.RUnlock()
	
	return map[string]interface{}{
		"metrics":   metrics,
		"timestamp": time.Now(),
	}, nil
}

// handleGetAlerts handles alert retrieval requests
func (om *ObservabilityModule) handleGetAlerts(msg map[string]interface{}) (interface{}, error) {
	om.mu.RLock()
	alerts := om.alertManager.GetAllAlerts()
	om.mu.RUnlock()
	
	return map[string]interface{}{
		"alerts":    alerts,
		"count":     len(alerts),
		"timestamp": time.Now(),
	}, nil
}

// handleCreateAlert handles alert creation requests
func (om *ObservabilityModule) handleCreateAlert(msg map[string]interface{}) (interface{}, error) {
	alertType, ok := msg["alert_type"].(string)
	if !ok {
		return nil, fmt.Errorf("alert_type is required")
	}
	
	severity, ok := msg["severity"].(string)
	if !ok {
		severity = "medium"
	}
	
	message, ok := msg["message"].(string)
	if !ok {
		return nil, fmt.Errorf("message is required")
	}
	
	alert := Alert{
		ID:        fmt.Sprintf("alert_%d", time.Now().Unix()),
		Type:      alertType,
		Severity:  severity,
		Message:   message,
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
		Resolved:  false,
	}
	
	om.mu.Lock()
	om.alertManager.CreateAlert(alert)
	om.mu.Unlock()
	
	return map[string]interface{}{
		"alert_id":  alert.ID,
		"status":    "created",
		"timestamp": time.Now(),
	}, nil
}

// handleResolveAlert handles alert resolution requests
func (om *ObservabilityModule) handleResolveAlert(msg map[string]interface{}) (interface{}, error) {
	alertID, ok := msg["alert_id"].(string)
	if !ok {
		return nil, fmt.Errorf("alert_id is required")
	}
	
	om.mu.Lock()
	success := om.alertManager.ResolveAlert(alertID)
	om.mu.Unlock()
	
	if !success {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}
	
	return map[string]interface{}{
		"alert_id":  alertID,
		"status":    "resolved",
		"timestamp": time.Now(),
	}, nil
}

// handleGetAnomalies handles anomaly retrieval requests
func (om *ObservabilityModule) handleGetAnomalies(msg map[string]interface{}) (interface{}, error) {
	om.mu.RLock()
	anomalies := om.anomalyDetector.GetDetectedAnomalies()
	om.mu.RUnlock()
	
	return map[string]interface{}{
		"anomalies": anomalies,
		"count":     len(anomalies),
		"timestamp": time.Now(),
	}, nil
}

// handleUpdateBaseline handles baseline update requests
func (om *ObservabilityModule) handleUpdateBaseline(msg map[string]interface{}) (interface{}, error) {
	metric, ok := msg["metric"].(string)
	if !ok {
		return nil, fmt.Errorf("metric is required")
	}
	
	value, ok := msg["value"].(float64)
	if !ok {
		return nil, fmt.Errorf("value is required and must be a number")
	}
	
	om.mu.Lock()
	om.anomalyDetector.UpdateBaseline(metric, value)
	om.mu.Unlock()
	
	return map[string]interface{}{
		"metric":    metric,
		"baseline":  value,
		"timestamp": time.Now(),
	}, nil
}

// collectMetrics continuously collects system metrics
func (om *ObservabilityModule) collectMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-om.GetContext().Done():
			return
		case <-ticker.C:
			om.performMetricsCollection()
		}
	}
}

// detectAnomalies continuously detects anomalies
func (om *ObservabilityModule) detectAnomalies() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-om.GetContext().Done():
			return
		case <-ticker.C:
			om.performAnomalyDetection()
		}
	}
}

// processAlerts continuously processes alerts
func (om *ObservabilityModule) processAlerts() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-om.GetContext().Done():
			return
		case <-ticker.C:
			om.processPendingAlerts()
		}
	}
}

// performMetricsCollection performs metrics collection
func (om *ObservabilityModule) performMetricsCollection() {
	om.mu.Lock()
	defer om.mu.Unlock()
	
	// Simulate metrics collection
	om.metricsCollector.SetMetric("cpu_usage", 45.2)
	om.metricsCollector.SetMetric("memory_usage", 67.8)
	om.metricsCollector.SetMetric("network_io", 1024.5)
	om.metricsCollector.SetMetric("disk_io", 512.3)
	om.metricsCollector.SetMetric("active_connections", 150)
	
	om.SetMetric("metrics_collected", om.metricsCollector.GetMetricCount())
	om.LogDebug("Metrics collection completed")
}

// performAnomalyDetection performs anomaly detection
func (om *ObservabilityModule) performAnomalyDetection() {
	om.mu.Lock()
	defer om.mu.Unlock()
	
	// Check for anomalies in collected metrics
	metrics := om.metricsCollector.GetAllMetrics()
	
	for metric, value := range metrics {
		if floatValue, ok := value.(float64); ok {
			if om.anomalyDetector.IsAnomaly(metric, floatValue) {
				om.createAnomalyAlert(metric, floatValue)
			}
		}
	}
	
	om.SetMetric("anomaly_checks", 1)
}

// processPendingAlerts processes pending alerts
func (om *ObservabilityModule) processPendingAlerts() {
	om.mu.RLock()
	alerts := om.alertManager.GetUnresolvedAlerts()
	om.mu.RUnlock()
	
	for _, alert := range alerts {
		om.LogWarn("Active alert: %s - %s", alert.Type, alert.Message)
		om.SetMetric("active_alerts", len(alerts))
	}
}

// createAnomalyAlert creates an alert for an anomaly
func (om *ObservabilityModule) createAnomalyAlert(metric string, value float64) {
	alert := Alert{
		ID:        fmt.Sprintf("anomaly_%s_%d", metric, time.Now().Unix()),
		Type:      "anomaly",
		Severity:  "high",
		Message:   fmt.Sprintf("Anomaly detected in %s: %.2f", metric, value),
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"metric": metric,
			"value":  value,
		},
		Resolved: false,
	}
	
	om.alertManager.CreateAlert(alert)
	om.LogWarn("Anomaly alert created: %s", alert.Message)
}

// initializeBaselines initializes baseline values for anomaly detection
func (om *ObservabilityModule) initializeBaselines() {
	om.anomalyDetector.SetBaseline("cpu_usage", 50.0)
	om.anomalyDetector.SetBaseline("memory_usage", 60.0)
	om.anomalyDetector.SetBaseline("network_io", 1000.0)
	om.anomalyDetector.SetBaseline("disk_io", 500.0)
	om.anomalyDetector.SetBaseline("active_connections", 100.0)
}

// HealthCheck performs a health check
func (om *ObservabilityModule) HealthCheck() error {
	if err := om.BaseModule.HealthCheck(); err != nil {
		return err
	}

	// Check if observability components are healthy
	om.mu.RLock()
	alertCount := om.alertManager.GetAlertCount()
	metricCount := om.metricsCollector.GetMetricCount()
	om.mu.RUnlock()

	if alertCount > 100 {
		om.LogWarn("High number of alerts: %d", alertCount)
	}

	if metricCount == 0 {
		om.LogWarn("No metrics collected, monitoring may be incomplete")
	}

	return nil
}

// GetMetrics returns observability module metrics
func (om *ObservabilityModule) GetMetrics() map[string]interface{} {
	metrics := om.BaseModule.GetMetrics()
	
	om.mu.RLock()
	metrics["alert_count"] = om.alertManager.GetAlertCount()
	metrics["metric_count"] = om.metricsCollector.GetMetricCount()
	metrics["baseline_count"] = om.anomalyDetector.GetBaselineCount()
	om.mu.RUnlock()
	
	return metrics
}

// MetricsCollector methods

// SetMetric sets a metric value
func (mc *MetricsCollector) SetMetric(key string, value interface{}) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.metrics[key] = value
}

// GetMetric gets a metric value
func (mc *MetricsCollector) GetMetric(key string) (interface{}, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	value, exists := mc.metrics[key]
	return value, exists
}

// GetAllMetrics returns all metrics
func (mc *MetricsCollector) GetAllMetrics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	
	metrics := make(map[string]interface{})
	for k, v := range mc.metrics {
		metrics[k] = v
	}
	return metrics
}

// GetMetricCount returns the number of metrics
func (mc *MetricsCollector) GetMetricCount() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return len(mc.metrics)
}

// AnomalyDetector methods

// SetBaseline sets a baseline value for a metric
func (ad *AnomalyDetector) SetBaseline(metric string, value float64) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.baselines[metric] = value
}

// IsAnomaly checks if a value is an anomaly
func (ad *AnomalyDetector) IsAnomaly(metric string, value float64) bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	
	baseline, exists := ad.baselines[metric]
	if !exists {
		return false
	}
	
	// Simple anomaly detection: value > 2x baseline
	return value > baseline*2
}

// GetDetectedAnomalies returns detected anomalies
func (ad *AnomalyDetector) GetDetectedAnomalies() []string {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	
	anomalies := make([]string, 0)
	for metric := range ad.baselines {
		anomalies = append(anomalies, metric)
	}
	return anomalies
}

// GetBaselineCount returns the number of baselines
func (ad *AnomalyDetector) GetBaselineCount() int {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return len(ad.baselines)
}

// UpdateBaseline updates a baseline value
func (ad *AnomalyDetector) UpdateBaseline(metric string, value float64) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.baselines[metric] = value
}

// AlertManager methods

// CreateAlert creates a new alert
func (am *AlertManager) CreateAlert(alert Alert) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.alerts[alert.ID] = alert
}

// ResolveAlert resolves an alert
func (am *AlertManager) ResolveAlert(alertID string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	alert, exists := am.alerts[alertID]
	if !exists {
		return false
	}
	
	alert.Resolved = true
	am.alerts[alertID] = alert
	return true
}

// GetAllAlerts returns all alerts
func (am *AlertManager) GetAllAlerts() []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	alerts := make([]Alert, 0, len(am.alerts))
	for _, alert := range am.alerts {
		alerts = append(alerts, alert)
	}
	return alerts
}

// GetUnresolvedAlerts returns unresolved alerts
func (am *AlertManager) GetUnresolvedAlerts() []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	alerts := make([]Alert, 0)
	for _, alert := range am.alerts {
		if !alert.Resolved {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// GetAlertCount returns the number of alerts
func (am *AlertManager) GetAlertCount() int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.alerts)
}
