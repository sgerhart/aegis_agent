package observability

import (
	"context"
	"fmt"
	"log"
	"math"
	"sort"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// AnomalyDetector detects behavioral anomalies in system processes and services
type AnomalyDetector struct {
	processMonitor    *ProcessMonitor
	serviceDiscovery  *ServiceDiscovery
	auditLogger       *telemetry.AuditLogger
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	running           bool
	
	// Anomaly detection state
	baselines         map[string]*BehavioralBaseline
	anomalies         map[string]*Anomaly
	detectionRules    []AnomalyDetectionRule
	anomalyCounter    int
	
	// Configuration
	detectionInterval time.Duration
	baselineWindow    time.Duration
	anomalyThreshold  float64
}

// BehavioralBaseline represents the baseline behavior for a process or service
type BehavioralBaseline struct {
	ID                string                 `json:"id"`
	Type              BaselineType           `json:"type"`
	EntityID          string                 `json:"entity_id"`
	EntityName        string                 `json:"entity_name"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	
	// Behavioral metrics
	CPUUsage          *MetricBaseline        `json:"cpu_usage"`
	MemoryUsage       *MetricBaseline        `json:"memory_usage"`
	NetworkActivity   *NetworkBaseline       `json:"network_activity"`
	FileAccess        *FileAccessBaseline    `json:"file_access"`
	ProcessSpawns     *ProcessSpawnBaseline  `json:"process_spawns"`
	
	// Statistical data
	DataPoints        []DataPoint            `json:"data_points"`
	LastSeen          time.Time              `json:"last_seen"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// Anomaly represents a detected behavioral anomaly
type Anomaly struct {
	ID                string                 `json:"id"`
	BaselineID        string                 `json:"baseline_id"`
	EntityID          string                 `json:"entity_id"`
	EntityName        string                 `json:"entity_name"`
	Type              AnomalyType            `json:"type"`
	Severity          AnomalySeverity        `json:"severity"`
	Description       string                 `json:"description"`
	DetectedAt        time.Time              `json:"detected_at"`
	ResolvedAt        time.Time              `json:"resolved_at,omitempty"`
	Status            AnomalyStatus          `json:"status"`
	
	// Anomaly details
	Metric            string                 `json:"metric"`
	ExpectedValue     float64                `json:"expected_value"`
	ActualValue       float64                `json:"actual_value"`
	Deviation         float64                `json:"deviation"`
	Confidence        float64                `json:"confidence"`
	
	// Context
	Context           map[string]interface{} `json:"context"`
	Recommendations   []string               `json:"recommendations"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// AnomalyDetectionRule defines rules for anomaly detection
type AnomalyDetectionRule struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Type              AnomalyType            `json:"type"`
	Metric            string                 `json:"metric"`
	Threshold         float64                `json:"threshold"`
	Window            time.Duration          `json:"window"`
	Enabled           bool                   `json:"enabled"`
	Priority          int                    `json:"priority"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// MetricBaseline represents baseline metrics for a specific measurement
type MetricBaseline struct {
	Mean              float64                `json:"mean"`
	StdDev            float64                `json:"std_dev"`
	Min               float64                `json:"min"`
	Max               float64                `json:"max"`
	Percentile95      float64                `json:"percentile_95"`
	Percentile99      float64                `json:"percentile_99"`
	DataPoints        []float64              `json:"data_points"`
	LastUpdated       time.Time              `json:"last_updated"`
}

// NetworkBaseline represents baseline network activity
type NetworkBaseline struct {
	BytesIn           *MetricBaseline        `json:"bytes_in"`
	BytesOut          *MetricBaseline        `json:"bytes_out"`
	Connections       *MetricBaseline        `json:"connections"`
	UniqueIPs         *MetricBaseline        `json:"unique_ips"`
	Ports             []int                  `json:"ports"`
	Protocols         []string               `json:"protocols"`
	LastUpdated       time.Time              `json:"last_updated"`
}

// FileAccessBaseline represents baseline file access patterns
type FileAccessBaseline struct {
	FilesAccessed     *MetricBaseline        `json:"files_accessed"`
	ReadOperations    *MetricBaseline        `json:"read_operations"`
	WriteOperations   *MetricBaseline        `json:"write_operations"`
	Directories       []string               `json:"directories"`
	FileTypes         []string               `json:"file_types"`
	LastUpdated       time.Time              `json:"last_updated"`
}

// ProcessSpawnBaseline represents baseline process spawning patterns
type ProcessSpawnBaseline struct {
	SpawnRate         *MetricBaseline        `json:"spawn_rate"`
	ChildProcesses    *MetricBaseline        `json:"child_processes"`
	Executables       []string               `json:"executables"`
	LastUpdated       time.Time              `json:"last_updated"`
}

// DataPoint represents a single data point for baseline calculation
type DataPoint struct {
	Timestamp         time.Time              `json:"timestamp"`
	Value             float64                `json:"value"`
	Metric            string                 `json:"metric"`
	Context           map[string]interface{} `json:"context"`
}

// Enums
type BaselineType string
const (
	BaselineTypeProcess BaselineType = "process"
	BaselineTypeService BaselineType = "service"
	BaselineTypeSystem  BaselineType = "system"
)

type AnomalyType string
const (
	AnomalyTypeCPU          AnomalyType = "cpu_anomaly"
	AnomalyTypeMemory       AnomalyType = "memory_anomaly"
	AnomalyTypeNetwork      AnomalyType = "network_anomaly"
	AnomalyTypeFileAccess   AnomalyType = "file_access_anomaly"
	AnomalyTypeProcessSpawn AnomalyType = "process_spawn_anomaly"
	AnomalyTypeBehavioral   AnomalyType = "behavioral_anomaly"
	AnomalyTypeSecurity     AnomalyType = "security_anomaly"
)

type AnomalySeverity string
const (
	AnomalySeverityLow      AnomalySeverity = "low"
	AnomalySeverityMedium   AnomalySeverity = "medium"
	AnomalySeverityHigh     AnomalySeverity = "high"
	AnomalySeverityCritical AnomalySeverity = "critical"
)

type AnomalyStatus string
const (
	AnomalyStatusActive     AnomalyStatus = "active"
	AnomalyStatusResolved   AnomalyStatus = "resolved"
	AnomalyStatusFalsePositive AnomalyStatus = "false_positive"
	AnomalyStatusInvestigated AnomalyStatus = "investigated"
)

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(processMonitor *ProcessMonitor, serviceDiscovery *ServiceDiscovery, auditLogger *telemetry.AuditLogger) *AnomalyDetector {
	ctx, cancel := context.WithCancel(context.Background())
	
	ad := &AnomalyDetector{
		processMonitor:    processMonitor,
		serviceDiscovery:  serviceDiscovery,
		auditLogger:       auditLogger,
		ctx:               ctx,
		cancel:            cancel,
		baselines:         make(map[string]*BehavioralBaseline),
		anomalies:         make(map[string]*Anomaly),
		detectionRules:    []AnomalyDetectionRule{},
		detectionInterval: 30 * time.Second,
		baselineWindow:    24 * time.Hour,
		anomalyThreshold:  2.0, // 2 standard deviations
	}
	
	// Initialize default detection rules
	ad.initializeDefaultRules()
	
	log.Printf("[anomaly_detector] Anomaly detector initialized")
	return ad
}

// Start starts the anomaly detector
func (ad *AnomalyDetector) Start() error {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	
	if ad.running {
		return fmt.Errorf("anomaly detector already running")
	}
	
	ad.running = true
	
	// Start detection goroutine
	go ad.detectAnomalies()
	
	// Start baseline update goroutine
	go ad.updateBaselines()
	
	log.Printf("[anomaly_detector] Anomaly detector started")
	
	// Log startup event
	ad.auditLogger.LogSystemEvent("anomaly_detector_start", "Anomaly detector started", map[string]interface{}{
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
		"detection_interval": ad.detectionInterval.String(),
		"baseline_window":   ad.baselineWindow.String(),
	})
	
	return nil
}

// Stop stops the anomaly detector
func (ad *AnomalyDetector) Stop() error {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	
	if !ad.running {
		return fmt.Errorf("anomaly detector not running")
	}
	
	ad.cancel()
	ad.running = false
	
	log.Printf("[anomaly_detector] Anomaly detector stopped")
	
	// Log shutdown event
	ad.auditLogger.LogSystemEvent("anomaly_detector_stop", "Anomaly detector stopped", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	
	return nil
}

// detectAnomalies performs continuous anomaly detection
func (ad *AnomalyDetector) detectAnomalies() {
	ticker := time.NewTicker(ad.detectionInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ad.performAnomalyDetection()
		case <-ad.ctx.Done():
			return
		}
	}
}

// updateBaselines updates behavioral baselines
func (ad *AnomalyDetector) updateBaselines() {
	ticker := time.NewTicker(ad.baselineWindow / 4) // Update every 6 hours
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ad.updateAllBaselines()
		case <-ad.ctx.Done():
			return
		}
	}
}

// performAnomalyDetection performs the main anomaly detection
func (ad *AnomalyDetector) performAnomalyDetection() {
	// Get all processes
	processes, err := ad.processMonitor.GetAllProcesses()
	if err != nil {
		log.Printf("[anomaly_detector] Failed to get processes: %v", err)
		return
	}
	
	// Detect anomalies for each process
	for _, process := range processes {
		ad.detectProcessAnomalies(process)
	}
	
	// Get all services
	services := ad.serviceDiscovery.GetServices()
	
	// Detect anomalies for each service
	for _, service := range services {
		ad.detectServiceAnomalies(service)
	}
}

// detectProcessAnomalies detects anomalies for a specific process
func (ad *AnomalyDetector) detectProcessAnomalies(process ProcessInfo) {
	baselineID := fmt.Sprintf("process_%d", process.PID)
	
	// Get or create baseline
	baseline := ad.getOrCreateBaseline(baselineID, BaselineTypeProcess, fmt.Sprintf("%d", process.PID), string(process.Comm[:]))
	
	// Detect CPU anomalies
	ad.detectCPUAnomalies(process, baseline)
	
	// Detect memory anomalies
	ad.detectMemoryAnomalies(process, baseline)
	
	// Detect network anomalies
	ad.detectNetworkAnomalies(process, baseline)
	
	// Detect file access anomalies
	ad.detectFileAccessAnomalies(process, baseline)
	
	// Detect process spawn anomalies
	ad.detectProcessSpawnAnomalies(process, baseline)
}

// detectServiceAnomalies detects anomalies for a specific service
func (ad *AnomalyDetector) detectServiceAnomalies(service *Service) {
	baselineID := fmt.Sprintf("service_%s", service.ID)
	
	// Get or create baseline
	baseline := ad.getOrCreateBaseline(baselineID, BaselineTypeService, service.ID, service.Name)
	
	// Detect service-specific anomalies
	ad.detectServiceHealthAnomalies(service, baseline)
}

// detectCPUAnomalies detects CPU usage anomalies
func (ad *AnomalyDetector) detectCPUAnomalies(process ProcessInfo, baseline *BehavioralBaseline) {
	// Simulate CPU usage (in reality would get from process monitor)
	cpuUsage := ad.simulateCPUUsage(process)
	
	// Check against baseline
	if baseline.CPUUsage != nil {
		deviation := ad.calculateDeviation(cpuUsage, baseline.CPUUsage)
		if deviation > ad.anomalyThreshold {
			ad.createAnomaly(baseline, AnomalyTypeCPU, "cpu_usage", cpuUsage, baseline.CPUUsage.Mean, deviation)
		}
	}
	
	// Update baseline
	ad.updateCPUBaseline(baseline, cpuUsage)
}

// detectMemoryAnomalies detects memory usage anomalies
func (ad *AnomalyDetector) detectMemoryAnomalies(process ProcessInfo, baseline *BehavioralBaseline) {
	// Simulate memory usage (in reality would get from process monitor)
	memoryUsage := ad.simulateMemoryUsage(process)
	
	// Check against baseline
	if baseline.MemoryUsage != nil {
		deviation := ad.calculateDeviation(memoryUsage, baseline.MemoryUsage)
		if deviation > ad.anomalyThreshold {
			ad.createAnomaly(baseline, AnomalyTypeMemory, "memory_usage", memoryUsage, baseline.MemoryUsage.Mean, deviation)
		}
	}
	
	// Update baseline
	ad.updateMemoryBaseline(baseline, memoryUsage)
}

// detectNetworkAnomalies detects network activity anomalies
func (ad *AnomalyDetector) detectNetworkAnomalies(process ProcessInfo, baseline *BehavioralBaseline) {
	// Get network connections
	connections, err := ad.processMonitor.GetProcessNetworkConnections(process.PID)
	if err != nil {
		return
	}
	
	// Calculate network metrics
	bytesIn, bytesOut := ad.calculateNetworkMetrics(connections)
	
	// Check against baseline
	if baseline.NetworkActivity != nil {
		if baseline.NetworkActivity.BytesIn != nil {
			deviation := ad.calculateDeviation(bytesIn, baseline.NetworkActivity.BytesIn)
			if deviation > ad.anomalyThreshold {
				ad.createAnomaly(baseline, AnomalyTypeNetwork, "bytes_in", bytesIn, baseline.NetworkActivity.BytesIn.Mean, deviation)
			}
		}
		
		if baseline.NetworkActivity.BytesOut != nil {
			deviation := ad.calculateDeviation(bytesOut, baseline.NetworkActivity.BytesOut)
			if deviation > ad.anomalyThreshold {
				ad.createAnomaly(baseline, AnomalyTypeNetwork, "bytes_out", bytesOut, baseline.NetworkActivity.BytesOut.Mean, deviation)
			}
		}
	}
	
	// Update baseline
	ad.updateNetworkBaseline(baseline, bytesIn, bytesOut, len(connections))
}

// detectFileAccessAnomalies detects file access anomalies
func (ad *AnomalyDetector) detectFileAccessAnomalies(process ProcessInfo, baseline *BehavioralBaseline) {
	// Get file access
	fileAccess, err := ad.processMonitor.GetProcessFileAccess(process.PID)
	if err != nil {
		return
	}
	
	// Calculate file access metrics
	filesAccessed := len(fileAccess)
	
	// Check against baseline
	if baseline.FileAccess != nil && baseline.FileAccess.FilesAccessed != nil {
		deviation := ad.calculateDeviation(float64(filesAccessed), baseline.FileAccess.FilesAccessed)
		if deviation > ad.anomalyThreshold {
			ad.createAnomaly(baseline, AnomalyTypeFileAccess, "files_accessed", float64(filesAccessed), baseline.FileAccess.FilesAccessed.Mean, deviation)
		}
	}
	
	// Update baseline
	ad.updateFileAccessBaseline(baseline, filesAccessed)
}

// detectProcessSpawnAnomalies detects process spawning anomalies
func (ad *AnomalyDetector) detectProcessSpawnAnomalies(process ProcessInfo, baseline *BehavioralBaseline) {
	// Simulate process spawn rate (in reality would track actual spawns)
	spawnRate := ad.simulateProcessSpawnRate(process)
	
	// Check against baseline
	if baseline.ProcessSpawns != nil && baseline.ProcessSpawns.SpawnRate != nil {
		deviation := ad.calculateDeviation(spawnRate, baseline.ProcessSpawns.SpawnRate)
		if deviation > ad.anomalyThreshold {
			ad.createAnomaly(baseline, AnomalyTypeProcessSpawn, "spawn_rate", spawnRate, baseline.ProcessSpawns.SpawnRate.Mean, deviation)
		}
	}
	
	// Update baseline
	ad.updateProcessSpawnBaseline(baseline, spawnRate)
}

// detectServiceHealthAnomalies detects service health anomalies
func (ad *AnomalyDetector) detectServiceHealthAnomalies(service *Service, baseline *BehavioralBaseline) {
	// Check service health
	health, err := ad.serviceDiscovery.CheckServiceHealth(service.ID)
	if err != nil {
		return
	}
	
	// Convert health to numeric value
	healthValue := 0.0
	if health == "healthy" {
		healthValue = 1.0
	} else if health == "degraded" {
		healthValue = 0.5
	} else if health == "unhealthy" {
		healthValue = 0.0
	}
	
	// Check against baseline (simplified)
	if healthValue < 0.5 {
		ad.createAnomaly(baseline, AnomalyTypeBehavioral, "health_status", healthValue, 1.0, 1.0)
	}
}

// Helper methods
func (ad *AnomalyDetector) getOrCreateBaseline(id string, baselineType BaselineType, entityID, entityName string) *BehavioralBaseline {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	
	baseline, exists := ad.baselines[id]
	if !exists {
		baseline = &BehavioralBaseline{
			ID:         id,
			Type:       baselineType,
			EntityID:   entityID,
			EntityName: entityName,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
			DataPoints: []DataPoint{},
			Metadata:   make(map[string]interface{}),
		}
		ad.baselines[id] = baseline
	}
	
	baseline.LastSeen = time.Now()
	return baseline
}

func (ad *AnomalyDetector) createAnomaly(baseline *BehavioralBaseline, anomalyType AnomalyType, metric string, actualValue, expectedValue, deviation float64) {
	anomalyID := fmt.Sprintf("anomaly_%d", ad.anomalyCounter)
	ad.anomalyCounter++
	
	anomaly := &Anomaly{
		ID:            anomalyID,
		BaselineID:    baseline.ID,
		EntityID:      baseline.EntityID,
		EntityName:    baseline.EntityName,
		Type:          anomalyType,
		Severity:      ad.calculateSeverity(deviation),
		Description:   fmt.Sprintf("Anomaly detected in %s for %s", metric, baseline.EntityName),
		DetectedAt:    time.Now(),
		Status:        AnomalyStatusActive,
		Metric:        metric,
		ExpectedValue: expectedValue,
		ActualValue:   actualValue,
		Deviation:     deviation,
		Confidence:    ad.calculateConfidence(deviation),
		Context:       make(map[string]interface{}),
		Recommendations: ad.generateRecommendations(anomalyType, deviation),
		Metadata:      make(map[string]interface{}),
	}
	
	ad.mu.Lock()
	ad.anomalies[anomalyID] = anomaly
	ad.mu.Unlock()
	
	// Log anomaly detection
	ad.auditLogger.LogCustomEvent(telemetry.EventTypeAnomalyEvent, telemetry.SeverityWarning,
		"Behavioral anomaly detected",
		map[string]interface{}{
			"anomaly_id":     anomalyID,
			"entity_id":      baseline.EntityID,
			"entity_name":    baseline.EntityName,
			"anomaly_type":   anomalyType,
			"metric":         metric,
			"deviation":      deviation,
			"severity":       anomaly.Severity,
		})
}

func (ad *AnomalyDetector) calculateDeviation(value float64, baseline *MetricBaseline) float64 {
	if baseline.StdDev == 0 {
		return 0
	}
	return math.Abs(value - baseline.Mean) / baseline.StdDev
}

func (ad *AnomalyDetector) calculateSeverity(deviation float64) AnomalySeverity {
	if deviation >= 4.0 {
		return AnomalySeverityCritical
	} else if deviation >= 3.0 {
		return AnomalySeverityHigh
	} else if deviation >= 2.0 {
		return AnomalySeverityMedium
	}
	return AnomalySeverityLow
}

func (ad *AnomalyDetector) calculateConfidence(deviation float64) float64 {
	// Higher deviation = higher confidence
	return math.Min(deviation/5.0, 1.0)
}

func (ad *AnomalyDetector) generateRecommendations(anomalyType AnomalyType, deviation float64) []string {
	var recommendations []string
	
	switch anomalyType {
	case AnomalyTypeCPU:
		recommendations = append(recommendations, "Investigate high CPU usage")
		recommendations = append(recommendations, "Check for runaway processes")
	case AnomalyTypeMemory:
		recommendations = append(recommendations, "Investigate memory leaks")
		recommendations = append(recommendations, "Check for memory-intensive operations")
	case AnomalyTypeNetwork:
		recommendations = append(recommendations, "Investigate unusual network activity")
		recommendations = append(recommendations, "Check for potential security threats")
	case AnomalyTypeFileAccess:
		recommendations = append(recommendations, "Investigate unusual file access patterns")
		recommendations = append(recommendations, "Check for potential data exfiltration")
	case AnomalyTypeProcessSpawn:
		recommendations = append(recommendations, "Investigate unusual process spawning")
		recommendations = append(recommendations, "Check for potential malware")
	}
	
	return recommendations
}

// Simulation methods (in reality would get actual data)
func (ad *AnomalyDetector) simulateCPUUsage(process ProcessInfo) float64 {
	// Simplified simulation
	return float64(process.PID % 100) / 100.0
}

func (ad *AnomalyDetector) simulateMemoryUsage(process ProcessInfo) float64 {
	// Simplified simulation
	return float64(process.PID % 1000) / 1000.0
}

func (ad *AnomalyDetector) simulateProcessSpawnRate(process ProcessInfo) float64 {
	// Simplified simulation
	return float64(process.PID % 10) / 10.0
}

func (ad *AnomalyDetector) calculateNetworkMetrics(connections []ProcessNetworkConn) (float64, float64) {
	bytesIn := 0.0
	bytesOut := 0.0
	
	for _, conn := range connections {
		bytesIn += float64(conn.BytesRecv)
		bytesOut += float64(conn.BytesSent)
	}
	
	return bytesIn, bytesOut
}

// Baseline update methods
func (ad *AnomalyDetector) updateCPUBaseline(baseline *BehavioralBaseline, value float64) {
	if baseline.CPUUsage == nil {
		baseline.CPUUsage = &MetricBaseline{}
	}
	ad.updateMetricBaseline(baseline.CPUUsage, value)
}

func (ad *AnomalyDetector) updateMemoryBaseline(baseline *BehavioralBaseline, value float64) {
	if baseline.MemoryUsage == nil {
		baseline.MemoryUsage = &MetricBaseline{}
	}
	ad.updateMetricBaseline(baseline.MemoryUsage, value)
}

func (ad *AnomalyDetector) updateNetworkBaseline(baseline *BehavioralBaseline, bytesIn, bytesOut float64, connectionCount int) {
	if baseline.NetworkActivity == nil {
		baseline.NetworkActivity = &NetworkBaseline{}
	}
	
	if baseline.NetworkActivity.BytesIn == nil {
		baseline.NetworkActivity.BytesIn = &MetricBaseline{}
	}
	if baseline.NetworkActivity.BytesOut == nil {
		baseline.NetworkActivity.BytesOut = &MetricBaseline{}
	}
	if baseline.NetworkActivity.Connections == nil {
		baseline.NetworkActivity.Connections = &MetricBaseline{}
	}
	
	ad.updateMetricBaseline(baseline.NetworkActivity.BytesIn, bytesIn)
	ad.updateMetricBaseline(baseline.NetworkActivity.BytesOut, bytesOut)
	ad.updateMetricBaseline(baseline.NetworkActivity.Connections, float64(connectionCount))
}

func (ad *AnomalyDetector) updateFileAccessBaseline(baseline *BehavioralBaseline, filesAccessed int) {
	if baseline.FileAccess == nil {
		baseline.FileAccess = &FileAccessBaseline{}
	}
	
	if baseline.FileAccess.FilesAccessed == nil {
		baseline.FileAccess.FilesAccessed = &MetricBaseline{}
	}
	
	ad.updateMetricBaseline(baseline.FileAccess.FilesAccessed, float64(filesAccessed))
}

func (ad *AnomalyDetector) updateProcessSpawnBaseline(baseline *BehavioralBaseline, spawnRate float64) {
	if baseline.ProcessSpawns == nil {
		baseline.ProcessSpawns = &ProcessSpawnBaseline{}
	}
	
	if baseline.ProcessSpawns.SpawnRate == nil {
		baseline.ProcessSpawns.SpawnRate = &MetricBaseline{}
	}
	
	ad.updateMetricBaseline(baseline.ProcessSpawns.SpawnRate, spawnRate)
}

func (ad *AnomalyDetector) updateMetricBaseline(baseline *MetricBaseline, value float64) {
	baseline.DataPoints = append(baseline.DataPoints, value)
	
	// Keep only last 1000 data points
	if len(baseline.DataPoints) > 1000 {
		baseline.DataPoints = baseline.DataPoints[len(baseline.DataPoints)-1000:]
	}
	
	// Recalculate statistics
	ad.calculateBaselineStatistics(baseline)
	baseline.LastUpdated = time.Now()
}

func (ad *AnomalyDetector) calculateBaselineStatistics(baseline *MetricBaseline) {
	if len(baseline.DataPoints) == 0 {
		return
	}
	
	// Calculate mean
	sum := 0.0
	for _, value := range baseline.DataPoints {
		sum += value
	}
	baseline.Mean = sum / float64(len(baseline.DataPoints))
	
	// Calculate standard deviation
	variance := 0.0
	for _, value := range baseline.DataPoints {
		variance += math.Pow(value - baseline.Mean, 2)
	}
	baseline.StdDev = math.Sqrt(variance / float64(len(baseline.DataPoints)))
	
	// Calculate min and max
	baseline.Min = baseline.DataPoints[0]
	baseline.Max = baseline.DataPoints[0]
	for _, value := range baseline.DataPoints {
		if value < baseline.Min {
			baseline.Min = value
		}
		if value > baseline.Max {
			baseline.Max = value
		}
	}
	
	// Calculate percentiles
	sorted := make([]float64, len(baseline.DataPoints))
	copy(sorted, baseline.DataPoints)
	sort.Float64s(sorted)
	
	baseline.Percentile95 = ad.calculatePercentile(sorted, 0.95)
	baseline.Percentile99 = ad.calculatePercentile(sorted, 0.99)
}

func (ad *AnomalyDetector) calculatePercentile(sorted []float64, percentile float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	
	index := int(percentile * float64(len(sorted)-1))
	return sorted[index]
}

func (ad *AnomalyDetector) updateAllBaselines() {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	
	for _, baseline := range ad.baselines {
		baseline.UpdatedAt = time.Now()
	}
}

func (ad *AnomalyDetector) initializeDefaultRules() {
	// CPU anomaly rule
	ad.detectionRules = append(ad.detectionRules, AnomalyDetectionRule{
		ID:          "cpu_anomaly_rule",
		Name:        "CPU Usage Anomaly",
		Description: "Detects unusual CPU usage patterns",
		Type:        AnomalyTypeCPU,
		Metric:      "cpu_usage",
		Threshold:   2.0,
		Window:      5 * time.Minute,
		Enabled:     true,
		Priority:    1,
		Metadata:    make(map[string]interface{}),
	})
	
	// Memory anomaly rule
	ad.detectionRules = append(ad.detectionRules, AnomalyDetectionRule{
		ID:          "memory_anomaly_rule",
		Name:        "Memory Usage Anomaly",
		Description: "Detects unusual memory usage patterns",
		Type:        AnomalyTypeMemory,
		Metric:      "memory_usage",
		Threshold:   2.0,
		Window:      5 * time.Minute,
		Enabled:     true,
		Priority:    1,
		Metadata:    make(map[string]interface{}),
	})
	
	// Network anomaly rule
	ad.detectionRules = append(ad.detectionRules, AnomalyDetectionRule{
		ID:          "network_anomaly_rule",
		Name:        "Network Activity Anomaly",
		Description: "Detects unusual network activity patterns",
		Type:        AnomalyTypeNetwork,
		Metric:      "network_activity",
		Threshold:   2.0,
		Window:      5 * time.Minute,
		Enabled:     true,
		Priority:    1,
		Metadata:    make(map[string]interface{}),
	})
}

// Public methods
func (ad *AnomalyDetector) GetAnomalies() map[string]*Anomaly {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	
	anomalies := make(map[string]*Anomaly)
	for id, anomaly := range ad.anomalies {
		anomalies[id] = anomaly
	}
	
	return anomalies
}

func (ad *AnomalyDetector) GetBaselines() map[string]*BehavioralBaseline {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	
	baselines := make(map[string]*BehavioralBaseline)
	for id, baseline := range ad.baselines {
		baselines[id] = baseline
	}
	
	return baselines
}

func (ad *AnomalyDetector) GetAnomalyStatistics() map[string]interface{} {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_anomalies":    len(ad.anomalies),
		"active_anomalies":   0,
		"resolved_anomalies": 0,
		"total_baselines":    len(ad.baselines),
		"detection_rules":    len(ad.detectionRules),
	}
	
	for _, anomaly := range ad.anomalies {
		switch anomaly.Status {
		case AnomalyStatusActive:
			stats["active_anomalies"] = stats["active_anomalies"].(int) + 1
		case AnomalyStatusResolved:
			stats["resolved_anomalies"] = stats["resolved_anomalies"].(int) + 1
		}
	}
	
	return stats
}

// Close closes the anomaly detector
func (ad *AnomalyDetector) Close() error {
	return ad.Stop()
}
