package modules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// ThreatIntelligenceModule provides threat detection and response capabilities
type ThreatIntelligenceModule struct {
	*BaseModule
	threatDetector  *ThreatDetector
	intelFeed       *IntelFeed
	responseEngine  *ResponseEngine
	mu              sync.RWMutex
}

// ThreatDetector detects threats based on various indicators
type ThreatDetector struct {
	indicators map[string]ThreatIndicator
	mu         sync.RWMutex
}

// IntelFeed manages threat intelligence feeds
type IntelFeed struct {
	feeds map[string]IntelSource
	mu    sync.RWMutex
}

// ResponseEngine handles automated threat response
type ResponseEngine struct {
	responses map[string]ResponseAction
	mu        sync.RWMutex
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// IntelSource represents a threat intelligence source
type IntelSource struct {
	Name        string                 `json:"name"`
	URL         string                 `json:"url"`
	Type        string                 `json:"type"`
	LastUpdate  time.Time              `json:"last_update"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ResponseAction represents an automated response action
type ResponseAction struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Parameters  map[string]interface{} `json:"parameters"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatEvent represents a detected threat event
type ThreatEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Indicators  []ThreatIndicator      `json:"indicators"`
	Response    string                 `json:"response"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewThreatIntelligenceModule creates a new threat intelligence module
func NewThreatIntelligenceModule(logger *telemetry.Logger) *ThreatIntelligenceModule {
	info := ModuleInfo{
		ID:          "threat_intelligence",
		Name:        "Threat Intelligence Module",
		Version:     "1.0.0",
		Description: "Provides threat detection, intelligence feeds, and automated response",
		Author:      "Aegis Team",
		License:     "MIT",
		Capabilities: []string{
			"threat_detection",
			"intelligence_feeds",
			"automated_response",
			"indicator_analysis",
			"threat_hunting",
			"incident_response",
		},
		Metadata: map[string]interface{}{
			"category": "security",
			"priority": "critical",
		},
	}

	tim := &ThreatIntelligenceModule{
		BaseModule:     NewBaseModule(info, logger),
		threatDetector: &ThreatDetector{
			indicators: make(map[string]ThreatIndicator),
		},
		intelFeed: &IntelFeed{
			feeds: make(map[string]IntelSource),
		},
		responseEngine: &ResponseEngine{
			responses: make(map[string]ResponseAction),
		},
	}

	return tim
}

// Initialize initializes the threat intelligence module
func (tim *ThreatIntelligenceModule) Initialize(ctx context.Context, config ModuleConfig) error {
	if err := tim.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	// Initialize threat intelligence components
	tim.initializeIntelFeeds()
	tim.initializeResponseActions()

	tim.LogInfo("Threat intelligence module initialized")
	return nil
}

// Start starts the threat intelligence module
func (tim *ThreatIntelligenceModule) Start(ctx context.Context) error {
	if err := tim.BaseModule.Start(ctx); err != nil {
		return err
	}

	// Start background threat intelligence processes
	go tim.updateIntelFeeds()
	go tim.scanForThreats()
	go tim.processThreatEvents()

	tim.LogInfo("Threat intelligence module started")
	return nil
}

// HandleMessage handles threat intelligence-related messages
func (tim *ThreatIntelligenceModule) HandleMessage(message interface{}) (interface{}, error) {
	switch msg := message.(type) {
	case map[string]interface{}:
		switch msg["type"] {
		case "add_indicator":
			return tim.handleAddIndicator(msg)
		case "scan_threats":
			return tim.handleScanThreats(msg)
		case "get_threats":
			return tim.handleGetThreats(msg)
		case "add_intel_feed":
			return tim.handleAddIntelFeed(msg)
		case "get_intel_feeds":
			return tim.handleGetIntelFeeds(msg)
		case "add_response_action":
			return tim.handleAddResponseAction(msg)
		case "trigger_response":
			return tim.handleTriggerResponse(msg)
		case "get_threat_events":
			return tim.handleGetThreatEvents(msg)
		default:
			return tim.BaseModule.HandleMessage(message)
		}
	default:
		return tim.BaseModule.HandleMessage(message)
	}
}

// handleAddIndicator handles threat indicator addition requests
func (tim *ThreatIntelligenceModule) handleAddIndicator(msg map[string]interface{}) (interface{}, error) {
	indicatorType, ok := msg["indicator_type"].(string)
	if !ok {
		return nil, fmt.Errorf("indicator_type is required")
	}
	
	value, ok := msg["value"].(string)
	if !ok {
		return nil, fmt.Errorf("value is required")
	}
	
	severity, ok := msg["severity"].(string)
	if !ok {
		severity = "medium"
	}
	
	confidence, ok := msg["confidence"].(float64)
	if !ok {
		confidence = 0.8
	}
	
	indicator := ThreatIndicator{
		ID:         fmt.Sprintf("ind_%d", time.Now().Unix()),
		Type:       indicatorType,
		Value:      value,
		Confidence: confidence,
		Severity:   severity,
		Source:     "manual",
		Timestamp:  time.Now(),
		Metadata:   make(map[string]interface{}),
	}
	
	tim.mu.Lock()
	tim.threatDetector.AddIndicator(indicator)
	tim.mu.Unlock()
	
	return map[string]interface{}{
		"indicator_id": indicator.ID,
		"status":       "added",
		"timestamp":    time.Now(),
	}, nil
}

// handleScanThreats handles threat scanning requests
func (tim *ThreatIntelligenceModule) handleScanThreats(msg map[string]interface{}) (interface{}, error) {
	target, ok := msg["target"].(string)
	if !ok {
		return nil, fmt.Errorf("target is required for threat scanning")
	}
	
	threats := tim.scanTargetForThreats(target)
	
	return map[string]interface{}{
		"target":    target,
		"threats":   threats,
		"count":     len(threats),
		"timestamp": time.Now(),
	}, nil
}

// handleGetThreats handles threat retrieval requests
func (tim *ThreatIntelligenceModule) handleGetThreats(msg map[string]interface{}) (interface{}, error) {
	tim.mu.RLock()
	threats := tim.threatDetector.GetAllThreats()
	tim.mu.RUnlock()
	
	return map[string]interface{}{
		"threats":   threats,
		"count":     len(threats),
		"timestamp": time.Now(),
	}, nil
}

// handleAddIntelFeed handles intelligence feed addition requests
func (tim *ThreatIntelligenceModule) handleAddIntelFeed(msg map[string]interface{}) (interface{}, error) {
	name, ok := msg["name"].(string)
	if !ok {
		return nil, fmt.Errorf("name is required")
	}
	
	url, ok := msg["url"].(string)
	if !ok {
		return nil, fmt.Errorf("url is required")
	}
	
	feedType, ok := msg["feed_type"].(string)
	if !ok {
		feedType = "ioc"
	}
	
	feed := IntelSource{
		Name:       name,
		URL:        url,
		Type:       feedType,
		LastUpdate: time.Now(),
		Enabled:    true,
		Metadata:   make(map[string]interface{}),
	}
	
	tim.mu.Lock()
	tim.intelFeed.AddFeed(feed)
	tim.mu.Unlock()
	
	return map[string]interface{}{
		"feed_name": name,
		"status":    "added",
		"timestamp": time.Now(),
	}, nil
}

// handleGetIntelFeeds handles intelligence feed retrieval requests
func (tim *ThreatIntelligenceModule) handleGetIntelFeeds(msg map[string]interface{}) (interface{}, error) {
	tim.mu.RLock()
	feeds := tim.intelFeed.GetAllFeeds()
	tim.mu.RUnlock()
	
	return map[string]interface{}{
		"feeds":     feeds,
		"count":     len(feeds),
		"timestamp": time.Now(),
	}, nil
}

// handleAddResponseAction handles response action addition requests
func (tim *ThreatIntelligenceModule) handleAddResponseAction(msg map[string]interface{}) (interface{}, error) {
	actionType, ok := msg["action_type"].(string)
	if !ok {
		return nil, fmt.Errorf("action_type is required")
	}
	
	description, ok := msg["description"].(string)
	if !ok {
		description = "Automated response action"
	}
	
	action := ResponseAction{
		ID:          fmt.Sprintf("resp_%d", time.Now().Unix()),
		Type:        actionType,
		Description: description,
		Enabled:     true,
		Parameters:  make(map[string]interface{}),
		Metadata:    make(map[string]interface{}),
	}
	
	tim.mu.Lock()
	tim.responseEngine.AddResponseAction(action)
	tim.mu.Unlock()
	
	return map[string]interface{}{
		"action_id": action.ID,
		"status":    "added",
		"timestamp": time.Now(),
	}, nil
}

// handleTriggerResponse handles response triggering requests
func (tim *ThreatIntelligenceModule) handleTriggerResponse(msg map[string]interface{}) (interface{}, error) {
	actionID, ok := msg["action_id"].(string)
	if !ok {
		return nil, fmt.Errorf("action_id is required")
	}
	
	threatID, ok := msg["threat_id"].(string)
	if !ok {
		threatID = "unknown"
	}
	
	success := tim.triggerResponseAction(actionID, threatID)
	
	return map[string]interface{}{
		"action_id": actionID,
		"threat_id": threatID,
		"success":   success,
		"timestamp": time.Now(),
	}, nil
}

// handleGetThreatEvents handles threat event retrieval requests
func (tim *ThreatIntelligenceModule) handleGetThreatEvents(msg map[string]interface{}) (interface{}, error) {
	tim.mu.RLock()
	events := tim.getThreatEvents()
	tim.mu.RUnlock()
	
	return map[string]interface{}{
		"events":    events,
		"count":     len(events),
		"timestamp": time.Now(),
	}, nil
}

// scanTargetForThreats scans a target for threats
func (tim *ThreatIntelligenceModule) scanTargetForThreats(target string) []ThreatEvent {
	// Simulate threat scanning
	threats := []ThreatEvent{
		{
			ID:          fmt.Sprintf("threat_%d", time.Now().Unix()),
			Type:        "malware",
			Severity:    "high",
			Description: fmt.Sprintf("Suspicious activity detected on %s", target),
			Source:      "behavioral_analysis",
			Timestamp:   time.Now(),
			Indicators:  []ThreatIndicator{},
			Response:    "quarantine",
			Metadata:    make(map[string]interface{}),
		},
	}
	
	return threats
}

// triggerResponseAction triggers a response action
func (tim *ThreatIntelligenceModule) triggerResponseAction(actionID, threatID string) bool {
	tim.mu.RLock()
	action, exists := tim.responseEngine.GetResponseAction(actionID)
	tim.mu.RUnlock()
	
	if !exists || !action.Enabled {
		return false
	}
	
	// Simulate response action execution
	tim.LogInfo("Executing response action %s for threat %s", actionID, threatID)
	
	// Update metrics
	tim.SetMetric("response_actions_triggered", 1)
	
	return true
}

// getThreatEvents returns recent threat events
func (tim *ThreatIntelligenceModule) getThreatEvents() []ThreatEvent {
	// Simulate threat events
	events := []ThreatEvent{
		{
			ID:          "event_001",
			Type:        "intrusion_attempt",
			Severity:    "high",
			Description: "Multiple failed login attempts detected",
			Source:      "auth_logs",
			Timestamp:   time.Now().Add(-1 * time.Hour),
			Indicators:  []ThreatIndicator{},
			Response:    "block_ip",
			Metadata:    make(map[string]interface{}),
		},
		{
			ID:          "event_002",
			Type:        "data_exfiltration",
			Severity:    "critical",
			Description: "Unusual data transfer patterns detected",
			Source:      "network_monitoring",
			Timestamp:   time.Now().Add(-30 * time.Minute),
			Indicators:  []ThreatIndicator{},
			Response:    "isolate_host",
			Metadata:    make(map[string]interface{}),
		},
	}
	
	return events
}

// updateIntelFeeds continuously updates intelligence feeds
func (tim *ThreatIntelligenceModule) updateIntelFeeds() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-tim.GetContext().Done():
			return
		case <-ticker.C:
			tim.performIntelFeedUpdate()
		}
	}
}

// scanForThreats continuously scans for threats
func (tim *ThreatIntelligenceModule) scanForThreats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tim.GetContext().Done():
			return
		case <-ticker.C:
			tim.performThreatScan()
		}
	}
}

// processThreatEvents continuously processes threat events
func (tim *ThreatIntelligenceModule) processThreatEvents() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tim.GetContext().Done():
			return
		case <-ticker.C:
			tim.processDetectedThreats()
		}
	}
}

// performIntelFeedUpdate performs intelligence feed updates
func (tim *ThreatIntelligenceModule) performIntelFeedUpdate() {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	// Simulate feed updates
	tim.SetMetric("intel_feed_updates", 1)
	tim.LogDebug("Intelligence feeds updated")
}

// performThreatScan performs threat scanning
func (tim *ThreatIntelligenceModule) performThreatScan() {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	// Simulate threat scanning
	tim.SetMetric("threat_scans", 1)
	tim.LogDebug("Threat scan completed")
}

// processDetectedThreats processes detected threats
func (tim *ThreatIntelligenceModule) processDetectedThreats() {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	// Simulate threat processing
	tim.SetMetric("threats_processed", 1)
	tim.LogDebug("Threat processing completed")
}

// initializeIntelFeeds initializes intelligence feeds
func (tim *ThreatIntelligenceModule) initializeIntelFeeds() {
	// Add default intelligence feeds
	feeds := []IntelSource{
		{
			Name:       "Malware IOCs",
			URL:        "https://feeds.malware.com/iocs",
			Type:       "ioc",
			LastUpdate: time.Now(),
			Enabled:    true,
			Metadata:   make(map[string]interface{}),
		},
		{
			Name:       "Threat Actors",
			URL:        "https://feeds.threats.com/actors",
			Type:       "actor",
			LastUpdate: time.Now(),
			Enabled:    true,
			Metadata:   make(map[string]interface{}),
		},
	}
	
	for _, feed := range feeds {
		tim.intelFeed.AddFeed(feed)
	}
}

// initializeResponseActions initializes response actions
func (tim *ThreatIntelligenceModule) initializeResponseActions() {
	// Add default response actions
	actions := []ResponseAction{
		{
			ID:          "quarantine_host",
			Type:        "quarantine",
			Description: "Quarantine suspicious host",
			Enabled:     true,
			Parameters:  make(map[string]interface{}),
			Metadata:    make(map[string]interface{}),
		},
		{
			ID:          "block_ip",
			Type:        "block",
			Description: "Block malicious IP address",
			Enabled:     true,
			Parameters:  make(map[string]interface{}),
			Metadata:    make(map[string]interface{}),
		},
		{
			ID:          "alert_admin",
			Type:        "alert",
			Description: "Send alert to administrators",
			Enabled:     true,
			Parameters:  make(map[string]interface{}),
			Metadata:    make(map[string]interface{}),
		},
	}
	
	for _, action := range actions {
		tim.responseEngine.AddResponseAction(action)
	}
}

// HealthCheck performs a health check
func (tim *ThreatIntelligenceModule) HealthCheck() error {
	if err := tim.BaseModule.HealthCheck(); err != nil {
		return err
	}

	// Check if threat intelligence components are healthy
	tim.mu.RLock()
	indicatorCount := tim.threatDetector.GetIndicatorCount()
	feedCount := tim.intelFeed.GetFeedCount()
	actionCount := tim.responseEngine.GetActionCount()
	tim.mu.RUnlock()

	if indicatorCount == 0 {
		tim.LogWarn("No threat indicators loaded, threat detection may be limited")
	}

	if feedCount == 0 {
		tim.LogWarn("No intelligence feeds configured, threat intelligence may be incomplete")
	}

	if actionCount == 0 {
		tim.LogWarn("No response actions configured, automated response may be limited")
	}

	return nil
}

// GetMetrics returns threat intelligence module metrics
func (tim *ThreatIntelligenceModule) GetMetrics() map[string]interface{} {
	metrics := tim.BaseModule.GetMetrics()
	
	tim.mu.RLock()
	metrics["indicator_count"] = tim.threatDetector.GetIndicatorCount()
	metrics["feed_count"] = tim.intelFeed.GetFeedCount()
	metrics["action_count"] = tim.responseEngine.GetActionCount()
	tim.mu.RUnlock()
	
	return metrics
}

// ThreatDetector methods

// AddIndicator adds a threat indicator
func (td *ThreatDetector) AddIndicator(indicator ThreatIndicator) {
	td.mu.Lock()
	defer td.mu.Unlock()
	td.indicators[indicator.ID] = indicator
}

// GetAllThreats returns all threat indicators
func (td *ThreatDetector) GetAllThreats() []ThreatIndicator {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	threats := make([]ThreatIndicator, 0, len(td.indicators))
	for _, indicator := range td.indicators {
		threats = append(threats, indicator)
	}
	return threats
}

// GetIndicatorCount returns the number of indicators
func (td *ThreatDetector) GetIndicatorCount() int {
	td.mu.RLock()
	defer td.mu.RUnlock()
	return len(td.indicators)
}

// IntelFeed methods

// AddFeed adds an intelligence feed
func (if_ *IntelFeed) AddFeed(feed IntelSource) {
	if_.mu.Lock()
	defer if_.mu.Unlock()
	if_.feeds[feed.Name] = feed
}

// GetAllFeeds returns all intelligence feeds
func (if_ *IntelFeed) GetAllFeeds() []IntelSource {
	if_.mu.RLock()
	defer if_.mu.RUnlock()
	
	feeds := make([]IntelSource, 0, len(if_.feeds))
	for _, feed := range if_.feeds {
		feeds = append(feeds, feed)
	}
	return feeds
}

// GetFeedCount returns the number of feeds
func (if_ *IntelFeed) GetFeedCount() int {
	if_.mu.RLock()
	defer if_.mu.RUnlock()
	return len(if_.feeds)
}

// ResponseEngine methods

// AddResponseAction adds a response action
func (re *ResponseEngine) AddResponseAction(action ResponseAction) {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.responses[action.ID] = action
}

// GetResponseAction gets a response action
func (re *ResponseEngine) GetResponseAction(actionID string) (ResponseAction, bool) {
	re.mu.RLock()
	defer re.mu.RUnlock()
	action, exists := re.responses[actionID]
	return action, exists
}

// GetActionCount returns the number of response actions
func (re *ResponseEngine) GetActionCount() int {
	re.mu.RLock()
	defer re.mu.RUnlock()
	return len(re.responses)
}
