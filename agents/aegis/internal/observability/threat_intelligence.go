package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// ThreatIntelligenceManager manages threat intelligence integration
type ThreatIntelligenceManager struct {
	auditLogger       *telemetry.AuditLogger
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	running           bool
	
	// Threat intelligence sources
	sources           map[string]*ThreatIntelligenceSource
	indicators        map[string]*ThreatIndicator
	threats           map[string]*Threat
	
	// Configuration
	updateInterval    time.Duration
	maxIndicators     int
	maxThreats        int
	
	// HTTP client for external APIs
	httpClient        *http.Client
}

// ThreatIntelligenceSource represents a threat intelligence source
type ThreatIntelligenceSource struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Type              SourceType             `json:"type"`
	URL               string                 `json:"url"`
	APIKey            string                 `json:"api_key,omitempty"`
	Enabled           bool                   `json:"enabled"`
	LastUpdate        time.Time              `json:"last_update"`
	UpdateInterval    time.Duration          `json:"update_interval"`
	Priority          int                    `json:"priority"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	ID                string                 `json:"id"`
	SourceID          string                 `json:"source_id"`
	Type              IndicatorType          `json:"type"`
	Value             string                 `json:"value"`
	Confidence        float64                `json:"confidence"`
	Severity          ThreatSeverity         `json:"severity"`
	Description       string                 `json:"description"`
	FirstSeen         time.Time              `json:"first_seen"`
	LastSeen          time.Time              `json:"last_seen"`
	ExpiresAt         time.Time              `json:"expires_at"`
	Tags              []string               `json:"tags"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// Threat represents a threat
type Threat struct {
	ID                string                 `json:"id"`
	SourceID          string                 `json:"source_id"`
	Name              string                 `json:"name"`
	Type              ThreatType             `json:"type"`
	Severity          ThreatSeverity         `json:"severity"`
	Description       string                 `json:"description"`
	Indicators        []string               `json:"indicators"`
	FirstSeen         time.Time              `json:"first_seen"`
	LastSeen          time.Time              `json:"last_seen"`
	Status            ThreatStatus           `json:"status"`
	Confidence        float64                `json:"confidence"`
	Tags              []string               `json:"tags"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ThreatMatch represents a match between system activity and threat intelligence
type ThreatMatch struct {
	ID                string                 `json:"id"`
	ThreatID          string                 `json:"threat_id"`
	IndicatorID       string                 `json:"indicator_id"`
	EntityID          string                 `json:"entity_id"`
	EntityType        string                 `json:"entity_type"`
	EntityName        string                 `json:"entity_name"`
	MatchType         MatchType              `json:"match_type"`
	Confidence        float64                `json:"confidence"`
	Severity          ThreatSeverity         `json:"severity"`
	Description       string                 `json:"description"`
	DetectedAt        time.Time              `json:"detected_at"`
	Status            MatchStatus            `json:"status"`
	Context           map[string]interface{} `json:"context"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// Enums
type SourceType string
const (
	SourceTypeAPI        SourceType = "api"
	SourceTypeFeed       SourceType = "feed"
	SourceTypeFile       SourceType = "file"
	SourceTypeDatabase   SourceType = "database"
	SourceTypeCustom     SourceType = "custom"
)

type IndicatorType string
const (
	IndicatorTypeIP        IndicatorType = "ip"
	IndicatorTypeDomain    IndicatorType = "domain"
	IndicatorTypeURL       IndicatorType = "url"
	IndicatorTypeHash      IndicatorType = "hash"
	IndicatorTypeEmail     IndicatorType = "email"
	IndicatorTypeProcess   IndicatorType = "process"
	IndicatorTypeFile      IndicatorType = "file"
	IndicatorTypeRegistry  IndicatorType = "registry"
)

type ThreatType string
const (
	ThreatTypeMalware      ThreatType = "malware"
	ThreatTypeAPT          ThreatType = "apt"
	ThreatTypeBotnet       ThreatType = "botnet"
	ThreatTypePhishing     ThreatType = "phishing"
	ThreatTypeRansomware   ThreatType = "ransomware"
	ThreatTypeTrojan       ThreatType = "trojan"
	ThreatTypeVirus        ThreatType = "virus"
	ThreatTypeWorm         ThreatType = "worm"
	ThreatTypeSpyware      ThreatType = "spyware"
	ThreatTypeAdware       ThreatType = "adware"
)

type ThreatSeverity string
const (
	ThreatSeverityLow      ThreatSeverity = "low"
	ThreatSeverityMedium   ThreatSeverity = "medium"
	ThreatSeverityHigh     ThreatSeverity = "high"
	ThreatSeverityCritical ThreatSeverity = "critical"
)

type ThreatStatus string
const (
	ThreatStatusActive     ThreatStatus = "active"
	ThreatStatusInactive   ThreatStatus = "inactive"
	ThreatStatusExpired    ThreatStatus = "expired"
	ThreatStatusFalsePositive ThreatStatus = "false_positive"
)

type MatchType string
const (
	MatchTypeExact        MatchType = "exact"
	MatchTypePartial      MatchType = "partial"
	MatchTypeFuzzy        MatchType = "fuzzy"
	MatchTypeBehavioral   MatchType = "behavioral"
)

type MatchStatus string
const (
	MatchStatusActive     MatchStatus = "active"
	MatchStatusInvestigated MatchStatus = "investigated"
	MatchStatusResolved   MatchStatus = "resolved"
	MatchStatusFalsePositive MatchStatus = "false_positive"
)

// NewThreatIntelligenceManager creates a new threat intelligence manager
func NewThreatIntelligenceManager(auditLogger *telemetry.AuditLogger) *ThreatIntelligenceManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	tim := &ThreatIntelligenceManager{
		auditLogger:       auditLogger,
		ctx:               ctx,
		cancel:            cancel,
		sources:           make(map[string]*ThreatIntelligenceSource),
		indicators:        make(map[string]*ThreatIndicator),
		threats:           make(map[string]*Threat),
		updateInterval:    15 * time.Minute,
		maxIndicators:     10000,
		maxThreats:        1000,
		httpClient:        &http.Client{Timeout: 30 * time.Second},
	}
	
	// Initialize default sources
	tim.initializeDefaultSources()
	
	log.Printf("[threat_intelligence] Threat intelligence manager initialized")
	return tim
}

// Start starts the threat intelligence manager
func (tim *ThreatIntelligenceManager) Start() error {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	if tim.running {
		return fmt.Errorf("threat intelligence manager already running")
	}
	
	tim.running = true
	
	// Start update goroutine
	go tim.updateThreatIntelligence()
	
	log.Printf("[threat_intelligence] Threat intelligence manager started")
	
	// Log startup event
	tim.auditLogger.LogSystemEvent("threat_intelligence_start", "Threat intelligence manager started", map[string]interface{}{
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"update_interval":  tim.updateInterval.String(),
		"sources_count":    len(tim.sources),
	})
	
	return nil
}

// Stop stops the threat intelligence manager
func (tim *ThreatIntelligenceManager) Stop() error {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	if !tim.running {
		return fmt.Errorf("threat intelligence manager not running")
	}
	
	tim.cancel()
	tim.running = false
	
	log.Printf("[threat_intelligence] Threat intelligence manager stopped")
	
	// Log shutdown event
	tim.auditLogger.LogSystemEvent("threat_intelligence_stop", "Threat intelligence manager stopped", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	
	return nil
}

// AddSource adds a threat intelligence source
func (tim *ThreatIntelligenceManager) AddSource(source *ThreatIntelligenceSource) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	// Generate ID if not provided
	if source.ID == "" {
		source.ID = fmt.Sprintf("source_%d", time.Now().Unix())
	}
	
	// Set default values
	if source.UpdateInterval == 0 {
		source.UpdateInterval = tim.updateInterval
	}
	if source.Metadata == nil {
		source.Metadata = make(map[string]interface{})
	}
	
	// Store source
	tim.sources[source.ID] = source
	
	// Log source addition
	tim.auditLogger.LogCustomEvent(telemetry.EventTypeThreatIntelligenceEvent, telemetry.SeverityInfo,
		"Threat intelligence source added",
		map[string]interface{}{
			"source_id":   source.ID,
			"source_name": source.Name,
			"source_type": source.Type,
			"enabled":     source.Enabled,
		})
	
	return nil
}

// updateThreatIntelligence updates threat intelligence from all sources
func (tim *ThreatIntelligenceManager) updateThreatIntelligence() {
	ticker := time.NewTicker(tim.updateInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			tim.performUpdate()
		case <-tim.ctx.Done():
			return
		}
	}
}

// performUpdate performs the actual threat intelligence update
func (tim *ThreatIntelligenceManager) performUpdate() {
	tim.mu.RLock()
	sources := make([]*ThreatIntelligenceSource, 0, len(tim.sources))
	for _, source := range tim.sources {
		if source.Enabled {
			sources = append(sources, source)
		}
	}
	tim.mu.RUnlock()
	
	// Update from each source
	for _, source := range sources {
		go tim.updateFromSource(source)
	}
}

// updateFromSource updates threat intelligence from a specific source
func (tim *ThreatIntelligenceManager) updateFromSource(source *ThreatIntelligenceSource) {
	log.Printf("[threat_intelligence] Updating from source: %s", source.Name)
	
	switch source.Type {
	case SourceTypeAPI:
		tim.updateFromAPI(source)
	case SourceTypeFeed:
		tim.updateFromFeed(source)
	case SourceTypeFile:
		tim.updateFromFile(source)
	case SourceTypeDatabase:
		tim.updateFromDatabase(source)
	case SourceTypeCustom:
		tim.updateFromCustom(source)
	}
	
	// Update last update time
	tim.mu.Lock()
	source.LastUpdate = time.Now()
	tim.mu.Unlock()
}

// updateFromAPI updates from an API source
func (tim *ThreatIntelligenceManager) updateFromAPI(source *ThreatIntelligenceSource) {
	// Create request
	req, err := http.NewRequest("GET", source.URL, nil)
	if err != nil {
		log.Printf("[threat_intelligence] Failed to create request for source %s: %v", source.Name, err)
		return
	}
	
	// Add API key if provided
	if source.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+source.APIKey)
	}
	
	// Make request
	resp, err := tim.httpClient.Do(req)
	if err != nil {
		log.Printf("[threat_intelligence] Failed to fetch from source %s: %v", source.Name, err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		log.Printf("[threat_intelligence] Source %s returned status %d", source.Name, resp.StatusCode)
		return
	}
	
	// Parse response (simplified)
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Printf("[threat_intelligence] Failed to parse response from source %s: %v", source.Name, err)
		return
	}
	
	// Process indicators and threats
	tim.processAPIResponse(source, data)
}

// updateFromFeed updates from a feed source
func (tim *ThreatIntelligenceManager) updateFromFeed(source *ThreatIntelligenceSource) {
	// Simplified feed update
	log.Printf("[threat_intelligence] Updating from feed: %s", source.Name)
	
	// Simulate feed data
	indicators := []map[string]interface{}{
		{
			"type":        "ip",
			"value":       "192.168.1.100",
			"confidence":  0.8,
			"severity":    "high",
			"description": "Malicious IP address",
			"tags":        []string{"malware", "botnet"},
		},
		{
			"type":        "domain",
			"value":       "malicious.example.com",
			"confidence":  0.9,
			"severity":    "critical",
			"description": "Malicious domain",
			"tags":        []string{"phishing", "malware"},
		},
	}
	
	threats := []map[string]interface{}{
		{
			"name":        "Sample Malware",
			"type":        "malware",
			"severity":    "high",
			"description": "Sample malware threat",
			"indicators":  []string{"192.168.1.100", "malicious.example.com"},
			"tags":        []string{"malware", "trojan"},
		},
	}
	
	// Process feed data
	tim.processFeedData(source, indicators, threats)
}

// updateFromFile updates from a file source
func (tim *ThreatIntelligenceManager) updateFromFile(source *ThreatIntelligenceSource) {
	// Simplified file update
	log.Printf("[threat_intelligence] Updating from file: %s", source.Name)
}

// updateFromDatabase updates from a database source
func (tim *ThreatIntelligenceManager) updateFromDatabase(source *ThreatIntelligenceSource) {
	// Simplified database update
	log.Printf("[threat_intelligence] Updating from database: %s", source.Name)
}

// updateFromCustom updates from a custom source
func (tim *ThreatIntelligenceManager) updateFromCustom(source *ThreatIntelligenceSource) {
	// Simplified custom update
	log.Printf("[threat_intelligence] Updating from custom source: %s", source.Name)
}

// processAPIResponse processes API response data
func (tim *ThreatIntelligenceManager) processAPIResponse(source *ThreatIntelligenceSource, data map[string]interface{}) {
	// Process indicators
	if indicators, ok := data["indicators"].([]interface{}); ok {
		for _, indicatorData := range indicators {
			if indicator, ok := indicatorData.(map[string]interface{}); ok {
				tim.processIndicator(source, indicator)
			}
		}
	}
	
	// Process threats
	if threats, ok := data["threats"].([]interface{}); ok {
		for _, threatData := range threats {
			if threat, ok := threatData.(map[string]interface{}); ok {
				tim.processThreat(source, threat)
			}
		}
	}
}

// processFeedData processes feed data
func (tim *ThreatIntelligenceManager) processFeedData(source *ThreatIntelligenceSource, indicators []map[string]interface{}, threats []map[string]interface{}) {
	// Process indicators
	for _, indicatorData := range indicators {
		tim.processIndicator(source, indicatorData)
	}
	
	// Process threats
	for _, threatData := range threats {
		tim.processThreat(source, threatData)
	}
}

// processIndicator processes a threat indicator
func (tim *ThreatIntelligenceManager) processIndicator(source *ThreatIntelligenceSource, data map[string]interface{}) {
	indicatorID := fmt.Sprintf("indicator_%d_%s", time.Now().Unix(), source.ID)
	
	indicator := &ThreatIndicator{
		ID:          indicatorID,
		SourceID:    source.ID,
		Type:        IndicatorType(getString(data, "type", "unknown")),
		Value:       getString(data, "value", ""),
		Confidence:  getFloat64(data, "confidence", 0.0),
		Severity:    ThreatSeverity(getString(data, "severity", "low")),
		Description: getString(data, "description", ""),
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Tags:        getStringSlice(data, "tags"),
		Metadata:    make(map[string]interface{}),
	}
	
	// Store indicator
	tim.mu.Lock()
	tim.indicators[indicatorID] = indicator
	tim.mu.Unlock()
	
	// Log indicator addition
	tim.auditLogger.LogCustomEvent(telemetry.EventTypeThreatIntelligenceEvent, telemetry.SeverityInfo,
		"Threat indicator added",
		map[string]interface{}{
			"indicator_id": indicatorID,
			"source_id":    source.ID,
			"type":         indicator.Type,
			"value":        indicator.Value,
			"severity":     indicator.Severity,
		})
}

// processThreat processes a threat
func (tim *ThreatIntelligenceManager) processThreat(source *ThreatIntelligenceSource, data map[string]interface{}) {
	threatID := fmt.Sprintf("threat_%d_%s", time.Now().Unix(), source.ID)
	
	threat := &Threat{
		ID:          threatID,
		SourceID:    source.ID,
		Name:        getString(data, "name", ""),
		Type:        ThreatType(getString(data, "type", "unknown")),
		Severity:    ThreatSeverity(getString(data, "severity", "low")),
		Description: getString(data, "description", ""),
		Indicators:  getStringSlice(data, "indicators"),
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		Status:      ThreatStatusActive,
		Confidence:  getFloat64(data, "confidence", 0.0),
		Tags:        getStringSlice(data, "tags"),
		Metadata:    make(map[string]interface{}),
	}
	
	// Store threat
	tim.mu.Lock()
	tim.threats[threatID] = threat
	tim.mu.Unlock()
	
	// Log threat addition
	tim.auditLogger.LogCustomEvent(telemetry.EventTypeThreatIntelligenceEvent, telemetry.SeverityInfo,
		"Threat added",
		map[string]interface{}{
			"threat_id":    threatID,
			"source_id":    source.ID,
			"name":         threat.Name,
			"type":         threat.Type,
			"severity":     threat.Severity,
		})
}

// CheckThreatMatch checks if system activity matches threat intelligence
func (tim *ThreatIntelligenceManager) CheckThreatMatch(entityID, entityType, entityName, value string) []*ThreatMatch {
	var matches []*ThreatMatch
	
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	// Check against indicators
	for _, indicator := range tim.indicators {
		if tim.matchesIndicator(value, indicator) {
			match := &ThreatMatch{
				ID:          fmt.Sprintf("match_%d", time.Now().Unix()),
				ThreatID:    "", // Will be set if threat is found
				IndicatorID: indicator.ID,
				EntityID:    entityID,
				EntityType:  entityType,
				EntityName:  entityName,
				MatchType:   MatchTypeExact,
				Confidence:  indicator.Confidence,
				Severity:    indicator.Severity,
				Description: fmt.Sprintf("Match with threat indicator: %s", indicator.Description),
				DetectedAt:  time.Now(),
				Status:      MatchStatusActive,
				Context:     make(map[string]interface{}),
				Metadata:    make(map[string]interface{}),
			}
			
			// Find associated threat
			for _, threat := range tim.threats {
				for _, threatIndicator := range threat.Indicators {
					if threatIndicator == indicator.ID {
						match.ThreatID = threat.ID
						break
					}
				}
			}
			
			matches = append(matches, match)
		}
	}
	
	// Log matches
	for _, match := range matches {
		tim.auditLogger.LogCustomEvent(telemetry.EventTypeThreatIntelligenceEvent, telemetry.SeverityWarning,
			"Threat intelligence match detected",
			map[string]interface{}{
				"match_id":     match.ID,
				"entity_id":    entityID,
				"entity_type":  entityType,
				"entity_name":  entityName,
				"indicator_id": match.IndicatorID,
				"threat_id":    match.ThreatID,
				"severity":     match.Severity,
				"confidence":   match.Confidence,
			})
	}
	
	return matches
}

// matchesIndicator checks if a value matches a threat indicator
func (tim *ThreatIntelligenceManager) matchesIndicator(value string, indicator *ThreatIndicator) bool {
	switch indicator.Type {
	case IndicatorTypeIP:
		return value == indicator.Value
	case IndicatorTypeDomain:
		return value == indicator.Value
	case IndicatorTypeURL:
		return value == indicator.Value
	case IndicatorTypeHash:
		return value == indicator.Value
	case IndicatorTypeEmail:
		return value == indicator.Value
	case IndicatorTypeProcess:
		return value == indicator.Value
	case IndicatorTypeFile:
		return value == indicator.Value
	default:
		return false
	}
}

// initializeDefaultSources initializes default threat intelligence sources
func (tim *ThreatIntelligenceManager) initializeDefaultSources() {
	// Add default feed source
	feedSource := &ThreatIntelligenceSource{
		ID:             "default_feed",
		Name:           "Default Threat Feed",
		Type:           SourceTypeFeed,
		URL:            "https://example.com/threats/feed",
		Enabled:        true,
		UpdateInterval: 15 * time.Minute,
		Priority:       1,
		Metadata:       make(map[string]interface{}),
	}
	tim.sources[feedSource.ID] = feedSource
	
	// Add default API source
	apiSource := &ThreatIntelligenceSource{
		ID:             "default_api",
		Name:           "Default Threat API",
		Type:           SourceTypeAPI,
		URL:            "https://api.example.com/threats",
		Enabled:        false, // Disabled by default
		UpdateInterval: 30 * time.Minute,
		Priority:       2,
		Metadata:       make(map[string]interface{}),
	}
	tim.sources[apiSource.ID] = apiSource
}

// Helper functions
func getString(data map[string]interface{}, key, defaultValue string) string {
	if value, ok := data[key].(string); ok {
		return value
	}
	return defaultValue
}

func getFloat64(data map[string]interface{}, key string, defaultValue float64) float64 {
	if value, ok := data[key].(float64); ok {
		return value
	}
	return defaultValue
}

func getStringSlice(data map[string]interface{}, key string) []string {
	if value, ok := data[key].([]interface{}); ok {
		result := make([]string, len(value))
		for i, v := range value {
			if str, ok := v.(string); ok {
				result[i] = str
			}
		}
		return result
	}
	return []string{}
}

// Public methods
func (tim *ThreatIntelligenceManager) GetSources() map[string]*ThreatIntelligenceSource {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	sources := make(map[string]*ThreatIntelligenceSource)
	for id, source := range tim.sources {
		sources[id] = source
	}
	
	return sources
}

func (tim *ThreatIntelligenceManager) GetIndicators() map[string]*ThreatIndicator {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	indicators := make(map[string]*ThreatIndicator)
	for id, indicator := range tim.indicators {
		indicators[id] = indicator
	}
	
	return indicators
}

func (tim *ThreatIntelligenceManager) GetThreats() map[string]*Threat {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	threats := make(map[string]*Threat)
	for id, threat := range tim.threats {
		threats[id] = threat
	}
	
	return threats
}

func (tim *ThreatIntelligenceManager) GetStatistics() map[string]interface{} {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	stats := map[string]interface{}{
		"sources_count":   len(tim.sources),
		"indicators_count": len(tim.indicators),
		"threats_count":   len(tim.threats),
		"enabled_sources": 0,
	}
	
	for _, source := range tim.sources {
		if source.Enabled {
			stats["enabled_sources"] = stats["enabled_sources"].(int) + 1
		}
	}
	
	return stats
}

// Close closes the threat intelligence manager
func (tim *ThreatIntelligenceManager) Close() error {
	return tim.Stop()
}
