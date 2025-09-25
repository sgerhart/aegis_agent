package modules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// BaseModule provides a base implementation for modules
type BaseModule struct {
	info       ModuleInfo
	config     ModuleConfig
	status     ModuleStatus
	logger     *telemetry.Logger
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	startTime  time.Time
	metrics    map[string]interface{}
	eventChan  chan telemetry.Event
	closed     sync.Once // Ensure channel is closed only once
}

// NewBaseModule creates a new base module
func NewBaseModule(info ModuleInfo, logger *telemetry.Logger) *BaseModule {
	return &BaseModule{
		info:      info,
		status:    ModuleStatusStopped,
		logger:    logger,
		metrics:   make(map[string]interface{}),
		eventChan: make(chan telemetry.Event, 100),
	}
}

// Initialize initializes the base module
func (bm *BaseModule) Initialize(ctx context.Context, config ModuleConfig) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	bm.config = config
	bm.ctx, bm.cancel = context.WithCancel(ctx)
	
	bm.logger.LogInfo("module_init", fmt.Sprintf("Base module initialized: %s", bm.info.ID), nil)
	return nil
}

// Start starts the base module
func (bm *BaseModule) Start(ctx context.Context) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	bm.status = ModuleStatusRunning
	bm.startTime = time.Now()
	
	// Start event processing goroutine
	go bm.processEvents()
	
	bm.logger.LogInfo("module_start", fmt.Sprintf("Base module started: %s", bm.info.ID), nil)
	return nil
}

// Stop stops the base module
func (bm *BaseModule) Stop(ctx context.Context) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	bm.status = ModuleStatusStopping
	
	// Cancel context to signal shutdown
	if bm.cancel != nil {
		bm.cancel()
	}
	
	// Close event channel safely using sync.Once
	bm.closed.Do(func() {
		if bm.eventChan != nil {
			close(bm.eventChan)
			bm.eventChan = nil
		}
	})
	
	bm.status = ModuleStatusStopped
	bm.logger.LogInfo("module_stop", fmt.Sprintf("Base module stopped: %s", bm.info.ID), nil)
	return nil
}

// Cleanup cleans up the base module
func (bm *BaseModule) Cleanup(ctx context.Context) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	// Clear metrics
	bm.metrics = make(map[string]interface{})
	
	bm.logger.LogInfo("module_cleanup", fmt.Sprintf("Base module cleaned up: %s", bm.info.ID), nil)
	return nil
}

// GetInfo returns the module info
func (bm *BaseModule) GetInfo() ModuleInfo {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.info
}

// GetStatus returns the module status
func (bm *BaseModule) GetStatus() ModuleStatus {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.status
}

// GetConfig returns the module configuration
func (bm *BaseModule) GetConfig() ModuleConfig {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.config
}

// HandleMessage handles messages (default implementation)
func (bm *BaseModule) HandleMessage(message interface{}) (interface{}, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	
	// Default implementation just logs the message
	bm.logger.LogDebug("module_message", fmt.Sprintf("Base module received message: %+v", message), nil)
	
	return map[string]interface{}{
		"module_id": bm.info.ID,
		"message":   "acknowledged",
		"timestamp": time.Now(),
	}, nil
}

// SendEvent sends an event
func (bm *BaseModule) SendEvent(event telemetry.Event) error {
	select {
	case bm.eventChan <- event:
		return nil
	case <-time.After(1 * time.Second):
		return fmt.Errorf("event channel full, dropping event")
	}
}

// HealthCheck performs a health check
func (bm *BaseModule) HealthCheck() error {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	
	if bm.status != ModuleStatusRunning {
		return fmt.Errorf("module %s is not running (status: %s)", bm.info.ID, bm.status)
	}
	
	// Check if context is still valid
	select {
	case <-bm.ctx.Done():
		return fmt.Errorf("module %s context cancelled", bm.info.ID)
	default:
		// Context is still valid
	}
	
	return nil
}

// GetMetrics returns module metrics
func (bm *BaseModule) GetMetrics() map[string]interface{} {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	
	metrics := make(map[string]interface{})
	
	// Copy base metrics
	for k, v := range bm.metrics {
		metrics[k] = v
	}
	
	// Add standard metrics
	metrics["status"] = string(bm.status)
	metrics["uptime"] = time.Since(bm.startTime).Seconds()
	metrics["module_id"] = bm.info.ID
	metrics["module_name"] = bm.info.Name
	metrics["module_version"] = bm.info.Version
	
	return metrics
}

// SetMetric sets a metric value
func (bm *BaseModule) SetMetric(key string, value interface{}) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.metrics[key] = value
}

// GetMetric gets a metric value
func (bm *BaseModule) GetMetric(key string) (interface{}, bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	value, exists := bm.metrics[key]
	return value, exists
}

// IncrementMetric increments a numeric metric
func (bm *BaseModule) IncrementMetric(key string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	if value, exists := bm.metrics[key]; exists {
		if intValue, ok := value.(int); ok {
			bm.metrics[key] = intValue + 1
		} else if floatValue, ok := value.(float64); ok {
			bm.metrics[key] = floatValue + 1.0
		}
	} else {
		bm.metrics[key] = 1
	}
}

// processEvents processes events in the background
func (bm *BaseModule) processEvents() {
	for event := range bm.eventChan {
		bm.logger.LogDebug("module_event", fmt.Sprintf("Base module processing event: %s", event.Type), nil)
		// Default implementation just logs events
		// Subclasses can override this behavior
	}
}

// GetContext returns the module's context
func (bm *BaseModule) GetContext() context.Context {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.ctx
}

// IsRunning checks if the module is running
func (bm *BaseModule) IsRunning() bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.status == ModuleStatusRunning
}

// GetUptime returns the module uptime
func (bm *BaseModule) GetUptime() time.Duration {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	
	if bm.startTime.IsZero() {
		return 0
	}
	
	return time.Since(bm.startTime)
}

// LogInfo logs an info message with module context
func (bm *BaseModule) LogInfo(format string, args ...interface{}) {
	bm.logger.LogInfo("module_info", fmt.Sprintf("[%s] %s", bm.info.ID, fmt.Sprintf(format, args...)), nil)
}

// LogError logs an error message with module context
func (bm *BaseModule) LogError(format string, args ...interface{}) {
	bm.logger.LogError("module_error", fmt.Sprintf("[%s] %s", bm.info.ID, fmt.Sprintf(format, args...)), nil)
}

// LogDebug logs a debug message with module context
func (bm *BaseModule) LogDebug(format string, args ...interface{}) {
	bm.logger.LogDebug("module_debug", fmt.Sprintf("[%s] %s", bm.info.ID, fmt.Sprintf(format, args...)), nil)
}

// LogWarn logs a warning message with module context
func (bm *BaseModule) LogWarn(format string, args ...interface{}) {
	bm.logger.LogWarn("module_warn", fmt.Sprintf("[%s] %s", bm.info.ID, fmt.Sprintf(format, args...)), nil)
}

// EmitTelemetryEvent emits a telemetry event
func (bm *BaseModule) EmitTelemetryEvent(eventType string, message string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	
	metadata["module_id"] = bm.info.ID
	metadata["module_name"] = bm.info.Name
	
	event := telemetry.Event{
		Type:      eventType,
		Message:   message,
		Timestamp: time.Now().Unix(),
		Metadata:  metadata,
	}
	
	bm.SendEvent(event)
}

// ModuleRegistryImpl implements the ModuleRegistry interface
type ModuleRegistryImpl struct {
	registry map[string]ModuleInfo
	factories map[string]ModuleFactory
	mu       sync.RWMutex
}

// NewModuleRegistry creates a new module registry
func NewModuleRegistry() *ModuleRegistryImpl {
	return &ModuleRegistryImpl{
		registry:  make(map[string]ModuleInfo),
		factories: make(map[string]ModuleFactory),
	}
}

// Register registers a module type
func (mr *ModuleRegistryImpl) Register(moduleType string, info ModuleInfo, factory ModuleFactory) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	
	if _, exists := mr.registry[moduleType]; exists {
		return fmt.Errorf("module type %s already registered", moduleType)
	}
	
	mr.registry[moduleType] = info
	mr.factories[moduleType] = factory
	
	return nil
}

// Unregister unregisters a module type
func (mr *ModuleRegistryImpl) Unregister(moduleType string) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	
	delete(mr.registry, moduleType)
	delete(mr.factories, moduleType)
	
	return nil
}

// GetModuleInfo returns module info for a type
func (mr *ModuleRegistryImpl) GetModuleInfo(moduleType string) (ModuleInfo, bool) {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	info, exists := mr.registry[moduleType]
	return info, exists
}

// GetAllModuleInfos returns all registered module infos
func (mr *ModuleRegistryImpl) GetAllModuleInfos() map[string]ModuleInfo {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	infos := make(map[string]ModuleInfo)
	for k, v := range mr.registry {
		infos[k] = v
	}
	return infos
}

// GetAvailableTypes returns all available module types
func (mr *ModuleRegistryImpl) GetAvailableTypes() []string {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	
	types := make([]string, 0, len(mr.registry))
	for moduleType := range mr.registry {
		types = append(types, moduleType)
	}
	return types
}

// CreateModule creates a module instance
func (mr *ModuleRegistryImpl) CreateModule(moduleType string, config ModuleConfig) (ModuleInterface, error) {
	mr.mu.RLock()
	factory, exists := mr.factories[moduleType]
	mr.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("module type %s not registered", moduleType)
	}
	
	return factory.CreateModule(moduleType, config)
}
