package modules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// ModuleManagerImpl implements the ModuleManager interface
type ModuleManagerImpl struct {
	modules      map[string]ModuleInterface
	configs      map[string]ModuleConfig
	statuses     map[string]ModuleStatus
	eventHandler EventHandler
	logger       *telemetry.Logger
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewModuleManager creates a new module manager
func NewModuleManager(logger *telemetry.Logger) *ModuleManagerImpl {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &ModuleManagerImpl{
		modules:      make(map[string]ModuleInterface),
		configs:      make(map[string]ModuleConfig),
		statuses:     make(map[string]ModuleStatus),
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// RegisterModule registers a new module
func (mm *ModuleManagerImpl) RegisterModule(module ModuleInterface) error {
	return mm.RegisterModuleWithConfig(module, ModuleConfig{Enabled: true})
}

// RegisterModuleWithConfig registers a new module with configuration
func (mm *ModuleManagerImpl) RegisterModuleWithConfig(module ModuleInterface, config ModuleConfig) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	info := module.GetInfo()
	moduleID := info.ID

	if _, exists := mm.modules[moduleID]; exists {
		return fmt.Errorf("module %s already registered", moduleID)
	}

	// Set default status
	mm.statuses[moduleID] = ModuleStatusStopped
	mm.modules[moduleID] = module
	mm.configs[moduleID] = config

	mm.logger.LogInfo("manager_info", fmt.Sprintf("Module registered: %s (%s)", moduleID, info.Name), nil)
	
	// Emit registration event
	if mm.eventHandler != nil {
		mm.eventHandler.HandleModuleEvent(ModuleEvent{
			ModuleID:  moduleID,
			Type:      "module_registered",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"module_name": info.Name,
				"version":     info.Version,
			},
			Severity: "info",
		})
	}

	return nil
}

// UnregisterModule unregisters a module
func (mm *ModuleManagerImpl) UnregisterModule(moduleID string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	module, exists := mm.modules[moduleID]
	if !exists {
		return fmt.Errorf("module %s not found", moduleID)
	}

	// Stop the module if it's running
	if mm.statuses[moduleID] == ModuleStatusRunning {
		mm.mu.Unlock()
		mm.StopModule(moduleID)
		mm.mu.Lock()
	}

	// Cleanup the module
	if err := module.Cleanup(mm.ctx); err != nil {
		mm.logger.LogError("manager_error", fmt.Sprintf("Failed to cleanup module %s: %v", moduleID, err), nil)
	}

	delete(mm.modules, moduleID)
	delete(mm.configs, moduleID)
	delete(mm.statuses, moduleID)

	mm.logger.LogInfo("manager_info", fmt.Sprintf("Module unregistered: %s", moduleID), nil)
	
	// Emit unregistration event
	if mm.eventHandler != nil {
		mm.eventHandler.HandleModuleEvent(ModuleEvent{
			ModuleID:  moduleID,
			Type:      "module_unregistered",
			Timestamp: time.Now(),
			Data:      map[string]interface{}{},
			Severity:  "info",
		})
	}

	return nil
}

// GetModule retrieves a module by ID
func (mm *ModuleManagerImpl) GetModule(moduleID string) (ModuleInterface, bool) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	
	module, exists := mm.modules[moduleID]
	return module, exists
}

// GetAllModules returns all registered modules
func (mm *ModuleManagerImpl) GetAllModules() map[string]ModuleInterface {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	
	modules := make(map[string]ModuleInterface)
	for id, module := range mm.modules {
		modules[id] = module
	}
	return modules
}

// StartModule starts a specific module
func (mm *ModuleManagerImpl) StartModule(moduleID string) error {
	mm.mu.Lock()
	module, exists := mm.modules[moduleID]
	if !exists {
		mm.mu.Unlock()
		return fmt.Errorf("module %s not found", moduleID)
	}
	
	config, hasConfig := mm.configs[moduleID]
	if !hasConfig {
		config = ModuleConfig{Enabled: true}
		mm.configs[moduleID] = config
	}
	
	if !config.Enabled {
		mm.statuses[moduleID] = ModuleStatusDisabled
		mm.mu.Unlock()
		return fmt.Errorf("module %s is disabled", moduleID)
	}
	
	mm.statuses[moduleID] = ModuleStatusStarting
	mm.mu.Unlock()

	// Initialize the module
	if err := module.Initialize(mm.ctx, config); err != nil {
		mm.mu.Lock()
		mm.statuses[moduleID] = ModuleStatusError
		mm.mu.Unlock()
		return fmt.Errorf("failed to initialize module %s: %w", moduleID, err)
	}

	// Start the module
	if err := module.Start(mm.ctx); err != nil {
		mm.mu.Lock()
		mm.statuses[moduleID] = ModuleStatusError
		mm.mu.Unlock()
		return fmt.Errorf("failed to start module %s: %w", moduleID, err)
	}

	mm.mu.Lock()
	mm.statuses[moduleID] = ModuleStatusRunning
	mm.mu.Unlock()

	mm.logger.LogInfo("manager_info", fmt.Sprintf("Module started: %s", moduleID), nil)
	
	// Emit start event
	if mm.eventHandler != nil {
		mm.eventHandler.HandleModuleEvent(ModuleEvent{
			ModuleID:  moduleID,
			Type:      "module_started",
			Timestamp: time.Now(),
			Data:      map[string]interface{}{},
			Severity:  "info",
		})
	}

	return nil
}

// StopModule stops a specific module
func (mm *ModuleManagerImpl) StopModule(moduleID string) error {
	mm.mu.Lock()
	module, exists := mm.modules[moduleID]
	if !exists {
		mm.mu.Unlock()
		return fmt.Errorf("module %s not found", moduleID)
	}
	
	mm.statuses[moduleID] = ModuleStatusStopping
	mm.mu.Unlock()

	// Stop the module
	if err := module.Stop(mm.ctx); err != nil {
		mm.mu.Lock()
		mm.statuses[moduleID] = ModuleStatusError
		mm.mu.Unlock()
		return fmt.Errorf("failed to stop module %s: %w", moduleID, err)
	}

	mm.mu.Lock()
	mm.statuses[moduleID] = ModuleStatusStopped
	mm.mu.Unlock()

	mm.logger.LogInfo("manager_info", fmt.Sprintf("Module stopped: %s", moduleID), nil)
	
	// Emit stop event
	if mm.eventHandler != nil {
		mm.eventHandler.HandleModuleEvent(ModuleEvent{
			ModuleID:  moduleID,
			Type:      "module_stopped",
			Timestamp: time.Now(),
			Data:      map[string]interface{}{},
			Severity:  "info",
		})
	}

	return nil
}

// RestartModule restarts a specific module
func (mm *ModuleManagerImpl) RestartModule(moduleID string) error {
	mm.logger.LogInfo("manager_info", fmt.Sprintf("Restarting module: %s", moduleID), nil)
	
	if err := mm.StopModule(moduleID); err != nil {
		return fmt.Errorf("failed to stop module %s during restart: %w", moduleID, err)
	}
	
	// Wait a bit before restarting
	time.Sleep(100 * time.Millisecond)
	
	if err := mm.StartModule(moduleID); err != nil {
		return fmt.Errorf("failed to start module %s during restart: %w", moduleID, err)
	}
	
	mm.logger.LogInfo("manager_info", fmt.Sprintf("Module restarted: %s", moduleID), nil)
	return nil
}

// StartAllModules starts all registered modules
func (mm *ModuleManagerImpl) StartAllModules() error {
	mm.mu.RLock()
	moduleIDs := make([]string, 0, len(mm.modules))
	for id := range mm.modules {
		moduleIDs = append(moduleIDs, id)
	}
	mm.mu.RUnlock()

	var errors []error
	for _, moduleID := range moduleIDs {
		if err := mm.StartModule(moduleID); err != nil {
			errors = append(errors, fmt.Errorf("failed to start module %s: %w", moduleID, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to start some modules: %v", errors)
	}

	mm.logger.LogInfo("manager_info", "All modules started successfully", nil)
	return nil
}

// StopAllModules stops all registered modules
func (mm *ModuleManagerImpl) StopAllModules() error {
	mm.mu.RLock()
	moduleIDs := make([]string, 0, len(mm.modules))
	for id := range mm.modules {
		moduleIDs = append(moduleIDs, id)
	}
	mm.mu.RUnlock()

	var errors []error
	for _, moduleID := range moduleIDs {
		if err := mm.StopModule(moduleID); err != nil {
			errors = append(errors, fmt.Errorf("failed to stop module %s: %w", moduleID, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to stop some modules: %v", errors)
	}

	mm.logger.LogInfo("manager_info", "All modules stopped successfully", nil)
	return nil
}

// GetModuleStatus returns the status of a specific module
func (mm *ModuleManagerImpl) GetModuleStatus(moduleID string) (ModuleStatus, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	
	status, exists := mm.statuses[moduleID]
	if !exists {
		return "", fmt.Errorf("module %s not found", moduleID)
	}
	
	return status, nil
}

// GetAllModuleStatuses returns the status of all modules
func (mm *ModuleManagerImpl) GetAllModuleStatuses() map[string]ModuleStatus {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	
	statuses := make(map[string]ModuleStatus)
	for id, status := range mm.statuses {
		statuses[id] = status
	}
	return statuses
}

// GetModuleHealth checks the health of a specific module
func (mm *ModuleManagerImpl) GetModuleHealth(moduleID string) error {
	mm.mu.RLock()
	module, exists := mm.modules[moduleID]
	mm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("module %s not found", moduleID)
	}
	
	return module.HealthCheck()
}

// GetAllModuleHealth checks the health of all modules
func (mm *ModuleManagerImpl) GetAllModuleHealth() map[string]error {
	mm.mu.RLock()
	modules := make(map[string]ModuleInterface)
	for id, module := range mm.modules {
		modules[id] = module
	}
	mm.mu.RUnlock()
	
	health := make(map[string]error)
	for id, module := range modules {
		health[id] = module.HealthCheck()
	}
	
	return health
}

// SendMessageToModule sends a message to a specific module
func (mm *ModuleManagerImpl) SendMessageToModule(moduleID string, message interface{}) (interface{}, error) {
	mm.mu.RLock()
	module, exists := mm.modules[moduleID]
	mm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("module %s not found", moduleID)
	}
	
	if mm.statuses[moduleID] != ModuleStatusRunning {
		return nil, fmt.Errorf("module %s is not running", moduleID)
	}
	
	return module.HandleMessage(message)
}

// BroadcastMessage sends a message to all running modules
func (mm *ModuleManagerImpl) BroadcastMessage(message interface{}) map[string]interface{} {
	mm.mu.RLock()
	runningModules := make([]string, 0)
	for id, status := range mm.statuses {
		if status == ModuleStatusRunning {
			runningModules = append(runningModules, id)
		}
	}
	mm.mu.RUnlock()
	
	results := make(map[string]interface{})
	for _, moduleID := range runningModules {
		if response, err := mm.SendMessageToModule(moduleID, message); err != nil {
			results[moduleID] = map[string]interface{}{
				"error": err.Error(),
			}
		} else {
			results[moduleID] = response
		}
	}
	
	return results
}

// SendEventToModule sends an event to a specific module
func (mm *ModuleManagerImpl) SendEventToModule(moduleID string, event telemetry.Event) error {
	mm.mu.RLock()
	module, exists := mm.modules[moduleID]
	mm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("module %s not found", moduleID)
	}
	
	return module.SendEvent(event)
}

// BroadcastEvent sends an event to all running modules
func (mm *ModuleManagerImpl) BroadcastEvent(event telemetry.Event) error {
	mm.mu.RLock()
	runningModules := make([]string, 0)
	for id, status := range mm.statuses {
		if status == ModuleStatusRunning {
			runningModules = append(runningModules, id)
		}
	}
	mm.mu.RUnlock()
	
	var errors []error
	for _, moduleID := range runningModules {
		if err := mm.SendEventToModule(moduleID, event); err != nil {
			errors = append(errors, fmt.Errorf("failed to send event to module %s: %w", moduleID, err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("failed to send event to some modules: %v", errors)
	}
	
	return nil
}

// UpdateModuleConfig updates the configuration of a specific module
func (mm *ModuleManagerImpl) UpdateModuleConfig(moduleID string, config ModuleConfig) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	
	if _, exists := mm.modules[moduleID]; !exists {
		return fmt.Errorf("module %s not found", moduleID)
	}
	
	mm.configs[moduleID] = config
	mm.logger.LogInfo("manager_info", fmt.Sprintf("Configuration updated for module: %s", moduleID), nil)
	
	return nil
}

// GetModuleConfig returns the configuration of a specific module
func (mm *ModuleManagerImpl) GetModuleConfig(moduleID string) (ModuleConfig, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	
	config, exists := mm.configs[moduleID]
	if !exists {
		return ModuleConfig{}, fmt.Errorf("module %s not found", moduleID)
	}
	
	return config, nil
}

// ReloadModuleConfig reloads the configuration of a specific module
func (mm *ModuleManagerImpl) ReloadModuleConfig(moduleID string) error {
	mm.mu.RLock()
	module, exists := mm.modules[moduleID]
	config := mm.configs[moduleID]
	mm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("module %s not found", moduleID)
	}
	
	// Reinitialize the module with the current config
	if err := module.Initialize(mm.ctx, config); err != nil {
		return fmt.Errorf("failed to reload config for module %s: %w", moduleID, err)
	}
	
	mm.logger.LogInfo("manager_info", fmt.Sprintf("Configuration reloaded for module: %s", moduleID), nil)
	return nil
}

// DiscoverModules discovers available modules (placeholder implementation)
func (mm *ModuleManagerImpl) DiscoverModules() []string {
	// This would typically scan a modules directory or registry
	// For now, return an empty list
	return []string{}
}

// LoadModule loads a module from a path (placeholder implementation)
func (mm *ModuleManagerImpl) LoadModule(modulePath string) error {
	// This would typically load a module from a file path
	// For now, return an error indicating not implemented
	return fmt.Errorf("module loading not implemented yet")
}

// UnloadModule unloads a module (placeholder implementation)
func (mm *ModuleManagerImpl) UnloadModule(moduleID string) error {
	// This would typically unload a dynamically loaded module
	// For now, just unregister the module
	return mm.UnregisterModule(moduleID)
}

// SetEventHandler sets the event handler for module events
func (mm *ModuleManagerImpl) SetEventHandler(handler EventHandler) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.eventHandler = handler
}

// Shutdown gracefully shuts down the module manager
func (mm *ModuleManagerImpl) Shutdown() error {
	mm.logger.LogInfo("manager_info", "Shutting down module manager...", nil)
	
	// Stop all modules
	if err := mm.StopAllModules(); err != nil {
		mm.logger.LogError("manager_error", fmt.Sprintf("Error stopping modules during shutdown: %v", err), nil)
	}
	
	// Cancel context
	mm.cancel()
	
	mm.logger.LogInfo("manager_info", "Module manager shutdown complete", nil)
	return nil
}
