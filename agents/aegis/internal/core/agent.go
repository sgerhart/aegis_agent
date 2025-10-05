package core

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"agents/aegis/internal/communication"
	"agents/aegis/internal/enforcement"
	"agents/aegis/internal/modules"
	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

// Agent represents the core Aegis security agent
type Agent struct {
	// Core components
	policyEngine *PolicyEngine
	ebpfManager  *EBPFManager
	enforcer     *enforcement.Enforcer
	telemetry    *telemetry.Logger
	
	// Communication
	commManager  *communication.WebSocketManager
	
	// Module system
	moduleManager *modules.ModuleManagerImpl
	moduleFactory *modules.ModuleFactoryImpl
	
	// State management
	stateManager *StateManager
	securityContinuity *SecurityContinuityChecker
	
	// Configuration
	config       *Config
	agentID      string
	
	// State management
	ctx          context.Context
	cancel       context.CancelFunc
	running      bool
	mu           sync.RWMutex
}

// Config represents the core agent configuration
type Config struct {
	AgentID       string                 `json:"agent_id"`
	BackendURL    string                 `json:"backend_url"`
	PolicyPath    string                 `json:"policy_path"`
	LogLevel      string                 `json:"log_level"`
	UpdateInterval time.Duration         `json:"update_interval"`
	EnabledModules []string              `json:"enabled_modules"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// NewAgent creates a new core agent instance
func NewAgent(config *Config) (*Agent, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	agent := &Agent{
		config:  config,
		agentID: config.AgentID,
		ctx:     ctx,
		cancel:  cancel,
		running: false,
	}
	
	// Initialize core components
	if err := agent.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}
	
	log.Printf("[core] Agent %s initialized successfully", agent.agentID)
	return agent, nil
}

// initializeComponents initializes all core agent components
func (a *Agent) initializeComponents() error {
	// Initialize telemetry logger
	a.telemetry = telemetry.NewLogger(a.config.LogLevel)
	
	// Initialize state manager
	stateManager, err := NewStateManager("", a.telemetry)
	if err != nil {
		return fmt.Errorf("failed to initialize state manager: %w", err)
	}
	a.stateManager = stateManager
	
	// Initialize eBPF manager
	ebpfManager, err := NewEBPFManager()
	if err != nil {
		return fmt.Errorf("failed to initialize eBPF manager: %w", err)
	}
	a.ebpfManager = ebpfManager
	
	// Initialize policy engine
	policyEngine, err := NewPolicyEngine(ebpfManager, a.telemetry)
	if err != nil {
		return fmt.Errorf("failed to initialize policy engine: %w", err)
	}
	a.policyEngine = policyEngine
	
	// Initialize enforcer
	enforcer, err := enforcement.NewEnforcer(ebpfManager, a.telemetry)
	if err != nil {
		return fmt.Errorf("failed to initialize enforcer: %w", err)
	}
	a.enforcer = enforcer
	
	// Initialize security continuity checker
	a.securityContinuity = NewSecurityContinuityChecker(stateManager, a.telemetry, ebpfManager, enforcer)
	
	// Communication manager will be initialized by the WebSocket communication module
	// No need to create a separate WebSocket manager here
	
	// Initialize module system
	a.moduleManager = modules.NewModuleManager(a.telemetry)
	a.moduleFactory = modules.NewModuleFactory(a.telemetry)
	
	// Provide core components to module manager
	coreComponents := &modules.CoreComponents{
		PolicyEngine: a.policyEngine, // PolicyEngine implements PolicyEngineInterface
		EBPFManager:  a.ebpfManager,
		Enforcer:     a.enforcer,
	}
	a.moduleManager.SetCoreComponents(coreComponents)
	
	// Register built-in modules
	if err := a.registerBuiltInModules(); err != nil {
		return fmt.Errorf("failed to register built-in modules: %w", err)
	}
	
	return nil
}

// registerBuiltInModules registers the built-in modules
func (a *Agent) registerBuiltInModules() error {
	// Register telemetry module
	telemetryFactory := func(config modules.ModuleConfig) (modules.ModuleInterface, error) {
		return modules.NewTelemetryModule(a.telemetry), nil
	}
	if err := a.moduleFactory.RegisterFactory("telemetry", telemetryFactory); err != nil {
		return fmt.Errorf("failed to register telemetry module factory: %w", err)
	}
	
	// Register WebSocket communication module
	websocketCommFactory := func(config modules.ModuleConfig) (modules.ModuleInterface, error) {
		return modules.NewWebSocketCommunicationModule(a.telemetry), nil
	}
	if err := a.moduleFactory.RegisterFactory("websocket_communication", websocketCommFactory); err != nil {
		return fmt.Errorf("failed to register WebSocket communication module factory: %w", err)
	}
	
	// Register legacy communication module for backward compatibility
	communicationFactory := func(config modules.ModuleConfig) (modules.ModuleInterface, error) {
		return modules.NewWebSocketCommunicationModule(a.telemetry), nil
	}
	if err := a.moduleFactory.RegisterFactory("communication", communicationFactory); err != nil {
		return fmt.Errorf("failed to register communication module factory: %w", err)
	}
	
	// Register analysis module
	analysisFactory := func(config modules.ModuleConfig) (modules.ModuleInterface, error) {
		return modules.NewAnalysisModule(a.telemetry), nil
	}
	if err := a.moduleFactory.RegisterFactory("analysis", analysisFactory); err != nil {
		return fmt.Errorf("failed to register analysis module factory: %w", err)
	}
	
	// Register observability module
	observabilityFactory := func(config modules.ModuleConfig) (modules.ModuleInterface, error) {
		return modules.NewObservabilityModule(a.telemetry), nil
	}
	if err := a.moduleFactory.RegisterFactory("observability", observabilityFactory); err != nil {
		return fmt.Errorf("failed to register observability module factory: %w", err)
	}
	
	// Register threat intelligence module
	threatIntelFactory := func(config modules.ModuleConfig) (modules.ModuleInterface, error) {
		return modules.NewThreatIntelligenceModule(a.telemetry), nil
	}
	if err := a.moduleFactory.RegisterFactory("threat_intelligence", threatIntelFactory); err != nil {
		return fmt.Errorf("failed to register threat intelligence module factory: %w", err)
	}
	
	// Register advanced policy module
	advancedPolicyFactory := func(config modules.ModuleConfig) (modules.ModuleInterface, error) {
		return modules.NewAdvancedPolicyModule(a.telemetry), nil
	}
	if err := a.moduleFactory.RegisterFactory("advanced_policy", advancedPolicyFactory); err != nil {
		return fmt.Errorf("failed to register advanced policy module factory: %w", err)
	}
	
	a.telemetry.LogInfo("agent_info", "Built-in modules registered successfully", nil)
	return nil
}

// Start starts the core agent
func (a *Agent) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	if a.running {
		return fmt.Errorf("agent is already running")
	}
	
	log.Printf("[core] Starting agent %s", a.agentID)
	
	// Initialize agent state
	capabilities := map[string]interface{}{
		"ebpf": a.ebpfManager.IsInitialized(),
		"tc":   false, // TODO: detect TC support
		"cgroup": false, // TODO: detect cgroup support
	}
	
	if err := a.stateManager.InitializeAgentState(a.agentID, "1.0.0", capabilities); err != nil {
		log.Printf("[core] Warning: failed to initialize agent state: %v", err)
	}
	
	// Perform security continuity check
	if err := a.securityContinuity.PerformStartupSecurityCheck(a.ctx); err != nil {
		log.Printf("[core] Warning: security continuity check failed: %v", err)
		// Continue startup but log the warning
	}
	
	// Communication manager will be set up after modules are initialized
	
	// Start policy engine
	if err := a.policyEngine.Start(); err != nil {
		return fmt.Errorf("failed to start policy engine: %w", err)
	}
	
	// Start enforcer
	if err := a.enforcer.Start(); err != nil {
		return fmt.Errorf("failed to start enforcer: %w", err)
	}
	
	// Start telemetry
	a.telemetry.Start()
	
	// Initialize all available modules and start enabled ones
	if err := a.initializeAllModules(); err != nil {
		log.Printf("[core] Warning: failed to initialize some modules: %v", err)
		// Continue without modules - agent can run with core functionality only
	}
	
		// Set module manager reference for all modules
		log.Printf("[core] Setting module manager reference for all modules")
		for moduleID, module := range a.moduleManager.GetAllModules() {
			// Check if module has a SetModuleManager method (for modules that embed BaseModule)
			if setter, ok := module.(interface{ SetModuleManager(modules.ModuleManager) }); ok {
				setter.SetModuleManager(a.moduleManager)
				log.Printf("[core] Module manager reference set for module: %s", moduleID)
			} else {
				log.Printf("[core] Warning: module %s does not support SetModuleManager", moduleID)
			}
		}

		// Set up communication manager from WebSocket communication module
		log.Printf("[core] Looking for websocket_communication module in module manager")
		if websocketModule, exists := a.moduleManager.GetModule("websocket_communication"); exists && websocketModule != nil {
			log.Printf("[core] Found websocket_communication module, setting up communication manager")
			if wcm, ok := websocketModule.(*modules.WebSocketCommunicationModule); ok {
				a.commManager = wcm.GetWebSocketManager()
				log.Printf("[core] Communication manager set up from WebSocket communication module")
			} else {
				log.Printf("[core] Warning: websocket_communication module is not of expected type")
			}
		} else {
			log.Printf("[core] Warning: websocket_communication module not found in module manager")
		}
	
	// Start communication manager
	if a.commManager != nil {
		if err := a.commManager.Start(); err != nil {
			log.Printf("[core] Warning: failed to start communication manager: %v", err)
		}
	}
	
	// Start enabled modules
	if err := a.startEnabledModules(); err != nil {
		log.Printf("[core] Warning: failed to start some modules: %v", err)
		// Continue without modules - agent can run with core functionality only
	}
	
	a.running = true
	log.Printf("[core] Agent %s started successfully", a.agentID)
	
	// Start main agent loop
	go a.mainLoop()
	
	return nil
}

// initializeAllModules initializes all available modules (but doesn't start them)
func (a *Agent) initializeAllModules() error {
	// List of all available modules
	allModules := []string{
		"telemetry",
		"websocket_communication", 
		"observability",
		"analysis",
		"threat_intelligence",
		"advanced_policy",
	}
	
	for _, moduleType := range allModules {
		// Create module instance with backend URL for WebSocket communication module
		settings := make(map[string]interface{})
		if moduleType == "websocket_communication" {
			settings["backend_url"] = a.config.BackendURL
			settings["agent_id"] = a.agentID
		}
		
		module, err := a.moduleFactory.CreateModule(moduleType, modules.ModuleConfig{
			Enabled:  false, // Start disabled by default
			Priority: 1,
			Settings: settings,
			Environment: make(map[string]string),
		})
		if err != nil {
			log.Printf("[core] Warning: failed to create module %s: %v", moduleType, err)
			continue
		}
		
		// Register module with config (disabled by default)
		moduleConfig := modules.ModuleConfig{
			Enabled:  false, // Will be enabled by backend or startEnabledModules
			Priority: 1,
			Settings: settings,
			Environment: make(map[string]string),
		}
		if err := a.moduleManager.RegisterModuleWithConfig(module, moduleConfig); err != nil {
			log.Printf("[core] Warning: failed to register module %s: %v", moduleType, err)
			continue
		}
		
		log.Printf("[core] Module %s registered (disabled by default)", moduleType)
	}
	
	return nil
}

// startEnabledModules starts all enabled modules
func (a *Agent) startEnabledModules() error {
	// Get enabled modules from config
	enabledModules := a.config.EnabledModules
	if len(enabledModules) == 0 {
		enabledModules = []string{"telemetry", "websocket_communication", "observability", "advanced_policy"}
	}
	
	for _, moduleType := range enabledModules {
		// Check if module is already registered
		if _, exists := a.moduleManager.GetModule(moduleType); exists {
			// Enable the module
			config, err := a.moduleManager.GetModuleConfig(moduleType)
			if err != nil {
				log.Printf("[core] Warning: failed to get config for module %s: %v", moduleType, err)
				continue
			}
			
			// Update config to enable the module
			config.Enabled = true
			if err := a.moduleManager.UpdateModuleConfig(moduleType, config); err != nil {
				log.Printf("[core] Warning: failed to enable module %s: %v", moduleType, err)
				continue
			}
			
			// Start the module
			if err := a.moduleManager.StartModule(moduleType); err != nil {
				log.Printf("[core] Warning: failed to start module %s: %v", moduleType, err)
				continue
			}
			
			log.Printf("[core] Module %s enabled and started successfully", moduleType)
		} else {
			log.Printf("[core] Warning: module %s not found in registered modules", moduleType)
		}
	}
	
	return nil
}

// Stop stops the core agent
func (a *Agent) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	if !a.running {
		return fmt.Errorf("agent is not running")
	}
	
	log.Printf("[core] Stopping agent %s", a.agentID)
	
	// Cancel context to stop all goroutines
	a.cancel()
	
	// Stop components in reverse order
	if a.enforcer != nil {
		if err := a.enforcer.Stop(); err != nil {
			log.Printf("[core] Error stopping enforcer: %v", err)
		}
	}
	
	if a.policyEngine != nil {
		if err := a.policyEngine.Stop(); err != nil {
			log.Printf("[core] Error stopping policy engine: %v", err)
		}
	}
	
	if a.commManager != nil {
		if err := a.commManager.Stop(); err != nil {
			log.Printf("[core] Error stopping communication manager: %v", err)
		}
	}
	
	// Stop all modules
	if a.moduleManager != nil {
		if err := a.moduleManager.StopAllModules(); err != nil {
			log.Printf("[core] Error stopping modules: %v", err)
		}
		if err := a.moduleManager.Shutdown(); err != nil {
			log.Printf("[core] Error shutting down module manager: %v", err)
		}
	}
	
	if a.telemetry != nil {
		a.telemetry.Stop()
	}
	
	if a.ebpfManager != nil {
		if err := a.ebpfManager.Close(); err != nil {
			log.Printf("[core] Error closing eBPF manager: %v", err)
		}
	}
	
	// Save state before shutdown
	if a.stateManager != nil {
		if err := a.stateManager.Shutdown(); err != nil {
			log.Printf("[core] Warning: failed to save state on shutdown: %v", err)
		}
	}
	
	a.running = false
	log.Printf("[core] Agent %s stopped successfully", a.agentID)
	
	return nil
}

// mainLoop is the main agent processing loop
func (a *Agent) mainLoop() {
	ticker := time.NewTicker(a.config.UpdateInterval)
	defer ticker.Stop()
	
	log.Printf("[core] Main loop started for agent %s", a.agentID)
	
	for {
		select {
		case <-a.ctx.Done():
			log.Printf("[core] Main loop stopped for agent %s", a.agentID)
			return
		case <-ticker.C:
			if err := a.processCycle(); err != nil {
				log.Printf("[core] Error in processing cycle: %v", err)
				a.telemetry.LogError("processing_cycle", err.Error(), nil)
			}
		}
	}
}

// processCycle performs one processing cycle
func (a *Agent) processCycle() error {
	// 1. Update policies from backend (if connected)
	if a.commManager != nil {
		if err := a.updatePoliciesFromBackend(); err != nil {
			log.Printf("[core] Warning: failed to update policies from backend: %v", err)
		}
	}
	
	// 2. Apply pending policies
	if err := a.policyEngine.ProcessPendingPolicies(); err != nil {
		return fmt.Errorf("failed to process pending policies: %w", err)
	}
	
	// 3. Enforce active policies
	if err := a.enforcer.EnforcePolicies(); err != nil {
		return fmt.Errorf("failed to enforce policies: %w", err)
	}
	
	// 4. Send status update (if connected)
	if a.commManager != nil {
		if err := a.sendStatusUpdate(); err != nil {
			log.Printf("[core] Warning: failed to send status update: %v", err)
		}
	}
	
	return nil
}

// updatePoliciesFromBackend retrieves and applies policies from backend
func (a *Agent) updatePoliciesFromBackend() error {
	// This would typically involve:
	// 1. Requesting policy updates from backend
	// 2. Validating received policies
	// 3. Applying valid policies
	// For now, this is a placeholder
	return nil
}

// sendStatusUpdate sends agent status to backend
func (a *Agent) sendStatusUpdate() error {
	status := &models.AgentStatus{
		AgentID:     a.agentID,
		Status:      "running",
		LastUpdate:  time.Now(),
		PolicyCount: a.policyEngine.GetPolicyCount(),
		Metadata:    make(map[string]interface{}),
	}
	
	if a.commManager != nil {
		return a.commManager.SendMessage("agent.status", communication.MessageTypeEvent, status)
	}
	
	return nil
}

// GetStatus returns the current agent status
func (a *Agent) GetStatus() *models.AgentStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	return &models.AgentStatus{
		AgentID:     a.agentID,
		Status:      a.getRunningStatus(),
		LastUpdate:  time.Now(),
		PolicyCount: a.policyEngine.GetPolicyCount(),
		Metadata:    a.getMetadata(),
	}
}

// getRunningStatus returns the current running status
func (a *Agent) getRunningStatus() string {
	if a.running {
		return "running"
	}
	return "stopped"
}

// getMetadata returns agent metadata
func (a *Agent) getMetadata() map[string]interface{} {
	metadata := make(map[string]interface{})
	
	metadata["agent_id"] = a.agentID
	metadata["backend_connected"] = a.commManager != nil
	metadata["ebpf_enabled"] = a.ebpfManager != nil
	metadata["policy_engine_active"] = a.policyEngine != nil
	metadata["enforcer_active"] = a.enforcer != nil
	
	return metadata
}

// IsRunning returns whether the agent is currently running
func (a *Agent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// GetAgentID returns the agent ID
func (a *Agent) GetAgentID() string {
	return a.agentID
}

// GetConfig returns a copy of the agent configuration
func (a *Agent) GetConfig() *Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	// Return a copy to prevent external modifications
	configCopy := *a.config
	return &configCopy
}

// GetModuleManager returns the module manager
func (a *Agent) GetModuleManager() modules.ModuleManager {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.moduleManager
}

// GetMetrics returns agent metrics
func (a *Agent) GetMetrics() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	metrics := make(map[string]interface{})
	
	// Add basic agent metrics
	metrics["agent_id"] = a.agentID
	metrics["running"] = a.running
	metrics["uptime_seconds"] = a.GetUptime().Seconds()
	metrics["log_level"] = a.config.LogLevel
	metrics["backend_url"] = a.config.BackendURL
	
	// Add module metrics if available
	if a.moduleManager != nil {
		statuses := a.moduleManager.GetAllModuleStatuses()
		metrics["total_modules"] = len(statuses)
		
		runningCount := 0
		for _, status := range statuses {
			if status == "running" {
				runningCount++
			}
		}
		metrics["running_modules"] = runningCount
	}
	
	// Add communication metrics if available
	if a.commManager != nil {
		// Add communication-specific metrics here
		metrics["communication_connected"] = true // Simplified
	}
	
	return metrics
}

// GetUptime returns the agent uptime
func (a *Agent) GetUptime() time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	if !a.running {
		return 0
	}
	
	// Get uptime from state manager
	if a.stateManager != nil {
		agentState := a.stateManager.GetAgentState()
		if !agentState.LastStartup.IsZero() {
			return time.Since(agentState.LastStartup)
		}
	}
	
	// Fallback to simple calculation
	return time.Since(time.Now().Add(-time.Hour)) // Simplified
}

// GetSecurityStatus returns the current security status
func (a *Agent) GetSecurityStatus() map[string]interface{} {
	if a.securityContinuity != nil {
		return a.securityContinuity.GetSecurityStatus()
	}
	
	return map[string]interface{}{
		"error": "security continuity checker not initialized",
	}
}

// GetStateSummary returns a summary of the agent state
func (a *Agent) GetStateSummary() map[string]interface{} {
	if a.stateManager != nil {
		return a.stateManager.GetStateSummary()
	}
	
	return map[string]interface{}{
		"error": "state manager not initialized",
	}
}

// HealthCheck performs a health check on the agent
func (a *Agent) HealthCheck() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	if !a.running {
		return fmt.Errorf("agent is not running")
	}
	
	// Check module manager health
	if a.moduleManager != nil {
		// Check if any critical modules are down
		statuses := a.moduleManager.GetAllModuleStatuses()
		for moduleID, status := range statuses {
			if moduleID == "websocket_communication" && status != "running" {
				return fmt.Errorf("critical module %s is not running", moduleID)
			}
		}
	}
	
	// Check communication health
	if a.commManager != nil {
		// Add communication health check here
	}
	
	return nil
}
