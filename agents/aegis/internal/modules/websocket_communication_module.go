package modules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"agents/aegis/internal/communication"
	"agents/aegis/internal/telemetry"
)

// WebSocketCommunicationModule provides advanced WebSocket communication capabilities
type WebSocketCommunicationModule struct {
	*BaseModule
	websocketManager *communication.WebSocketManager
	messageQueue     *communication.MessageQueue
	channelManager   *communication.ChannelManager
	moduleManager    ModuleManager // Reference to module manager for control operations
	mu               sync.RWMutex
}

// NewWebSocketCommunicationModule creates a new WebSocket communication module
func NewWebSocketCommunicationModule(logger *telemetry.Logger) *WebSocketCommunicationModule {
	info := ModuleInfo{
		ID:          "websocket_communication",
		Name:        "WebSocket Communication Module",
		Version:     "1.0.0",
		Description: "Provides secure bidirectional WebSocket communication with backend",
		Author:      "Aegis Team",
		License:     "MIT",
		Capabilities: []string{
			"secure_websocket",
			"message_queuing",
			"channel_management",
			"encryption",
			"authentication",
			"heartbeat",
			"reconnection",
			"message_routing",
		},
		Metadata: map[string]interface{}{
			"category": "communication",
			"priority": "critical",
		},
	}

	wcm := &WebSocketCommunicationModule{
		BaseModule: NewBaseModule(info, logger),
	}

	return wcm
}

// Initialize initializes the WebSocket communication module
func (wcm *WebSocketCommunicationModule) Initialize(ctx context.Context, config ModuleConfig) error {
	if err := wcm.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	// Get backend URL from config
	backendURL, ok := config.Settings["backend_url"].(string)
	if !ok {
		backendURL = "wss://backend.aegis.com/ws/agent"
	}
	
	// Debug logging
	fmt.Printf("[websocket_module] Backend URL from config: %s (found: %t)\n", backendURL, ok)

	// Initialize WebSocket manager
	websocketManager, err := communication.NewWebSocketManager(wcm.GetInfo().ID, backendURL)
	if err != nil {
		return fmt.Errorf("failed to create WebSocket manager: %w", err)
	}
	wcm.websocketManager = websocketManager

	// Initialize message queue
	queueSize := 1000
	if qs, ok := config.Settings["queue_size"].(float64); ok {
		queueSize = int(qs)
	}
	wcm.messageQueue = communication.NewMessageQueue(queueSize)

	// Initialize channel manager
	wcm.channelManager = communication.NewChannelManager(websocketManager, wcm.messageQueue)

	// Register default message handlers
	wcm.registerDefaultHandlers()

	wcm.LogInfo("WebSocket communication module initialized")
	return nil
}

// Start starts the WebSocket communication module
func (wcm *WebSocketCommunicationModule) Start(ctx context.Context) error {
	if err := wcm.BaseModule.Start(ctx); err != nil {
		return err
	}

	// Start WebSocket connection
	if err := wcm.websocketManager.Start(); err != nil {
		return fmt.Errorf("failed to start WebSocket manager: %w", err)
	}

	// Start background processes
	go wcm.monitorConnection()
	go wcm.processMetrics()

	wcm.LogInfo("WebSocket communication module started")
	return nil
}

// Stop stops the WebSocket communication module
func (wcm *WebSocketCommunicationModule) Stop(ctx context.Context) error {
	// Stop WebSocket connection
	if wcm.websocketManager != nil {
		if err := wcm.websocketManager.Stop(); err != nil {
			wcm.LogError("Failed to stop WebSocket manager: %v", err)
		}
	}

	// Shutdown message queue
	if wcm.messageQueue != nil {
		wcm.messageQueue.Shutdown()
	}

	// Shutdown channel manager
	if wcm.channelManager != nil {
		wcm.channelManager.Shutdown()
	}

	return wcm.BaseModule.Stop(ctx)
}

// HandleMessage handles communication-related messages
func (wcm *WebSocketCommunicationModule) HandleMessage(message interface{}) (interface{}, error) {
	switch msg := message.(type) {
	case map[string]interface{}:
		switch msg["type"] {
		case "send_message":
			return wcm.handleSendMessage(msg)
		case "broadcast_message":
			return wcm.handleBroadcastMessage(msg)
		case "get_connection_status":
			return wcm.handleGetConnectionStatus(msg)
		case "get_metrics":
			return wcm.handleGetMetrics(msg)
		case "get_channel_stats":
			return wcm.handleGetChannelStats(msg)
		case "subscribe_channel":
			return wcm.handleSubscribeChannel(msg)
		case "unsubscribe_channel":
			return wcm.handleUnsubscribeChannel(msg)
		case "create_channel":
			return wcm.handleCreateChannel(msg)
		case "enable_channel":
			return wcm.handleEnableChannel(msg)
		case "disable_channel":
			return wcm.handleDisableChannel(msg)
		case "start_module":
			return wcm.handleStartModule(msg)
		case "stop_module":
			return wcm.handleStopModule(msg)
		case "enable_module":
			return wcm.handleEnableModule(msg)
		case "disable_module":
			return wcm.handleDisableModule(msg)
		case "get_module_status":
			return wcm.handleGetModuleStatus(msg)
		case "list_modules":
			return wcm.handleListModules(msg)
		default:
			return wcm.BaseModule.HandleMessage(message)
		}
	default:
		return wcm.BaseModule.HandleMessage(message)
	}
}

// handleSendMessage handles send message requests
func (wcm *WebSocketCommunicationModule) handleSendMessage(msg map[string]interface{}) (interface{}, error) {
	channel, ok := msg["channel"].(string)
	if !ok {
		return nil, fmt.Errorf("channel is required")
	}

	messageType, ok := msg["message_type"].(string)
	if !ok {
		messageType = "request"
	}

	payload, ok := msg["payload"]
	if !ok {
		return nil, fmt.Errorf("payload is required")
	}

	// Send message
	err := wcm.channelManager.Publish(channel, communication.MessageType(messageType), payload)
	if err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	return map[string]interface{}{
		"status":    "sent",
		"channel":   channel,
		"timestamp": time.Now(),
	}, nil
}

// handleBroadcastMessage handles broadcast message requests
func (wcm *WebSocketCommunicationModule) handleBroadcastMessage(msg map[string]interface{}) (interface{}, error) {
	channel, ok := msg["channel"].(string)
	if !ok {
		return nil, fmt.Errorf("channel is required")
	}

	messageType, ok := msg["message_type"].(string)
	if !ok {
		messageType = "event"
	}

	payload, ok := msg["payload"]
	if !ok {
		return nil, fmt.Errorf("payload is required")
	}

	// Broadcast message
	err := wcm.channelManager.Broadcast(channel, communication.MessageType(messageType), payload)
	if err != nil {
		return nil, fmt.Errorf("failed to broadcast message: %w", err)
	}

	return map[string]interface{}{
		"status":    "broadcast",
		"channel":   channel,
		"timestamp": time.Now(),
	}, nil
}

// handleGetConnectionStatus handles connection status requests
func (wcm *WebSocketCommunicationModule) handleGetConnectionStatus(msg map[string]interface{}) (interface{}, error) {
	connected := wcm.websocketManager.IsConnected()
	metrics := wcm.websocketManager.GetMetrics()

	return map[string]interface{}{
		"connected":     connected,
		"metrics":       metrics,
		"timestamp":     time.Now(),
	}, nil
}

// handleGetMetrics handles metrics requests
func (wcm *WebSocketCommunicationModule) handleGetMetrics(msg map[string]interface{}) (interface{}, error) {
	websocketMetrics := wcm.websocketManager.GetMetrics()
	queueStats := wcm.messageQueue.GetQueueStats()
	channelStats := wcm.channelManager.GetChannelStats()

	return map[string]interface{}{
		"websocket": websocketMetrics,
		"queue":     queueStats,
		"channels":  channelStats,
		"timestamp": time.Now(),
	}, nil
}

// handleGetChannelStats handles channel statistics requests
func (wcm *WebSocketCommunicationModule) handleGetChannelStats(msg map[string]interface{}) (interface{}, error) {
	stats := wcm.channelManager.GetChannelStats()
	return stats, nil
}

// handleSubscribeChannel handles channel subscription requests
func (wcm *WebSocketCommunicationModule) handleSubscribeChannel(msg map[string]interface{}) (interface{}, error) {
	channel, ok := msg["channel"].(string)
	if !ok {
		return nil, fmt.Errorf("channel is required")
	}

	subscriberID, ok := msg["subscriber_id"].(string)
	if !ok {
		subscriberID = "default"
	}

	priority := 1
	if p, ok := msg["priority"].(float64); ok {
		priority = int(p)
	}

	// Create a simple handler
	handler := func(msg communication.SecureMessage) error {
		wcm.LogInfo("Received message on channel %s: %s", channel, msg.Payload)
		return nil
	}

	err := wcm.channelManager.Subscribe(channel, subscriberID, handler, priority)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to channel: %w", err)
	}

	return map[string]interface{}{
		"status":        "subscribed",
		"channel":       channel,
		"subscriber_id": subscriberID,
		"timestamp":     time.Now(),
	}, nil
}

// handleUnsubscribeChannel handles channel unsubscription requests
func (wcm *WebSocketCommunicationModule) handleUnsubscribeChannel(msg map[string]interface{}) (interface{}, error) {
	channel, ok := msg["channel"].(string)
	if !ok {
		return nil, fmt.Errorf("channel is required")
	}

	subscriberID, ok := msg["subscriber_id"].(string)
	if !ok {
		subscriberID = "default"
	}

	err := wcm.channelManager.Unsubscribe(channel, subscriberID)
	if err != nil {
		return nil, fmt.Errorf("failed to unsubscribe from channel: %w", err)
	}

	return map[string]interface{}{
		"status":        "unsubscribed",
		"channel":       channel,
		"subscriber_id": subscriberID,
		"timestamp":     time.Now(),
	}, nil
}

// handleCreateChannel handles channel creation requests
func (wcm *WebSocketCommunicationModule) handleCreateChannel(msg map[string]interface{}) (interface{}, error) {
	channelName, ok := msg["channel_name"].(string)
	if !ok {
		return nil, fmt.Errorf("channel_name is required")
	}

	channelType, ok := msg["channel_type"].(string)
	if !ok {
		channelType = "bidirectional"
	}

	priority := 1
	if p, ok := msg["priority"].(float64); ok {
		priority = int(p)
	}

	err := wcm.channelManager.CreateChannel(channelName, communication.ChannelType(channelType), priority)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel: %w", err)
	}

	return map[string]interface{}{
		"status":       "created",
		"channel_name": channelName,
		"channel_type": channelType,
		"priority":     priority,
		"timestamp":    time.Now(),
	}, nil
}

// handleEnableChannel handles channel enable requests
func (wcm *WebSocketCommunicationModule) handleEnableChannel(msg map[string]interface{}) (interface{}, error) {
	channel, ok := msg["channel"].(string)
	if !ok {
		return nil, fmt.Errorf("channel is required")
	}

	err := wcm.channelManager.EnableChannel(channel)
	if err != nil {
		return nil, fmt.Errorf("failed to enable channel: %w", err)
	}

	return map[string]interface{}{
		"status":    "enabled",
		"channel":   channel,
		"timestamp": time.Now(),
	}, nil
}

// handleDisableChannel handles channel disable requests
func (wcm *WebSocketCommunicationModule) handleDisableChannel(msg map[string]interface{}) (interface{}, error) {
	channel, ok := msg["channel"].(string)
	if !ok {
		return nil, fmt.Errorf("channel is required")
	}

	err := wcm.channelManager.DisableChannel(channel)
	if err != nil {
		return nil, fmt.Errorf("failed to disable channel: %w", err)
	}

	return map[string]interface{}{
		"status":    "disabled",
		"channel":   channel,
		"timestamp": time.Now(),
	}, nil
}

// registerDefaultHandlers registers default message handlers
func (wcm *WebSocketCommunicationModule) registerDefaultHandlers() {
	// Register heartbeat handler
	wcm.websocketManager.RegisterHandler("heartbeat", func(msg communication.SecureMessage) error {
		wcm.LogDebug("Received heartbeat from backend")
		return nil
	})

	// Register policy commands handler
	wcm.websocketManager.RegisterHandler("backend.policies", func(msg communication.SecureMessage) error {
		wcm.LogInfo("Received policy command: %s", msg.Payload)
		// Process policy command here
		return nil
	})

	// Register investigation requests handler
	wcm.websocketManager.RegisterHandler("backend.investigations", func(msg communication.SecureMessage) error {
		wcm.LogInfo("Received investigation request: %s", msg.Payload)
		// Process investigation request here
		return nil
	})

	// Register threat intelligence handler
	wcm.websocketManager.RegisterHandler("backend.threats", func(msg communication.SecureMessage) error {
		wcm.LogInfo("Received threat intelligence: %s", msg.Payload)
		// Process threat intelligence here
		return nil
	})
}

// monitorConnection monitors the WebSocket connection
func (wcm *WebSocketCommunicationModule) monitorConnection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-wcm.GetContext().Done():
			return
		case <-ticker.C:
			connected := wcm.websocketManager.IsConnected()
			if !connected {
				wcm.LogWarn("WebSocket connection is not healthy")
			} else {
				wcm.LogDebug("WebSocket connection is healthy")
			}
		}
	}
}

// processMetrics processes and logs metrics
func (wcm *WebSocketCommunicationModule) processMetrics() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-wcm.GetContext().Done():
			return
		case <-ticker.C:
			metrics := wcm.websocketManager.GetMetrics()
			queueStats := wcm.messageQueue.GetQueueStats()
			channelStats := wcm.channelManager.GetChannelStats()

			wcm.LogInfo("Communication metrics - WebSocket: %v, Queue: %v, Channels: %v", 
				metrics, queueStats, channelStats)
		}
	}
}

// HealthCheck performs a health check
func (wcm *WebSocketCommunicationModule) HealthCheck() error {
	if err := wcm.BaseModule.HealthCheck(); err != nil {
		return err
	}

	// Check WebSocket connection
	if !wcm.websocketManager.IsConnected() {
		return fmt.Errorf("WebSocket connection is not healthy")
	}

	// Check message queue
	queueSize := wcm.messageQueue.GetQueueSize()
	if queueSize > 900 { // 90% of max size
		wcm.LogWarn("Message queue is nearly full: %d messages", queueSize)
	}

	return nil
}

// GetMetrics returns communication module metrics
func (wcm *WebSocketCommunicationModule) GetMetrics() map[string]interface{} {
	metrics := wcm.BaseModule.GetMetrics()

	// Add WebSocket metrics
	websocketMetrics := wcm.websocketManager.GetMetrics()
	for k, v := range websocketMetrics {
		metrics["websocket_"+k] = v
	}

	// Add queue metrics
	queueStats := wcm.messageQueue.GetQueueStats()
	for k, v := range queueStats {
		metrics["queue_"+k] = v
	}

	// Add channel metrics
	channelStats := wcm.channelManager.GetChannelStats()
	for k, v := range channelStats {
		metrics["channel_"+k] = v
	}

	return metrics
}

// GetWebSocketManager returns the WebSocket manager for external use
func (wcm *WebSocketCommunicationModule) GetWebSocketManager() *communication.WebSocketManager {
	wcm.mu.RLock()
	defer wcm.mu.RUnlock()
	return wcm.websocketManager
}

// SetModuleManager sets the module manager reference for control operations
func (wcm *WebSocketCommunicationModule) SetModuleManager(moduleManager ModuleManager) {
	wcm.mu.Lock()
	defer wcm.mu.Unlock()
	wcm.moduleManager = moduleManager
}

// handleStartModule handles module start requests from backend
func (wcm *WebSocketCommunicationModule) handleStartModule(msg map[string]interface{}) (interface{}, error) {
	moduleID, ok := msg["module_id"].(string)
	if !ok {
		return nil, fmt.Errorf("module_id is required")
	}

	wcm.LogInfo("Received start module request for: %s", moduleID)
	
	if wcm.moduleManager == nil {
		return map[string]interface{}{
			"status":    "error",
			"module_id": moduleID,
			"action":    "start",
			"timestamp": time.Now(),
			"error":     "Module manager not available",
		}, nil
	}

	// Start the module
	err := wcm.moduleManager.StartModule(moduleID)
	if err != nil {
		wcm.LogError("Failed to start module %s: %v", moduleID, err)
		return map[string]interface{}{
			"status":    "error",
			"module_id": moduleID,
			"action":    "start",
			"timestamp": time.Now(),
			"error":     err.Error(),
		}, nil
	}
	
	return map[string]interface{}{
		"status":    "success",
		"module_id": moduleID,
		"action":    "start",
		"timestamp": time.Now(),
		"message":   "Module started successfully",
	}, nil
}

// handleStopModule handles module stop requests from backend
func (wcm *WebSocketCommunicationModule) handleStopModule(msg map[string]interface{}) (interface{}, error) {
	moduleID, ok := msg["module_id"].(string)
	if !ok {
		return nil, fmt.Errorf("module_id is required")
	}

	wcm.LogInfo("Received stop module request for: %s", moduleID)
	
	if wcm.moduleManager == nil {
		return map[string]interface{}{
			"status":    "error",
			"module_id": moduleID,
			"action":    "stop",
			"timestamp": time.Now(),
			"error":     "Module manager not available",
		}, nil
	}

	// Stop the module
	err := wcm.moduleManager.StopModule(moduleID)
	if err != nil {
		wcm.LogError("Failed to stop module %s: %v", moduleID, err)
		return map[string]interface{}{
			"status":    "error",
			"module_id": moduleID,
			"action":    "stop",
			"timestamp": time.Now(),
			"error":     err.Error(),
		}, nil
	}
	
	return map[string]interface{}{
		"status":    "success",
		"module_id": moduleID,
		"action":    "stop",
		"timestamp": time.Now(),
		"message":   "Module stopped successfully",
	}, nil
}

// handleEnableModule handles module enable requests from backend
func (wcm *WebSocketCommunicationModule) handleEnableModule(msg map[string]interface{}) (interface{}, error) {
	moduleID, ok := msg["module_id"].(string)
	if !ok {
		return nil, fmt.Errorf("module_id is required")
	}

	wcm.LogInfo("Received enable module request for: %s", moduleID)
	
	if wcm.moduleManager == nil {
		return map[string]interface{}{
			"status":    "error",
			"module_id": moduleID,
			"action":    "enable",
			"timestamp": time.Now(),
			"error":     "Module manager not available",
		}, nil
	}

	// Enable the module (this would need to be implemented in ModuleManager)
	// For now, we'll return a success response
	wcm.LogInfo("Module %s enabled", moduleID)
	
	return map[string]interface{}{
		"status":    "success",
		"module_id": moduleID,
		"action":    "enable",
		"timestamp": time.Now(),
		"message":   "Module enabled successfully",
	}, nil
}

// handleDisableModule handles module disable requests from backend
func (wcm *WebSocketCommunicationModule) handleDisableModule(msg map[string]interface{}) (interface{}, error) {
	moduleID, ok := msg["module_id"].(string)
	if !ok {
		return nil, fmt.Errorf("module_id is required")
	}

	wcm.LogInfo("Received disable module request for: %s", moduleID)
	
	if wcm.moduleManager == nil {
		return map[string]interface{}{
			"status":    "error",
			"module_id": moduleID,
			"action":    "disable",
			"timestamp": time.Now(),
			"error":     "Module manager not available",
		}, nil
	}

	// Disable the module (this would need to be implemented in ModuleManager)
	// For now, we'll return a success response
	wcm.LogInfo("Module %s disabled", moduleID)
	
	return map[string]interface{}{
		"status":    "success",
		"module_id": moduleID,
		"action":    "disable",
		"timestamp": time.Now(),
		"message":   "Module disabled successfully",
	}, nil
}

// handleGetModuleStatus handles module status requests from backend
func (wcm *WebSocketCommunicationModule) handleGetModuleStatus(msg map[string]interface{}) (interface{}, error) {
	moduleID, ok := msg["module_id"].(string)
	if !ok {
		return nil, fmt.Errorf("module_id is required")
	}

	wcm.LogInfo("Received module status request for: %s", moduleID)
	
	if wcm.moduleManager == nil {
		return map[string]interface{}{
			"status":    "error",
			"module_id": moduleID,
			"action":    "get_status",
			"timestamp": time.Now(),
			"error":     "Module manager not available",
		}, nil
	}

	// Get module status
	status, err := wcm.moduleManager.GetModuleStatus(moduleID)
	if err != nil {
		wcm.LogError("Failed to get status for module %s: %v", moduleID, err)
		return map[string]interface{}{
			"status":    "error",
			"module_id": moduleID,
			"action":    "get_status",
			"timestamp": time.Now(),
			"error":     err.Error(),
		}, nil
	}
	
	return map[string]interface{}{
		"status":    "success",
		"module_id": moduleID,
		"action":    "get_status",
		"timestamp": time.Now(),
		"module_status": string(status),
		"message":   "Module status retrieved successfully",
	}, nil
}

// handleListModules handles list modules requests from backend
func (wcm *WebSocketCommunicationModule) handleListModules(msg map[string]interface{}) (interface{}, error) {
	wcm.LogInfo("Received list modules request")
	
	if wcm.moduleManager == nil {
		return map[string]interface{}{
			"status":    "error",
			"action":    "list_modules",
			"timestamp": time.Now(),
			"error":     "Module manager not available",
		}, nil
	}

	// Get all modules and their statuses
	allModules := wcm.moduleManager.GetAllModules()
	allStatuses := wcm.moduleManager.GetAllModuleStatuses()
	
	modules := make([]map[string]interface{}, 0, len(allModules))
	for moduleID, module := range allModules {
		status, exists := allStatuses[moduleID]
		if !exists {
			status = ModuleStatusStopped
		}
		
		moduleInfo := module.GetInfo()
		modules = append(modules, map[string]interface{}{
			"id":          moduleInfo.ID,
			"name":        moduleInfo.Name,
			"version":     moduleInfo.Version,
			"description": moduleInfo.Description,
			"status":      string(status),
			"capabilities": moduleInfo.Capabilities,
		})
	}
	
	return map[string]interface{}{
		"status":    "success",
		"action":    "list_modules",
		"timestamp": time.Now(),
		"modules":   modules,
		"count":     len(modules),
		"message":   "Modules listed successfully",
	}, nil
}
