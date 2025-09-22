package modules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"agents/aegis/internal/communication"
	"agents/aegis/internal/telemetry"
)

// CommunicationModule provides secure communication capabilities
type CommunicationModule struct {
	*BaseModule
	connectionManager *communication.SecureConnectionManager
	messageQueue      []interface{}
	queueSize         int
	mu                sync.RWMutex
}

// NewCommunicationModule creates a new communication module
func NewCommunicationModule(logger *telemetry.Logger) *CommunicationModule {
	info := ModuleInfo{
		ID:          "communication",
		Name:        "Secure Communication Module",
		Version:     "1.0.0",
		Description: "Provides secure bidirectional communication with backend",
		Author:      "Aegis Team",
		License:     "MIT",
		Capabilities: []string{
			"secure_websocket",
			"message_queuing",
			"encryption",
			"authentication",
			"heartbeat",
		},
		Metadata: map[string]interface{}{
			"category": "communication",
			"priority": "critical",
		},
	}

	cm := &CommunicationModule{
		BaseModule: NewBaseModule(info, logger),
		messageQueue: make([]interface{}, 0),
		queueSize:    1000,
	}

	return cm
}

// Initialize initializes the communication module
func (cm *CommunicationModule) Initialize(ctx context.Context, config ModuleConfig) error {
	if err := cm.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	// Configure queue size from settings
	if queueSize, ok := config.Settings["queue_size"].(float64); ok {
		cm.queueSize = int(queueSize)
	}

	// Initialize connection manager
	var err error
	cm.connectionManager, err = communication.NewSecureConnectionManager("agent-001", "ws://localhost:8080/ws")
	if err != nil {
		cm.LogError("Failed to initialize connection manager: %v", err)
	}

	cm.LogInfo("Communication module initialized with queue size %d", cm.queueSize)
	return nil
}

// Start starts the communication module
func (cm *CommunicationModule) Start(ctx context.Context) error {
	if err := cm.BaseModule.Start(ctx); err != nil {
		return err
	}

	// Start background processes
	go cm.processMessageQueue()
	go cm.monitorConnection()

	cm.LogInfo("Communication module started")
	return nil
}

// Stop stops the communication module
func (cm *CommunicationModule) Stop(ctx context.Context) error {
	// Disconnect from backend
	if cm.connectionManager != nil {
		cm.connectionManager.Stop()
	}

	return cm.BaseModule.Stop(ctx)
}

// HandleMessage handles communication-related messages
func (cm *CommunicationModule) HandleMessage(message interface{}) (interface{}, error) {
	switch msg := message.(type) {
	case map[string]interface{}:
		switch msg["type"] {
		case "connect":
			return cm.handleConnect(msg)
		case "disconnect":
			return cm.handleDisconnect(msg)
		case "send_message":
			return cm.handleSendMessage(msg)
		case "get_status":
			return cm.handleGetStatus(msg)
		default:
			return cm.BaseModule.HandleMessage(message)
		}
	default:
		return cm.BaseModule.HandleMessage(message)
	}
}

// handleConnect handles connection requests
func (cm *CommunicationModule) handleConnect(msg map[string]interface{}) (interface{}, error) {
	endpoint, ok := msg["endpoint"].(string)
	if !ok {
		return nil, fmt.Errorf("endpoint is required")
	}

	if err := cm.connectionManager.Start(); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	cm.SetMetric("connection_status", "connected")
	cm.SetMetric("last_connection_time", time.Now().Unix())

	return map[string]interface{}{
		"status":   "connected",
		"endpoint": endpoint,
	}, nil
}

// handleDisconnect handles disconnection requests
func (cm *CommunicationModule) handleDisconnect(msg map[string]interface{}) (interface{}, error) {
	cm.connectionManager.Stop()

	cm.SetMetric("connection_status", "disconnected")
	cm.SetMetric("last_disconnection_time", time.Now().Unix())

	return map[string]interface{}{
		"status": "disconnected",
	}, nil
}

// handleSendMessage handles message sending requests
func (cm *CommunicationModule) handleSendMessage(msg map[string]interface{}) (interface{}, error) {
	messageData, ok := msg["message"]
	if !ok {
		return nil, fmt.Errorf("message is required")
	}

	// Queue the message
	cm.queueMessage(messageData)

	return map[string]interface{}{
		"status": "queued",
	}, nil
}

// handleGetStatus handles status requests
func (cm *CommunicationModule) handleGetStatus(msg map[string]interface{}) (interface{}, error) {
	status := "disconnected"
	if cm.connectionManager != nil && cm.connectionManager.IsConnectionHealthy() {
		status = "connected"
	}

	cm.mu.RLock()
	queueSize := len(cm.messageQueue)
	cm.mu.RUnlock()

	return map[string]interface{}{
		"connection_status": status,
		"queue_size":        queueSize,
		"module_status":     string(cm.GetStatus()),
	}, nil
}

// queueMessage queues a message for sending
func (cm *CommunicationModule) queueMessage(message interface{}) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if len(cm.messageQueue) >= cm.queueSize {
		// Remove oldest message if queue is full
		cm.messageQueue = cm.messageQueue[1:]
		cm.SetMetric("messages_dropped", 1)
	}

	cm.messageQueue = append(cm.messageQueue, message)
	cm.SetMetric("messages_queued", len(cm.messageQueue))
}

// processMessageQueue processes queued messages
func (cm *CommunicationModule) processMessageQueue() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-cm.GetContext().Done():
			return
		case <-ticker.C:
			cm.processQueuedMessages()
		}
	}
}

// processQueuedMessages processes messages from the queue
func (cm *CommunicationModule) processQueuedMessages() {
	if cm.connectionManager == nil || !cm.connectionManager.IsConnectionHealthy() {
		return
	}

	cm.mu.Lock()
	if len(cm.messageQueue) == 0 {
		cm.mu.Unlock()
		return
	}

	// Get the next message
	message := cm.messageQueue[0]
	cm.messageQueue = cm.messageQueue[1:]
	cm.mu.Unlock()

	// Send the message
	if err := cm.connectionManager.SendMessage("default", "event", message); err != nil {
		cm.LogError("Failed to send message: %v", err)
		cm.SetMetric("messages_failed", 1)
		
		// Re-queue the message if it failed
		cm.queueMessage(message)
	} else {
		cm.SetMetric("messages_sent", 1)
	}
}

// monitorConnection monitors the connection status
func (cm *CommunicationModule) monitorConnection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-cm.GetContext().Done():
			return
		case <-ticker.C:
			if cm.connectionManager != nil {
				if cm.connectionManager.IsConnectionHealthy() {
					cm.SetMetric("connection_healthy", 1)
				} else {
					cm.SetMetric("connection_healthy", 0)
					cm.LogWarn("Connection is not healthy")
				}
			}
		}
	}
}

// SendMessage sends a message to the backend
func (cm *CommunicationModule) SendMessage(message interface{}) error {
	if cm.connectionManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}

	return cm.connectionManager.SendMessage("default", "event", message)
}

// ReceiveMessage receives a message from the backend
func (cm *CommunicationModule) ReceiveMessage() (interface{}, error) {
	if cm.connectionManager == nil {
		return nil, fmt.Errorf("connection manager not initialized")
	}

	// This would typically be implemented with a callback or channel
	// For now, return an error indicating not implemented
	return nil, fmt.Errorf("receive message not implemented")
}

// Connect connects to the backend
func (cm *CommunicationModule) Connect(endpoint string) error {
	if cm.connectionManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}

	return cm.connectionManager.Start()
}

// Disconnect disconnects from the backend
func (cm *CommunicationModule) Disconnect() error {
	if cm.connectionManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}

	cm.connectionManager.Stop()
	return nil
}

// IsConnected checks if connected to the backend
func (cm *CommunicationModule) IsConnected() bool {
	if cm.connectionManager == nil {
		return false
	}

	return cm.connectionManager.IsConnectionHealthy()
}

// HealthCheck performs a health check
func (cm *CommunicationModule) HealthCheck() error {
	if err := cm.BaseModule.HealthCheck(); err != nil {
		return err
	}

	// Check queue health
	cm.mu.RLock()
	queueSize := len(cm.messageQueue)
	cm.mu.RUnlock()

	if queueSize > cm.queueSize*2 {
		return fmt.Errorf("message queue is too large: %d", queueSize)
	}

	return nil
}

// GetMetrics returns communication module metrics
func (cm *CommunicationModule) GetMetrics() map[string]interface{} {
	metrics := cm.BaseModule.GetMetrics()
	
	cm.mu.RLock()
	metrics["queue_size"] = len(cm.messageQueue)
	metrics["max_queue_size"] = cm.queueSize
	cm.mu.RUnlock()
	
	if cm.connectionManager != nil {
		metrics["connected"] = cm.connectionManager.IsConnectionHealthy()
	}
	
	return metrics
}
