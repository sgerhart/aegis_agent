package communication

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ChannelManager manages communication channels
type ChannelManager struct {
	channels      map[string]*Channel
	websocketMgr  *WebSocketManager
	messageQueue  *MessageQueue
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// Channel represents a communication channel
type Channel struct {
	Name        string                 `json:"name"`
	Type        ChannelType            `json:"type"`
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	Subscribers []ChannelSubscriber    `json:"subscribers"`
	Metadata    map[string]interface{} `json:"metadata"`
	mu          sync.RWMutex
}

// ChannelType represents the type of channel
type ChannelType string

const (
	ChannelTypeAgentToBackend ChannelType = "agent_to_backend"
	ChannelTypeBackendToAgent ChannelType = "backend_to_agent"
	ChannelTypeBidirectional  ChannelType = "bidirectional"
)

// ChannelSubscriber represents a channel subscriber
type ChannelSubscriber struct {
	ID          string                 `json:"id"`
	Handler     MessageHandler         `json:"-"`
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewChannelManager creates a new channel manager
func NewChannelManager(websocketMgr *WebSocketManager, messageQueue *MessageQueue) *ChannelManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	cm := &ChannelManager{
		channels:     make(map[string]*Channel),
		websocketMgr: websocketMgr,
		messageQueue: messageQueue,
		ctx:          ctx,
		cancel:       cancel,
	}
	
	// Initialize default channels
	cm.initializeDefaultChannels()
	
	return cm
}

// initializeDefaultChannels initializes default communication channels
func (cm *ChannelManager) initializeDefaultChannels() {
	// Agent to Backend channels
	agentToBackendChannels := []struct {
		name     string
		priority int
	}{
		{"policies", 1},
		{"anomalies", 2},
		{"threats", 2},
		{"processes", 3},
		{"dependencies", 3},
		{"tests", 4},
		{"rollbacks", 4},
		{"heartbeat", 5},
		{"status", 5},
		{"logs", 6},
	}
	
	for _, ch := range agentToBackendChannels {
		cm.CreateChannel(fmt.Sprintf("agent.%s", ch.name), ChannelTypeAgentToBackend, ch.priority)
	}
	
	// Backend to Agent channels
	backendToAgentChannels := []struct {
		name     string
		priority int
	}{
		{"policies", 1},
		{"investigations", 2},
		{"threats", 2},
		{"processes", 3},
		{"tests", 4},
		{"rollbacks", 4},
	}
	
	for _, ch := range backendToAgentChannels {
		cm.CreateChannel(fmt.Sprintf("backend.%s", ch.name), ChannelTypeBackendToAgent, ch.priority)
	}
}

// CreateChannel creates a new communication channel
func (cm *ChannelManager) CreateChannel(name string, channelType ChannelType, priority int) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if _, exists := cm.channels[name]; exists {
		return fmt.Errorf("channel %s already exists", name)
	}
	
	channel := &Channel{
		Name:        name,
		Type:        channelType,
		Priority:    priority,
		Enabled:     true,
		Subscribers: make([]ChannelSubscriber, 0),
		Metadata:    make(map[string]interface{}),
	}
	
	cm.channels[name] = channel
	
	// Register with message queue
	processor := NewWebSocketMessageProcessor(cm.websocketMgr, name)
	cm.messageQueue.RegisterProcessor(processor)
	
	log.Printf("[channel_manager] Channel created: %s (type: %s, priority: %d)", name, channelType, priority)
	return nil
}

// Subscribe subscribes to a channel
func (cm *ChannelManager) Subscribe(channelName string, subscriberID string, handler MessageHandler, priority int) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	channel, exists := cm.channels[channelName]
	if !exists {
		return fmt.Errorf("channel %s not found", channelName)
	}
	
	// Check if subscriber already exists
	for _, sub := range channel.Subscribers {
		if sub.ID == subscriberID {
			return fmt.Errorf("subscriber %s already subscribed to channel %s", subscriberID, channelName)
		}
	}
	
	// Add subscriber
	subscriber := ChannelSubscriber{
		ID:       subscriberID,
		Handler:  handler,
		Priority: priority,
		Enabled:  true,
		Metadata: make(map[string]interface{}),
	}
	
	channel.Subscribers = append(channel.Subscribers, subscriber)
	
	log.Printf("[channel_manager] Subscriber %s subscribed to channel %s", subscriberID, channelName)
	return nil
}

// Unsubscribe unsubscribes from a channel
func (cm *ChannelManager) Unsubscribe(channelName string, subscriberID string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	channel, exists := cm.channels[channelName]
	if !exists {
		return fmt.Errorf("channel %s not found", channelName)
	}
	
	// Find and remove subscriber
	for i, sub := range channel.Subscribers {
		if sub.ID == subscriberID {
			channel.Subscribers = append(channel.Subscribers[:i], channel.Subscribers[i+1:]...)
			log.Printf("[channel_manager] Subscriber %s unsubscribed from channel %s", subscriberID, channelName)
			return nil
		}
	}
	
	return fmt.Errorf("subscriber %s not found in channel %s", subscriberID, channelName)
}

// Publish publishes a message to a channel
func (cm *ChannelManager) Publish(channelName string, messageType MessageType, message interface{}) error {
	cm.mu.RLock()
	channel, exists := cm.channels[channelName]
	cm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("channel %s not found", channelName)
	}
	
	if !channel.Enabled {
		return fmt.Errorf("channel %s is disabled", channelName)
	}
	
	// Determine priority based on channel type and message type
	priority := cm.calculatePriority(channel, messageType)
	
	// Enqueue message
	if err := cm.messageQueue.Enqueue(channelName, messageType, message, priority); err != nil {
		return fmt.Errorf("failed to enqueue message: %w", err)
	}
	
	log.Printf("[channel_manager] Message published to channel %s (priority: %d)", channelName, priority)
	return nil
}

// Broadcast broadcasts a message to all subscribers of a channel
func (cm *ChannelManager) Broadcast(channelName string, messageType MessageType, message interface{}) error {
	cm.mu.RLock()
	channel, exists := cm.channels[channelName]
	cm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("channel %s not found", channelName)
	}
	
	if !channel.Enabled {
		return fmt.Errorf("channel %s is disabled", channelName)
	}
	
	// Send to all enabled subscribers
	channel.mu.RLock()
	subscribers := make([]ChannelSubscriber, 0)
	for _, sub := range channel.Subscribers {
		if sub.Enabled {
			subscribers = append(subscribers, sub)
		}
	}
	channel.mu.RUnlock()
	
	// Create message
	msg := SecureMessage{
		ID:        cm.generateMessageID(),
		Type:      messageType,
		Channel:   channelName,
		Payload:   fmt.Sprintf("%v", message), // Simple string conversion for now
		Timestamp: time.Now().Unix(),
		Headers:   make(map[string]string),
	}
	
	// Send to each subscriber
	for _, sub := range subscribers {
		if err := sub.Handler(msg); err != nil {
			log.Printf("[channel_manager] Failed to send to subscriber %s: %v", sub.ID, err)
		}
	}
	
	log.Printf("[channel_manager] Message broadcast to %d subscribers on channel %s", len(subscribers), channelName)
	return nil
}

// GetChannel returns a channel by name
func (cm *ChannelManager) GetChannel(channelName string) (*Channel, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	channel, exists := cm.channels[channelName]
	return channel, exists
}

// GetAllChannels returns all channels
func (cm *ChannelManager) GetAllChannels() map[string]*Channel {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	channels := make(map[string]*Channel)
	for name, channel := range cm.channels {
		channels[name] = channel
	}
	
	return channels
}

// EnableChannel enables a channel
func (cm *ChannelManager) EnableChannel(channelName string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	channel, exists := cm.channels[channelName]
	if !exists {
		return fmt.Errorf("channel %s not found", channelName)
	}
	
	channel.Enabled = true
	log.Printf("[channel_manager] Channel %s enabled", channelName)
	return nil
}

// DisableChannel disables a channel
func (cm *ChannelManager) DisableChannel(channelName string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	channel, exists := cm.channels[channelName]
	if !exists {
		return fmt.Errorf("channel %s not found", channelName)
	}
	
	channel.Enabled = false
	log.Printf("[channel_manager] Channel %s disabled", channelName)
	return nil
}

// GetChannelStats returns channel statistics
func (cm *ChannelManager) GetChannelStats() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_channels":    len(cm.channels),
		"enabled_channels":  0,
		"disabled_channels": 0,
		"total_subscribers": 0,
		"channels":          make(map[string]interface{}),
	}
	
	enabledCount := 0
	disabledCount := 0
	totalSubscribers := 0
	
	for name, channel := range cm.channels {
		channelStats := map[string]interface{}{
			"name":         channel.Name,
			"type":         channel.Type,
			"priority":     channel.Priority,
			"enabled":      channel.Enabled,
			"subscribers":  len(channel.Subscribers),
		}
		
		stats["channels"].(map[string]interface{})[name] = channelStats
		
		if channel.Enabled {
			enabledCount++
		} else {
			disabledCount++
		}
		
		totalSubscribers += len(channel.Subscribers)
	}
	
	stats["enabled_channels"] = enabledCount
	stats["disabled_channels"] = disabledCount
	stats["total_subscribers"] = totalSubscribers
	
	return stats
}

// calculatePriority calculates message priority based on channel and message type
func (cm *ChannelManager) calculatePriority(channel *Channel, messageType MessageType) int {
	basePriority := channel.Priority
	
	// Adjust priority based on message type
	switch messageType {
	case MessageTypeHeartbeat:
		return basePriority + 10 // Highest priority for heartbeats
	case MessageTypeEvent:
		return basePriority + 5  // High priority for events
	case MessageTypeRequest:
		return basePriority      // Normal priority for requests
	case MessageTypeResponse:
		return basePriority - 1  // Lower priority for responses
	case MessageTypeAck:
		return basePriority - 2  // Lowest priority for acknowledgments
	default:
		return basePriority
	}
}

// generateMessageID generates a unique message ID
func (cm *ChannelManager) generateMessageID() string {
	return fmt.Sprintf("channel_%d_%d", time.Now().UnixNano(), len(cm.channels))
}

// Shutdown gracefully shuts down the channel manager
func (cm *ChannelManager) Shutdown() {
	cm.cancel()
	log.Printf("[channel_manager] Channel manager shutdown")
}
