package communication

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// MessageQueue provides reliable message queuing
type MessageQueue struct {
	queue      []QueuedMessage
	maxSize    int
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	processors []MessageProcessor
}

// MessageProcessor defines a message processor interface
type MessageProcessor interface {
	ProcessMessage(msg QueuedMessage) error
	GetChannel() string
}

// QueuedMessage represents a queued message
type QueuedMessage struct {
	ID         string                 `json:"id"`
	Channel    string                 `json:"channel"`
	Message    interface{}            `json:"message"`
	MessageType MessageType           `json:"message_type"`
	Timestamp  time.Time              `json:"timestamp"`
	Retries    int                    `json:"retries"`
	MaxRetries int                    `json:"max_retries"`
	Priority   int                    `json:"priority"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// NewMessageQueue creates a new message queue
func NewMessageQueue(maxSize int) *MessageQueue {
	ctx, cancel := context.WithCancel(context.Background())
	
	mq := &MessageQueue{
		queue:      make([]QueuedMessage, 0),
		maxSize:    maxSize,
		ctx:        ctx,
		cancel:     cancel,
		processors: make([]MessageProcessor, 0),
	}
	
	// Start background processor
	go mq.processQueue()
	
	return mq
}

// Enqueue adds a message to the queue
func (mq *MessageQueue) Enqueue(channel string, messageType MessageType, message interface{}, priority int) error {
	mq.mu.Lock()
	defer mq.mu.Unlock()
	
	// Check queue size
	if len(mq.queue) >= mq.maxSize {
		// Remove oldest low-priority message
		mq.removeOldestLowPriority()
	}
	
	queuedMsg := QueuedMessage{
		ID:          mq.generateMessageID(),
		Channel:     channel,
		Message:     message,
		MessageType: messageType,
		Timestamp:   time.Now(),
		Retries:     0,
		MaxRetries:  3,
		Priority:    priority,
		Metadata:    make(map[string]interface{}),
	}
	
	mq.queue = append(mq.queue, queuedMsg)
	
	log.Printf("[message_queue] Message enqueued: %s (priority: %d)", queuedMsg.ID, priority)
	return nil
}

// RegisterProcessor registers a message processor
func (mq *MessageQueue) RegisterProcessor(processor MessageProcessor) {
	mq.mu.Lock()
	defer mq.mu.Unlock()
	
	mq.processors = append(mq.processors, processor)
	log.Printf("[message_queue] Processor registered for channel: %s", processor.GetChannel())
}

// processQueue processes messages from the queue
func (mq *MessageQueue) processQueue() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-mq.ctx.Done():
			return
		case <-ticker.C:
			mq.processNextMessage()
		}
	}
}

// processNextMessage processes the next message in the queue
func (mq *MessageQueue) processNextMessage() {
	mq.mu.Lock()
	if len(mq.queue) == 0 {
		mq.mu.Unlock()
		return
	}
	
	// Get highest priority message
	msg := mq.getHighestPriorityMessage()
	if msg.ID == "" {
		mq.mu.Unlock()
		return
	}
	
	// Remove message from queue
	mq.removeMessage(msg.ID)
	mq.mu.Unlock()
	
	// Process message
	if err := mq.processMessage(msg); err != nil {
		log.Printf("[message_queue] Failed to process message %s: %v", msg.ID, err)
		
		// Retry logic
		if msg.Retries < msg.MaxRetries {
			msg.Retries++
			mq.mu.Lock()
			mq.queue = append(mq.queue, msg)
			mq.mu.Unlock()
		} else {
			log.Printf("[message_queue] Message %s exceeded max retries, dropping", msg.ID)
		}
	}
}

// processMessage processes a single message
func (mq *MessageQueue) processMessage(msg QueuedMessage) error {
	// Find processor for channel
	var processor MessageProcessor
	for _, p := range mq.processors {
		if p.GetChannel() == msg.Channel {
			processor = p
			break
		}
	}
	
	if processor == nil {
		return fmt.Errorf("no processor found for channel: %s", msg.Channel)
	}
	
	// Process message
	return processor.ProcessMessage(msg)
}

// getHighestPriorityMessage gets the highest priority message
func (mq *MessageQueue) getHighestPriorityMessage() QueuedMessage {
	if len(mq.queue) == 0 {
		return QueuedMessage{}
	}
	
	highest := mq.queue[0]
	
	for _, msg := range mq.queue[1:] {
		if msg.Priority > highest.Priority {
			highest = msg
		}
	}
	
	return highest
}

// removeMessage removes a message from the queue
func (mq *MessageQueue) removeMessage(id string) {
	for i, msg := range mq.queue {
		if msg.ID == id {
			mq.queue = append(mq.queue[:i], mq.queue[i+1:]...)
			break
		}
	}
}

// removeOldestLowPriority removes the oldest low-priority message
func (mq *MessageQueue) removeOldestLowPriority() {
	if len(mq.queue) == 0 {
		return
	}
	
	// Find oldest low-priority message
	oldestIndex := 0
	oldestTime := mq.queue[0].Timestamp
	
	for i, msg := range mq.queue[1:] {
		if msg.Priority == 0 && msg.Timestamp.Before(oldestTime) {
			oldestTime = msg.Timestamp
			oldestIndex = i + 1
		}
	}
	
	// Remove oldest message
	mq.queue = append(mq.queue[:oldestIndex], mq.queue[oldestIndex+1:]...)
}

// GetQueueSize returns the current queue size
func (mq *MessageQueue) GetQueueSize() int {
	mq.mu.RLock()
	defer mq.mu.RUnlock()
	return len(mq.queue)
}

// GetQueueStats returns queue statistics
func (mq *MessageQueue) GetQueueStats() map[string]interface{} {
	mq.mu.RLock()
	defer mq.mu.RUnlock()
	
	stats := map[string]interface{}{
		"queue_size":    len(mq.queue),
		"max_size":      mq.maxSize,
		"processors":    len(mq.processors),
		"utilization":   float64(len(mq.queue)) / float64(mq.maxSize) * 100,
	}
	
	// Count messages by priority
	priorityCounts := make(map[int]int)
	for _, msg := range mq.queue {
		priorityCounts[msg.Priority]++
	}
	stats["priority_counts"] = priorityCounts
	
	return stats
}

// Clear clears the message queue
func (mq *MessageQueue) Clear() {
	mq.mu.Lock()
	defer mq.mu.Unlock()
	
	mq.queue = make([]QueuedMessage, 0)
	log.Printf("[message_queue] Queue cleared")
}

// Shutdown gracefully shuts down the message queue
func (mq *MessageQueue) Shutdown() {
	mq.cancel()
	log.Printf("[message_queue] Message queue shutdown")
}

// generateMessageID generates a unique message ID
func (mq *MessageQueue) generateMessageID() string {
	return fmt.Sprintf("queue_%d_%d", time.Now().UnixNano(), len(mq.queue))
}

// WebSocketMessageProcessor processes messages for WebSocket delivery
type WebSocketMessageProcessor struct {
	websocketManager *WebSocketManager
	channel          string
}

// NewWebSocketMessageProcessor creates a new WebSocket message processor
func NewWebSocketMessageProcessor(websocketManager *WebSocketManager, channel string) *WebSocketMessageProcessor {
	return &WebSocketMessageProcessor{
		websocketManager: websocketManager,
		channel:          channel,
	}
}

// ProcessMessage processes a queued message
func (wmp *WebSocketMessageProcessor) ProcessMessage(msg QueuedMessage) error {
	// Send message via WebSocket
	return wmp.websocketManager.SendMessage(msg.Channel, msg.MessageType, msg.Message)
}

// GetChannel returns the channel this processor handles
func (wmp *WebSocketMessageProcessor) GetChannel() string {
	return wmp.channel
}

// FileMessageProcessor processes messages for file-based delivery
type FileMessageProcessor struct {
	filePath string
	channel  string
	mu       sync.Mutex
}

// NewFileMessageProcessor creates a new file message processor
func NewFileMessageProcessor(filePath, channel string) *FileMessageProcessor {
	return &FileMessageProcessor{
		filePath: filePath,
		channel:  channel,
	}
}

// ProcessMessage processes a queued message by writing to file
func (fmp *FileMessageProcessor) ProcessMessage(msg QueuedMessage) error {
	fmp.mu.Lock()
	defer fmp.mu.Unlock()
	
	// Serialize message
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}
	
	// Append to file
	file, err := os.OpenFile(fmp.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()
	
	_, err = file.Write(append(data, '\n'))
	if err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	
	return nil
}

// GetChannel returns the channel this processor handles
func (fmp *FileMessageProcessor) GetChannel() string {
	return fmp.channel
}
