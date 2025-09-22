package communication

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	mathrand "math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
)

// WebSocketManager manages WebSocket connections with the backend
type WebSocketManager struct {
	agentID           string
	backendURL        string
	privateKey        ed25519.PrivateKey
	publicKey         ed25519.PublicKey
	sharedKey         []byte
	sessionToken      string
	sessionExpires    time.Time
	connection        *websocket.Conn
	reconnectDelay    time.Duration
	maxReconnectDelay time.Duration
	messageQueue      chan QueuedMessage
	responseHandlers  map[string]chan interface{}
	channels          *CommunicationChannels
	messageRouter     *MessageRouter
	healthChecker     *HealthChecker
	metrics           *ConnectionMetrics
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	running           bool
}

// MessageRouter handles message routing and processing
type MessageRouter struct {
	handlers        map[string]MessageHandler
	responseChans   map[string]chan interface{}
	mu              sync.RWMutex
}

// MessageHandler defines a message handler function
type MessageHandler func(message SecureMessage) error

// HealthChecker monitors connection health
type HealthChecker struct {
	lastHeartbeat    time.Time
	heartbeatTimeout time.Duration
	mu               sync.RWMutex
}

// ConnectionMetrics tracks connection statistics
type ConnectionMetrics struct {
	MessagesSent     int64
	MessagesReceived int64
	Reconnects       int64
	Errors           int64
	LastActivity     time.Time
	mu               sync.RWMutex
}

// AuthenticationRequest represents an authentication request
type AuthenticationRequest struct {
	AgentID      string `json:"agent_id"`
	PublicKey    string `json:"public_key"`
	Timestamp    int64  `json:"timestamp"`
	Nonce        string `json:"nonce"`
	Signature    string `json:"signature"`
}

// AuthenticationResponse represents an authentication response
type AuthenticationResponse struct {
	Success      bool   `json:"success"`
	BackendKey   string `json:"backend_key"`
	SessionToken string `json:"session_token"`
	ExpiresAt    int64  `json:"expires_at"`
	Message      string `json:"message,omitempty"`
}

// NewWebSocketManager creates a new WebSocket manager
func NewWebSocketManager(agentID, backendURL string) (*WebSocketManager, error) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create communication channels
	channels := &CommunicationChannels{
		PolicyUpdates:    fmt.Sprintf("agent.%s.policies", agentID),
		AnomalyAlerts:    fmt.Sprintf("agent.%s.anomalies", agentID),
		ThreatMatches:    fmt.Sprintf("agent.%s.threats", agentID),
		ProcessEvents:    fmt.Sprintf("agent.%s.processes", agentID),
		DependencyData:   fmt.Sprintf("agent.%s.dependencies", agentID),
		TestResults:      fmt.Sprintf("agent.%s.tests", agentID),
		RollbackStatus:   fmt.Sprintf("agent.%s.rollbacks", agentID),
		Heartbeat:        fmt.Sprintf("agent.%s.heartbeat", agentID),
		Status:           fmt.Sprintf("agent.%s.status", agentID),
		Logs:             fmt.Sprintf("agent.%s.logs", agentID),
		
		PolicyCommands:   fmt.Sprintf("backend.%s.policies", agentID),
		InvestigationReq: fmt.Sprintf("backend.%s.investigations", agentID),
		ThreatIntel:      fmt.Sprintf("backend.%s.threats", agentID),
		ProcessPolicies:  fmt.Sprintf("backend.%s.processes", agentID),
		TestCommands:     fmt.Sprintf("backend.%s.tests", agentID),
		RollbackCommands: fmt.Sprintf("backend.%s.rollbacks", agentID),
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &WebSocketManager{
		agentID:           agentID,
		backendURL:        backendURL,
		privateKey:        privateKey,
		publicKey:         publicKey,
		reconnectDelay:    5 * time.Second,
		maxReconnectDelay: 60 * time.Second,
		messageQueue:      make(chan QueuedMessage, 1000),
		responseHandlers:  make(map[string]chan interface{}),
		channels:          channels,
		messageRouter: &MessageRouter{
			handlers:      make(map[string]MessageHandler),
			responseChans: make(map[string]chan interface{}),
		},
		healthChecker: &HealthChecker{
			heartbeatTimeout: 30 * time.Second,
		},
		metrics: &ConnectionMetrics{},
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

// Start starts the WebSocket connection
func (wsm *WebSocketManager) Start() error {
	wsm.mu.Lock()
	defer wsm.mu.Unlock()

	if wsm.running {
		return fmt.Errorf("WebSocket manager is already running")
	}

	// Establish initial connection
	if err := wsm.connect(); err != nil {
		return fmt.Errorf("failed to establish initial connection: %w", err)
	}

	// Start background processes
	go wsm.messageProcessor()
	go wsm.heartbeat()
	go wsm.connectionMonitor()
	go wsm.queueProcessor()

	wsm.running = true
	log.Printf("[websocket] WebSocket manager started for agent %s", wsm.agentID)
	return nil
}

// Stop stops the WebSocket connection
func (wsm *WebSocketManager) Stop() error {
	wsm.mu.Lock()
	defer wsm.mu.Unlock()

	if !wsm.running {
		return nil
	}

	wsm.cancel()
	wsm.running = false

	if wsm.connection != nil {
		wsm.connection.Close()
	}

	log.Printf("[websocket] WebSocket manager stopped for agent %s", wsm.agentID)
	return nil
}

// SendMessage sends a message to the backend
func (wsm *WebSocketManager) SendMessage(channel string, messageType MessageType, payload interface{}) error {
	wsm.mu.RLock()
	conn := wsm.connection
	wsm.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected to backend")
	}

	// Encrypt payload
	encryptedPayload, nonce, err := wsm.encryptPayload(payload)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %w", err)
	}

	// Create secure message
	msg := SecureMessage{
		ID:        wsm.generateMessageID(),
		Type:      messageType,
		Channel:   channel,
		Payload:   encryptedPayload,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
		Headers:   make(map[string]string),
	}

	// Sign message
	msg.Signature = wsm.signMessage(msg)

	// Send message
	if err := conn.WriteJSON(msg); err != nil {
		wsm.incrementErrorCount()
		return fmt.Errorf("failed to send message: %w", err)
	}

	wsm.incrementSentCount()
	log.Printf("[websocket] Message sent to channel %s", channel)
	return nil
}

// RegisterHandler registers a message handler for a channel
func (wsm *WebSocketManager) RegisterHandler(channel string, handler MessageHandler) {
	wsm.messageRouter.mu.Lock()
	defer wsm.messageRouter.mu.Unlock()
	wsm.messageRouter.handlers[channel] = handler
}

// IsConnected returns true if connected to backend
func (wsm *WebSocketManager) IsConnected() bool {
	wsm.mu.RLock()
	defer wsm.mu.RUnlock()
	return wsm.connection != nil && wsm.running
}

// GetMetrics returns connection metrics
func (wsm *WebSocketManager) GetMetrics() map[string]interface{} {
	wsm.metrics.mu.RLock()
	defer wsm.metrics.mu.RUnlock()

	return map[string]interface{}{
		"messages_sent":     wsm.metrics.MessagesSent,
		"messages_received": wsm.metrics.MessagesReceived,
		"reconnects":        wsm.metrics.Reconnects,
		"errors":            wsm.metrics.Errors,
		"last_activity":     wsm.metrics.LastActivity,
		"connected":         wsm.IsConnected(),
	}
}

// connect establishes a WebSocket connection
func (wsm *WebSocketManager) connect() error {
	// Create secure WebSocket connection
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // Use proper cert validation in production
		},
		HandshakeTimeout: 30 * time.Second,
	}

	// Add authentication headers
	headers := http.Header{}
	headers.Set("X-Agent-ID", wsm.agentID)
	headers.Set("X-Agent-Public-Key", base64.StdEncoding.EncodeToString(wsm.publicKey))
	headers.Set("User-Agent", "Aegis-Agent/1.0")

	conn, _, err := dialer.Dial(wsm.backendURL, headers)
	if err != nil {
		return fmt.Errorf("failed to dial WebSocket: %w", err)
	}

	// Set connection parameters
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Authenticate
	if err := wsm.authenticate(conn); err != nil {
		conn.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}

	wsm.connection = conn
	log.Printf("[websocket] Connected to backend at %s", wsm.backendURL)
	return nil
}

// authenticate performs mutual authentication
func (wsm *WebSocketManager) authenticate(conn *websocket.Conn) error {
	// Create authentication request
	nonce := wsm.generateNonce()
	timestamp := time.Now().Unix()

	authReq := AuthenticationRequest{
		AgentID:   wsm.agentID,
		PublicKey: base64.StdEncoding.EncodeToString(wsm.publicKey),
		Timestamp: timestamp,
		Nonce:     nonce,
	}

	// Sign the request
	signature := wsm.signRequest(authReq)
	authReq.Signature = signature

	// Send authentication request
	if err := conn.WriteJSON(authReq); err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	// Receive authentication response
	var authResp AuthenticationResponse
	if err := conn.ReadJSON(&authResp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	// Validate response
	if !authResp.Success {
		return fmt.Errorf("authentication failed: %s", authResp.Message)
	}

	// Store session information
	wsm.sessionToken = authResp.SessionToken
	wsm.sessionExpires = time.Unix(authResp.ExpiresAt, 0)

	// Derive shared key from backend key
	backendKey, err := base64.StdEncoding.DecodeString(authResp.BackendKey)
	if err != nil {
		return fmt.Errorf("failed to decode backend key: %w", err)
	}

	// Generate shared key using ECDH-like key agreement
	wsm.sharedKey = wsm.deriveSharedKey(backendKey)

	log.Printf("[websocket] Authentication successful, session expires at %v", wsm.sessionExpires)
	return nil
}

// messageProcessor processes incoming messages
func (wsm *WebSocketManager) messageProcessor() {
	for {
		select {
		case <-wsm.ctx.Done():
			return
		default:
			wsm.mu.RLock()
			conn := wsm.connection
			wsm.mu.RUnlock()

			if conn == nil {
				time.Sleep(1 * time.Second)
				continue
			}

			var msg SecureMessage
			if err := conn.ReadJSON(&msg); err != nil {
				log.Printf("[websocket] Failed to read message: %v", err)
				wsm.incrementErrorCount()
				time.Sleep(1 * time.Second)
				continue
			}

			// Process message
			if err := wsm.processMessage(msg); err != nil {
				log.Printf("[websocket] Failed to process message: %v", err)
				wsm.incrementErrorCount()
			}

			wsm.incrementReceivedCount()
		}
	}
}

// processMessage processes a received message
func (wsm *WebSocketManager) processMessage(msg SecureMessage) error {
	// Verify signature
	if !wsm.verifySignature(msg) {
		return fmt.Errorf("invalid message signature")
	}

	// Decrypt payload
	payload, err := wsm.decryptPayload(msg.Payload, msg.Nonce)
	if err != nil {
		return fmt.Errorf("failed to decrypt payload: %w", err)
	}

	// Update message with decrypted payload
	msg.Payload = payload

	// Route to handler
	wsm.messageRouter.mu.RLock()
	handler, exists := wsm.messageRouter.handlers[msg.Channel]
	wsm.messageRouter.mu.RUnlock()

	if exists {
		return handler(msg)
	}

	log.Printf("[websocket] No handler for channel: %s", msg.Channel)
	return nil
}

// heartbeat sends periodic heartbeat messages
func (wsm *WebSocketManager) heartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-wsm.ctx.Done():
			return
		case <-ticker.C:
			if err := wsm.SendMessage(wsm.channels.Heartbeat, MessageTypeHeartbeat, map[string]interface{}{
				"timestamp": time.Now().Unix(),
				"agent_id":  wsm.agentID,
			}); err != nil {
				log.Printf("[websocket] Failed to send heartbeat: %v", err)
			}
		}
	}
}

// connectionMonitor monitors connection health
func (wsm *WebSocketManager) connectionMonitor() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-wsm.ctx.Done():
			return
		case <-ticker.C:
			if !wsm.isConnectionHealthy() {
				log.Printf("[websocket] Connection unhealthy, attempting reconnection...")
				if err := wsm.reconnect(); err != nil {
					log.Printf("[websocket] Reconnection failed: %v", err)
				}
			}
		}
	}
}

// queueProcessor processes queued messages
func (wsm *WebSocketManager) queueProcessor() {
	for {
		select {
		case <-wsm.ctx.Done():
			return
		case msg := <-wsm.messageQueue:
			if err := wsm.processQueuedMessage(msg); err != nil {
				log.Printf("[websocket] Failed to process queued message: %v", err)
				// Retry logic
				if msg.Retries < msg.MaxRetries {
					msg.Retries++
					select {
					case wsm.messageQueue <- msg:
					default:
						log.Printf("[websocket] Message queue full, dropping message")
					}
				}
			}
		}
	}
}

// processQueuedMessage processes a queued message
func (wsm *WebSocketManager) processQueuedMessage(msg QueuedMessage) error {
	return wsm.SendMessage(msg.Channel, MessageTypeRequest, msg.Message)
}

// reconnect establishes a new connection
func (wsm *WebSocketManager) reconnect() error {
	// Close existing connection
	wsm.mu.Lock()
	if wsm.connection != nil {
		wsm.connection.Close()
		wsm.connection = nil
	}
	wsm.mu.Unlock()

	// Wait before reconnecting
	time.Sleep(wsm.reconnectDelay)

	// Establish new connection
	if err := wsm.connect(); err != nil {
		// Increase reconnect delay
		wsm.reconnectDelay = time.Duration(float64(wsm.reconnectDelay) * 1.5)
		if wsm.reconnectDelay > wsm.maxReconnectDelay {
			wsm.reconnectDelay = wsm.maxReconnectDelay
		}
		return err
	}

	// Reset reconnect delay
	wsm.reconnectDelay = 5 * time.Second
	wsm.incrementReconnectCount()
	log.Printf("[websocket] Successfully reconnected to backend")
	return nil
}

// isConnectionHealthy checks if the connection is healthy
func (wsm *WebSocketManager) isConnectionHealthy() bool {
	wsm.mu.RLock()
	defer wsm.mu.RUnlock()

	if wsm.connection == nil {
		return false
	}

	// Check if session is expired
	if time.Now().After(wsm.sessionExpires) {
		return false
	}

	// Check last heartbeat
	wsm.healthChecker.mu.RLock()
	lastHeartbeat := wsm.healthChecker.lastHeartbeat
	timeout := wsm.healthChecker.heartbeatTimeout
	wsm.healthChecker.mu.RUnlock()

	return time.Since(lastHeartbeat) < timeout
}

// encryptPayload encrypts a payload using ChaCha20-Poly1305
func (wsm *WebSocketManager) encryptPayload(payload interface{}) (string, string, error) {
	// Serialize payload
	data, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	// Generate nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}

	// Encrypt using ChaCha20-Poly1305
	cipher, err := chacha20poly1305.New(wsm.sharedKey)
	if err != nil {
		return "", "", err
	}

	encrypted := cipher.Seal(nil, nonce, data, nil)

	return base64.StdEncoding.EncodeToString(encrypted),
		   base64.StdEncoding.EncodeToString(nonce), nil
}

// decryptPayload decrypts a payload using ChaCha20-Poly1305
func (wsm *WebSocketManager) decryptPayload(encryptedPayload, nonceStr string) (string, error) {
	// Decode encrypted payload
	encrypted, err := base64.StdEncoding.DecodeString(encryptedPayload)
	if err != nil {
		return "", err
	}

	// Decode nonce
	nonce, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil {
		return "", err
	}

	// Decrypt using ChaCha20-Poly1305
	cipher, err := chacha20poly1305.New(wsm.sharedKey)
	if err != nil {
		return "", err
	}

	decrypted, err := cipher.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// signMessage signs a message using Ed25519
func (wsm *WebSocketManager) signMessage(msg SecureMessage) string {
	// Create data to sign
	data := fmt.Sprintf("%s:%s:%s:%d:%s", msg.ID, msg.Type, msg.Channel, msg.Timestamp, msg.Payload)

	// Sign the data
	signature := ed25519.Sign(wsm.privateKey, []byte(data))

	return base64.StdEncoding.EncodeToString(signature)
}

// verifySignature verifies a message signature
func (wsm *WebSocketManager) verifySignature(msg SecureMessage) bool {
	// Create data to verify
	data := fmt.Sprintf("%s:%s:%s:%d:%s", msg.ID, msg.Type, msg.Channel, msg.Timestamp, msg.Payload)

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return false
	}

	// Verify signature (using agent's public key for now)
	return ed25519.Verify(wsm.publicKey, []byte(data), signature)
}

// signRequest signs an authentication request
func (wsm *WebSocketManager) signRequest(req AuthenticationRequest) string {
	// Create data to sign
	data := fmt.Sprintf("%s:%s:%d:%s", req.AgentID, req.PublicKey, req.Timestamp, req.Nonce)

	// Sign the data
	signature := ed25519.Sign(wsm.privateKey, []byte(data))

	return base64.StdEncoding.EncodeToString(signature)
}

// deriveSharedKey derives a shared key from the backend key
func (wsm *WebSocketManager) deriveSharedKey(backendKey []byte) []byte {
	// Simple key derivation using SHA256
	// In production, use proper ECDH key agreement
	combined := append(wsm.privateKey, backendKey...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

// generateMessageID generates a unique message ID
func (wsm *WebSocketManager) generateMessageID() string {
	return fmt.Sprintf("msg_%d_%d", time.Now().UnixNano(), mathrand.Int63())
}

// generateNonce generates a random nonce
func (wsm *WebSocketManager) generateNonce() string {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(nonce)
}

// incrementSentCount increments the sent message count
func (wsm *WebSocketManager) incrementSentCount() {
	wsm.metrics.mu.Lock()
	defer wsm.metrics.mu.Unlock()
	wsm.metrics.MessagesSent++
	wsm.metrics.LastActivity = time.Now()
}

// incrementReceivedCount increments the received message count
func (wsm *WebSocketManager) incrementReceivedCount() {
	wsm.metrics.mu.Lock()
	defer wsm.metrics.mu.Unlock()
	wsm.metrics.MessagesReceived++
	wsm.metrics.LastActivity = time.Now()
}

// incrementReconnectCount increments the reconnect count
func (wsm *WebSocketManager) incrementReconnectCount() {
	wsm.metrics.mu.Lock()
	defer wsm.metrics.mu.Unlock()
	wsm.metrics.Reconnects++
}

// incrementErrorCount increments the error count
func (wsm *WebSocketManager) incrementErrorCount() {
	wsm.metrics.mu.Lock()
	defer wsm.metrics.mu.Unlock()
	wsm.metrics.Errors++
}
