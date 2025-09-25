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
	reconnectChan     chan struct{}
	mu                sync.RWMutex
	writeMu           sync.Mutex // Mutex for WebSocket writes to prevent concurrent writes
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
			heartbeatTimeout: 15 * time.Second,
		},
		metrics:       &ConnectionMetrics{},
		reconnectChan: make(chan struct{}, 1),
		ctx:           ctx,
		cancel:        cancel,
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
	go wsm.reconnectionHandler()

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

	// Serialize payload to JSON and base64 encode (matching backend expectations)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadB64 := base64.StdEncoding.EncodeToString(payloadJSON)

	// Create secure message
	msg := SecureMessage{
		ID:        wsm.generateMessageID(),
		Type:      messageType,
		Channel:   channel,
		Payload:   payloadB64, // Base64 encoded JSON payload
		Timestamp: time.Now().Unix(),
		Nonce:     base64.StdEncoding.EncodeToString([]byte("message_nonce")), // Consistent nonce for messages
		Signature: "", // Will be set after creating the message
		Headers:   make(map[string]string),
	}

	// Sign all messages with Ed25519 (backend expects all messages to be signed)
	msg.Signature = wsm.signMessage(msg)
	log.Printf("[websocket] Message type: %s, channel: %s, signed with signature: %s", messageType, channel, msg.Signature)

	// Send message with write mutex to prevent concurrent writes
	wsm.writeMu.Lock()
	err = conn.WriteJSON(msg)
	wsm.writeMu.Unlock()
	
	if err != nil {
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
	
	// Initialize heartbeat time
	wsm.healthChecker.mu.Lock()
	wsm.healthChecker.lastHeartbeat = time.Now()
	wsm.healthChecker.mu.Unlock()
	
	log.Printf("[websocket] Connected to backend at %s", wsm.backendURL)
	return nil
}

// authenticate performs mutual authentication using SecureMessage format
func (wsm *WebSocketManager) authenticate(conn *websocket.Conn) error {
	// Create authentication request (matching Python example)
	timestamp := time.Now().Unix()
	nonce := wsm.generateNonce()
	publicKeyB64 := base64.StdEncoding.EncodeToString(wsm.publicKey)
	
	// CRITICAL: Backend expects this exact signature data format
	signatureData := fmt.Sprintf("%s:%s:%d:%s", wsm.agentID, publicKeyB64, timestamp, nonce)
	signature := wsm.signData(signatureData)
	
	authReq := AuthenticationRequest{
		AgentID:   wsm.agentID,
		PublicKey: publicKeyB64,
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: signature,
	}

	// Serialize auth request and base64 encode it
	authReqJSON, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}
	authReqB64 := base64.StdEncoding.EncodeToString(authReqJSON)

	// Create SecureMessage wrapper (backend requirement)
	secureMessage := SecureMessage{
		ID:        fmt.Sprintf("auth_req_%d", timestamp),
		Type:      MessageTypeRequest,
		Channel:   "auth",
		Payload:   authReqB64, // Base64 encoded auth request
		Timestamp: timestamp,
		Nonce:     base64.StdEncoding.EncodeToString([]byte("secure_nonce")),
		Signature: "", // Can be empty for auth messages
		Headers:   make(map[string]string),
	}

	// Send SecureMessage (not direct auth request)
	if err := conn.WriteJSON(secureMessage); err != nil {
		return fmt.Errorf("failed to send auth message: %w", err)
	}

	// Receive authentication response
	var authRespMsg SecureMessage
	if err := conn.ReadJSON(&authRespMsg); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	// Decode response payload (base64 encoded JSON)
	responsePayloadBytes, err := base64.StdEncoding.DecodeString(authRespMsg.Payload)
	if err != nil {
		return fmt.Errorf("failed to decode response payload: %w", err)
	}

	// Parse response
	var authResp AuthenticationResponse
	if err := json.Unmarshal(responsePayloadBytes, &authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
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

			// Set read deadline to keep connection alive
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))

			var msg SecureMessage
			if err := conn.ReadJSON(&msg); err != nil {
				log.Printf("[websocket] Failed to read message: %v", err)
				wsm.incrementErrorCount()
				
				// Trigger graceful reconnection but don't exit the loop
				wsm.triggerGracefulReconnection()
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
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	log.Printf("[websocket] Heartbeat goroutine started")
	
	for {
		select {
		case <-wsm.ctx.Done():
			log.Printf("[websocket] Heartbeat goroutine stopping")
			return
		case <-ticker.C:
			log.Printf("[websocket] Heartbeat ticker triggered")
			wsm.sendHeartbeat()
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

	timeSince := time.Since(lastHeartbeat)
	isHealthy := timeSince < timeout
	
	if !isHealthy {
		log.Printf("[websocket] Connection unhealthy: lastHeartbeat=%v, timeSince=%v, timeout=%v", lastHeartbeat, timeSince, timeout)
	}
	
	return isHealthy
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
	// Create data to sign - match backend expectation exactly
	// Backend expects: agent_id:public_key:timestamp:nonce
	publicKeyB64 := base64.StdEncoding.EncodeToString(wsm.publicKey)
	
	// Use the exact same format as the working Python example
	data := fmt.Sprintf("%s:%s:%d:%s", wsm.agentID, publicKeyB64, msg.Timestamp, msg.Nonce)
	
	log.Printf("[websocket] Signing data: %s", data)

	// Sign the data
	signature := ed25519.Sign(wsm.privateKey, []byte(data))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	
	log.Printf("[websocket] Generated signature: %s", signatureB64)

	return signatureB64
}

// signData signs arbitrary data with Ed25519 (for authentication)
func (wsm *WebSocketManager) signData(data string) string {
	// Sign the data
	signature := ed25519.Sign(wsm.privateKey, []byte(data))
	
	// Return base64 encoded signature
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

// deriveTempKey derives a temporary key for initial authentication
func (wsm *WebSocketManager) deriveTempKey() []byte {
	// Use agent's private key as temporary key for initial auth
	hash := sha256.Sum256(wsm.privateKey)
	return hash[:]
}

// encryptPayloadWithKey encrypts payload with a specific key
func (wsm *WebSocketManager) encryptPayloadWithKey(payload interface{}, key []byte) (string, string, error) {
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
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return "", "", err
	}

	encrypted := cipher.Seal(nil, nonce, data, nil)

	return base64.StdEncoding.EncodeToString(encrypted),
		   base64.StdEncoding.EncodeToString(nonce), nil
}

// decryptPayloadWithKey decrypts payload with a specific key
func (wsm *WebSocketManager) decryptPayloadWithKey(encryptedPayload, nonceStr string, key []byte) (string, error) {
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
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}

	decrypted, err := cipher.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
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

// sendHeartbeat sends a heartbeat message to keep connection alive
func (wsm *WebSocketManager) sendHeartbeat() {
	wsm.mu.RLock()
	conn := wsm.connection
	wsm.mu.RUnlock()

	if conn == nil {
		return
	}

	// Create heartbeat message
	heartbeatMsg := SecureMessage{
		ID:        fmt.Sprintf("heartbeat_%d", time.Now().Unix()),
		Type:      MessageTypeHeartbeat,
		Channel:   fmt.Sprintf("agent.%s.heartbeat", wsm.agentID),
		Payload:   base64.StdEncoding.EncodeToString([]byte(`{"status":"alive","timestamp":` + fmt.Sprintf("%d", time.Now().Unix()) + `}`)),
		Timestamp: time.Now().Unix(),
		Nonce:     base64.StdEncoding.EncodeToString([]byte("heartbeat_nonce")),
		Signature: "",
		Headers:   make(map[string]string),
	}

	// Heartbeats are unsigned (as per Python example)
	// heartbeatMsg.Signature = wsm.signMessage(heartbeatMsg)

	// Send heartbeat with write mutex to prevent concurrent writes
	wsm.writeMu.Lock()
	err := conn.WriteJSON(heartbeatMsg)
	wsm.writeMu.Unlock()
	
	if err != nil {
		log.Printf("[websocket] Failed to send heartbeat: %v", err)
		wsm.incrementErrorCount()
		wsm.triggerGracefulReconnection()
		return
	}

	// Update last heartbeat time
	wsm.healthChecker.mu.Lock()
	wsm.healthChecker.lastHeartbeat = time.Now()
	wsm.healthChecker.mu.Unlock()

	log.Printf("[websocket] Heartbeat sent, lastHeartbeat updated to: %v", wsm.healthChecker.lastHeartbeat)
}

// reconnectionHandler handles graceful reconnection requests
func (wsm *WebSocketManager) reconnectionHandler() {
	for {
		select {
		case <-wsm.ctx.Done():
			return
		case <-wsm.reconnectChan:
			log.Printf("[websocket] Reconnection requested, attempting graceful reconnection...")
			
		// Wait a bit before reconnecting to avoid rapid reconnection loops
		time.Sleep(5 * time.Second)
			
			// Attempt reconnection
			if err := wsm.reconnect(); err != nil {
				log.Printf("[websocket] Graceful reconnection failed: %v", err)
				// Schedule another reconnection attempt
				go func() {
					time.Sleep(5 * time.Second)
					select {
					case wsm.reconnectChan <- struct{}{}:
					default:
					}
				}()
			} else {
				log.Printf("[websocket] Graceful reconnection successful")
			}
		}
	}
}

// triggerGracefulReconnection triggers a graceful reconnection attempt
func (wsm *WebSocketManager) triggerGracefulReconnection() {
	log.Printf("[websocket] Triggering graceful reconnection...")
	
	// Don't close connection immediately, let the reconnection handler deal with it
	// Trigger reconnection
	select {
	case wsm.reconnectChan <- struct{}{}:
	default:
		// Channel is full, reconnection already in progress
	}
}
