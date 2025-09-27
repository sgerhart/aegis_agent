package communication

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net/http"
	"strings"
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
	sessionExpiresAt  string
	agentUID          string
	bootstrapToken    string
	isRegistered      bool
	isAuthenticated   bool
	isReconnecting    bool  // Flag to prevent reconnection loops
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
	connectionState   string // "disconnected", "connecting", "connected", "reconnecting"
	lastConnectAttempt time.Time
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
		reconnectDelay:    2 * time.Second,
		maxReconnectDelay: 300 * time.Second, // 5 minutes max
		messageQueue:      make(chan QueuedMessage, 1000),
		responseHandlers:  make(map[string]chan interface{}),
		channels:          channels,
		messageRouter: &MessageRouter{
			handlers:      make(map[string]MessageHandler),
			responseChans: make(map[string]chan interface{}),
		},
		healthChecker: &HealthChecker{
			heartbeatTimeout: 60 * time.Second, // 1 minute timeout for production
		},
		metrics:           &ConnectionMetrics{},
		reconnectChan:      make(chan struct{}, 1),
		ctx:                ctx,
		cancel:             cancel,
		connectionState:    "disconnected",
		lastConnectAttempt: time.Time{},
	}, nil
}

// Start starts the WebSocket connection
func (wsm *WebSocketManager) Start() error {
	log.Printf("[websocket] Start() method called for agent %s", wsm.agentID)
	wsm.mu.Lock()

	if wsm.running {
		wsm.mu.Unlock()
		log.Printf("[websocket] WebSocket manager is already running")
		return fmt.Errorf("WebSocket manager is already running")
	}

	// Start background processes first
	go wsm.messageProcessor()
	go wsm.heartbeat()
	go wsm.connectionMonitor()
	go wsm.queueProcessor()
	go wsm.reconnectionHandler()

	wsm.running = true
	wsm.mu.Unlock() // Release lock before calling connect()

	// Attempt WebSocket connection first, then register through WebSocket
	log.Printf("[websocket] Attempting initial connection to %s", wsm.backendURL)
	if err := wsm.connect(); err != nil {
		log.Printf("[websocket] Initial connection failed, will retry: %v", err)
		// Trigger reconnection in background
		go func() {
			wsm.reconnectChan <- struct{}{}
		}()
	} else {
		log.Printf("[websocket] Initial connection established successfully")
	}
	log.Printf("[websocket] WebSocket manager started for agent %s (connecting in background)", wsm.agentID)
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
	
	wsm.mu.RLock()
	state := wsm.connectionState
	lastAttempt := wsm.lastConnectAttempt
	wsm.mu.RUnlock()

	return map[string]interface{}{
		"messages_sent":     wsm.metrics.MessagesSent,
		"messages_received": wsm.metrics.MessagesReceived,
		"reconnects":        wsm.metrics.Reconnects,
		"errors":            wsm.metrics.Errors,
		"last_activity":     wsm.metrics.LastActivity,
		"connected":         wsm.IsConnected(),
		"connection_state":  state,
		"last_connect_attempt": lastAttempt,
	}
}

// connect establishes a WebSocket connection
func (wsm *WebSocketManager) connect() error {
	log.Printf("[websocket] connect() method called - START")
	
	// Update connection state (mutex already locked by Start() method)
	log.Printf("[websocket] Updating connection state")
	wsm.connectionState = "connecting"
	wsm.lastConnectAttempt = time.Now()
	
	log.Printf("[websocket] Connection state updated, proceeding with dialer setup")

	// Create WebSocket connection with appropriate TLS settings
	log.Printf("[websocket] Creating WebSocket dialer")
	dialer := websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
	}
	
	// Only configure TLS for wss:// URLs
	if len(wsm.backendURL) > 6 && wsm.backendURL[:6] == "wss://" {
		log.Printf("[websocket] Configuring TLS for WSS URL")
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: false, // Use proper cert validation in production
		}
	}
	
	log.Printf("[websocket] Dialer configured, setting up headers")

	// Add authentication headers
	headers := http.Header{}
	headers.Set("X-Agent-ID", wsm.agentID)
	headers.Set("X-Agent-Public-Key", base64.StdEncoding.EncodeToString(wsm.publicKey))
	headers.Set("User-Agent", "Aegis-Agent/1.0")
	
	// Add registration information if available
	if wsm.agentUID != "" {
		headers.Set("X-Agent-UID", wsm.agentUID)
	}
	if wsm.bootstrapToken != "" {
		headers.Set("X-Bootstrap-Token", wsm.bootstrapToken)
	}

	log.Printf("[websocket] Attempting to connect to %s", wsm.backendURL)
	log.Printf("[websocket] Headers: %v", headers)
	
	// Add timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Create a channel to receive the connection result
	type dialResult struct {
		conn *websocket.Conn
		resp *http.Response
		err  error
	}
	
	resultChan := make(chan dialResult, 1)
	
	// Dial in a goroutine to avoid blocking
	go func() {
		conn, resp, err := dialer.Dial(wsm.backendURL, headers)
		resultChan <- dialResult{conn: conn, resp: resp, err: err}
	}()
	
	// Wait for connection or timeout
	var conn *websocket.Conn
	select {
	case result := <-resultChan:
		if result.err != nil {
			log.Printf("[websocket] Failed to dial WebSocket: %v", result.err)
			return fmt.Errorf("failed to dial WebSocket: %w", result.err)
		}
		conn = result.conn
		log.Printf("[websocket] WebSocket connection established successfully")
	case <-ctx.Done():
		log.Printf("[websocket] WebSocket connection timed out after 10 seconds")
		return fmt.Errorf("WebSocket connection timed out")
	}

	// Set connection parameters
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// WebSocket connection established, proceed with normal messaging
	log.Printf("[websocket] WebSocket connection established, proceeding with normal messaging")

	wsm.mu.Lock()
	wsm.connection = conn
	wsm.connectionState = "connected"
	wsm.mu.Unlock()
	
	// Initialize heartbeat time first
	log.Printf("[websocket] Initializing heartbeat time")
	wsm.healthChecker.mu.Lock()
	wsm.healthChecker.lastHeartbeat = time.Now()
	wsm.healthChecker.mu.Unlock()
	log.Printf("[websocket] Heartbeat time initialized")
	
	// DO NOT send heartbeat before authentication - backend will reject it
	log.Printf("[websocket] Skipping initial heartbeat - must authenticate first")
	
	// Reset authentication state on new connection - each connection needs fresh authentication
	wsm.isAuthenticated = false
	wsm.isRegistered = false
	log.Printf("[websocket] Reset authentication state for new connection")
	
	// Correct WebSocket flow: 1. Connect -> 2. Authenticate -> 3. Register -> 4. Heartbeats
	log.Printf("[websocket] Starting WebSocket authentication")
	if err := wsm.performWebSocketAuthentication(conn); err != nil {
		log.Printf("[websocket] Warning: failed to perform WebSocket authentication: %v", err)
		return fmt.Errorf("authentication failed: %w", err)
	} else {
		log.Printf("[websocket] WebSocket authentication completed successfully")
		wsm.isAuthenticated = true
	}
	
	log.Printf("[websocket] Starting WebSocket registration")
	if err := wsm.performWebSocketRegistration(conn); err != nil {
		log.Printf("[websocket] Warning: failed to perform WebSocket registration: %v", err)
		return fmt.Errorf("registration failed: %w", err)
	} else {
		log.Printf("[websocket] WebSocket registration completed successfully")
		wsm.isRegistered = true
	}
	
	log.Printf("[websocket] Connected to backend at %s", wsm.backendURL)
	return nil
}

// performWebSocketRegistration performs agent registration through WebSocket messages (as per working example)
func (wsm *WebSocketManager) performWebSocketRegistration(conn *websocket.Conn) error {
	log.Printf("[websocket] Performing WebSocket registration for agent %s", wsm.agentID)
	
	// Step 1: Send registration init message
	log.Printf("[websocket] Sending registration init message")
	if err := wsm.sendRegistrationInit(conn); err != nil {
		return fmt.Errorf("failed to send registration init: %w", err)
	}
	
	// Step 2: Wait for registration init response
	log.Printf("[websocket] Waiting for registration init response")
	var initResponse map[string]interface{}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := conn.ReadJSON(&initResponse); err != nil {
		return fmt.Errorf("failed to read registration init response: %w", err)
	}
	
	log.Printf("[websocket] Registration init response received: %v", initResponse)
	
	// Parse response
	channel, _ := initResponse["channel"].(string)
	if channel != "agent.registration" {
		return fmt.Errorf("unexpected response channel: %s", channel)
	}
	
	payloadStr, _ := initResponse["payload"].(string)
	
	// The registration response payload is direct JSON, not base64-encoded
	var regData map[string]interface{}
	if err := json.Unmarshal([]byte(payloadStr), &regData); err != nil {
		return fmt.Errorf("failed to unmarshal registration response: %w", err)
	}
	
	registrationID, _ := regData["registration_id"].(string)
	nonce, _ := regData["nonce"].(string)
	serverTime, _ := regData["server_time"].(string)
	
	if registrationID == "" || nonce == "" || serverTime == "" {
		return fmt.Errorf("missing required fields in registration response")
	}
	
	log.Printf("[websocket] Registration ID: %s", registrationID)
	
	// Step 3: Send registration complete message
	log.Printf("[websocket] Sending registration complete message")
	if err := wsm.sendRegistrationComplete(conn, registrationID, nonce, serverTime); err != nil {
		return fmt.Errorf("failed to send registration complete: %w", err)
	}
	
	// Step 4: Wait for registration complete response
	log.Printf("[websocket] Waiting for registration complete response")
	var completeResponse map[string]interface{}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := conn.ReadJSON(&completeResponse); err != nil {
		return fmt.Errorf("failed to read registration complete response: %w", err)
	}
	
	log.Printf("[websocket] Registration complete response received: %v", completeResponse)
	
	// Parse complete response
	completeChannel, _ := completeResponse["channel"].(string)
	if completeChannel != "agent.registration.complete" {
		return fmt.Errorf("unexpected complete response channel: %s", completeChannel)
	}
	
	completePayloadStr, _ := completeResponse["payload"].(string)
	
	// The registration complete response payload is direct JSON, not base64-encoded
	var completeData map[string]interface{}
	if err := json.Unmarshal([]byte(completePayloadStr), &completeData); err != nil {
		return fmt.Errorf("failed to unmarshal registration complete response: %w", err)
	}
	
	// Extract agent_uid and bootstrap_token
	agentUID, _ := completeData["agent_uid"].(string)
	bootstrapToken, _ := completeData["bootstrap_token"].(string)
	
	if agentUID == "" || bootstrapToken == "" {
		return fmt.Errorf("missing agent_uid or bootstrap_token in registration complete response")
	}
	
	// Store registration credentials
	wsm.agentUID = agentUID
	wsm.bootstrapToken = bootstrapToken
	
	log.Printf("[websocket] Registration successful - Agent UID: %s", agentUID)
	return nil
}

// sendRegistrationInit sends the registration init message
func (wsm *WebSocketManager) sendRegistrationInit(conn *websocket.Conn) error {
	// Registration data (as per working example)
	registrationData := map[string]interface{}{
		"org_id":          "default-org",
		"host_id":         wsm.agentID,
		"agent_pubkey":    base64.StdEncoding.EncodeToString(wsm.publicKey),
		"machine_id_hash": "test-machine-hash",
		"agent_version":   "1.0.0",
		"capabilities":    map[string]interface{}{},
		"platform": map[string]interface{}{
			"arch": "arm64",
			"os":   "linux",
		},
		"network": map[string]interface{}{
			"interface": "eth0",
		},
	}
	
	// Base64 encode the registration data
	jsonData, err := json.Marshal(registrationData)
	if err != nil {
		return fmt.Errorf("failed to marshal registration data: %w", err)
	}
	payloadB64 := base64.StdEncoding.EncodeToString(jsonData)
	
	// Create SecureMessage
	message := map[string]interface{}{
		"id":        fmt.Sprintf("reg_init_%d", time.Now().UnixNano()),
		"type":      "request",
		"channel":   "agent.registration",
		"timestamp": time.Now().Unix(),
		"payload":   payloadB64,
		"headers":   map[string]string{},
	}
	
	return conn.WriteJSON(message)
}

// sendRegistrationComplete sends the registration complete message
func (wsm *WebSocketManager) sendRegistrationComplete(conn *websocket.Conn, registrationID, nonce, serverTime string) error {
	// Create signature data: nonce_bytes + server_time + host_id (as per backend verification logic)
	// Decode the nonce from base64 to bytes first
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}
	
	// Create the exact data the backend expects: nonce_bytes + server_time + host_id
	signatureData := append(nonceBytes, []byte(serverTime+wsm.agentID)...)
	
	// Sign the data
	signature := ed25519.Sign(wsm.privateKey, signatureData)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	
	// Completion data
	completionData := map[string]interface{}{
		"registration_id": registrationID,
		"host_id":         wsm.agentID,
		"signature":       signatureB64,
	}
	
	// Base64 encode the completion data
	jsonData, err := json.Marshal(completionData)
	if err != nil {
		return fmt.Errorf("failed to marshal completion data: %w", err)
	}
	payloadB64 := base64.StdEncoding.EncodeToString(jsonData)
	
	// Create SecureMessage
	message := map[string]interface{}{
		"id":        fmt.Sprintf("reg_complete_%d", time.Now().UnixNano()),
		"type":      "request",
		"channel":   "agent.registration.complete",
		"timestamp": time.Now().Unix(),
		"payload":   payloadB64,
		"headers":   map[string]string{},
	}
	
	return conn.WriteJSON(message)
}

// performWebSocketAuthentication performs agent authentication through WebSocket messages (DEPRECATED)
func (wsm *WebSocketManager) performWebSocketAuthentication(conn *websocket.Conn) error {
	log.Printf("[websocket] Performing WebSocket authentication for agent %s", wsm.agentID)
	
	// Create authentication data
	timestamp := time.Now().Unix()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	
	// Create signature data: agent_id:public_key:timestamp:nonce
	signatureData := fmt.Sprintf("%s:%s:%d:%s", 
		wsm.agentID, 
		base64.StdEncoding.EncodeToString(wsm.publicKey), 
		timestamp, 
		nonceB64)
	
	// Sign the data
	signature := ed25519.Sign(wsm.privateKey, []byte(signatureData))
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	
	// Send authentication request according to WebSocket Protocol Specification
	authData := map[string]interface{}{
		"agent_id":   wsm.agentID,
		"public_key": base64.StdEncoding.EncodeToString(wsm.publicKey),
		"timestamp":  timestamp,
		"nonce":      nonceB64,
		"signature":  signatureB64,
	}
	
	// Base64 encode the authentication payload
	jsonData, err := json.Marshal(authData)
	if err != nil {
		return fmt.Errorf("failed to marshal auth payload: %w", err)
	}
	payloadB64 := base64.StdEncoding.EncodeToString(jsonData)
	
	// Create SecureMessage with channel "auth"
	authMessage := map[string]interface{}{
		"id":        fmt.Sprintf("auth_%d", time.Now().UnixNano()),
		"type":      "request",
		"channel":   "auth",
		"timestamp": time.Now().Unix(),
		"payload":   payloadB64,
		"headers":   map[string]string{},
	}
	
	// Send authentication request using SecureMessage format
	log.Printf("[websocket] Sending WebSocket authentication request")
	if err := conn.WriteJSON(authMessage); err != nil {
		return fmt.Errorf("failed to send authentication request: %w", err)
	}
	
	// Set timeout for reading response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	
	// Read authentication response as SecureMessage
	var authResponse map[string]interface{}
	if err := conn.ReadJSON(&authResponse); err != nil {
		log.Printf("[websocket] Failed to read authentication response: %v", err)
		return fmt.Errorf("failed to read authentication response: %w", err)
	}
	
	log.Printf("[websocket] Authentication response received: %v", authResponse)
	
	// Check if authentication was successful
	channel, _ := authResponse["channel"].(string)
	if channel != "auth" {
		return fmt.Errorf("unexpected response channel: %s", channel)
	}
	
	// Parse the payload
	payloadStr, _ := authResponse["payload"].(string)
	payloadBytes, err := base64.StdEncoding.DecodeString(payloadStr)
	if err != nil {
		return fmt.Errorf("failed to decode auth response payload: %w", err)
	}
	
	var authResponseData map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &authResponseData); err != nil {
		return fmt.Errorf("failed to unmarshal auth response: %w", err)
	}
	
	// Check if authentication was successful
	success, hasSuccess := authResponseData["success"].(bool)
	if !hasSuccess || !success {
		message := "Authentication failed"
		if msg, hasMsg := authResponseData["message"].(string); hasMsg {
			message = msg
		}
		return fmt.Errorf("authentication failed: %s", message)
	}
	
	// Store session information
	if sessionToken, ok := authResponseData["session_token"].(string); ok {
		wsm.sessionToken = sessionToken
		log.Printf("[websocket] Session token received: %s", sessionToken[:20]+"...")
	}
	
	if expiresAt, ok := authResponseData["expires_at"].(float64); ok {
		wsm.sessionExpires = time.Unix(int64(expiresAt), 0)
		log.Printf("[websocket] Session expires at: %v", wsm.sessionExpires)
	}
	
	// Store backend key for shared key derivation
	if backendKey, ok := authResponseData["backend_key"].(string); ok {
		backendKeyBytes, err := base64.StdEncoding.DecodeString(backendKey)
		if err != nil {
			return fmt.Errorf("failed to decode backend key: %w", err)
		}
		
		// Derive shared key: SHA256(agent_private_key + backend_public_key)
		sharedKey := sha256.Sum256(append(wsm.privateKey, backendKeyBytes...))
		wsm.sharedKey = sharedKey[:]
		log.Printf("[websocket] Shared key derived successfully")
	}
	
	log.Printf("[websocket] WebSocket authentication successful")
	return nil
}

// performHTTPRegistration performs agent registration via HTTP through WebSocket Gateway (as per AGENT_TEAM_FINAL_SOLUTION.md)
func (wsm *WebSocketManager) performHTTPRegistration() error {
	log.Printf("[websocket] Performing HTTP registration for agent %s", wsm.agentID)
	log.Printf("[websocket] HTTP registration method started")
	
	// Convert WebSocket URL to HTTP URL for registration
	log.Printf("[websocket] Converting WebSocket URL to HTTP URL")
	httpURL := strings.Replace(wsm.backendURL, "ws://", "http://", 1)
	httpURL = strings.Replace(httpURL, "wss://", "https://", 1)
	httpURL = strings.TrimSuffix(httpURL, "/ws/agent")
	log.Printf("[websocket] HTTP URL: %s", httpURL)
	
	// Step 1: Registration Init
	initURL := httpURL + "/agents/register/init"
	initData := map[string]interface{}{
		"org_id":           "default-org",
		"host_id":          wsm.agentID,
		"agent_pubkey":     base64.StdEncoding.EncodeToString(wsm.publicKey),
		"machine_id_hash":  wsm.agentID + "-hash",
		"agent_version":    "1.0.1",
		"capabilities": map[string]interface{}{
			"websocket":   true,
			"heartbeat":   true,
			"enforcement": true,
		},
		"platform": map[string]interface{}{
			"os":   "linux",
			"arch": "arm64",
		},
		"network": map[string]interface{}{
			"interface": "eth0",
		},
	}
	
	jsonData, err := json.Marshal(initData)
	if err != nil {
		return fmt.Errorf("failed to marshal init data: %w", err)
	}
	
	resp, err := http.Post(initURL, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send registration init: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration init failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var initResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&initResponse); err != nil {
		return fmt.Errorf("failed to decode init response: %w", err)
	}
	
	log.Printf("[websocket] Registration init response: %v", initResponse)
	
	// Extract registration data
	nonce, hasNonce := initResponse["nonce"].(string)
	if !hasNonce {
		return fmt.Errorf("no nonce in init response")
	}
	
	serverTime, hasServerTime := initResponse["server_time"].(string)
	if !hasServerTime {
		return fmt.Errorf("no server_time in init response")
	}
	
	registrationID, hasRegID := initResponse["registration_id"].(string)
	if !hasRegID {
		return fmt.Errorf("no registration_id in init response")
	}
	
	// Step 2: Registration Complete with signature
	completeURL := httpURL + "/agents/register/complete"
	
	// Sign the data: nonce + server_time + host_id (exactly what backend expects)
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}
	
	dataToSign := append(nonceBytes, []byte(serverTime+wsm.agentID)...)
	signature := ed25519.Sign(wsm.privateKey, dataToSign)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	
	completeData := map[string]interface{}{
		"registration_id": registrationID,
		"host_id":         wsm.agentID,
		"signature":       signatureB64,
	}
	
	jsonData, err = json.Marshal(completeData)
	if err != nil {
		return fmt.Errorf("failed to marshal complete data: %w", err)
	}
	
	resp, err = http.Post(completeURL, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send registration complete: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration complete failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var completeResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&completeResponse); err != nil {
		return fmt.Errorf("failed to decode complete response: %w", err)
	}
	
	log.Printf("[websocket] Registration complete response: %v", completeResponse)
	
	log.Printf("[websocket] HTTP registration successful for agent %s", wsm.agentID)
	return nil
}

// performWebSocketRegistration_DUPLICATE_REMOVED performs agent registration through WebSocket messages
func (wsm *WebSocketManager) performWebSocketRegistration_DUPLICATE_REMOVED(conn *websocket.Conn) error {
	log.Printf("[websocket] Performing WebSocket registration for agent %s", wsm.agentID)
	log.Printf("[websocket] WebSocket registration method started")
	
	// Step 1: Send registration_init message
	log.Printf("[websocket] Creating registration_init message")
	
	// Registration data
	registrationData := map[string]interface{}{
		"org_id":           "default-org",
		"host_id":          wsm.agentID,
		"agent_pubkey":     base64.StdEncoding.EncodeToString(wsm.publicKey),
		"machine_id_hash":  wsm.agentID + "-hash",
		"agent_version":    "1.0.1",
		"capabilities": map[string]interface{}{
			"websocket":   true,
			"heartbeat":   true,
			"enforcement": true,
		},
		"platform": map[string]interface{}{
			"os":   "linux",
			"arch": "arm64",
		},
		"network": map[string]interface{}{
			"interface": "eth0",
		},
	}
	
	// Convert to JSON and base64 encode
	jsonData, err := json.Marshal(registrationData)
	if err != nil {
		return fmt.Errorf("failed to marshal registration data: %w", err)
	}
	payloadB64 := base64.StdEncoding.EncodeToString(jsonData)
	
	initMsg := map[string]interface{}{
		"id":        fmt.Sprintf("reg_init_%d", time.Now().UnixNano()),
		"type":      "request",
		"channel":   "agent.registration",
		"timestamp": time.Now().Unix(),
		"payload":   payloadB64,
		"headers":   make(map[string]string),
	}
	
	// Send registration_init request
	if err := conn.WriteJSON(initMsg); err != nil {
		return fmt.Errorf("failed to send registration_init request: %w", err)
	}
	
	log.Printf("[websocket] Registration init request sent: %s", initMsg["id"])
	
	// Set timeout for reading response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	
	// Read registration_init response
	var initResponse map[string]interface{}
	if err := conn.ReadJSON(&initResponse); err != nil {
		log.Printf("[websocket] Failed to read registration_init response: %v", err)
		return fmt.Errorf("failed to read registration_init response: %w", err)
	}
	
	log.Printf("[websocket] Registration init response received: %v", initResponse)
	
	// Check if init was successful
	responseType, hasType := initResponse["type"].(string)
	if !hasType || responseType != "response" {
		return fmt.Errorf("registration init failed - invalid response type")
	}
	
	// Extract registration data from response payload
	payloadStr, hasPayload := initResponse["payload"].(string)
	if !hasPayload {
		return fmt.Errorf("no payload in registration response")
	}
	
	payloadBytes, err := base64.StdEncoding.DecodeString(payloadStr)
	if err != nil {
		return fmt.Errorf("failed to decode response payload: %w", err)
	}
	
	var regData map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &regData); err != nil {
		return fmt.Errorf("failed to parse registration data: %w", err)
	}
	
	log.Printf("[websocket] Registration data: %v", regData)
	
	// Step 2: Send registration_complete message with signature
	nonce, hasNonce := regData["nonce"].(string)
	if !hasNonce {
		return fmt.Errorf("no nonce in registration response")
	}
	
	serverTime, hasServerTime := regData["server_time"].(string)
	if !hasServerTime {
		return fmt.Errorf("no server_time in registration response")
	}
	
	registrationID, hasRegID := regData["registration_id"].(string)
	if !hasRegID {
		return fmt.Errorf("no registration_id in registration response")
	}
	
	// Sign the data: nonce + server_time + host_id
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}
	
	dataToSign := append(nonceBytes, []byte(serverTime+wsm.agentID)...)
	signature := ed25519.Sign(wsm.privateKey, dataToSign)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	
	// Completion data
	completionData := map[string]interface{}{
		"registration_id": registrationID,
		"host_id":         wsm.agentID,
		"signature":       signatureB64,
	}
	
	// Convert to JSON and base64 encode
	jsonData, err = json.Marshal(completionData)
	if err != nil {
		return fmt.Errorf("failed to marshal completion data: %w", err)
	}
	payloadB64 = base64.StdEncoding.EncodeToString(jsonData)
	
	completeMsg := map[string]interface{}{
		"id":        fmt.Sprintf("reg_complete_%d", time.Now().UnixNano()),
		"type":      "request",
		"channel":   "agent.registration.complete",
		"timestamp": time.Now().Unix(),
		"payload":   payloadB64,
		"headers":   make(map[string]string),
	}
	
	// Send registration_complete request
	if err := conn.WriteJSON(completeMsg); err != nil {
		return fmt.Errorf("failed to send registration_complete request: %w", err)
	}
	
	log.Printf("[websocket] Registration complete request sent: %s", completeMsg["id"])
	
	// Set timeout for reading response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	
	// Read registration_complete response
	var completeResponse map[string]interface{}
	if err := conn.ReadJSON(&completeResponse); err != nil {
		log.Printf("[websocket] Failed to read registration_complete response: %v", err)
		return fmt.Errorf("failed to read registration_complete response: %w", err)
	}
	
	log.Printf("[websocket] Registration complete response received: %v", completeResponse)
	
	// Check if registration was successful
	successType, hasSuccessType := completeResponse["type"].(string)
	if !hasSuccessType || successType != "response" {
		return fmt.Errorf("registration complete failed")
	}
	
	log.Printf("[websocket] WebSocket registration successful for agent %s", wsm.agentID)
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

	// Send agent registration after successful authentication
	if err := wsm.sendAgentRegistration(conn); err != nil {
		log.Printf("[websocket] Warning: failed to send agent registration: %v", err)
		// Don't fail authentication for registration issues
	}

	log.Printf("[websocket] Authentication successful, session expires at %v", wsm.sessionExpires)
	return nil
}

// sendAgentRegistration performs HTTP-based two-step registration
func (wsm *WebSocketManager) sendAgentRegistration(conn *websocket.Conn) error {
	// Extract base URL from WebSocket URL (ws://host:port -> http://host:port)
	baseURL := wsm.backendURL
	if len(baseURL) > 5 && baseURL[:5] == "ws://" {
		baseURL = "http://" + baseURL[5:]
	} else if len(baseURL) > 6 && baseURL[:6] == "wss://" {
		baseURL = "https://" + baseURL[6:]
	}

	// Remove WebSocket path if present
	if idx := len(baseURL) - len("/ws/agent"); idx > 0 && baseURL[idx:] == "/ws/agent" {
		baseURL = baseURL[:idx]
	}

	log.Printf("[websocket] Performing HTTP registration with base URL: %s", baseURL)

	// Create registration client
	registrationClient := NewRegistrationClient(wsm.agentID, wsm.privateKey, wsm.publicKey, baseURL)

	// Perform two-step registration
	if err := registrationClient.Register(); err != nil {
		log.Printf("[websocket] HTTP registration failed: %v", err)
		return fmt.Errorf("HTTP registration failed: %w", err)
	}

	log.Printf("[websocket] HTTP registration successful for agent %s", wsm.agentID)
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
	ticker := time.NewTicker(60 * time.Second) // Send heartbeat every 60 seconds (production-ready)
	defer ticker.Stop()

	log.Printf("[websocket] Heartbeat goroutine started")
	
	for {
		select {
		case <-wsm.ctx.Done():
			log.Printf("[websocket] Heartbeat goroutine stopping")
			return
		case <-ticker.C:
			log.Printf("[websocket] Heartbeat ticker triggered")
			// Only send heartbeat if authenticated
			wsm.mu.RLock()
			authenticated := wsm.isAuthenticated
			wsm.mu.RUnlock()
			
			if authenticated {
				wsm.sendHeartbeat()
			} else {
				log.Printf("[websocket] Skipping heartbeat - not authenticated yet")
			}
		}
	}
}

// connectionMonitor monitors connection health
func (wsm *WebSocketManager) connectionMonitor() {
	ticker := time.NewTicker(120 * time.Second) // Check every 2 minutes (production-ready)
	defer ticker.Stop()

	for {
		select {
		case <-wsm.ctx.Done():
			return
		case <-ticker.C:
			// Only check health if we're in connected state
			wsm.mu.RLock()
			state := wsm.connectionState
			wsm.mu.RUnlock()
			
			if state == "connected" && !wsm.isConnectionHealthy() {
				log.Printf("[websocket] Connection unhealthy, attempting reconnection...")
				wsm.mu.Lock()
				wsm.connectionState = "reconnecting"
				wsm.mu.Unlock()
				
				if err := wsm.reconnect(); err != nil {
					log.Printf("[websocket] Reconnection failed: %v", err)
					wsm.mu.Lock()
					wsm.connectionState = "disconnected"
					wsm.mu.Unlock()
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
	// Prevent reconnection loops
	wsm.mu.Lock()
	if wsm.isReconnecting {
		wsm.mu.Unlock()
		log.Printf("[websocket] Already reconnecting, skipping duplicate reconnection attempt")
		return nil
	}
	wsm.isReconnecting = true
	wsm.mu.Unlock()
	
	// Close existing connection
	wsm.mu.Lock()
	if wsm.connection != nil {
		wsm.connection.Close()
		wsm.connection = nil
	}
	wsm.connectionState = "reconnecting"
	wsm.mu.Unlock()

	// Wait before reconnecting with exponential backoff
	time.Sleep(wsm.reconnectDelay)
	log.Printf("[websocket] Attempting reconnection after %v delay", wsm.reconnectDelay)

	// Establish new connection
	if err := wsm.connect(); err != nil {
		// Increase reconnect delay with exponential backoff
		wsm.reconnectDelay = time.Duration(float64(wsm.reconnectDelay) * 1.5)
		if wsm.reconnectDelay > wsm.maxReconnectDelay {
			wsm.reconnectDelay = wsm.maxReconnectDelay
		}
		log.Printf("[websocket] Reconnection failed, next attempt in %v: %v", wsm.reconnectDelay, err)
		
		// Update state to disconnected on failure
		wsm.mu.Lock()
		wsm.connectionState = "disconnected"
		wsm.mu.Unlock()
		return err
	}

	// Reset reconnect delay on successful connection
	wsm.reconnectDelay = 2 * time.Second
	wsm.incrementReconnectCount()
	
	// Reset reconnecting flag
	wsm.mu.Lock()
	wsm.isReconnecting = false
	wsm.mu.Unlock()
	
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
		Channel:   "heartbeat",
		Payload:   base64.StdEncoding.EncodeToString([]byte("{}")),
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
		// Don't trigger reconnection on heartbeat failure - let the connection health check handle it
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
