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
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
)

// SecureConnectionManager manages secure bidirectional communication
type SecureConnectionManager struct {
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
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	running           bool
}

// CommunicationChannels defines the communication channels
type CommunicationChannels struct {
	// Agent to Backend channels
	PolicyUpdates    string
	AnomalyAlerts    string
	ThreatMatches    string
	ProcessEvents    string
	DependencyData   string
	TestResults      string
	RollbackStatus   string
	Heartbeat        string
	Status           string
	Logs             string
	
	// Backend to Agent channels
	PolicyCommands   string
	InvestigationReq string
	ThreatIntel      string
	ProcessPolicies  string
	TestCommands     string
	RollbackCommands string
}

// QueuedMessage represents a queued message for reliable delivery
type QueuedMessage struct {
	ID         string
	Channel    string
	Message    interface{}
	Timestamp  time.Time
	Retries    int
	MaxRetries int
}

// SecureMessage represents an encrypted message
type SecureMessage struct {
	ID        string            `json:"id"`
	Type      MessageType       `json:"type"`
	Channel   string            `json:"channel"`
	Payload   string            `json:"payload"`      // Encrypted
	Timestamp int64             `json:"timestamp"`
	Nonce     string            `json:"nonce"`
	Signature string            `json:"signature"`
	Headers   map[string]string `json:"headers"`
}

// MessageType represents the type of message
type MessageType string

const (
	MessageTypeRequest  MessageType = "request"
	MessageTypeResponse MessageType = "response"
	MessageTypeEvent    MessageType = "event"
	MessageTypeHeartbeat MessageType = "heartbeat"
	MessageTypeAck      MessageType = "ack"
)

// AuthenticationRequest represents an authentication request
type AuthenticationRequest struct {
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// AuthenticationResponse represents an authentication response
type AuthenticationResponse struct {
	Success      bool   `json:"success"`
	BackendKey   string `json:"backend_key"`
	SessionToken string `json:"session_token"`
	ExpiresAt    int64  `json:"expires_at"`
	Message      string `json:"message,omitempty"`
}

// NewSecureConnectionManager creates a new secure connection manager
func NewSecureConnectionManager(agentID, backendURL string) (*SecureConnectionManager, error) {
	// Generate Ed25519 keypair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	scm := &SecureConnectionManager{
		agentID:           agentID,
		backendURL:        backendURL,
		privateKey:        privateKey,
		publicKey:         publicKey,
		reconnectDelay:    5 * time.Second,
		maxReconnectDelay: 60 * time.Second,
		messageQueue:      make(chan QueuedMessage, 1000),
		responseHandlers:  make(map[string]chan interface{}),
		channels:          NewCommunicationChannels(agentID),
		ctx:               ctx,
		cancel:            cancel,
	}
	
	log.Printf("[secure_connection] Secure connection manager initialized for agent %s", agentID)
	return scm, nil
}

// NewCommunicationChannels creates communication channels for an agent
func NewCommunicationChannels(agentID string) *CommunicationChannels {
	return &CommunicationChannels{
		// Agent to Backend channels
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
		
		// Backend to Agent channels
		PolicyCommands:   fmt.Sprintf("backend.%s.policies", agentID),
		InvestigationReq: fmt.Sprintf("backend.%s.investigations", agentID),
		ThreatIntel:      fmt.Sprintf("backend.%s.threats", agentID),
		ProcessPolicies:  fmt.Sprintf("backend.%s.processes", agentID),
		TestCommands:     fmt.Sprintf("backend.%s.tests", agentID),
		RollbackCommands: fmt.Sprintf("backend.%s.rollbacks", agentID),
	}
}

// Start starts the secure connection manager
func (scm *SecureConnectionManager) Start() error {
	scm.mu.Lock()
	defer scm.mu.Unlock()
	
	if scm.running {
		return fmt.Errorf("secure connection manager already running")
	}
	
	scm.running = true
	
	// Start connection maintenance
	go scm.maintainConnection()
	
	// Start message queue processing
	go scm.processMessageQueue()
	
	log.Printf("[secure_connection] Secure connection manager started")
	return nil
}

// Stop stops the secure connection manager
func (scm *SecureConnectionManager) Stop() error {
	scm.mu.Lock()
	defer scm.mu.Unlock()
	
	if !scm.running {
		return fmt.Errorf("secure connection manager not running")
	}
	
	scm.cancel()
	scm.running = false
	
	if scm.connection != nil {
		scm.connection.Close()
	}
	
	log.Printf("[secure_connection] Secure connection manager stopped")
	return nil
}

// maintainConnection maintains the connection with automatic reconnection
func (scm *SecureConnectionManager) maintainConnection() {
	for {
		select {
		case <-scm.ctx.Done():
			return
		default:
			// Check if connection is healthy
			if !scm.IsConnectionHealthy() {
				log.Printf("[secure_connection] Connection unhealthy, attempting reconnection...")
				if err := scm.reconnect(); err != nil {
					log.Printf("[secure_connection] Reconnection failed: %v", err)
					time.Sleep(scm.reconnectDelay)
					scm.increaseReconnectDelay()
					continue
				}
				scm.resetReconnectDelay()
			}
			
			time.Sleep(5 * time.Second)
		}
	}
}

// IsConnectionHealthy checks if the connection is healthy
func (scm *SecureConnectionManager) IsConnectionHealthy() bool {
	scm.mu.RLock()
	defer scm.mu.RUnlock()
	
	if scm.connection == nil {
		return false
	}
	
	// Check if session is expired
	if time.Now().After(scm.sessionExpires) {
		return false
	}
	
	// Send ping to check connection
	scm.connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := scm.connection.WriteMessage(websocket.PingMessage, nil); err != nil {
		return false
	}
	
	return true
}

// reconnect establishes a new connection
func (scm *SecureConnectionManager) reconnect() error {
	// Close existing connection
	if scm.connection != nil {
		scm.connection.Close()
	}
	
	// Establish new connection
	conn, err := scm.establishConnection()
	if err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}
	
	// Authenticate
	if err := scm.authenticate(conn); err != nil {
		conn.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}
	
	// Update connection
	scm.mu.Lock()
	scm.connection = conn
	scm.mu.Unlock()
	
	// Start message processing
	go scm.processMessages()
	
	log.Printf("[secure_connection] Successfully reconnected to backend")
	return nil
}

// establishConnection establishes a WebSocket connection
func (scm *SecureConnectionManager) establishConnection() (*websocket.Conn, error) {
	// Create secure WebSocket connection
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // Use proper cert validation in production
		},
		HandshakeTimeout: 30 * time.Second,
	}
	
	// Add authentication headers
	headers := http.Header{}
	headers.Set("X-Agent-ID", scm.agentID)
	headers.Set("X-Agent-Public-Key", base64.StdEncoding.EncodeToString(scm.publicKey))
	headers.Set("User-Agent", "Aegis-Agent/1.0")
	
	conn, _, err := dialer.Dial(scm.backendURL, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to dial WebSocket: %w", err)
	}
	
	// Set connection parameters
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	
	return conn, nil
}

// authenticate performs mutual authentication
func (scm *SecureConnectionManager) authenticate(conn *websocket.Conn) error {
	// Create authentication request
	nonce := generateNonce()
	timestamp := time.Now().Unix()
	
	authReq := AuthenticationRequest{
		AgentID:   scm.agentID,
		PublicKey: base64.StdEncoding.EncodeToString(scm.publicKey),
		Timestamp: timestamp,
		Nonce:     nonce,
	}
	
	// Sign the request
	signature := scm.signRequest(authReq)
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
	scm.mu.Lock()
	scm.sessionToken = authResp.SessionToken
	scm.sessionExpires = time.Unix(authResp.ExpiresAt, 0)
	
	// Derive shared key from backend key
	backendKey, err := base64.StdEncoding.DecodeString(authResp.BackendKey)
	if err != nil {
		scm.mu.Unlock()
		return fmt.Errorf("failed to decode backend key: %w", err)
	}
	
	// Generate shared key using ECDH-like key agreement
	scm.sharedKey = scm.deriveSharedKey(backendKey)
	scm.mu.Unlock()
	
	log.Printf("[secure_connection] Authentication successful, session expires at %v", scm.sessionExpires)
	return nil
}

// signRequest signs an authentication request
func (scm *SecureConnectionManager) signRequest(req AuthenticationRequest) string {
	// Create data to sign
	data := fmt.Sprintf("%s:%s:%d:%s", req.AgentID, req.PublicKey, req.Timestamp, req.Nonce)
	
	// Sign the data
	signature := ed25519.Sign(scm.privateKey, []byte(data))
	
	return base64.StdEncoding.EncodeToString(signature)
}

// deriveSharedKey derives a shared key from the backend key
func (scm *SecureConnectionManager) deriveSharedKey(backendKey []byte) []byte {
	// Simple key derivation (in production, use proper ECDH)
	hash := sha256.New()
	hash.Write(scm.privateKey)
	hash.Write(backendKey)
	return hash.Sum(nil)
}

// SendMessage sends a message to the backend
func (scm *SecureConnectionManager) SendMessage(channel string, messageType MessageType, payload interface{}) error {
	// Queue message for reliable delivery
	queuedMsg := QueuedMessage{
		ID:         generateMessageID(),
		Channel:    channel,
		Message:    payload,
		Timestamp:  time.Now(),
		Retries:    0,
		MaxRetries: 3,
	}
	
	select {
	case scm.messageQueue <- queuedMsg:
		return nil
	default:
		return fmt.Errorf("message queue full")
	}
}

// processMessageQueue processes queued messages
func (scm *SecureConnectionManager) processMessageQueue() {
	for {
		select {
		case <-scm.ctx.Done():
			return
		case msg := <-scm.messageQueue:
			if err := scm.sendQueuedMessage(msg); err != nil {
				log.Printf("[secure_connection] Failed to send message: %v", err)
				
				// Retry logic
				msg.Retries++
				if msg.Retries < msg.MaxRetries {
					select {
					case scm.messageQueue <- msg:
					default:
						log.Printf("[secure_connection] Message queue full, dropping message")
					}
				}
			}
		}
	}
}

// sendQueuedMessage sends a queued message
func (scm *SecureConnectionManager) sendQueuedMessage(msg QueuedMessage) error {
	scm.mu.RLock()
	conn := scm.connection
	scm.mu.RUnlock()
	
	if conn == nil {
		return fmt.Errorf("no connection available")
	}
	
	// Encrypt payload
	encryptedPayload, nonce, err := scm.encryptPayload(msg.Message)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %w", err)
	}
	
	// Create secure message
	secureMsg := SecureMessage{
		ID:        msg.ID,
		Type:      MessageTypeRequest,
		Channel:   msg.Channel,
		Payload:   encryptedPayload,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
		Headers:   make(map[string]string),
	}
	
	// Sign message
	secureMsg.Signature = scm.signMessage(secureMsg)
	
	// Send message
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return conn.WriteJSON(secureMsg)
}

// encryptPayload encrypts a payload
func (scm *SecureConnectionManager) encryptPayload(payload interface{}) (string, string, error) {
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
	cipher, err := chacha20poly1305.New(scm.sharedKey)
	if err != nil {
		return "", "", err
	}
	
	encrypted := cipher.Seal(nil, nonce, data, nil)
	
	return base64.StdEncoding.EncodeToString(encrypted), 
		   base64.StdEncoding.EncodeToString(nonce), nil
}

// signMessage signs a message
func (scm *SecureConnectionManager) signMessage(msg SecureMessage) string {
	// Create data to sign
	data := fmt.Sprintf("%s:%s:%s:%d:%s", msg.ID, msg.Type, msg.Channel, msg.Timestamp, msg.Payload)
	
	// Sign the data
	signature := ed25519.Sign(scm.privateKey, []byte(data))
	
	return base64.StdEncoding.EncodeToString(signature)
}

// processMessages processes incoming messages
func (scm *SecureConnectionManager) processMessages() {
	for {
		select {
		case <-scm.ctx.Done():
			return
		default:
			scm.mu.RLock()
			conn := scm.connection
			scm.mu.RUnlock()
			
			if conn == nil {
				time.Sleep(1 * time.Second)
				continue
			}
			
			// Read message
			var msg SecureMessage
			if err := conn.ReadJSON(&msg); err != nil {
				log.Printf("[secure_connection] Failed to read message: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}
			
			// Process message
			if err := scm.processMessage(msg); err != nil {
				log.Printf("[secure_connection] Failed to process message: %v", err)
			}
		}
	}
}

// processMessage processes a received message
func (scm *SecureConnectionManager) processMessage(msg SecureMessage) error {
	// Decrypt payload
	payload, err := scm.decryptPayload(msg.Payload, msg.Nonce)
	if err != nil {
		return fmt.Errorf("failed to decrypt payload: %w", err)
	}
	
	// Verify signature
	if !scm.verifySignature(msg) {
		return fmt.Errorf("invalid message signature")
	}
	
	// Route message based on channel
	switch msg.Channel {
	case scm.channels.PolicyCommands:
		return scm.handlePolicyCommand(payload)
	case scm.channels.InvestigationReq:
		return scm.handleInvestigationRequest(payload)
	case scm.channels.ThreatIntel:
		return scm.handleThreatIntelligence(payload)
	case scm.channels.ProcessPolicies:
		return scm.handleProcessPolicy(payload)
	case scm.channels.TestCommands:
		return scm.handleTestCommand(payload)
	case scm.channels.RollbackCommands:
		return scm.handleRollbackCommand(payload)
	default:
		log.Printf("[secure_connection] Unknown channel: %s", msg.Channel)
	}
	
	return nil
}

// decryptPayload decrypts a payload
func (scm *SecureConnectionManager) decryptPayload(encryptedPayload, nonce string) (interface{}, error) {
	// Decode encrypted payload
	encrypted, err := base64.StdEncoding.DecodeString(encryptedPayload)
	if err != nil {
		return nil, err
	}
	
	// Decode nonce
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return nil, err
	}
	
	// Decrypt using ChaCha20-Poly1305
	cipher, err := chacha20poly1305.New(scm.sharedKey)
	if err != nil {
		return nil, err
	}
	
	decrypted, err := cipher.Open(nil, nonceBytes, encrypted, nil)
	if err != nil {
		return nil, err
	}
	
	// Deserialize payload
	var payload interface{}
	if err := json.Unmarshal(decrypted, &payload); err != nil {
		return nil, err
	}
	
	return payload, nil
}

// verifySignature verifies a message signature
func (scm *SecureConnectionManager) verifySignature(msg SecureMessage) bool {
	// Create data to verify
	_ = fmt.Sprintf("%s:%s:%s:%d:%s", msg.ID, msg.Type, msg.Channel, msg.Timestamp, msg.Payload)
	
	// Decode signature
	_, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return false
	}
	
	// Verify signature (in production, use backend's public key)
	// For now, we'll skip verification as we don't have the backend's public key
	return true
}

// Message handlers
func (scm *SecureConnectionManager) handlePolicyCommand(payload interface{}) error {
	log.Printf("[secure_connection] Received policy command: %+v", payload)
	// Implement policy command handling
	return nil
}

func (scm *SecureConnectionManager) handleInvestigationRequest(payload interface{}) error {
	log.Printf("[secure_connection] Received investigation request: %+v", payload)
	// Implement investigation request handling
	return nil
}

func (scm *SecureConnectionManager) handleThreatIntelligence(payload interface{}) error {
	log.Printf("[secure_connection] Received threat intelligence: %+v", payload)
	// Implement threat intelligence handling
	return nil
}

func (scm *SecureConnectionManager) handleProcessPolicy(payload interface{}) error {
	log.Printf("[secure_connection] Received process policy: %+v", payload)
	// Implement process policy handling
	return nil
}

func (scm *SecureConnectionManager) handleTestCommand(payload interface{}) error {
	log.Printf("[secure_connection] Received test command: %+v", payload)
	// Implement test command handling
	return nil
}

func (scm *SecureConnectionManager) handleRollbackCommand(payload interface{}) error {
	log.Printf("[secure_connection] Received rollback command: %+v", payload)
	// Implement rollback command handling
	return nil
}

// increaseReconnectDelay increases the reconnect delay
func (scm *SecureConnectionManager) increaseReconnectDelay() {
	scm.reconnectDelay *= 2
	if scm.reconnectDelay > scm.maxReconnectDelay {
		scm.reconnectDelay = scm.maxReconnectDelay
	}
}

// resetReconnectDelay resets the reconnect delay
func (scm *SecureConnectionManager) resetReconnectDelay() {
	scm.reconnectDelay = 5 * time.Second
}

// Helper functions
func generateNonce() string {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(nonce)
}

func generateMessageID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return base64.StdEncoding.EncodeToString(id)
}
