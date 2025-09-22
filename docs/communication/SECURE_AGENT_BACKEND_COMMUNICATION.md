# Secure Agent-Backend Communication Architecture

## Problem Statement

In enterprise environments, agents are typically deployed behind firewalls with no inbound connectivity, while backends are hosted in the cloud. This creates a challenge for bidirectional communication:

- **Agent → Backend**: Possible (outbound connections)
- **Backend → Agent**: Blocked (inbound connections blocked by firewall)
- **Security**: All communication must be encrypted and authenticated
- **Reliability**: Connection must be resilient to network interruptions

## Solution: Secure Bidirectional Communication Channel

### Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Aegis Agent   │    │  Communication   │    │   Backend API   │
│  (Behind FW)    │◄──►│     Gateway      │◄──►│    (Cloud)      │
│                 │    │   (NATS/WebSocket)│    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Core Components

1. **Agent-Initiated Connection**: Agent establishes persistent connection
2. **Communication Gateway**: NATS/WebSocket gateway for bidirectional messaging
3. **Secure Tunneling**: Encrypted communication with mutual authentication
4. **Connection Management**: Automatic reconnection and health monitoring
5. **Message Queuing**: Reliable message delivery with acknowledgments

## Implementation Strategy

### 1. **Agent-Initiated Persistent Connection**

#### WebSocket Connection with Reconnection
```go
type SecureConnectionManager struct {
    backendURL        string
    agentID          string
    privateKey       ed25519.PrivateKey
    publicKey        ed25519.PublicKey
    connection       *websocket.Conn
    reconnectDelay   time.Duration
    maxReconnectDelay time.Duration
    messageQueue     chan []byte
    responseHandlers map[string]chan []byte
    mu               sync.RWMutex
    ctx              context.Context
    cancel           context.CancelFunc
}

func (scm *SecureConnectionManager) Connect() error {
    // 1. Establish initial connection
    conn, err := scm.establishConnection()
    if err != nil {
        return fmt.Errorf("failed to establish connection: %w", err)
    }
    
    // 2. Perform mutual authentication
    if err := scm.authenticate(conn); err != nil {
        return fmt.Errorf("authentication failed: %w", err)
    }
    
    // 3. Start message processing
    go scm.processMessages()
    go scm.heartbeat()
    
    return nil
}

func (scm *SecureConnectionManager) establishConnection() (*websocket.Conn, error) {
    // Create secure WebSocket connection
    dialer := websocket.Dialer{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: false, // Use proper cert validation
        },
    }
    
    // Add authentication headers
    headers := http.Header{}
    headers.Set("X-Agent-ID", scm.agentID)
    headers.Set("X-Agent-Public-Key", base64.StdEncoding.EncodeToString(scm.publicKey))
    
    conn, _, err := dialer.Dial(scm.backendURL, headers)
    if err != nil {
        return nil, fmt.Errorf("failed to dial WebSocket: %w", err)
    }
    
    return conn, nil
}
```

#### Mutual Authentication Protocol
```go
type AuthenticationRequest struct {
    AgentID      string `json:"agent_id"`
    PublicKey    string `json:"public_key"`
    Timestamp    int64  `json:"timestamp"`
    Nonce        string `json:"nonce"`
    Signature    string `json:"signature"`
}

type AuthenticationResponse struct {
    Success      bool   `json:"success"`
    BackendKey   string `json:"backend_key"`
    SessionToken string `json:"session_token"`
    ExpiresAt    int64  `json:"expires_at"`
    Message      string `json:"message,omitempty"`
}

func (scm *SecureConnectionManager) authenticate(conn *websocket.Conn) error {
    // 1. Create authentication request
    nonce := generateNonce()
    timestamp := time.Now().Unix()
    
    authReq := AuthenticationRequest{
        AgentID:   scm.agentID,
        PublicKey: base64.StdEncoding.EncodeToString(scm.publicKey),
        Timestamp: timestamp,
        Nonce:     nonce,
    }
    
    // 2. Sign the request
    signature := scm.signRequest(authReq)
    authReq.Signature = signature
    
    // 3. Send authentication request
    if err := conn.WriteJSON(authReq); err != nil {
        return fmt.Errorf("failed to send auth request: %w", err)
    }
    
    // 4. Receive authentication response
    var authResp AuthenticationResponse
    if err := conn.ReadJSON(&authResp); err != nil {
        return fmt.Errorf("failed to read auth response: %w", err)
    }
    
    // 5. Validate response
    if !authResp.Success {
        return fmt.Errorf("authentication failed: %s", authResp.Message)
    }
    
    // 6. Store session token
    scm.sessionToken = authResp.SessionToken
    scm.sessionExpires = time.Unix(authResp.ExpiresAt, 0)
    
    return nil
}
```

### 2. **Message Protocol with Encryption**

#### Encrypted Message Structure
```go
type SecureMessage struct {
    ID           string            `json:"id"`
    Type         MessageType       `json:"type"`
    Channel      string            `json:"channel"`
    Payload      string            `json:"payload"`      // Encrypted
    Timestamp    int64            `json:"timestamp"`
    Nonce        string            `json:"nonce"`
    Signature    string            `json:"signature"`
    Headers      map[string]string `json:"headers"`
}

type MessageType string
const (
    MessageTypeRequest  MessageType = "request"
    MessageTypeResponse MessageType = "response"
    MessageTypeEvent    MessageType = "event"
    MessageTypeHeartbeat MessageType = "heartbeat"
    MessageTypeAck      MessageType = "ack"
)

func (scm *SecureConnectionManager) SendMessage(channel string, messageType MessageType, payload interface{}) error {
    // 1. Encrypt payload
    encryptedPayload, nonce, err := scm.encryptPayload(payload)
    if err != nil {
        return fmt.Errorf("failed to encrypt payload: %w", err)
    }
    
    // 2. Create message
    msg := SecureMessage{
        ID:        generateMessageID(),
        Type:      messageType,
        Channel:   channel,
        Payload:   encryptedPayload,
        Timestamp: time.Now().Unix(),
        Nonce:     nonce,
        Headers:   make(map[string]string),
    }
    
    // 3. Sign message
    msg.Signature = scm.signMessage(msg)
    
    // 4. Send message
    return scm.connection.WriteJSON(msg)
}

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
```

### 3. **Channel-Based Communication**

#### Communication Channels
```go
type CommunicationChannels struct {
    // Agent to Backend channels
    PolicyUpdates    string // "agent.{agent_id}.policies"
    AnomalyAlerts    string // "agent.{agent_id}.anomalies"
    ThreatMatches    string // "agent.{agent_id}.threats"
    ProcessEvents    string // "agent.{agent_id}.processes"
    DependencyData   string // "agent.{agent_id}.dependencies"
    TestResults      string // "agent.{agent_id}.tests"
    RollbackStatus   string // "agent.{agent_id}.rollbacks"
    
    // Backend to Agent channels
    PolicyCommands   string // "backend.{agent_id}.policies"
    InvestigationReq string // "backend.{agent_id}.investigations"
    ThreatIntel      string // "backend.{agent_id}.threats"
    ProcessPolicies  string // "backend.{agent_id}.processes"
    TestCommands     string // "backend.{agent_id}.tests"
    RollbackCommands string // "backend.{agent_id}.rollbacks"
    
    // Bidirectional channels
    Heartbeat        string // "agent.{agent_id}.heartbeat"
    Status           string // "agent.{agent_id}.status"
    Logs             string // "agent.{agent_id}.logs"
}

func NewCommunicationChannels(agentID string) *CommunicationChannels {
    return &CommunicationChannels{
        PolicyUpdates:    fmt.Sprintf("agent.%s.policies", agentID),
        AnomalyAlerts:    fmt.Sprintf("agent.%s.anomalies", agentID),
        ThreatMatches:    fmt.Sprintf("agent.%s.threats", agentID),
        ProcessEvents:    fmt.Sprintf("agent.%s.processes", agentID),
        DependencyData:   fmt.Sprintf("agent.%s.dependencies", agentID),
        TestResults:      fmt.Sprintf("agent.%s.tests", agentID),
        RollbackStatus:   fmt.Sprintf("agent.%s.rollbacks", agentID),
        
        PolicyCommands:   fmt.Sprintf("backend.%s.policies", agentID),
        InvestigationReq: fmt.Sprintf("backend.%s.investigations", agentID),
        ThreatIntel:      fmt.Sprintf("backend.%s.threats", agentID),
        ProcessPolicies:  fmt.Sprintf("backend.%s.processes", agentID),
        TestCommands:     fmt.Sprintf("backend.%s.tests", agentID),
        RollbackCommands: fmt.Sprintf("backend.%s.rollbacks", agentID),
        
        Heartbeat:        fmt.Sprintf("agent.%s.heartbeat", agentID),
        Status:           fmt.Sprintf("agent.%s.status", agentID),
        Logs:             fmt.Sprintf("agent.%s.logs", agentID),
    }
}
```

### 4. **Message Processing and Routing**

#### Message Router
```go
type MessageRouter struct {
    channels        *CommunicationChannels
    handlers        map[string]MessageHandler
    responseChans   map[string]chan interface{}
    mu              sync.RWMutex
}

type MessageHandler func(message SecureMessage) error

func (mr *MessageRouter) RegisterHandler(channel string, handler MessageHandler) {
    mr.mu.Lock()
    defer mr.mu.Unlock()
    mr.handlers[channel] = handler
}

func (mr *MessageRouter) ProcessMessage(msg SecureMessage) error {
    // 1. Decrypt payload
    payload, err := mr.decryptPayload(msg.Payload, msg.Nonce)
    if err != nil {
        return fmt.Errorf("failed to decrypt payload: %w", err)
    }
    
    // 2. Verify signature
    if !mr.verifySignature(msg) {
        return fmt.Errorf("invalid message signature")
    }
    
    // 3. Route to handler
    mr.mu.RLock()
    handler, exists := mr.handlers[msg.Channel]
    mr.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("no handler for channel: %s", msg.Channel)
    }
    
    // 4. Execute handler
    return handler(msg)
}
```

### 5. **Backend Integration**

#### Backend WebSocket Gateway
```go
type BackendGateway struct {
    agentConnections map[string]*AgentConnection
    messageRouter    *MessageRouter
    mu               sync.RWMutex
}

type AgentConnection struct {
    AgentID       string
    Connection    *websocket.Conn
    PublicKey     ed25519.PublicKey
    SessionToken  string
    LastSeen      time.Time
    Channels      *CommunicationChannels
}

func (bg *BackendGateway) HandleAgentConnection(conn *websocket.Conn) {
    // 1. Authenticate agent
    agentID, err := bg.authenticateAgent(conn)
    if err != nil {
        log.Printf("Agent authentication failed: %v", err)
        conn.Close()
        return
    }
    
    // 2. Create agent connection
    agentConn := &AgentConnection{
        AgentID:    agentID,
        Connection: conn,
        LastSeen:   time.Now(),
        Channels:   NewCommunicationChannels(agentID),
    }
    
    // 3. Register connection
    bg.mu.Lock()
    bg.agentConnections[agentID] = agentConn
    bg.mu.Unlock()
    
    // 4. Start message processing
    go bg.processAgentMessages(agentConn)
    
    log.Printf("Agent %s connected successfully", agentID)
}

func (bg *BackendGateway) SendToAgent(agentID string, channel string, message interface{}) error {
    bg.mu.RLock()
    agentConn, exists := bg.agentConnections[agentID]
    bg.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("agent %s not connected", agentID)
    }
    
    // Send message to agent
    return agentConn.SendMessage(channel, MessageTypeRequest, message)
}
```

### 6. **Connection Resilience**

#### Automatic Reconnection
```go
func (scm *SecureConnectionManager) maintainConnection() {
    for {
        select {
        case <-scm.ctx.Done():
            return
        default:
            // Check connection health
            if !scm.isConnectionHealthy() {
                log.Printf("Connection unhealthy, attempting reconnection...")
                if err := scm.reconnect(); err != nil {
                    log.Printf("Reconnection failed: %v", err)
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

func (scm *SecureConnectionManager) reconnect() error {
    // 1. Close existing connection
    if scm.connection != nil {
        scm.connection.Close()
    }
    
    // 2. Establish new connection
    conn, err := scm.establishConnection()
    if err != nil {
        return err
    }
    
    // 3. Re-authenticate
    if err := scm.authenticate(conn); err != nil {
        return err
    }
    
    // 4. Update connection
    scm.connection = conn
    
    // 5. Resume message processing
    go scm.processMessages()
    
    return nil
}
```

### 7. **Message Queuing and Reliability**

#### Reliable Message Delivery
```go
type MessageQueue struct {
    messages    []QueuedMessage
    maxSize     int
    mu          sync.RWMutex
}

type QueuedMessage struct {
    ID        string
    Channel   string
    Message   interface{}
    Timestamp time.Time
    Retries   int
    MaxRetries int
}

func (mq *MessageQueue) Enqueue(channel string, message interface{}) {
    mq.mu.Lock()
    defer mq.mu.Unlock()
    
    queuedMsg := QueuedMessage{
        ID:         generateMessageID(),
        Channel:    channel,
        Message:    message,
        Timestamp:  time.Now(),
        Retries:    0,
        MaxRetries: 3,
    }
    
    mq.messages = append(mq.messages, queuedMsg)
    
    // Maintain queue size
    if len(mq.messages) > mq.maxSize {
        mq.messages = mq.messages[1:]
    }
}

func (mq *MessageQueue) ProcessQueue(connection *websocket.Conn) {
    for {
        mq.mu.LLock()
        if len(mq.messages) == 0 {
            mq.mu.LUnlock()
            time.Sleep(1 * time.Second)
            continue
        }
        
        // Get next message
        msg := mq.messages[0]
        mq.messages = mq.messages[1:]
        mq.mu.LUnlock()
        
        // Send message
        if err := mq.sendMessage(connection, msg); err != nil {
            // Retry logic
            msg.Retries++
            if msg.Retries < msg.MaxRetries {
                mq.mu.Lock()
                mq.messages = append([]QueuedMessage{msg}, mq.messages...)
                mq.mu.Unlock()
            }
        }
    }
}
```

## Security Features

### 1. **End-to-End Encryption**
- **ChaCha20-Poly1305** for message encryption
- **Ed25519** for digital signatures
- **Perfect Forward Secrecy** with key rotation
- **Mutual Authentication** between agent and backend

### 2. **Message Integrity**
- **Digital Signatures** on all messages
- **Nonce-based Encryption** to prevent replay attacks
- **Timestamp Validation** to prevent old message replay
- **Message Ordering** with sequence numbers

### 3. **Access Control**
- **Agent Authentication** with public key cryptography
- **Session Management** with token-based authentication
- **Channel-based Authorization** for different message types
- **Rate Limiting** to prevent abuse

### 4. **Audit and Monitoring**
- **Comprehensive Logging** of all communications
- **Connection Monitoring** with health checks
- **Message Tracking** with delivery confirmations
- **Security Event Detection** for suspicious activity

## Deployment Considerations

### 1. **Network Configuration**
- **Outbound HTTPS/WSS** connections only
- **Firewall Rules** for WebSocket traffic
- **Proxy Support** for corporate environments
- **Load Balancer** configuration for backend

### 2. **Certificate Management**
- **TLS Certificates** for secure connections
- **Certificate Pinning** for additional security
- **Automatic Renewal** of certificates
- **Certificate Validation** on both ends

### 3. **Scalability**
- **Connection Pooling** for multiple agents
- **Message Queuing** for high-volume scenarios
- **Load Balancing** across backend instances
- **Horizontal Scaling** of communication gateway

## Benefits

### 1. **Security**
- **End-to-end encryption** protects all communications
- **Mutual authentication** ensures both parties are verified
- **Message integrity** prevents tampering
- **Audit trails** for compliance and forensics

### 2. **Reliability**
- **Automatic reconnection** handles network interruptions
- **Message queuing** ensures delivery during outages
- **Health monitoring** detects and resolves issues
- **Graceful degradation** maintains partial functionality

### 3. **Performance**
- **Persistent connections** reduce connection overhead
- **Message batching** optimizes network usage
- **Compression** reduces bandwidth requirements
- **Efficient routing** minimizes latency

### 4. **Maintainability**
- **Modular design** enables easy updates
- **Comprehensive logging** aids in troubleshooting
- **Health monitoring** provides operational visibility
- **Standard protocols** ensure compatibility

## Conclusion

This secure bidirectional communication architecture enables the enhanced Aegis Agent to maintain persistent, encrypted communication with cloud backends while operating behind firewalls. The solution provides:

- **Agent-initiated connections** that bypass firewall restrictions
- **Bidirectional communication** for real-time collaboration
- **End-to-end encryption** for security
- **Automatic reconnection** for reliability
- **Message queuing** for resilience
- **Comprehensive monitoring** for operational visibility

This architecture transforms the agent-backend relationship from simple polling to intelligent, secure, real-time collaboration while maintaining the security and reliability required for enterprise deployments.
