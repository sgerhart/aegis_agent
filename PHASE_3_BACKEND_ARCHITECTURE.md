# Phase 3: Backend Architecture Requirements

## 🎯 **Critical Backend Changes Required**

You're absolutely right! Implementing Phase 3 (Secure Communication) will require **significant backend changes**. This document outlines exactly what needs to be implemented on the backend side.

## 📋 **Current State vs. Required State**

### **Current Backend (Phase 1-2)**
- ✅ Simple HTTP API for artifact polling
- ✅ Basic agent registration
- ✅ Policy storage and retrieval
- ✅ RESTful endpoints

### **Required Backend (Phase 3)**
- 🔄 **WebSocket Gateway** for bidirectional communication
- 🔄 **Authentication Service** for agent verification
- 🔄 **Message Router** for channel-based communication
- 🔄 **Encryption/Decryption** service
- 🔄 **Connection Manager** for agent sessions
- 🔄 **Message Queue** for reliable delivery

## 🏗️ **Backend Architecture Overview**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Aegis Agent   │    │  Backend Gateway │    │  Backend API    │
│  (Behind FW)    │◄──►│   (WebSocket)    │◄──►│   (Existing)    │
│                 │    │                  │    │                 │
│ - WebSocket     │    │ - Auth Service   │    │ - Policy Store  │
│ - Encryption    │    │ - Message Router │    │ - Agent Registry│
│ - Reconnection  │    │ - Connection Mgr │    │ - Event Store   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🔧 **Required Backend Components**

### **1. WebSocket Gateway Service**

#### **New Service: `websocket-gateway`**
```go
// Backend WebSocket Gateway
type WebSocketGateway struct {
    upgrader          websocket.Upgrader
    agentConnections  map[string]*AgentConnection
    messageRouter     *MessageRouter
    authService       *AuthenticationService
    encryptionService *EncryptionService
    mu                sync.RWMutex
}

type AgentConnection struct {
    AgentID       string
    Connection    *websocket.Conn
    PublicKey     ed25519.PublicKey
    SessionToken  string
    LastSeen      time.Time
    Channels      *CommunicationChannels
    IsAuthenticated bool
}
```

#### **HTTP Upgrade Handler**
```go
func (wsg *WebSocketGateway) HandleWebSocketUpgrade(w http.ResponseWriter, r *http.Request) {
    // 1. Upgrade HTTP to WebSocket
    conn, err := wsg.upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket upgrade failed: %v", err)
        return
    }
    
    // 2. Extract agent information from headers
    agentID := r.Header.Get("X-Agent-ID")
    publicKeyStr := r.Header.Get("X-Agent-Public-Key")
    
    if agentID == "" || publicKeyStr == "" {
        log.Printf("Missing required headers")
        conn.Close()
        return
    }
    
    // 3. Start connection handler
    go wsg.handleAgentConnection(conn, agentID, publicKeyStr)
}
```

### **2. Authentication Service**

#### **New Service: `auth-service`**
```go
type AuthenticationService struct {
    agentRegistry map[string]*AgentRecord
    privateKey    ed25519.PrivateKey
    publicKey     ed25519.PublicKey
    mu            sync.RWMutex
}

type AgentRecord struct {
    AgentID       string
    PublicKey     ed25519.PublicKey
    IsActive      bool
    LastSeen      time.Time
    CreatedAt     time.Time
    Metadata      map[string]interface{}
}

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
```

#### **Authentication Logic**
```go
func (as *AuthenticationService) AuthenticateAgent(req AuthenticationRequest) (*AuthenticationResponse, error) {
    // 1. Validate agent exists and is active
    agent, exists := as.agentRegistry[req.AgentID]
    if !exists || !agent.IsActive {
        return &AuthenticationResponse{
            Success: false,
            Message: "Agent not found or inactive",
        }, nil
    }
    
    // 2. Verify public key matches
    if !bytes.Equal(agent.PublicKey, []byte(req.PublicKey)) {
        return &AuthenticationResponse{
            Success: false,
            Message: "Invalid public key",
        }, nil
    }
    
    // 3. Verify signature
    if !as.verifySignature(req, agent.PublicKey) {
        return &AuthenticationResponse{
            Success: false,
            Message: "Invalid signature",
        }, nil
    }
    
    // 4. Generate session token
    sessionToken := as.generateSessionToken(req.AgentID)
    
    // 5. Generate backend key for encryption
    backendKey := as.generateBackendKey()
    
    return &AuthenticationResponse{
        Success:      true,
        BackendKey:   base64.StdEncoding.EncodeToString(backendKey),
        SessionToken: sessionToken,
        ExpiresAt:    time.Now().Add(24 * time.Hour).Unix(),
    }, nil
}
```

### **3. Message Router Service**

#### **New Service: `message-router`**
```go
type MessageRouter struct {
    channels        map[string]*Channel
    handlers        map[string]MessageHandler
    encryptionService *EncryptionService
    mu              sync.RWMutex
}

type Channel struct {
    Name        string
    Subscribers map[string]*AgentConnection
    MessageQueue []QueuedMessage
    mu          sync.RWMutex
}

type MessageHandler func(agentID string, message SecureMessage) error
```

#### **Message Routing Logic**
```go
func (mr *MessageRouter) RouteMessage(agentID string, message SecureMessage) error {
    // 1. Decrypt message
    payload, err := mr.encryptionService.DecryptMessage(message)
    if err != nil {
        return fmt.Errorf("failed to decrypt message: %w", err)
    }
    
    // 2. Verify signature
    if !mr.encryptionService.VerifySignature(message) {
        return fmt.Errorf("invalid message signature")
    }
    
    // 3. Route to appropriate handler
    mr.mu.RLock()
    handler, exists := mr.handlers[message.Channel]
    mr.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("no handler for channel: %s", message.Channel)
    }
    
    // 4. Execute handler
    return handler(agentID, message)
}

func (mr *MessageRouter) BroadcastToChannel(channelName string, message interface{}) error {
    mr.mu.RLock()
    channel, exists := mr.channels[channelName]
    mr.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("channel not found: %s", channelName)
    }
    
    // Send to all subscribers
    channel.mu.RLock()
    for agentID, conn := range channel.Subscribers {
        if err := mr.sendToAgent(conn, message); err != nil {
            log.Printf("Failed to send to agent %s: %v", agentID, err)
        }
    }
    channel.mu.RUnlock()
    
    return nil
}
```

### **4. Encryption Service**

#### **New Service: `encryption-service`**
```go
type EncryptionService struct {
    privateKey ed25519.PrivateKey
    publicKey  ed25519.PublicKey
}

func (es *EncryptionService) EncryptMessage(message interface{}, sharedKey []byte) (*SecureMessage, error) {
    // 1. Serialize message
    data, err := json.Marshal(message)
    if err != nil {
        return nil, err
    }
    
    // 2. Generate nonce
    nonce := make([]byte, 12)
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    
    // 3. Encrypt using ChaCha20-Poly1305
    cipher, err := chacha20poly1305.New(sharedKey)
    if err != nil {
        return nil, err
    }
    
    encrypted := cipher.Seal(nil, nonce, data, nil)
    
    // 4. Create secure message
    secureMsg := &SecureMessage{
        ID:        generateMessageID(),
        Type:      MessageTypeRequest,
        Channel:   "default",
        Payload:   base64.StdEncoding.EncodeToString(encrypted),
        Timestamp: time.Now().Unix(),
        Nonce:     base64.StdEncoding.EncodeToString(nonce),
        Headers:   make(map[string]string),
    }
    
    // 5. Sign message
    secureMsg.Signature = es.signMessage(secureMsg)
    
    return secureMsg, nil
}

func (es *EncryptionService) DecryptMessage(msg SecureMessage) (interface{}, error) {
    // 1. Decode encrypted payload
    encrypted, err := base64.StdEncoding.DecodeString(msg.Payload)
    if err != nil {
        return nil, err
    }
    
    // 2. Decode nonce
    nonce, err := base64.StdEncoding.DecodeString(msg.Nonce)
    if err != nil {
        return nil, err
    }
    
    // 3. Decrypt using ChaCha20-Poly1305
    cipher, err := chacha20poly1305.New(es.sharedKey)
    if err != nil {
        return nil, err
    }
    
    decrypted, err := cipher.Open(nil, nonce, encrypted, nil)
    if err != nil {
        return nil, err
    }
    
    // 4. Deserialize
    var result interface{}
    if err := json.Unmarshal(decrypted, &result); err != nil {
        return nil, err
    }
    
    return result, nil
}
```

### **5. Connection Manager**

#### **New Service: `connection-manager`**
```go
type ConnectionManager struct {
    connections map[string]*AgentConnection
    healthChecker *HealthChecker
    mu          sync.RWMutex
}

func (cm *ConnectionManager) RegisterConnection(agentID string, conn *AgentConnection) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    // Close existing connection if any
    if existing, exists := cm.connections[agentID]; exists {
        existing.Connection.Close()
    }
    
    cm.connections[agentID] = conn
    log.Printf("Agent %s connected", agentID)
}

func (cm *ConnectionManager) SendToAgent(agentID string, channel string, message interface{}) error {
    cm.mu.RLock()
    conn, exists := cm.connections[agentID]
    cm.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("agent %s not connected", agentID)
    }
    
    // Send message to agent
    return conn.SendMessage(channel, MessageTypeRequest, message)
}

func (cm *ConnectionManager) BroadcastToAllAgents(channel string, message interface{}) error {
    cm.mu.RLock()
    connections := make([]*AgentConnection, 0, len(cm.connections))
    for _, conn := range cm.connections {
        connections = append(connections, conn)
    }
    cm.mu.RUnlock()
    
    // Send to all connected agents
    for _, conn := range connections {
        if err := conn.SendMessage(channel, MessageTypeRequest, message); err != nil {
            log.Printf("Failed to send to agent %s: %v", conn.AgentID, err)
        }
    }
    
    return nil
}
```

## 🗄️ **Database Schema Changes**

### **New Tables Required**

#### **1. Agent Connections Table**
```sql
CREATE TABLE agent_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    session_token VARCHAR(255) NOT NULL,
    connected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_connections_agent_id ON agent_connections(agent_id);
CREATE INDEX idx_agent_connections_active ON agent_connections(is_active);
```

#### **2. Message Queue Table**
```sql
CREATE TABLE message_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) NOT NULL,
    channel VARCHAR(255) NOT NULL,
    message_type VARCHAR(50) NOT NULL,
    payload TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL,
    nonce TEXT NOT NULL,
    signature TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL DEFAULT (NOW() + INTERVAL '1 hour')
);

CREATE INDEX idx_message_queue_agent_id ON message_queue(agent_id);
CREATE INDEX idx_message_queue_status ON message_queue(status);
CREATE INDEX idx_message_queue_created_at ON message_queue(created_at);
```

#### **3. Communication Channels Table**
```sql
CREATE TABLE communication_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) NOT NULL,
    channel_name VARCHAR(255) NOT NULL,
    channel_type VARCHAR(50) NOT NULL, -- 'agent_to_backend' or 'backend_to_agent'
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(agent_id, channel_name)
);

CREATE INDEX idx_communication_channels_agent_id ON communication_channels(agent_id);
CREATE INDEX idx_communication_channels_type ON communication_channels(channel_type);
```

## 🔌 **API Endpoints Required**

### **New WebSocket Endpoints**

#### **1. WebSocket Connection**
```
GET /ws/agent
Headers:
  - X-Agent-ID: {agent_id}
  - X-Agent-Public-Key: {base64_public_key}
  - User-Agent: Aegis-Agent/1.0

Response: WebSocket connection upgrade
```

#### **2. Agent Status Endpoint**
```
GET /api/v1/agents/{agent_id}/status
Response: {
  "agent_id": "string",
  "connected": boolean,
  "last_seen": "timestamp",
  "channels": ["string"],
  "session_expires": "timestamp"
}
```

#### **3. Send Message to Agent**
```
POST /api/v1/agents/{agent_id}/send
Body: {
  "channel": "string",
  "message": {},
  "message_type": "request|response|event"
}
Response: {
  "message_id": "string",
  "status": "sent|queued|failed"
}
```

#### **4. Broadcast to All Agents**
```
POST /api/v1/agents/broadcast
Body: {
  "channel": "string",
  "message": {},
  "message_type": "request|response|event"
}
Response: {
  "message_id": "string",
  "sent_to": ["agent_id1", "agent_id2"],
  "failed": ["agent_id3"]
}
```

## 🚀 **Implementation Phases**

### **Phase 3.1: Core WebSocket Infrastructure**
- [ ] WebSocket gateway service
- [ ] Basic connection handling
- [ ] Agent authentication
- [ ] Message routing

### **Phase 3.2: Security Implementation**
- [ ] Encryption/decryption service
- [ ] Digital signature verification
- [ ] Session management
- [ ] Key rotation

### **Phase 3.3: Message Management**
- [ ] Message queuing system
- [ ] Reliable delivery
- [ ] Retry logic
- [ ] Message persistence

### **Phase 3.4: Advanced Features**
- [ ] Channel management
- [ ] Broadcast capabilities
- [ ] Health monitoring
- [ ] Metrics and logging

## 📊 **Backend Service Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                    Backend Services                         │
├─────────────────────────────────────────────────────────────┤
│  WebSocket Gateway  │  Auth Service  │  Message Router     │
│  - Connection Mgr   │  - Agent Auth  │  - Channel Mgr      │
│  - Upgrade Handler  │  - Key Mgmt    │  - Message Queue    │
│  - Health Monitor   │  - Sessions    │  - Broadcast        │
├─────────────────────────────────────────────────────────────┤
│  Encryption Service │  Database      │  Existing API       │
│  - ChaCha20-Poly1305│  - Connections │  - Policy Store     │
│  - Ed25519 Signatures│  - Messages    │  - Agent Registry  │
│  - Key Derivation   │  - Channels    │  - Event Store      │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 **Configuration Requirements**

### **Environment Variables**
```bash
# WebSocket Configuration
WEBSOCKET_PORT=8080
WEBSOCKET_PATH=/ws/agent
WEBSOCKET_READ_BUFFER_SIZE=1024
WEBSOCKET_WRITE_BUFFER_SIZE=1024

# Authentication
AUTH_PRIVATE_KEY_PATH=/etc/aegis/auth/private.pem
AUTH_PUBLIC_KEY_PATH=/etc/aegis/auth/public.pem
SESSION_TIMEOUT=24h

# Encryption
ENCRYPTION_ALGORITHM=chacha20poly1305
KEY_ROTATION_INTERVAL=24h

# Message Queue
MESSAGE_QUEUE_SIZE=10000
MESSAGE_RETRY_ATTEMPTS=3
MESSAGE_TTL=1h

# Database
DATABASE_URL=postgresql://user:pass@localhost/aegis
MESSAGE_QUEUE_TABLE=message_queue
CONNECTIONS_TABLE=agent_connections
```

### **Docker Compose Example**
```yaml
version: '3.8'
services:
  websocket-gateway:
    image: aegis/websocket-gateway:latest
    ports:
      - "8080:8080"
    environment:
      - WEBSOCKET_PORT=8080
      - DATABASE_URL=postgresql://postgres:password@db:5432/aegis
    depends_on:
      - db
      - redis

  auth-service:
    image: aegis/auth-service:latest
    environment:
      - AUTH_PRIVATE_KEY_PATH=/etc/auth/private.pem
      - DATABASE_URL=postgresql://postgres:password@db:5432/aegis
    depends_on:
      - db

  message-router:
    image: aegis/message-router:latest
    environment:
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://postgres:password@db:5432/aegis
    depends_on:
      - db
      - redis

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=aegis
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

## ⚠️ **Critical Considerations**

### **1. Backward Compatibility**
- Existing HTTP API must remain functional
- Gradual migration from polling to WebSocket
- Fallback mechanisms for WebSocket failures

### **2. Security Requirements**
- All WebSocket connections must use WSS (TLS)
- Certificate management and rotation
- Rate limiting and DDoS protection
- Input validation and sanitization

### **3. Scalability**
- Load balancing across multiple gateway instances
- Database connection pooling
- Message queue partitioning
- Horizontal scaling support

### **4. Monitoring and Observability**
- Connection metrics and health checks
- Message delivery statistics
- Error rates and failure analysis
- Performance monitoring

## 🎯 **Migration Strategy**

### **Phase 1: Parallel Implementation**
- Implement WebSocket gateway alongside existing API
- Agents can choose between HTTP polling and WebSocket
- Gradual agent migration

### **Phase 2: Feature Parity**
- Ensure all HTTP API functionality available via WebSocket
- Implement bidirectional communication features
- Performance optimization

### **Phase 3: Full Migration**
- Deprecate HTTP polling API
- All agents use WebSocket communication
- Remove legacy code

## 📈 **Expected Benefits**

### **Performance Improvements**
- **Latency**: 50-80% reduction in message delivery time
- **Throughput**: 10x increase in message processing capacity
- **Efficiency**: Real-time communication vs. polling

### **Enhanced Capabilities**
- **Bidirectional**: Backend can initiate communication
- **Real-time**: Immediate policy updates and commands
- **Reliability**: Automatic reconnection and message queuing
- **Security**: End-to-end encryption and authentication

## 🚨 **Risk Assessment**

### **High Risk**
- **Backend Complexity**: Significant increase in backend complexity
- **Database Load**: Additional tables and queries
- **Network Dependencies**: WebSocket connections require stable network

### **Medium Risk**
- **Migration Complexity**: Gradual migration required
- **Testing**: More complex testing scenarios
- **Monitoring**: Additional monitoring requirements

### **Low Risk**
- **Agent Changes**: Agent-side changes are well-defined
- **Security**: Well-established encryption standards
- **Performance**: Expected performance improvements

## 🎉 **Conclusion**

Phase 3 implementation requires **substantial backend changes** but provides **significant benefits**:

- **Real-time bidirectional communication**
- **Enhanced security with end-to-end encryption**
- **Improved performance and reliability**
- **Foundation for advanced features**

The backend team will need to implement:
1. **WebSocket Gateway Service**
2. **Authentication Service**
3. **Message Router Service**
4. **Encryption Service**
5. **Connection Manager**
6. **Database schema changes**
7. **New API endpoints**

This is a **major architectural change** that transforms the agent-backend relationship from simple polling to intelligent, secure, real-time collaboration! 🚀
