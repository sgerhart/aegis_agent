# Backend Team Handoff Package
## Aegis Agent WebSocket Communication Infrastructure

---

## 🎯 **Overview**

The Aegis Agent now has a **complete WebSocket communication infrastructure** on the agent side. This document provides everything the backend team needs to implement the corresponding backend services.

## 📋 **What's Ready on Agent Side**

### ✅ **Complete Agent Infrastructure**
- **WebSocket Connection Management**: Automatic connection, reconnection, health monitoring
- **End-to-End Encryption**: ChaCha20-Poly1305 encryption for all messages
- **Digital Signatures**: Ed25519 signatures for message integrity
- **Mutual Authentication**: Agent-backend authentication protocol
- **Message Queuing**: Reliable delivery with retry logic
- **Channel-Based Routing**: 16 organized communication channels

### ✅ **Agent Capabilities**
- **Real-time bidirectional communication**
- **Automatic reconnection** (5s → 60s exponential backoff)
- **Message queuing** (1000 messages with priority)
- **Health monitoring** (30-second heartbeats)
- **Channel management** (subscribe/unsubscribe)
- **Comprehensive metrics** and monitoring

---

## 🏗️ **Backend Services Required**

### **1. WebSocket Gateway Service**
**Purpose**: Handle WebSocket connections from agents

**Key Features**:
- WebSocket connection upgrade from HTTP
- Agent authentication and verification
- Connection management and health monitoring
- Message routing to appropriate handlers

**Endpoints**:
```
GET /ws/agent
Headers:
  - X-Agent-ID: {agent_id}
  - X-Agent-Public-Key: {base64_public_key}
  - User-Agent: Aegis-Agent/1.0
```

### **2. Authentication Service**
**Purpose**: Verify agent identity and establish secure sessions

**Key Features**:
- Agent public key verification
- Ed25519 signature validation
- Session token generation
- Shared key derivation

**Authentication Flow**:
1. Agent sends authentication request with signed data
2. Backend verifies signature using agent's public key
3. Backend generates session token and backend key
4. Both sides derive shared encryption key

### **3. Message Router Service**
**Purpose**: Route messages between agents and backend services

**Key Features**:
- Channel-based message routing
- Message decryption and verification
- Handler registration and execution
- Message broadcasting

**Channels to Handle**:
- `agent.{id}.policies` - Policy updates
- `agent.{id}.anomalies` - Anomaly alerts
- `agent.{id}.threats` - Threat intelligence
- `agent.{id}.processes` - Process events
- `agent.{id}.heartbeat` - Health checks
- `backend.{id}.policies` - Policy commands
- `backend.{id}.investigations` - Investigation requests

### **4. Encryption Service**
**Purpose**: Handle message encryption/decryption

**Key Features**:
- ChaCha20-Poly1305 encryption/decryption
- Ed25519 signature verification
- Nonce generation and validation
- Key management and rotation

### **5. Connection Manager**
**Purpose**: Manage active agent connections

**Key Features**:
- Track connected agents
- Monitor connection health
- Handle disconnections
- Message broadcasting

---

## 🔐 **Security Requirements**

### **Encryption**
- **Algorithm**: ChaCha20-Poly1305 (AEAD)
- **Key Management**: Ed25519 key pairs
- **Nonce**: 12-byte random nonces
- **Key Derivation**: SHA256-based shared key generation

### **Authentication**
- **Mutual Authentication**: Both agent and backend verify each other
- **Digital Signatures**: Ed25519 signatures on all messages
- **Session Tokens**: Time-limited session management
- **Public Key Verification**: Agent public key validation

### **Message Integrity**
- **Digital Signatures**: Every message is signed
- **Timestamp Validation**: Prevents replay attacks
- **Nonce Uniqueness**: Unique nonces for each message
- **Message Ordering**: Sequence-based ordering

---

## 📊 **Database Schema Required**

### **Agent Connections Table**
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

### **Message Queue Table**
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

### **Communication Channels Table**
```sql
CREATE TABLE communication_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) NOT NULL,
    channel_name VARCHAR(255) NOT NULL,
    channel_type VARCHAR(50) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(agent_id, channel_name)
);

CREATE INDEX idx_communication_channels_agent_id ON communication_channels(agent_id);
CREATE INDEX idx_communication_channels_type ON communication_channels(channel_type);
```

---

## 🔌 **API Endpoints Required**

### **WebSocket Connection**
```
GET /ws/agent
Headers:
  - X-Agent-ID: {agent_id}
  - X-Agent-Public-Key: {base64_public_key}
  - User-Agent: Aegis-Agent/1.0

Response: WebSocket connection upgrade
```

### **Agent Status**
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

### **Send Message to Agent**
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

### **Broadcast to All Agents**
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

---

## 📝 **Message Protocol**

### **Authentication Request**
```json
{
  "agent_id": "string",
  "public_key": "base64_encoded_public_key",
  "timestamp": 1234567890,
  "nonce": "base64_encoded_nonce",
  "signature": "base64_encoded_signature"
}
```

### **Authentication Response**
```json
{
  "success": true,
  "backend_key": "base64_encoded_backend_key",
  "session_token": "session_token_string",
  "expires_at": 1234567890,
  "message": "optional_message"
}
```

### **Secure Message**
```json
{
  "id": "message_id",
  "type": "request|response|event|heartbeat|ack",
  "channel": "channel_name",
  "payload": "encrypted_payload",
  "timestamp": 1234567890,
  "nonce": "base64_encoded_nonce",
  "signature": "base64_encoded_signature",
  "headers": {}
}
```

---

## 🚀 **Implementation Phases**

### **Phase 1: Core WebSocket Infrastructure (Week 1-2)**
- [ ] WebSocket gateway service
- [ ] Basic connection handling
- [ ] Agent authentication
- [ ] Message routing

### **Phase 2: Security Implementation (Week 2-3)**
- [ ] Encryption/decryption service
- [ ] Digital signature verification
- [ ] Session management
- [ ] Key rotation

### **Phase 3: Message Management (Week 3-4)**
- [ ] Message queuing system
- [ ] Reliable delivery
- [ ] Retry logic
- [ ] Message persistence

### **Phase 4: Advanced Features (Week 4-5)**
- [ ] Channel management
- [ ] Broadcast capabilities
- [ ] Health monitoring
- [ ] Metrics and logging

---

## 🧪 **Testing Requirements**

### **Agent Connection Testing**
- [ ] Multiple agent connections
- [ ] Connection authentication
- [ ] Message encryption/decryption
- [ ] Automatic reconnection

### **Message Flow Testing**
- [ ] Bidirectional messaging
- [ ] Channel-based routing
- [ ] Message queuing
- [ ] Error handling

### **Security Testing**
- [ ] Authentication bypass attempts
- [ ] Message tampering detection
- [ ] Replay attack prevention
- [ ] Session management

### **Performance Testing**
- [ ] High-volume message processing
- [ ] Connection scaling
- [ ] Memory usage
- [ ] Latency measurement

---

## 📚 **Documentation References**

### **Agent-Side Documentation**
- `PHASE_3_BACKEND_ARCHITECTURE.md` - Detailed backend architecture
- `PHASE_3_WEBSOCKET_COMMUNICATION_SUMMARY.md` - Complete implementation summary
- `agents/aegis/internal/communication/` - Agent communication code

### **Key Agent Files**
- `websocket_manager.go` - WebSocket connection management
- `message_queue.go` - Message queuing system
- `channel_manager.go` - Channel management
- `types.go` - Type definitions

---

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

---

## ⚠️ **Critical Considerations**

### **Backward Compatibility**
- Existing HTTP API must remain functional
- Gradual migration from polling to WebSocket
- Fallback mechanisms for WebSocket failures

### **Security Requirements**
- All WebSocket connections must use WSS (TLS)
- Certificate management and rotation
- Rate limiting and DDoS protection
- Input validation and sanitization

### **Scalability**
- Load balancing across multiple gateway instances
- Database connection pooling
- Message queue partitioning
- Horizontal scaling support

### **Monitoring and Observability**
- Connection metrics and health checks
- Message delivery statistics
- Error rates and failure analysis
- Performance monitoring

---

## 🎯 **Success Criteria**

### **Functional Requirements**
- [ ] Agents can establish secure WebSocket connections
- [ ] Bidirectional communication works reliably
- [ ] All message types are supported
- [ ] Authentication and encryption work correctly

### **Performance Requirements**
- [ ] Support 1000+ concurrent agent connections
- [ ] Message latency < 100ms
- [ ] 99.9% message delivery success rate
- [ ] Automatic reconnection within 30 seconds

### **Security Requirements**
- [ ] All communications encrypted end-to-end
- [ ] Mutual authentication working
- [ ] No message tampering possible
- [ ] Session management secure

---

## 📞 **Support and Questions**

### **Agent-Side Contact**
- **Primary**: Steven Gerhart (steve@dentro.io)
- **Repository**: `/Users/stevengerhart/workspace/github/sgerhart/aegis_agent`
- **Documentation**: See `PHASE_3_BACKEND_ARCHITECTURE.md` for detailed specs

### **Key Resources**
- Agent communication code: `agents/aegis/internal/communication/`
- Type definitions: `agents/aegis/internal/communication/types.go`
- WebSocket manager: `agents/aegis/internal/communication/websocket_manager.go`
- Channel manager: `agents/aegis/internal/communication/channel_manager.go`

---

## 🚀 **Ready to Start!**

The agent-side WebSocket infrastructure is **100% complete and ready**. The backend team can now implement the required services using this comprehensive handoff package.

**Estimated Implementation Time**: 4-5 weeks
**Priority**: High (enables real-time agent-backend communication)

**Good luck with the implementation!** 🎉
