# Backend Team Quick Reference
## Aegis Agent WebSocket Communication

---

## 🚀 **Quick Start**

### **1. WebSocket Endpoint**
```
GET /ws/agent
Headers:
  - X-Agent-ID: {agent_id}
  - X-Agent-Public-Key: {base64_public_key}
  - User-Agent: Aegis-Agent/1.0
```

### **2. Authentication Flow**
1. Agent sends signed authentication request
2. Verify Ed25519 signature with agent's public key
3. Generate session token and backend key
4. Return authentication response
5. Both sides derive shared encryption key

### **3. Message Encryption**
- **Algorithm**: ChaCha20-Poly1305
- **Key**: Derived from Ed25519 key agreement
- **Nonce**: 12-byte random nonces
- **Signature**: Ed25519 on all messages

---

## 📊 **Required Database Tables**

```sql
-- Agent connections
CREATE TABLE agent_connections (
    id UUID PRIMARY KEY,
    agent_id VARCHAR(255) UNIQUE,
    public_key TEXT,
    session_token VARCHAR(255),
    connected_at TIMESTAMP,
    last_seen TIMESTAMP,
    is_active BOOLEAN
);

-- Message queue
CREATE TABLE message_queue (
    id UUID PRIMARY KEY,
    agent_id VARCHAR(255),
    channel VARCHAR(255),
    message_type VARCHAR(50),
    payload TEXT,
    encrypted_payload TEXT,
    nonce TEXT,
    signature TEXT,
    status VARCHAR(50),
    retry_count INTEGER,
    created_at TIMESTAMP
);
```

---

## 🔌 **API Endpoints**

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/ws/agent` | WebSocket connection |
| `GET` | `/api/v1/agents/{id}/status` | Agent status |
| `POST` | `/api/v1/agents/{id}/send` | Send to agent |
| `POST` | `/api/v1/agents/broadcast` | Broadcast to all |

---

## 📝 **Message Types**

### **Authentication Request**
```json
{
  "agent_id": "string",
  "public_key": "base64",
  "timestamp": 1234567890,
  "nonce": "base64",
  "signature": "base64"
}
```

### **Secure Message**
```json
{
  "id": "string",
  "type": "request|response|event|heartbeat|ack",
  "channel": "string",
  "payload": "encrypted",
  "timestamp": 1234567890,
  "nonce": "base64",
  "signature": "base64"
}
```

---

## 🏗️ **Required Services**

1. **WebSocket Gateway** - Handle connections
2. **Authentication Service** - Verify agents
3. **Message Router** - Route messages
4. **Encryption Service** - Encrypt/decrypt
5. **Connection Manager** - Manage sessions

---

## 🔐 **Security Checklist**

- [ ] WSS (TLS) for all connections
- [ ] Ed25519 signature verification
- [ ] ChaCha20-Poly1305 encryption
- [ ] Session token validation
- [ ] Rate limiting
- [ ] Input validation

---

## 📚 **Full Documentation**

- **Complete Guide**: `BACKEND_TEAM_HANDOFF.md`
- **Architecture**: `PHASE_3_BACKEND_ARCHITECTURE.md`
- **Agent Summary**: `PHASE_3_WEBSOCKET_COMMUNICATION_SUMMARY.md`

---

## ⚡ **Implementation Priority**

1. **Week 1**: WebSocket gateway + authentication
2. **Week 2**: Message routing + encryption
3. **Week 3**: Message queuing + reliability
4. **Week 4**: Advanced features + monitoring

---

**Questions?** Contact: Steven Gerhart (steve@dentro.io)
