# WebSocket Protocol Specification
## Aegis Agent ↔ Backend Communication

---

## 📋 **Protocol Overview**

This document specifies the exact WebSocket communication protocol between Aegis Agents and the backend system.

---

## 🔌 **Connection Establishment**

### **WebSocket Upgrade Request**
```
GET /ws/agent HTTP/1.1
Host: backend.aegis.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: {base64_encoded_key}
Sec-WebSocket-Version: 13
X-Agent-ID: {agent_id}
X-Agent-Public-Key: {base64_encoded_ed25519_public_key}
User-Agent: Aegis-Agent/1.0
```

### **WebSocket Upgrade Response**
```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: {calculated_accept_key}
```

---

## 🔐 **Authentication Protocol**

### **Step 1: Agent Authentication Request**
```json
{
  "agent_id": "aegis-agent-001",
  "public_key": "base64_encoded_ed25519_public_key",
  "timestamp": 1695326400,
  "nonce": "base64_encoded_16_byte_nonce",
  "signature": "base64_encoded_ed25519_signature"
}
```

**Signature Data**: `agent_id:public_key:timestamp:nonce`

### **Step 2: Backend Authentication Response**
```json
{
  "success": true,
  "backend_key": "base64_encoded_backend_public_key",
  "session_token": "jwt_session_token",
  "expires_at": 1695412800,
  "message": "Authentication successful"
}
```

**Error Response**:
```json
{
  "success": false,
  "message": "Authentication failed: invalid signature"
}
```

---

## 🔑 **Key Derivation**

### **Shared Key Generation**
```go
// Agent side
sharedKey := sha256.Sum256(append(agentPrivateKey, backendPublicKey))

// Backend side  
sharedKey := sha256.Sum256(append(backendPrivateKey, agentPublicKey))
```

### **Encryption Key Usage**
- **Algorithm**: ChaCha20-Poly1305
- **Key**: 32-byte shared key
- **Nonce**: 12-byte random nonce per message
- **Tag**: 16-byte authentication tag

---

## 📨 **Message Protocol**

### **Message Structure**
```json
{
  "id": "msg_1695326400_123456789",
  "type": "request|response|event|heartbeat|ack",
  "channel": "agent.001.policies",
  "payload": "base64_encoded_encrypted_payload",
  "timestamp": 1695326400,
  "nonce": "base64_encoded_12_byte_nonce",
  "signature": "base64_encoded_ed25519_signature",
  "headers": {
    "priority": "high",
    "retry_count": "0"
  }
}
```

### **Message Types**

#### **Request Message**
```json
{
  "id": "msg_1695326400_123456789",
  "type": "request",
  "channel": "agent.001.policies",
  "payload": "encrypted_request_data",
  "timestamp": 1695326400,
  "nonce": "base64_nonce",
  "signature": "base64_signature",
  "headers": {
    "request_id": "req_123",
    "timeout": "30s"
  }
}
```

#### **Response Message**
```json
{
  "id": "msg_1695326401_123456790",
  "type": "response",
  "channel": "agent.001.policies",
  "payload": "encrypted_response_data",
  "timestamp": 1695326401,
  "nonce": "base64_nonce",
  "signature": "base64_signature",
  "headers": {
    "request_id": "req_123",
    "status": "success"
  }
}
```

#### **Event Message**
```json
{
  "id": "msg_1695326402_123456791",
  "type": "event",
  "channel": "agent.001.anomalies",
  "payload": "encrypted_event_data",
  "timestamp": 1695326402,
  "nonce": "base64_nonce",
  "signature": "base64_signature",
  "headers": {
    "event_type": "anomaly_detected",
    "severity": "high"
  }
}
```

#### **Heartbeat Message**
```json
{
  "id": "msg_1695326403_123456792",
  "type": "heartbeat",
  "channel": "agent.001.heartbeat",
  "payload": "encrypted_heartbeat_data",
  "timestamp": 1695326403,
  "nonce": "base64_nonce",
  "signature": "base64_signature",
  "headers": {
    "agent_status": "healthy",
    "uptime": "3600s"
  }
}
```

#### **Acknowledgment Message**
```json
{
  "id": "msg_1695326404_123456793",
  "type": "ack",
  "channel": "agent.001.policies",
  "payload": "encrypted_ack_data",
  "timestamp": 1695326404,
  "nonce": "base64_nonce",
  "signature": "base64_signature",
  "headers": {
    "ack_for": "msg_1695326400_123456789",
    "status": "received"
  }
}
```

---

## 📡 **Communication Channels**

### **Agent → Backend Channels**
| Channel | Purpose | Priority | Frequency |
|---------|---------|----------|-----------|
| `agent.{id}.policies` | Policy updates | 1 | On change |
| `agent.{id}.anomalies` | Anomaly alerts | 2 | Real-time |
| `agent.{id}.threats` | Threat matches | 2 | Real-time |
| `agent.{id}.processes` | Process events | 3 | Periodic |
| `agent.{id}.dependencies` | Dependency data | 3 | On change |
| `agent.{id}.tests` | Test results | 4 | On completion |
| `agent.{id}.rollbacks` | Rollback status | 4 | On change |
| `agent.{id}.heartbeat` | Health checks | 5 | 30s |
| `agent.{id}.status` | Agent status | 5 | 60s |
| `agent.{id}.logs` | Log messages | 6 | Real-time |

### **Backend → Agent Channels**
| Channel | Purpose | Priority | Frequency |
|---------|---------|----------|-----------|
| `backend.{id}.policies` | Policy commands | 1 | On change |
| `backend.{id}.investigations` | Investigation requests | 2 | On demand |
| `backend.{id}.threats` | Threat intelligence | 2 | Periodic |
| `backend.{id}.processes` | Process policies | 3 | On change |
| `backend.{id}.tests` | Test commands | 4 | On demand |
| `backend.{id}.rollbacks` | Rollback commands | 4 | On demand |

---

## 🔒 **Security Implementation**

### **Message Encryption**
```go
// Encrypt payload
func encryptPayload(payload []byte, sharedKey []byte) (string, string, error) {
    // Generate 12-byte nonce
    nonce := make([]byte, 12)
    rand.Read(nonce)
    
    // Create ChaCha20-Poly1305 cipher
    cipher, err := chacha20poly1305.New(sharedKey)
    if err != nil {
        return "", "", err
    }
    
    // Encrypt payload
    encrypted := cipher.Seal(nil, nonce, payload, nil)
    
    return base64.StdEncoding.EncodeToString(encrypted),
           base64.StdEncoding.EncodeToString(nonce), nil
}
```

### **Message Decryption**
```go
// Decrypt payload
func decryptPayload(encryptedPayload, nonceStr string, sharedKey []byte) ([]byte, error) {
    // Decode encrypted payload
    encrypted, err := base64.StdEncoding.DecodeString(encryptedPayload)
    if err != nil {
        return nil, err
    }
    
    // Decode nonce
    nonce, err := base64.StdEncoding.DecodeString(nonceStr)
    if err != nil {
        return nil, err
    }
    
    // Create ChaCha20-Poly1305 cipher
    cipher, err := chacha20poly1305.New(sharedKey)
    if err != nil {
        return nil, err
    }
    
    // Decrypt payload
    decrypted, err := cipher.Open(nil, nonce, encrypted, nil)
    if err != nil {
        return nil, err
    }
    
    return decrypted, nil
}
```

### **Message Signing**
```go
// Sign message
func signMessage(msg SecureMessage, privateKey ed25519.PrivateKey) string {
    // Create data to sign
    data := fmt.Sprintf("%s:%s:%s:%d:%s", 
        msg.ID, msg.Type, msg.Channel, msg.Timestamp, msg.Payload)
    
    // Sign the data
    signature := ed25519.Sign(privateKey, []byte(data))
    
    return base64.StdEncoding.EncodeToString(signature)
}
```

### **Signature Verification**
```go
// Verify message signature
func verifySignature(msg SecureMessage, publicKey ed25519.PublicKey) bool {
    // Create data to verify
    data := fmt.Sprintf("%s:%s:%s:%d:%s", 
        msg.ID, msg.Type, msg.Channel, msg.Timestamp, msg.Payload)
    
    // Decode signature
    signature, err := base64.StdEncoding.DecodeString(msg.Signature)
    if err != nil {
        return false
    }
    
    // Verify signature
    return ed25519.Verify(publicKey, []byte(data), signature)
}
```

---

## ⏱️ **Timing and Intervals**

### **Connection Management**
- **Heartbeat Interval**: 30 seconds
- **Connection Timeout**: 60 seconds
- **Reconnect Delay**: 5 seconds (exponential backoff)
- **Max Reconnect Delay**: 60 seconds
- **Session Timeout**: 24 hours

### **Message Processing**
- **Queue Processing**: 100ms intervals
- **Message TTL**: 1 hour
- **Max Retries**: 3 attempts
- **Retry Delay**: 1 second (exponential backoff)

---

## 📊 **Error Handling**

### **Connection Errors**
```json
{
  "error": "connection_failed",
  "message": "Failed to establish WebSocket connection",
  "code": 1001,
  "retry_after": 5
}
```

### **Authentication Errors**
```json
{
  "error": "authentication_failed",
  "message": "Invalid signature",
  "code": 4001,
  "retry_after": 0
}
```

### **Message Errors**
```json
{
  "error": "message_failed",
  "message": "Failed to decrypt message",
  "code": 4002,
  "retry_after": 1
}
```

---

## 🧪 **Testing Scenarios**

### **Connection Testing**
1. **Normal Connection**: Agent connects successfully
2. **Authentication Failure**: Invalid signature rejected
3. **Connection Drop**: Automatic reconnection
4. **Multiple Agents**: Multiple concurrent connections

### **Message Testing**
1. **Bidirectional Messaging**: Agent ↔ Backend messages
2. **Channel Routing**: Messages routed to correct channels
3. **Encryption/Decryption**: All messages encrypted
4. **Signature Verification**: All messages signed

### **Error Testing**
1. **Network Interruption**: Connection recovery
2. **Invalid Messages**: Error handling
3. **Rate Limiting**: Connection throttling
4. **Session Expiry**: Re-authentication

---

## 📈 **Performance Requirements**

### **Connection Limits**
- **Max Concurrent Connections**: 1000
- **Connection Rate**: 100/second
- **Message Rate**: 1000/second per connection

### **Latency Requirements**
- **Message Delivery**: < 100ms
- **Authentication**: < 500ms
- **Reconnection**: < 30 seconds

### **Reliability Requirements**
- **Message Delivery**: 99.9% success rate
- **Connection Uptime**: 99.5% availability
- **Error Recovery**: < 5 seconds

---

## 🔧 **Implementation Checklist**

### **Backend Services**
- [ ] WebSocket gateway service
- [ ] Authentication service
- [ ] Message router service
- [ ] Encryption service
- [ ] Connection manager
- [ ] Database schema
- [ ] API endpoints

### **Security Implementation**
- [ ] TLS/WSS configuration
- [ ] Ed25519 key management
- [ ] ChaCha20-Poly1305 encryption
- [ ] Signature verification
- [ ] Session management
- [ ] Rate limiting

### **Testing & Validation**
- [ ] Unit tests
- [ ] Integration tests
- [ ] Load testing
- [ ] Security testing
- [ ] Error handling tests

---

**This specification provides the complete technical details needed to implement the backend WebSocket communication system.** 🚀
