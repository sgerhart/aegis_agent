# 📡 Comprehensive API Reference

This document consolidates all backend API documentation, WebSocket protocol specifications, and team handoff information.

---

## 🌐 **Backend Architecture Overview**

### **Services**
- **WebSocket Gateway**: `ws://192.168.1.157:8080/ws/agent` (WebSocket connection)
- **Actions API**: `http://192.168.1.157:8083` (HTTP registration endpoints)

### **Connection Flow**
The agent connects to the **WebSocket Gateway** on port 8080, then sends registration messages through the WebSocket connection. The WebSocket Gateway acts as a proxy to the Actions API.

---

## 🔌 **WebSocket Protocol Specification**

### **Connection Establishment**

#### **WebSocket URL**
```
ws://192.168.1.157:8080/ws/agent
```

#### **Required Headers**
```http
GET /ws/agent HTTP/1.1
Host: 192.168.1.157:8080
X-Agent-ID: aegis-linux-service
X-Agent-Public-Key: <base64_encoded_ed25519_public_key>
User-Agent: Aegis-Agent/1.0
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: <random_base64_key>
```

### **Message Format**

#### **SecureMessage Structure**
All WebSocket messages follow the SecureMessage format:

```json
{
  "id": "unique_message_id",
  "type": "request|response|heartbeat",
  "channel": "message_channel",
  "payload": "<base64_encoded_payload>",
  "timestamp": 1234567890,
  "nonce": "<base64_encoded_nonce>",
  "signature": "<base64_encoded_signature>",
  "headers": {
    "key": "value"
  }
}
```

#### **Field Descriptions**
- **id**: Unique message identifier
- **type**: Message type (request, response, heartbeat)
- **channel**: Message channel for routing
- **payload**: Base64-encoded message content
- **timestamp**: Unix timestamp
- **nonce**: Base64-encoded random nonce
- **signature**: Base64-encoded Ed25519 signature
- **headers**: Additional message headers

### **Authentication Protocol**

#### **Authentication Request**
```json
{
  "id": "auth_msg_1234567890",
  "type": "request",
  "channel": "auth",
  "payload": "<base64_encoded_auth_request>",
  "timestamp": 1234567890,
  "nonce": "<base64_encoded_nonce>",
  "signature": "<base64_encoded_signature>",
  "headers": {}
}
```

#### **Authentication Request Payload**
```json
{
  "agent_id": "aegis-linux-service",
  "public_key": "<base64_encoded_ed25519_public_key>",
  "timestamp": 1234567890,
  "nonce": "<base64_encoded_16_byte_nonce>",
  "signature": "<base64_encoded_ed25519_signature>"
}
```

#### **Signature Data for Authentication**
The agent must sign this EXACT string:
```
agent_id:public_key:timestamp:nonce
```

#### **Authentication Response**
```json
{
  "id": "auth_response_1234567890",
  "type": "response",
  "channel": "auth",
  "payload": "<base64_encoded_auth_response>",
  "timestamp": 1234567890,
  "headers": {}
}
```

#### **Authentication Response Payload**
```json
{
  "success": true,
  "session_token": "<session_token>",
  "expires_at": 1234567890,
  "backend_key": "<base64_encoded_backend_public_key>"
}
```

### **Registration Protocol**

#### **Registration Init Request**
```json
{
  "id": "reg_init_1234567890",
  "type": "request",
  "channel": "agent.registration",
  "payload": "<base64_encoded_reg_init>",
  "timestamp": 1234567890,
  "headers": {}
}
```

#### **Registration Init Payload**
```json
{
  "host_id": "aegis-linux-service",
  "public_key": "<base64_encoded_public_key>"
}
```

#### **Registration Init Response**
```json
{
  "id": "reg_init_response_1234567890",
  "type": "response",
  "channel": "agent.registration",
  "payload": "<base64_encoded_reg_response>",
  "timestamp": 1234567890,
  "headers": {}
}
```

#### **Registration Init Response Payload**
```json
{
  "registration_id": "f8c3d7df-69ba-4180-af78-c920e8863768",
  "nonce": "3OGmm70KIBAPoyjEmv5e/aCumzEoTl0Vzzp2ZF1nKNE=",
  "server_time": "2025-09-27T02:38:04Z"
}
```

#### **Registration Complete Request**
```json
{
  "id": "reg_complete_1234567890",
  "type": "request",
  "channel": "agent.registration.complete",
  "payload": "<base64_encoded_reg_complete>",
  "timestamp": 1234567890,
  "headers": {}
}
```

#### **Registration Complete Payload**
```json
{
  "registration_id": "f8c3d7df-69ba-4180-af78-c920e8863768",
  "host_id": "aegis-linux-service",
  "signature": "<base64_encoded_signature>"
}
```

#### **Signature Data for Registration Complete**
The agent must sign this EXACT data:
```
nonce_bytes + server_time + host_id
```

Where:
- `nonce_bytes`: Base64 decoded bytes from the registration init response
- `server_time`: String from the registration init response
- `host_id`: String from the registration complete request

#### **Registration Complete Response**
```json
{
  "id": "reg_complete_response_1234567890",
  "type": "response",
  "channel": "agent.registration.complete",
  "payload": "<base64_encoded_complete_response>",
  "timestamp": 1234567890,
  "headers": {}
}
```

#### **Registration Complete Response Payload**
```json
{
  "success": true,
  "agent_uid": "agent_uid_from_backend",
  "bootstrap_token": "bootstrap_token_from_backend"
}
```

### **Heartbeat Protocol**

#### **Heartbeat Message**
```json
{
  "id": "heartbeat_1234567890",
  "type": "heartbeat",
  "timestamp": 1234567890,
  "payload": "{}",
  "headers": {}
}
```

#### **Heartbeat Response**
```json
{
  "id": "heartbeat_response_1234567890",
  "type": "response",
  "channel": "heartbeat",
  "payload": "{}",
  "timestamp": 1234567890,
  "headers": {}
}
```

---

## 🔐 **Security Implementation**

### **Cryptographic Requirements**
- **Key Algorithm**: Ed25519
- **Encryption**: ChaCha20-Poly1305
- **Hash**: SHA-256
- **Nonce**: 16 bytes random

### **Signature Verification Process**
1. **Generate nonce**: 16 random bytes
2. **Create signature data**: Concatenate required fields
3. **Sign data**: Use Ed25519 private key
4. **Encode signature**: Base64 encode the signature
5. **Include in message**: Add to SecureMessage

### **Message Encryption**
1. **Derive shared key**: SHA256(agent_private_key + backend_public_key)
2. **Encrypt payload**: ChaCha20-Poly1305 encryption
3. **Base64 encode**: Encode encrypted payload
4. **Include in message**: Add to SecureMessage payload field

---

## 📡 **HTTP API Endpoints**

### **Health Check**
```http
GET /healthz HTTP/1.1
Host: 192.168.1.157:8080
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-09-27T02:43:19Z",
  "services": {
    "websocket_gateway": "healthy",
    "actions_api": "healthy"
  }
}
```

### **Agent Registration (HTTP)**
```http
POST /agents/register/init HTTP/1.1
Host: 192.168.1.157:8080
Content-Type: application/json

{
  "host_id": "aegis-linux-service",
  "public_key": "<base64_encoded_public_key>"
}
```

**Response:**
```json
{
  "registration_id": "f8c3d7df-69ba-4180-af78-c920e8863768",
  "nonce": "3OGmm70KIBAPoyjEmv5e/aCumzEoTl0Vzzp2ZF1nKNE=",
  "server_time": "2025-09-27T02:38:04Z"
}
```

```http
POST /agents/register/complete HTTP/1.1
Host: 192.168.1.157:8080
Content-Type: application/json

{
  "registration_id": "f8c3d7df-69ba-4180-af78-c920e8863768",
  "host_id": "aegis-linux-service",
  "signature": "<base64_encoded_signature>"
}
```

**Response:**
```json
{
  "success": true,
  "agent_uid": "agent_uid_from_backend",
  "bootstrap_token": "bootstrap_token_from_backend"
}
```

### **Agent Management**
```http
GET /agents HTTP/1.1
Host: 192.168.1.157:8083
```

**Response:**
```json
{
  "agents": [
    {
      "uid": "agent_uid",
      "host_id": "aegis-linux-service",
      "status": "active",
      "last_seen": "2025-09-27T02:43:19Z",
      "registered_at": "2025-09-27T02:38:04Z"
    }
  ],
  "total": 1
}
```

```http
GET /agents/{uid} HTTP/1.1
Host: 192.168.1.157:8083
```

**Response:**
```json
{
  "uid": "agent_uid",
  "host_id": "aegis-linux-service",
  "status": "active",
  "last_seen": "2025-09-27T02:43:19Z",
  "registered_at": "2025-09-27T02:38:04Z",
  "modules": {
    "telemetry": "running",
    "websocket_communication": "running",
    "observability": "running"
  }
}
```

---

## 🧪 **Backend Testing Guide**

### **Testing Agent Connection**
```bash
# Test WebSocket connection
wscat -c ws://192.168.1.157:8080/ws/agent

# Test HTTP health check
curl http://192.168.1.157:8080/healthz

# Test agent registration
curl -X POST http://192.168.1.157:8080/agents/register/init \
  -H "Content-Type: application/json" \
  -d '{"host_id": "test-agent", "public_key": "test-key"}'
```

### **Testing Authentication Flow**
```python
import websocket
import json
import base64
import time

def test_authentication():
    ws = websocket.WebSocket()
    ws.connect("ws://192.168.1.157:8080/ws/agent")
    
    # Send authentication request
    auth_data = {
        "agent_id": "test-agent",
        "public_key": "test-public-key",
        "timestamp": int(time.time()),
        "nonce": base64.b64encode(b"test-nonce").decode(),
        "signature": "test-signature"
    }
    
    auth_message = {
        "id": "auth_test",
        "type": "request",
        "channel": "auth",
        "payload": base64.b64encode(json.dumps(auth_data).encode()).decode(),
        "timestamp": int(time.time()),
        "headers": {}
    }
    
    ws.send(json.dumps(auth_message))
    response = ws.recv()
    print("Authentication response:", response)
    
    ws.close()

test_authentication()
```

---

## 🔄 **Backend Team Handoff**

### **Current Status**
- ✅ **WebSocket Gateway**: Fully functional on port 8080
- ✅ **Actions API**: Registration endpoints working on port 8083
- ✅ **Authentication**: Ed25519 signature verification implemented
- ✅ **Registration Flow**: Two-step registration process working
- ✅ **Message Protocol**: SecureMessage format implemented

### **Agent Implementation Status**
- ✅ **WebSocket Connection**: Stable connection to gateway
- ✅ **Authentication**: Proper authentication flow implemented
- ✅ **Registration**: Complete registration process working
- ✅ **Heartbeats**: Periodic heartbeat messages working
- ✅ **Error Handling**: Comprehensive error handling and recovery

### **Backend Requirements Met**
- ✅ **Message Format**: SecureMessage with base64-encoded payloads
- ✅ **Signature Verification**: Correct Ed25519 signature verification
- ✅ **Channel Routing**: Proper channel-based message routing
- ✅ **Session Management**: Proper session token handling
- ✅ **Error Responses**: Comprehensive error response format

### **Integration Points**
1. **WebSocket Gateway**: Agent connects and authenticates successfully
2. **Actions API**: Registration process completes successfully
3. **Message Routing**: Messages properly routed through channels
4. **Session Management**: Session tokens properly managed
5. **Error Handling**: Errors properly handled and reported

### **Testing Recommendations**
1. **Load Testing**: Test with multiple concurrent agents
2. **Error Scenarios**: Test various error conditions
3. **Security Testing**: Test signature verification edge cases
4. **Performance Testing**: Test message throughput and latency
5. **Integration Testing**: Test end-to-end agent-backend communication

---

## 📊 **Quick Reference**

### **Connection URLs**
- **WebSocket**: `ws://192.168.1.157:8080/ws/agent`
- **HTTP Health**: `http://192.168.1.157:8080/healthz`
- **HTTP Registration**: `http://192.168.1.157:8080/agents/register/init`

### **Required Headers**
- **X-Agent-ID**: Agent identifier
- **X-Agent-Public-Key**: Base64-encoded Ed25519 public key
- **User-Agent**: Aegis-Agent/1.0

### **Message Channels**
- **auth**: Authentication messages
- **agent.registration**: Registration init messages
- **agent.registration.complete**: Registration complete messages
- **heartbeat**: Heartbeat messages

### **Signature Data Formats**
- **Authentication**: `agent_id:public_key:timestamp:nonce`
- **Registration Complete**: `nonce_bytes + server_time + host_id`

### **Error Codes**
- **400**: Bad Request (malformed message)
- **401**: Unauthorized (authentication/signature failure)
- **403**: Forbidden (insufficient permissions)
- **500**: Internal Server Error (backend error)
