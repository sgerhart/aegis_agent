# 🔍 Why Agent is Not Authenticating - Root Cause Analysis

## 🎯 **The Problem**

The agent is **NOT sending authentication messages** before sending other messages like heartbeats and registrations. This causes the backend to reject all messages because `conn.IsAuthenticated = false`.

## 📋 **Expected Authentication Flow**

Based on the backend code analysis, here's what the agent MUST do:

### **1. WebSocket Connection Headers**
```http
GET /ws/agent HTTP/1.1
Host: localhost:8080
X-Agent-ID: aegis-linux-service
X-Agent-Public-Key: <base64_encoded_ed25519_public_key>
User-Agent: Aegis-Agent/1.0
Upgrade: websocket
Connection: Upgrade
```

### **2. IMMEDIATE Authentication Message (Required First)**
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

### **3. Authentication Request Payload (Base64 Encoded)**
```json
{
  "agent_id": "aegis-linux-service",
  "public_key": "<base64_encoded_ed25519_public_key>",
  "timestamp": 1234567890,
  "nonce": "<base64_encoded_16_byte_nonce>",
  "signature": "<base64_encoded_ed25519_signature>"
}
```

### **4. Signature Data to Sign**
The agent must sign this EXACT string:
```
agent_id:public_key:timestamp:nonce
```

For example:
```
aegis-linux-service:j2WcrQtAByTAd7X9QUicfy6E0nk+BFKzauQmQBzW8VI=:1234567890:base64_nonce_here
```

## 🚨 **Current Agent Behavior (WRONG)**

Based on the logs, the agent is doing this:

1. ✅ Connect to WebSocket with proper headers
2. ❌ **SKIP authentication message**
3. ❌ Send heartbeat message (gets rejected - not authenticated)
4. ✅ Send registration init message (gets processed because it's handled specially)
5. ✅ Send registration complete message (gets processed because it's handled specially)
6. ❌ Send heartbeat message again (gets rejected - still not authenticated)
7. ❌ Connection drops due to rejected messages

## 🔧 **Backend Authentication Logic**

The backend has this logic in `handleTextMessage()`:

```go
// Check if this is an authentication message
if message.Type == types.MessageTypeRequest && message.Channel == "auth" {
    log.Printf("Processing authentication message from agent %s", conn.AgentID)
    return wsg.handleAuthentication(conn, message)
}

// Check if agent is authenticated
if !conn.IsAuthenticated {
    log.Printf("Agent %s not authenticated, rejecting message", conn.AgentID)
    return fmt.Errorf("agent not authenticated")
}
```

**This means:**
- ✅ `channel: "auth"` messages are processed without authentication
- ❌ All other messages require `conn.IsAuthenticated = true`
- ❌ The agent never sends an `auth` message, so `IsAuthenticated` stays `false`

## 🎯 **The Fix**

The agent team needs to modify their code to:

### **1. Send Authentication Message FIRST**
```javascript
// After WebSocket connection is established
function authenticate() {
    const authRequest = {
        agent_id: "aegis-linux-service",
        public_key: agentPublicKeyBase64,
        timestamp: Math.floor(Date.now() / 1000),
        nonce: generateNonce(),
        signature: signAuthenticationData(authRequest)
    };
    
    const authMessage = {
        id: `auth_${Date.now()}`,
        type: "request",
        channel: "auth",
        payload: btoa(JSON.stringify(authRequest)),
        timestamp: Math.floor(Date.now() / 1000),
        nonce: generateNonce(),
        signature: signMessage(authMessage),
        headers: {}
    };
    
    websocket.send(JSON.stringify(authMessage));
}
```

### **2. Wait for Authentication Success**
```javascript
websocket.onmessage = function(event) {
    const message = JSON.parse(event.data);
    
    if (message.channel === "auth" && message.type === "response") {
        const response = JSON.parse(atob(message.payload));
        if (response.success) {
            console.log("Authentication successful!");
            authenticated = true;
            // NOW send registration and heartbeat messages
            sendRegistration();
            startHeartbeat();
        }
    }
};
```

### **3. Only Send Other Messages After Authentication**
```javascript
function sendHeartbeat() {
    if (!authenticated) {
        console.log("Not authenticated, skipping heartbeat");
        return;
    }
    
    // Send heartbeat message
    const heartbeat = { ... };
    websocket.send(JSON.stringify(heartbeat));
}
```

## 📊 **Authentication Message Format Requirements**

### **SecureMessage Wrapper:**
- `id`: Unique message ID
- `type`: "request"
- `channel`: "auth" (exactly this)
- `payload`: Base64 encoded AuthenticationRequest JSON
- `timestamp`: Unix timestamp
- `nonce`: Base64 encoded nonce
- `signature`: Ed25519 signature of message data
- `headers`: Empty object

### **AuthenticationRequest Payload:**
- `agent_id`: Agent identifier
- `public_key`: Base64 encoded Ed25519 public key
- `timestamp`: Unix timestamp
- `nonce`: Base64 encoded 16-byte nonce
- `signature`: Ed25519 signature of "agent_id:public_key:timestamp:nonce"

## 🎯 **Summary**

**The agent is not authenticating because it never sends the required `channel: "auth"` message.**

**The agent team needs to:**
1. Send authentication message immediately after WebSocket connection
2. Wait for authentication success response
3. Only send other messages (heartbeat, registration) after authentication
4. Follow the exact message format and signature requirements

**This is a client-side issue, not a backend issue. The backend is working correctly by rejecting unauthenticated messages.**
