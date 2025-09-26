# Agent Authentication Diagnostic Guide
## Troubleshooting "agent not authenticated" Errors

---

## 🔍 **Root Cause Analysis**

Based on the backend logs, the issue is **NOT** with the backend. The WebSocket Gateway is working perfectly:

### **✅ Successful Authentications:**
- `test-agent-fixed`: authenticated successfully
- `test-agent-signed`: authenticated successfully  
- `debug-agent-002`: authenticated successfully
- `working-agent-001`: authenticated successfully

### **❌ Failed Authentications:**
- `test-agent-corrected`: agent not authenticated

---

## 🎯 **The Real Problem**

The error `"agent not authenticated"` occurs when:

1. **Agent connects successfully** (WebSocket upgrade works)
2. **Agent sends a message** (not an authentication request)
3. **Backend checks authentication status** (finds `conn.IsAuthenticated = false`)
4. **Backend rejects the message** with "agent not authenticated"

---

## 🔧 **Diagnostic Steps**

### **Step 1: Check if Authentication Message is Sent**

The agent MUST send an authentication message immediately after connecting:

```python
# ❌ WRONG: Sending regular messages without authenticating first
await websocket.send(json.dumps({"type": "heartbeat", "data": "ping"}))

# ✅ CORRECT: Send authentication message first
auth_message = create_secure_auth_message()
await websocket.send(json.dumps(auth_message))
```

### **Step 2: Verify Message Format**

The authentication message MUST be in SecureMessage format:

```python
# ❌ WRONG: Direct authentication request
auth_request = {
    "agent_id": "test-agent",
    "public_key": "...",
    "signature": "..."
}
await websocket.send(json.dumps(auth_request))

# ✅ CORRECT: SecureMessage wrapper
secure_message = {
    "id": "auth_req_1234567890",
    "type": "request",        # Must be "request"
    "channel": "auth",        # Must be "auth"
    "payload": base64.b64encode(json.dumps(auth_request).encode()).decode(),
    "timestamp": 1234567890,
    "nonce": base64.b64encode(b"secure_nonce").decode(),
    "signature": "",
    "headers": {}
}
await websocket.send(json.dumps(secure_message))
```

### **Step 3: Check Authentication Flow**

```python
async def authenticate_agent(websocket):
    # 1. Send authentication message
    auth_message = create_secure_auth_message()
    await websocket.send(json.dumps(auth_message))
    
    # 2. Wait for authentication response
    response = await websocket.recv()
    response_data = json.loads(response)
    
    # 3. Check if authentication was successful
    payload = json.loads(base64.b64decode(response_data["payload"]).decode())
    if payload.get("success"):
        print("✅ Authentication successful!")
        return True
    else:
        print(f"❌ Authentication failed: {payload.get('message')}")
        return False

# 4. Only send other messages AFTER successful authentication
if await authenticate_agent(websocket):
    await send_heartbeat(websocket)
    await send_other_messages(websocket)
```

---

## 🚨 **Common Mistakes**

### **Mistake 1: Skipping Authentication**
```python
# ❌ WRONG: Agent connects and immediately sends heartbeat
async with websockets.connect(url, headers=headers) as websocket:
    await websocket.send(json.dumps({"type": "heartbeat"}))  # Will fail!
```

### **Mistake 2: Wrong Message Format**
```python
# ❌ WRONG: Sending raw authentication request
auth_req = {"agent_id": "test", "signature": "..."}
await websocket.send(json.dumps(auth_req))

# ✅ CORRECT: Wrapped in SecureMessage
secure_msg = {
    "type": "request",
    "channel": "auth", 
    "payload": base64.b64encode(json.dumps(auth_req).encode()).decode(),
    # ... other fields
}
await websocket.send(json.dumps(secure_msg))
```

### **Mistake 3: Wrong Channel**
```python
# ❌ WRONG: Using wrong channel
secure_msg = {
    "type": "request",
    "channel": "heartbeat",  # Wrong channel!
    # ...
}

# ✅ CORRECT: Use "auth" channel for authentication
secure_msg = {
    "type": "request", 
    "channel": "auth",       # Correct channel!
    # ...
}
```

---

## 🧪 **Diagnostic Test**

Run this test to verify your agent's authentication flow:

```python
async def diagnostic_test():
    # Connect
    async with websockets.connect(url, headers=headers) as websocket:
        print("✅ Connected")
        
        # Send authentication
        auth_msg = create_secure_auth_message()
        await websocket.send(json.dumps(auth_msg))
        print("📤 Authentication sent")
        
        # Wait for response
        response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
        print(f"📨 Response: {response}")
        
        # Try to send heartbeat (should work if authenticated)
        heartbeat_msg = {
            "id": f"heartbeat_{int(time.time())}",
            "type": "heartbeat",
            "channel": f"agent.{agent_id}.heartbeat",
            "payload": base64.b64encode(json.dumps({"status": "alive"}).encode()).decode(),
            "timestamp": int(time.time()),
            "nonce": base64.b64encode(b"heartbeat_nonce").decode(),
            "signature": "",
            "headers": {}
        }
        
        await websocket.send(json.dumps(heartbeat_msg))
        print("💓 Heartbeat sent")
```

---

## 📋 **Checklist**

Before sending any messages, verify:

- [ ] **WebSocket connection established** with proper headers
- [ ] **Authentication message sent** immediately after connection
- [ ] **SecureMessage format** used (type: "request", channel: "auth")
- [ ] **Authentication response received** and parsed
- [ ] **Success flag checked** before sending other messages
- [ ] **Only send other messages** after successful authentication

---

## 🔍 **Backend Log Analysis**

Look for these patterns in the backend logs:

### **Successful Authentication:**
```
WebSocket connection established for agent: test-agent-001
Agent test-agent-001 authenticated successfully
```

### **Failed Authentication:**
```
WebSocket connection established for agent: test-agent-001
Error handling text message from agent test-agent-001: agent not authenticated
```

The key difference is the **missing** "Agent X authenticated successfully" message.

---

## 🎯 **Solution**

1. **Use the working example**: `agent_authentication_test.py`
2. **Follow the exact format**: SecureMessage wrapper with auth channel
3. **Send authentication first**: Before any other messages
4. **Wait for success**: Check authentication response
5. **Test incrementally**: Connect → Authenticate → Send heartbeat

---

**The backend is working perfectly. The issue is in the agent's message format or flow!** 🔧
