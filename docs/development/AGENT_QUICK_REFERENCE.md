# Agent Quick Reference Card
## AegisFlux WebSocket Gateway Integration

---

## 🚀 **Quick Start**

### **1. Install Dependencies**
```bash
pip install websockets cryptography
```

### **2. Run Test Script**
```bash
python3 agent_authentication_test.py
```

### **3. Expected Output**
```
🔗 Connecting to ws://localhost:8080/ws/agent
🆔 Agent ID: working-agent-001
🔑 Public Key: <your_public_key>
✅ WebSocket connection established
📤 Sending authentication request...
🎉 Authentication SUCCESSFUL!
📋 Session Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
⏰ Expires At: 1758746926
💓 Heartbeat sent
🔌 Connection closed
🏁 Test completed
```

---

## 🔌 **Connection Details**

| Parameter | Value |
|-----------|-------|
| **WebSocket URL** | `ws://localhost:8080/ws/agent` |
| **Health Check** | `http://localhost:8080/health` |
| **Protocol** | WebSocket with Ed25519 authentication |

---

## 📋 **Required Headers**

```http
X-Agent-ID: <your_agent_id>
X-Agent-Public-Key: <base64_ed25519_public_key>
User-Agent: Aegis-Agent/1.0
```

---

## 🔐 **Authentication Flow**

### **Step 1: Generate Ed25519 Key Pair**
```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Get base64 public key
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
public_key_b64 = base64.b64encode(public_bytes).decode('utf-8')
```

### **Step 2: Create Signature**
```python
# CRITICAL: Use this exact format
signature_data = f"{agent_id}:{public_key_b64}:{timestamp}:{nonce}"
signature = private_key.sign(signature_data.encode('utf-8'))
signature_b64 = base64.b64encode(signature).decode('utf-8')
```

### **Step 3: Send SecureMessage**
```python
secure_message = {
    "id": f"auth_req_{timestamp}",
    "type": "request",           # Must be "request"
    "channel": "auth",           # Must be "auth"
    "payload": base64.b64encode(json.dumps(auth_request).encode()).decode(),
    "timestamp": timestamp,
    "nonce": base64.b64encode(b"secure_nonce").decode(),
    "signature": "",
    "headers": {}
}
```

---

## ✅ **Success Indicators**

- ✅ WebSocket connection established
- ✅ "Authentication SUCCESSFUL!" message
- ✅ JWT session token received
- ✅ Backend logs: "Agent <id> authenticated successfully"

---

## ❌ **Common Errors**

| Error | Solution |
|-------|----------|
| `Missing required headers` | Add X-Agent-ID, X-Agent-Public-Key, User-Agent |
| `Invalid signature` | Check signature data format: `agent_id:public_key:timestamp:nonce` |
| `agent not authenticated` | Use SecureMessage format with `type: "request"`, `channel: "auth"` |
| `Public key mismatch` | Ensure same public key in headers and auth request |

---

## 🔍 **Debug Commands**

### **Check Backend Status**
```bash
curl http://localhost:8080/health
```

### **View Backend Logs**
```bash
docker compose -f infra/compose/docker-compose.yml logs websocket-gateway
```

### **Test WebSocket Endpoint**
```bash
curl -I http://localhost:8080/ws/agent
# Should return HTTP 400 (expected for non-WebSocket)
```

---

## 📞 **Support**

- **Working Example**: `agent_authentication_test.py`
- **Full Documentation**: `AGENT_AUTHENTICATION_EXAMPLE.md`
- **Backend Status**: ✅ Fully functional and tested

---

**Ready to integrate! The backend is waiting for your agent connections.** 🚀
