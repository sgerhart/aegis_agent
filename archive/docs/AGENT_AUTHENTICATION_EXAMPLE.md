# Agent Authentication Working Example
## WebSocket Gateway Integration Guide

---

## 🎯 **Overview**

This document provides a **working example** of how to authenticate with the AegisFlux WebSocket Gateway. The backend is fully functional and ready for agent connections.

### **✅ Verified Working Components:**
- WebSocket Gateway Service (Port 8080)
- Ed25519 Signature Authentication
- JWT Session Token Generation
- SecureMessage Protocol
- All Message Handlers Registered

---

## 🔌 **Connection Details**

### **WebSocket Endpoint:**
```
ws://localhost:8080/ws/agent
```

### **Required Headers:**
```http
X-Agent-ID: <your_agent_id>
X-Agent-Public-Key: <base64_encoded_ed25519_public_key>
User-Agent: Aegis-Agent/1.0
```

---

## 🔐 **Authentication Flow**

### **Step 1: WebSocket Connection**
```python
import asyncio
import websockets
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

async def connect_to_websocket():
    headers = {
        "X-Agent-ID": "your-agent-001",
        "X-Agent-Public-Key": "your_base64_public_key_here",
        "User-Agent": "Aegis-Agent/1.0"
    }
    
    async with websockets.connect(
        "ws://localhost:8080/ws/agent", 
        additional_headers=headers
    ) as websocket:
        # Connection established
        return websocket
```

### **Step 2: Generate Ed25519 Key Pair**
```python
def generate_keypair():
    """Generate Ed25519 key pair for authentication"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Get public key in base64 format
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    public_key_b64 = base64.b64encode(public_bytes).decode('utf-8')
    
    return private_key, public_key_b64
```

### **Step 3: Create Authentication Request**
```python
def create_auth_request(agent_id, private_key, public_key_b64):
    """Create authentication request with Ed25519 signature"""
    
    # Create signature data (exact format backend expects)
    timestamp = int(time.time())
    nonce = base64.b64encode(b"your_nonce_here").decode('utf-8')
    
    # CRITICAL: Backend expects this exact format
    signature_data = f"{agent_id}:{public_key_b64}:{timestamp}:{nonce}"
    
    # Sign the data
    signature = private_key.sign(signature_data.encode('utf-8'))
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    # Create authentication request
    auth_request = {
        "agent_id": agent_id,
        "public_key": public_key_b64,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature_b64
    }
    
    return auth_request
```

### **Step 4: Wrap in SecureMessage Format**
```python
def create_secure_message(auth_request, private_key):
    """Wrap authentication request in SecureMessage format"""
    
    timestamp = int(time.time())
    
    # Create SecureMessage (backend expects this wrapper)
    secure_message = {
        "id": f"auth_req_{timestamp}",
        "type": "request",           # CRITICAL: Must be "request"
        "channel": "auth",           # CRITICAL: Must be "auth"
        "payload": base64.b64encode(json.dumps(auth_request).encode()).decode(),
        "timestamp": timestamp,
        "nonce": base64.b64encode(b"secure_nonce").decode(),
        "signature": "",             # Can be empty for auth messages
        "headers": {}
    }
    
    return secure_message
```

---

## 📋 **Complete Working Example**

### **Full Authentication Code:**
```python
#!/usr/bin/env python3
"""
Working Agent Authentication Example
This code has been tested and works with the AegisFlux WebSocket Gateway
"""

import asyncio
import websockets
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class AegisAgent:
    def __init__(self, agent_id="test-agent-001"):
        self.agent_id = agent_id
        self.private_key, self.public_key_b64 = self.generate_keypair()
        self.websocket = None
        self.authenticated = False
        
    def generate_keypair(self):
        """Generate Ed25519 key pair"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        public_key_b64 = base64.b64encode(public_bytes).decode('utf-8')
        
        return private_key, public_key_b64
    
    def sign_data(self, data):
        """Sign data with Ed25519 private key"""
        signature = self.private_key.sign(data.encode('utf-8'))
        return base64.b64encode(signature).decode('utf-8')
    
    async def connect(self, url="ws://localhost:8080/ws/agent"):
        """Connect to WebSocket Gateway"""
        headers = {
            "X-Agent-ID": self.agent_id,
            "X-Agent-Public-Key": self.public_key_b64,
            "User-Agent": "Aegis-Agent/1.0"
        }
        
        print(f"🔗 Connecting to {url}")
        print(f"🆔 Agent ID: {self.agent_id}")
        print(f"🔑 Public Key: {self.public_key_b64}")
        
        self.websocket = await websockets.connect(url, additional_headers=headers)
        print("✅ WebSocket connection established")
        
    async def authenticate(self):
        """Authenticate with the backend"""
        if not self.websocket:
            raise Exception("Not connected to WebSocket")
            
        # Create authentication request
        timestamp = int(time.time())
        nonce = base64.b64encode(b"auth_nonce_1234").decode('utf-8')
        
        # CRITICAL: Backend expects this exact signature data format
        signature_data = f"{self.agent_id}:{self.public_key_b64}:{timestamp}:{nonce}"
        signature = self.sign_data(signature_data)
        
        auth_request = {
            "agent_id": self.agent_id,
            "public_key": self.public_key_b64,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature
        }
        
        # Wrap in SecureMessage format (backend requirement)
        secure_message = {
            "id": f"auth_req_{timestamp}",
            "type": "request",
            "channel": "auth",
            "payload": base64.b64encode(json.dumps(auth_request).encode()).decode(),
            "timestamp": timestamp,
            "nonce": base64.b64encode(b"secure_nonce").decode(),
            "signature": "",
            "headers": {}
        }
        
        print("📤 Sending authentication request...")
        await self.websocket.send(json.dumps(secure_message))
        
        # Wait for response
        response = await asyncio.wait_for(self.websocket.recv(), timeout=10.0)
        response_data = json.loads(response)
        
        # Decode response payload
        payload_data = json.loads(base64.b64decode(response_data["payload"]).decode())
        
        if payload_data.get("success"):
            self.authenticated = True
            print("🎉 Authentication SUCCESSFUL!")
            print(f"📋 Session Token: {payload_data.get('session_token', 'N/A')[:50]}...")
            print(f"⏰ Expires At: {payload_data.get('expires_at', 'N/A')}")
            return True
        else:
            print(f"❌ Authentication FAILED: {payload_data.get('message', 'Unknown error')}")
            return False
    
    async def send_heartbeat(self):
        """Send heartbeat message"""
        if not self.authenticated:
            raise Exception("Not authenticated")
            
        heartbeat_message = {
            "id": f"heartbeat_{int(time.time())}",
            "type": "heartbeat",
            "channel": f"agent.{self.agent_id}.heartbeat",
            "payload": base64.b64encode(json.dumps({"status": "alive"}).encode()).decode(),
            "timestamp": int(time.time()),
            "nonce": base64.b64encode(b"heartbeat_nonce").decode(),
            "signature": "",
            "headers": {}
        }
        
        await self.websocket.send(json.dumps(heartbeat_message))
        print("💓 Heartbeat sent")
    
    async def close(self):
        """Close WebSocket connection"""
        if self.websocket:
            await self.websocket.close()
            print("🔌 Connection closed")

# Example usage
async def main():
    agent = AegisAgent("working-agent-001")
    
    try:
        # Connect to WebSocket Gateway
        await agent.connect()
        
        # Authenticate
        success = await agent.authenticate()
        
        if success:
            # Send heartbeat
            await agent.send_heartbeat()
            
            # Keep connection alive for testing
            await asyncio.sleep(5)
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await agent.close()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 🧪 **Testing the Example**

### **1. Save the code above as `agent_example.py`**

### **2. Install dependencies:**
```bash
pip install websockets cryptography
```

### **3. Run the example:**
```bash
python3 agent_example.py
```

### **Expected Output:**
```
🔗 Connecting to ws://localhost:8080/ws/agent
🆔 Agent ID: working-agent-001
🔑 Public Key: <base64_public_key>
✅ WebSocket connection established
📤 Sending authentication request...
🎉 Authentication SUCCESSFUL!
📋 Session Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
⏰ Expires At: 1758746606
💓 Heartbeat sent
🔌 Connection closed
```

---

## 📋 **Critical Requirements**

### **✅ Must Use These Exact Formats:**

1. **Signature Data Format:**
   ```
   agent_id:public_key_b64:timestamp:nonce
   ```

2. **SecureMessage Structure:**
   ```json
   {
     "id": "auth_req_<timestamp>",
     "type": "request",
     "channel": "auth",
     "payload": "<base64_encoded_auth_request>",
     "timestamp": <unix_timestamp>,
     "nonce": "<base64_encoded_nonce>",
     "signature": "",
     "headers": {}
   }
   ```

3. **WebSocket Headers:**
   ```
   X-Agent-ID: <agent_id>
   X-Agent-Public-Key: <base64_ed25519_public_key>
   User-Agent: Aegis-Agent/1.0
   ```

---

## 🔍 **Troubleshooting**

### **Common Issues:**

1. **"Missing required headers"**
   - Ensure all three headers are present
   - Check header names are exact (case-sensitive)

2. **"Invalid signature"**
   - Verify signature data format: `agent_id:public_key:timestamp:nonce`
   - Ensure public key is base64 encoded correctly
   - Check that timestamp is Unix timestamp

3. **"agent not authenticated"**
   - Make sure you're sending SecureMessage format
   - Verify `type: "request"` and `channel: "auth"`
   - Check that payload is base64 encoded

### **Debug Tips:**

1. **Check Backend Logs:**
   ```bash
   docker compose -f infra/compose/docker-compose.yml logs websocket-gateway
   ```

2. **Test Connection:**
   ```bash
   curl http://localhost:8080/health
   ```

3. **Verify WebSocket Endpoint:**
   ```bash
   curl -I http://localhost:8080/ws/agent
   # Should return HTTP 400 (expected for non-WebSocket requests)
   ```

---

## 📞 **Support**

### **Backend Status:**
- ✅ WebSocket Gateway: Running on port 8080
- ✅ Authentication Service: Fully functional
- ✅ Ed25519 Signatures: Working correctly
- ✅ JWT Tokens: Generated successfully
- ✅ Message Handlers: All registered

### **Contact:**
- **Repository**: `/Users/stevengerhart/workspace/github/sgerhart/aegisflux`
- **WebSocket Endpoint**: `ws://localhost:8080/ws/agent`
- **Health Check**: `http://localhost:8080/health`

---

**This example has been tested and verified to work with the AegisFlux WebSocket Gateway. Use it as a reference for your agent implementation!** 🚀
