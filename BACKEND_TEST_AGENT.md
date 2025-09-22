# Backend Test Agent
## For Testing WebSocket Backend Implementation

---

## 🧪 **Test Agent Overview**

This document provides a simple test agent that the backend team can use to validate their WebSocket implementation.

---

## 🚀 **Quick Test Setup**

### **1. Build Test Agent**
```bash
cd /Users/stevengerhart/workspace/github/sgerhart/aegis_agent/agents/aegis
go build -o test-agent ./cmd/aegis/main_core.go
```

### **2. Run Test Agent**
```bash
./test-agent --agent-id "test-agent-001" --backend-url "wss://your-backend.com/ws/agent" --log-level debug
```

### **3. Expected Behavior**
- Agent connects to WebSocket endpoint
- Performs authentication handshake
- Sends periodic heartbeat messages
- Responds to backend messages
- Handles reconnection automatically

---

## 📊 **Test Scenarios**

### **Scenario 1: Basic Connection**
```bash
# Test basic WebSocket connection
./test-agent --agent-id "basic-test" --backend-url "wss://localhost:8080/ws/agent"
```

**Expected Output**:
```
[websocket] Connected to backend at wss://localhost:8080/ws/agent
[websocket] Authentication successful, session expires at 2025-09-22 21:14:55
[websocket] WebSocket manager started for agent basic-test
```

### **Scenario 2: Authentication Failure**
```bash
# Test with invalid backend URL
./test-agent --agent-id "auth-test" --backend-url "wss://invalid-backend.com/ws/agent"
```

**Expected Output**:
```
[websocket] Failed to establish initial connection: failed to dial WebSocket: dial tcp: no such host
[core] Warning: failed to initialize communication manager: failed to establish initial connection
```

### **Scenario 3: Message Exchange**
```bash
# Test message sending
./test-agent --agent-id "message-test" --backend-url "wss://localhost:8080/ws/agent"
```

**Expected Behavior**:
- Agent sends heartbeat every 30 seconds
- Agent sends status updates
- Agent responds to backend messages

---

## 🔍 **Debugging Commands**

### **Enable Debug Logging**
```bash
./test-agent --agent-id "debug-test" --backend-url "wss://localhost:8080/ws/agent" --log-level debug
```

### **Test Specific Features**
```bash
# Test with specific agent ID
./test-agent --agent-id "custom-agent-123" --backend-url "wss://localhost:8080/ws/agent"

# Test with different log level
./test-agent --agent-id "test-agent" --backend-url "wss://localhost:8080/ws/agent" --log-level info
```

---

## 📝 **Test Message Examples**

### **Heartbeat Message**
```json
{
  "id": "msg_1695326400_123456789",
  "type": "heartbeat",
  "channel": "agent.test-agent-001.heartbeat",
  "payload": "encrypted_heartbeat_data",
  "timestamp": 1695326400,
  "nonce": "base64_nonce",
  "signature": "base64_signature",
  "headers": {
    "agent_status": "healthy",
    "uptime": "3600s"
  }
}
```

### **Status Update Message**
```json
{
  "id": "msg_1695326401_123456790",
  "type": "event",
  "channel": "agent.test-agent-001.status",
  "payload": "encrypted_status_data",
  "timestamp": 1695326401,
  "nonce": "base64_nonce",
  "signature": "base64_signature",
  "headers": {
    "status": "running",
    "policies": "5",
    "enforcement": "active"
  }
}
```

---

## 🔧 **Backend Testing Checklist**

### **Connection Testing**
- [ ] WebSocket upgrade works
- [ ] Authentication handshake completes
- [ ] Session tokens are generated
- [ ] Connection health monitoring works

### **Message Testing**
- [ ] Messages are encrypted/decrypted correctly
- [ ] Signatures are verified
- [ ] Channel routing works
- [ ] Heartbeat messages received

### **Error Testing**
- [ ] Invalid authentication rejected
- [ ] Connection drops handled
- [ ] Reconnection works
- [ ] Error messages formatted correctly

---

## 📊 **Monitoring and Metrics**

### **Agent Metrics**
The test agent provides metrics via the communication module:

```bash
# Get connection status
curl -X GET "http://localhost:8080/api/v1/agents/test-agent-001/status"

# Get metrics
curl -X GET "http://localhost:8080/api/v1/agents/test-agent-001/metrics"
```

### **Expected Metrics**
```json
{
  "connected": true,
  "metrics": {
    "messages_sent": 150,
    "messages_received": 75,
    "reconnects": 0,
    "errors": 0,
    "last_activity": "2025-09-21T21:14:55Z"
  }
}
```

---

## 🚨 **Troubleshooting**

### **Common Issues**

#### **Connection Refused**
```
Error: failed to dial WebSocket: dial tcp [::1]:8080: connect: connection refused
```
**Solution**: Ensure backend WebSocket service is running on port 8080

#### **Authentication Failed**
```
Error: authentication failed: invalid signature
```
**Solution**: Check Ed25519 key verification in backend

#### **TLS Handshake Error**
```
Error: failed to dial WebSocket: tls: handshake failure
```
**Solution**: Ensure WSS (TLS) is properly configured

### **Debug Steps**
1. Check backend WebSocket service is running
2. Verify TLS certificate configuration
3. Check authentication key management
4. Review backend logs for errors
5. Test with different agent IDs

---

## 📚 **Additional Resources**

### **Agent Documentation**
- `PHASE_3_WEBSOCKET_COMMUNICATION_SUMMARY.md` - Complete implementation summary
- `WEBSOCKET_PROTOCOL_SPECIFICATION.md` - Detailed protocol specification
- `BACKEND_TEAM_HANDOFF.md` - Complete backend requirements

### **Agent Source Code**
- `agents/aegis/internal/communication/websocket_manager.go` - WebSocket manager
- `agents/aegis/internal/communication/channel_manager.go` - Channel management
- `agents/aegis/internal/modules/websocket_communication_module.go` - Communication module

---

## 🎯 **Success Criteria**

### **Backend Implementation is Ready When**:
- [ ] Test agent connects successfully
- [ ] Authentication handshake completes
- [ ] Heartbeat messages are exchanged
- [ ] Bidirectional messaging works
- [ ] Reconnection works after connection drop
- [ ] All message types are supported
- [ ] Encryption/decryption works correctly
- [ ] Signature verification works
- [ ] Error handling is robust

---

**Use this test agent to validate your backend WebSocket implementation!** 🚀
