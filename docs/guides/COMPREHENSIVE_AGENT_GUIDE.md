# 📖 Comprehensive Agent Guide

This document consolidates all agent guides, troubleshooting, and production readiness information into a single comprehensive resource.

---

## 🚀 **Quick Start & Connection Guide**

### **Backend Architecture**
- **WebSocket Gateway**: `ws://192.168.1.157:8080/ws/agent` (WebSocket connection)
- **Actions API**: `http://192.168.1.157:8083` (HTTP registration endpoints)

### **Connection Flow**
The agent connects to the **WebSocket Gateway** on port 8080, then sends registration messages through the WebSocket connection. The WebSocket Gateway acts as a proxy to the Actions API.

### **Step-by-Step Connection Process**

#### **Step 1: Establish WebSocket Connection**
1. **Connect to WebSocket Gateway**:
   ```
   WebSocket URL: ws://192.168.1.157:8080/ws/agent
   ```

2. **Required Headers** (if needed):
   ```
   agentID: your-agent-id
   publicKey: your-base64-encoded-public-key
   ```

3. **Connection should establish successfully** - you should see connection confirmation

#### **Step 2: Send Authentication Message (CRITICAL FIRST STEP)**
**MUST send authentication message immediately after connection:**

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

**Authentication Request Payload (Base64 Encoded):**
```json
{
  "agent_id": "your-agent-id",
  "public_key": "<base64_encoded_ed25519_public_key>",
  "timestamp": 1234567890,
  "nonce": "<base64_encoded_16_byte_nonce>",
  "signature": "<base64_encoded_ed25519_signature>"
}
```

**Signature Data to Sign:**
```
agent_id:public_key:timestamp:nonce
```

#### **Step 3: Registration Process**
After successful authentication, send registration messages:

1. **Registration Init Message:**
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

2. **Registration Init Payload:**
```json
{
  "host_id": "your-agent-id",
  "public_key": "<base64_encoded_public_key>"
}
```

3. **Registration Complete Message:**
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

4. **Registration Complete Payload:**
```json
{
  "registration_id": "<from_init_response>",
  "host_id": "your-agent-id",
  "signature": "<base64_encoded_signature>"
}
```

**Registration Complete Signature Data:**
```
nonce_bytes + server_time + host_id
```

#### **Step 4: Send Heartbeats**
After successful registration, send periodic heartbeats:
```json
{
  "id": "heartbeat_1234567890",
  "type": "heartbeat",
  "timestamp": 1234567890,
  "payload": "{}",
  "headers": {}
}
```

---

## 🔧 **Troubleshooting Guide**

### **Common Issues and Solutions**

#### **Issue 1: Connection Timeout After 5 Minutes**
**Symptom**: Agent connects but connection closes after 5 minutes with "i/o timeout"

**Root Cause**: Agent connects but never sends any messages

**Solution**: 
- Send a message immediately after WebSocket connection is established
- Start with authentication or registration init message
- Don't wait - send a message within seconds of connecting

**Code Example**:
```python
def on_open(ws):
    print("Connected!")
    # Send message immediately
    send_registration_init()
```

#### **Issue 2: Abnormal Closure (Close Code 1006)**
**Symptom**: WebSocket closes with "websocket: close 1006 (abnormal closure): unexpected EOF"

**Root Cause**: Agent-side WebSocket handling issue or network problem

**Solutions**:
1. **Check WebSocket library**: Ensure you're using a stable WebSocket library
2. **Handle reconnection**: Implement automatic reconnection logic
3. **Check network**: Verify network stability and firewall rules
4. **Backend logs**: Check backend logs for any error messages

#### **Issue 3: "agent not authenticated" Error**
**Symptom**: Backend responds with "agent not authenticated" for all messages

**Root Cause**: Agent is sending messages before authentication

**Solution**:
- Send authentication message FIRST after WebSocket connection
- Wait for authentication success before sending other messages
- Ensure proper message format and signature

#### **Issue 4: Signature Verification Failed**
**Symptom**: Registration complete fails with "401 signature verify failed"

**Root Cause**: Incorrect signature data or format

**Solution**:
- Ensure nonce is base64-decoded to bytes before signing
- Sign the exact data: `nonce_bytes + server_time + host_id`
- Verify base64 encoding of the final signature

#### **Issue 5: Infinite Registration Loop**
**Symptom**: Agent keeps registering repeatedly, creating multiple agent records

**Root Cause**: Agent not maintaining session state across reconnections

**Solution**:
- Implement session persistence
- Only register once per session
- Store authentication state and reuse

### **Debugging Steps**

#### **1. Check Connection**
```bash
# Test WebSocket connection
curl -i -N -H "Connection: Upgrade" \
     -H "Upgrade: websocket" \
     -H "Sec-WebSocket-Version: 13" \
     -H "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==" \
     http://192.168.1.157:8080/ws/agent
```

#### **2. Verify Backend Status**
```bash
# Check backend health
curl http://192.168.1.157:8080/healthz

# Check registered agents
curl http://192.168.1.157:8083/agents
```

#### **3. Check Agent Logs**
```bash
# Check systemd service logs
journalctl -u aegis-agent -f

# Check agent binary logs
./aegis-agent --log-level debug
```

---

## 🚀 **Production Readiness Checklist**

### **📋 Current Status: FRAMEWORK COMPLETE, FUNCTIONALITY MISSING**

The agent has a solid architectural foundation but lacks real functionality. Here's what needs to be done to make it production-ready.

---

## 🎯 **CRITICAL ISSUES TO FIX**

### **1. Shutdown Panic** ❌ **CRITICAL**
- **Issue**: `panic: close of closed channel` during shutdown
- **Impact**: Agent crashes on shutdown
- **Status**: **MUST FIX BEFORE PRODUCTION**
- **Priority**: **P0 - BLOCKING**

### **2. Module Functionality** ❌ **CRITICAL**
- **Issue**: All modules are simulation-only
- **Impact**: Agent doesn't actually do anything useful
- **Status**: **MUST IMPLEMENT REAL FUNCTIONALITY**
- **Priority**: **P0 - BLOCKING**

### **3. eBPF Permissions** ⚠️ **HIGH**
- **Issue**: `MEMLOCK` permission errors
- **Impact**: Policy enforcement doesn't work
- **Status**: **NEEDS PROPER PERMISSIONS**
- **Priority**: **P1 - HIGH**

---

## ✅ **WHAT'S WORKING (PRODUCTION READY)**

### **Core Infrastructure** ✅
- **WebSocket Communication**: Stable, encrypted, authenticated
- **Module Management**: Dynamic start/stop/enable/disable
- **Identity Management**: Ed25519 key generation and management
- **Configuration**: Environment-based configuration
- **Logging**: Structured logging with appropriate levels
- **Graceful Shutdown**: Proper cleanup (when not panicking)

### **Module System** ✅
- **Module Discovery**: Automatic module detection
- **Lifecycle Management**: Start, stop, enable, disable
- **Status Reporting**: Real-time module status
- **Error Handling**: Module-level error isolation
- **Backend Control**: Remote module management via WebSocket

### **Communication** ✅
- **WebSocket Gateway**: Secure backend communication
- **Message Encryption**: ChaCha20-Poly1305 encryption
- **Authentication**: Ed25519 signature verification
- **Heartbeat System**: Connection health monitoring
- **Reconnection Logic**: Automatic reconnection on failure

---

## 🔧 **WHAT NEEDS TO BE IMPLEMENTED**

### **1. Real Module Functionality** ❌ **CRITICAL**

#### **Current State**: All modules are simulation-only
```go
// Example from telemetry module
func (tm *TelemetryModule) collectMetrics() {
    // SIMULATION ONLY - NOT REAL
    metrics := map[string]interface{}{
        "cpu_usage": 45.2,           // Fake data
        "memory_usage": 67.8,        // Fake data
        "network_connections": 23,   // Fake data
    }
    tm.reportMetrics(metrics)
}
```

#### **Required Implementation**:
```go
// Real telemetry collection
func (tm *TelemetryModule) collectMetrics() {
    // Real CPU usage
    cpuUsage, err := getCPUUsage()
    if err != nil {
        tm.logger.Error("Failed to get CPU usage", "error", err)
        return
    }
    
    // Real memory usage
    memUsage, err := getMemoryUsage()
    if err != nil {
        tm.logger.Error("Failed to get memory usage", "error", err)
        return
    }
    
    // Real network connections
    connCount, err := getNetworkConnections()
    if err != nil {
        tm.logger.Error("Failed to get network connections", "error", err)
        return
    }
    
    metrics := map[string]interface{}{
        "cpu_usage": cpuUsage,
        "memory_usage": memUsage,
        "network_connections": connCount,
    }
    tm.reportMetrics(metrics)
}
```

### **2. eBPF Policy Enforcement** ❌ **CRITICAL**

#### **Current State**: eBPF loading fails with permission errors
```
ERROR: failed to load eBPF program: operation not permitted
ERROR: failed to attach TC hook: permission denied
```

#### **Required Implementation**:
1. **Proper Permissions**: Run with CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_BPF
2. **eBPF Program Loading**: Implement real eBPF program loading
3. **TC Hook Attachment**: Attach to network interfaces
4. **Policy Enforcement**: Actually enforce network policies

### **3. Shutdown Panic Fix** ❌ **CRITICAL**

#### **Current State**: Panic during shutdown
```
panic: close of closed channel
goroutine 1 [running]:
main.main()
    /path/to/main.go:123 +0x456
```

#### **Required Implementation**:
```go
// Proper channel management
type Agent struct {
    shutdownCh chan struct{}
    once       sync.Once
}

func (a *Agent) Shutdown() {
    a.once.Do(func() {
        close(a.shutdownCh)
    })
}
```

---

## 🎯 **PRODUCTION DEPLOYMENT CHECKLIST**

### **Pre-Deployment** ✅
- [x] Agent builds successfully
- [x] WebSocket communication works
- [x] Module management works
- [x] Configuration system works
- [x] Logging system works
- [x] Graceful shutdown (mostly)

### **Deployment** ✅
- [x] Systemd service file
- [x] Environment configuration
- [x] Log rotation setup
- [x] Health check endpoint
- [x] Monitoring integration

### **Post-Deployment** ❌ **NEEDS WORK**
- [ ] Real module functionality
- [ ] eBPF policy enforcement
- [ ] Performance monitoring
- [ ] Error rate monitoring
- [ ] Resource usage monitoring

---

## 🚀 **IMPLEMENTATION PRIORITIES**

### **Phase 1: Critical Fixes (Week 1)**
1. **Fix Shutdown Panic** - Prevent crashes
2. **Implement Real Telemetry** - Actual system metrics
3. **Fix eBPF Permissions** - Enable policy enforcement

### **Phase 2: Core Functionality (Week 2-3)**
1. **Real Policy Enforcement** - Actual network policies
2. **Real Analysis Module** - Actual dependency analysis
3. **Real Threat Intelligence** - Actual threat detection

### **Phase 3: Production Hardening (Week 4)**
1. **Performance Optimization** - Memory and CPU usage
2. **Error Handling** - Comprehensive error recovery
3. **Monitoring Integration** - Prometheus/Grafana

---

## 📊 **SUCCESS METRICS**

### **Functional Metrics**
- [ ] Agent processes real system events
- [ ] eBPF policies are enforced
- [ ] Modules report real data
- [ ] No crashes or panics

### **Performance Metrics**
- [ ] Memory usage < 100MB
- [ ] CPU usage < 5%
- [ ] Network latency < 10ms
- [ ] Startup time < 5 seconds

### **Reliability Metrics**
- [ ] 99.9% uptime
- [ ] < 1% error rate
- [ ] Automatic recovery from failures
- [ ] Graceful degradation

---

## 🎯 **CONCLUSION**

The Aegis Agent has a **solid architectural foundation** but needs **real functionality implementation** to be production-ready. The core infrastructure is excellent, but the modules need to be implemented with actual system interaction rather than simulation.

**Next Steps:**
1. Fix critical issues (shutdown panic, eBPF permissions)
2. Implement real module functionality
3. Add comprehensive error handling
4. Performance optimization and monitoring

**Timeline**: 2-4 weeks for full production readiness
