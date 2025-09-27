# Aegis Agent Binary Organization

## 📦 **Available Binaries**

### **Production Binary**
- **File**: `aegis-agent-production`
- **Purpose**: Optimized for production deployment
- **Features**: 
  - Fixed signature encoding (nonce + server_time + host_id)
  - Proper response parsing for agent_uid/bootstrap_token
  - Production-ready WebSocket configuration
  - Minimal logging overhead

### **Debug Binary**
- **File**: `aegis-agent-debug`
- **Purpose**: Development and troubleshooting
- **Features**:
  - Enhanced logging and debugging output
  - Detailed signature data logging
  - Verbose WebSocket connection logs
  - Registration process tracing

### **Legacy Binary**
- **File**: `aegis-agent`
- **Purpose**: Original version (may have issues)
- **Status**: ⚠️ **Deprecated** - Use production or debug versions

## 🚀 **Usage**

### **Using the Runner Script (Recommended)**
```bash
# Production mode
./run-agent.sh production

# Debug mode with custom settings
./run-agent.sh debug --agent-id "my-agent" --log-level debug

# Custom backend URL
./run-agent.sh production --backend-url "ws://backend:8080/ws/agent"
```

### **Direct Binary Execution**
```bash
# Production
./aegis-agent-production --agent-id "my-agent" --backend-url "ws://192.168.1.157:8080/ws/agent"

# Debug
./aegis-agent-debug --agent-id "my-agent" --backend-url "ws://192.168.1.157:8080/ws/agent" --log-level debug
```

## 🔧 **Key Fixes in Production/Debug Binaries**

### **✅ Signature Fix**
- **Before**: Signed `agent_id + ":" + nonce` ❌
- **After**: Signs `nonce + server_time.encode() + host_id.encode()` ✅

### **✅ Response Parsing Fix**
- **Before**: Expected `{"success": true}` ❌
- **After**: Handles `{"agent_uid": "...", "bootstrap_token": "..."}` ✅

### **✅ WebSocket Configuration**
- **Before**: Basic connection with frequent reconnections ❌
- **After**: Production-ready with exponential backoff ✅

## 📋 **Registration Flow (Fixed)**

1. **Step 1**: `/agents/register/init` → Returns `registration_id`, `nonce`, `server_time`
2. **Step 2**: `/agents/register/complete` → Signs `nonce + server_time + host_id` → Returns `agent_uid`, `bootstrap_token`
3. **Success**: Agent registered and WebSocket authenticated

## 🧪 **Testing**

### **Test Registration Success**
```bash
# Run with debug logging to see registration process
./run-agent.sh debug --agent-id "test-agent" --log-level debug
```

Look for these success indicators:
- `[registration] Step 1 complete: registration_id=..., nonce=..., server_time=..., host_id=...`
- `[registration] Data to sign (bytes): ...`
- `[registration] Generated signature: ...`
- `[registration] Complete registration response: {"agent_uid":"...","bootstrap_token":"..."}`

### **Expected Output**
```
✅ WebSocket connection established successfully
✅ Step 1 complete: registration_id=..., nonce=..., server_time=..., host_id=...
✅ Data to sign (bytes): [hex data]
✅ Generated signature: [base64 signature]
✅ Complete registration response: {"agent_uid":"...","bootstrap_token":"..."}
✅ Agent registered successfully
```

## 🚨 **Troubleshooting**

### **If Registration Still Fails**
1. Check backend connectivity: `curl http://192.168.1.157:8080/agents/register/init`
2. Verify signature format in logs
3. Check backend logs for specific error messages
4. Use debug binary for detailed logging

### **Common Issues**
- **401 Unauthorized**: Signature format incorrect (should be fixed in production binary)
- **Connection refused**: Backend not running or wrong URL
- **Unknown error**: Response parsing issue (should be fixed in production binary)

## 📁 **File Structure**
```
agents/aegis/
├── aegis-agent-production    # ✅ Production binary (FIXED)
├── aegis-agent-debug        # ✅ Debug binary (FIXED)
├── aegis-agent              # ⚠️ Legacy binary (deprecated)
├── run-agent.sh             # 🚀 Runner script
└── BINARY_ORGANIZATION.md   # 📋 This file
```

## 🎯 **Recommendation**

**Use `aegis-agent-production` for all deployments** - it contains the complete fix for the 401 Unauthorized issue and proper registration flow.
