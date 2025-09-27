# 🔧 Agent Signature Fix - 401 Unauthorized Issue

## 🎯 **Root Cause Identified**

The 401 Unauthorized error is actually a **signature validation failure**. The backend expects the agent to sign **only the nonce**, but the agent is signing `agent_id + ":" + nonce`.

## ❌ **Current Agent Implementation (WRONG)**

```python
# ❌ WRONG - Agent is signing agent_id + ":" + nonce
data_to_sign = f"{agent_id}:{nonce}"
signature = private_key.sign(data_to_sign.encode())
```

## ✅ **Correct Agent Implementation (FIXED)**

```python
# ✅ CORRECT - Agent should sign nonce + server_time + host_id
data_to_sign = nonce + server_time + host_id  # Backend expects this exact format
signature = private_key.sign(data_to_sign.encode())
```

## 🔧 **Complete Fixed Registration Flow**

### **Step 1: Registration Init**
```python
# ✅ This part is correct - no changes needed
response = requests.post(
    "http://192.168.1.157:8080/agents/register/init",
    json={
        "org_id": "your-org",
        "host_id": "your-host",
        "agent_pubkey": base64.b64encode(public_key).decode(),
        "agent_version": "1.0.0",
        "capabilities": {},
        "platform": {"os": "linux", "arch": "arm64"},
        "network": {"interface": "eth0"}
    }
)

if response.status_code == 200:
    reg_data = response.json()
    nonce = reg_data["nonce"]
    registration_id = reg_data["registration_id"]
```

### **Step 2: Registration Complete (FIXED)**
```python
# ✅ FIXED - Sign nonce + server_time + host_id (exactly what backend expects)
data_to_sign = nonce + server_time + host_id  # Backend expects this exact format
signature = private_key.sign(data_to_sign.encode())
signed_nonce = base64.b64encode(signature).decode()

# Complete registration
complete_response = requests.post(
    "http://192.168.1.157:8080/agents/register/complete",
    json={
        "registration_id": registration_id,
        "host_id": host_id,  # Required by backend
        "signature": signed_nonce  # Backend expects 'signature' field, not 'signed_nonce'
    }
)
```

## 🧪 **Test the Fix**

### **1. Test Registration Init**
```bash
curl -X POST http://192.168.1.157:8080/agents/register/init \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "test-org",
    "host_id": "test-host",
    "agent_pubkey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "agent_version": "1.0.0",
    "capabilities": {},
    "platform": {"os": "linux", "arch": "arm64"},
    "network": {"interface": "eth0"}
  }'
```

**Expected Response:**
```json
{
  "nonce": "base64-encoded-nonce",
  "registration_id": "uuid-here",
  "server_time": "2025-09-26T16:30:00Z"
}
```

### **2. Test Registration Complete (with correct signature)**
```bash
# Use the nonce + server_time + host_id from step 1 and sign the concatenated data
curl -X POST http://192.168.1.157:8080/agents/register/complete \
  -H "Content-Type: application/json" \
  -d '{
    "registration_id": "uuid-from-step-1",
    "host_id": "test-host",
    "signature": "correctly-signed-nonce+server_time+host_id"
  }'
```

## 🔍 **Backend Signature Verification**

The backend verifies the signature by:
1. Taking the `signature` from the request
2. Decoding it from base64
3. Verifying it against `nonce + server_time + host_id` using the `agent_pubkey` from Step 1
4. **Key Point**: It expects the signature to be of `nonce + server_time + host_id`, not `agent_id + nonce`

## 🎯 **Summary of Changes Needed**

### **In Agent Code:**
1. **Change signing logic**: Sign `nonce + server_time + host_id`, not `agent_id + ":" + nonce`
2. **Change request field**: Use `signature` field instead of `signed_nonce`
3. **Add host_id**: Include `host_id` in the completion request
4. **Keep everything else the same**: Same key pair, same endpoints, same flow

### **Before (WRONG):**
```python
data_to_sign = f"{agent_id}:{nonce}"  # ❌ Wrong
# Request: {"signed_nonce": "...", "agent_version": "1.0.0"}  # ❌ Wrong fields
```

### **After (CORRECT):**
```python
data_to_sign = nonce + server_time + host_id  # ✅ Correct
# Request: {"host_id": "test-host", "signature": "..."}  # ✅ Correct fields
```

## 🚀 **Expected Result**

After this fix:
- ✅ Step 1 (Registration Init) will work
- ✅ Step 2 (Registration Complete) will work  
- ✅ Agent will be successfully registered
- ✅ WebSocket connection will be stable
- ✅ No more 401 Unauthorized errors

The signature mismatch was the root cause of the 401 error! 🎉
