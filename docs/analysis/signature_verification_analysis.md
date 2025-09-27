# 🔍 Registration Complete Signature Verification Issue

## 🚨 **The Problem**

The agent's signature verification is failing during the registration complete step with error: `"401 signature verify failed"`

## 📋 **Backend Signature Verification Logic**

From `backend/actions-api/internal/api/agents.go` line 71:

```go
msg := append(pend.Nonce, []byte(pend.ServerTime+req.HostID)...)
sig, err := base64.StdEncoding.DecodeString(req.Signature)
if err != nil { http.Error(w, "bad signature", 400); return }
if !ed25519.Verify(ed25519.PublicKey(pend.PubKey), msg, sig) {
    http.Error(w, "signature verify failed", 401); return
}
```

## 🎯 **What the Backend Expects**

The backend expects the signature to be over this EXACT data:
```
nonce + server_time + host_id
```

**Where:**
- `nonce`: Base64 decoded bytes from the registration init response
- `server_time`: String from the registration init response (e.g., "2025-09-27T02:38:04Z")
- `host_id`: String from the registration complete request

## 📊 **Example from Logs**

**Registration Init Response:**
```json
{
  "registration_id": "00f7832c-60c6-4242-9e0d-e2866a08b0c5",
  "nonce": "PAmLwALfSbsOPTFTcT9rft/JuWHMrwhicHj1QDkEZlk=",
  "server_time": "2025-09-27T02:38:04Z"
}
```

**Registration Complete Request:**
```json
{
  "host_id": "aegis-linux-service",
  "registration_id": "00f7832c-60c6-4242-9e0d-e2866a08b0c5",
  "signature": "O9i3mzSnY8Y5QwZPGai1/A2vAKTwvIdbNVWYgYLywgpWU4O7WpUJOgaRW62DJCst5ZtIgHGwZuCIomMUyhU3DQ=="
}
```

**Expected Data to Sign:**
```
base64_decode("PAmLwALfSbsOPTFTcT9rft/JuWHMrwhicHj1QDkEZlk=") + "2025-09-27T02:38:04Z" + "aegis-linux-service"
```

## 🔧 **The Fix**

The agent needs to:

### **1. Decode the Nonce**
```javascript
// From registration init response
const nonceBase64 = "PAmLwALfSbsOPTFTcT9rft/JuWHMrwhicHj1QDkEZlk=";
const nonceBytes = atob(nonceBase64); // Decode base64 to binary string
```

### **2. Create the Data to Sign**
```javascript
const serverTime = "2025-09-27T02:38:04Z";
const hostId = "aegis-linux-service";
const dataToSign = nonceBytes + serverTime + hostId;
```

### **3. Sign the Data**
```javascript
// Using the same Ed25519 private key from registration init
const signature = ed25519Sign(privateKey, dataToSign);
const signatureBase64 = btoa(signature);
```

### **4. Send Registration Complete**
```javascript
const registrationComplete = {
    host_id: hostId,
    registration_id: registrationId,
    signature: signatureBase64
};
```

## 🚨 **Common Mistakes**

### **❌ Wrong: Signing only nonce**
```javascript
const signature = ed25519Sign(privateKey, nonceBase64); // WRONG
```

### **❌ Wrong: Signing nonce + registration_id**
```javascript
const signature = ed25519Sign(privateKey, nonceBase64 + registrationId); // WRONG
```

### **❌ Wrong: Not decoding nonce**
```javascript
const signature = ed25519Sign(privateKey, nonceBase64 + serverTime + hostId); // WRONG
```

### **✅ Correct: Decode nonce, then sign nonce + server_time + host_id**
```javascript
const nonceBytes = atob(nonceBase64);
const dataToSign = nonceBytes + serverTime + hostId;
const signature = ed25519Sign(privateKey, dataToSign);
```

## 📋 **Complete Agent Flow**

### **Step 1: Registration Init**
```javascript
// Agent sends registration init
const initResponse = await fetch('/agents/register/init', {
    method: 'POST',
    body: JSON.stringify(registrationData)
});

const initData = await initResponse.json();
// initData = { registration_id, nonce, server_time }
```

### **Step 2: Registration Complete**
```javascript
// Agent creates signature for completion
const nonceBytes = atob(initData.nonce);
const dataToSign = nonceBytes + initData.server_time + hostId;
const signature = ed25519Sign(privateKey, dataToSign);

// Agent sends registration complete
const completeResponse = await fetch('/agents/register/complete', {
    method: 'POST',
    body: JSON.stringify({
        host_id: hostId,
        registration_id: initData.registration_id,
        signature: btoa(signature)
    })
});
```

## 🎯 **Summary**

**The agent is failing signature verification because it's not signing the correct data.**

**Required signature data:** `nonce_bytes + server_time + host_id`

**Current agent issue:** Likely signing the wrong data or not properly decoding the nonce.

**The agent team needs to fix the signature creation logic in their registration complete step.**
