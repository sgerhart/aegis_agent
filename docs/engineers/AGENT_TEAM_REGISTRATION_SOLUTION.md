# Agent Team Registration Solution

## 🚨 Issue Identified

Your agent is calling the **wrong endpoint** for registration:

**❌ Current (Incorrect):**
```
http://192.168.1.157:8080/agents/register/init
```

**✅ Should Be:**
```
http://192.168.1.157:8083/agents/register/init
```

## 🔍 Root Cause Analysis

1. **Port 8080** = WebSocket Gateway (WebSocket connections only)
2. **Port 8083** = Actions API (HTTP registration endpoints)
3. Your agent is getting a `404 page not found` response from the WebSocket Gateway
4. The agent tries to parse this HTML response as JSON, causing the parsing error

## 🛠️ Solution

### Step 1: Update Agent Configuration

Change your agent's registration endpoint from:
```python
# ❌ WRONG
registration_url = "http://192.168.1.157:8080/agents/register/init"

# ✅ CORRECT  
registration_url = "http://192.168.1.157:8083/agents/register/init"
```

### Step 2: Test the Correct Endpoint

You can test the correct endpoint manually:

```bash
curl -X POST http://192.168.1.157:8083/agents/register/init \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "test-org",
    "host_id": "test-host", 
    "agent_pubkey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "machine_id_hash": "test-hash",
    "agent_version": "1.0.0",
    "capabilities": {},
    "platform": {"os": "linux", "arch": "arm64"},
    "network": {"interface": "eth0"}
  }'
```

**Expected Response:**
```json
{
  "registration_id": "uuid-here",
  "nonce": "base64-encoded-nonce", 
  "server_time": "2025-09-26T16:16:15Z"
}
```

### Step 3: Complete Registration Flow

The registration is a **two-step process**:

1. **Step 1**: POST to `/agents/register/init` (returns registration_id and nonce)
2. **Step 2**: POST to `/agents/register/complete` (with signed nonce)

### Step 4: WebSocket Connection

After successful HTTP registration, connect to WebSocket:
```
ws://192.168.1.157:8080/ws/agent
```

## 📋 Architecture Overview

```
Agent Registration & Communication Flow:

┌─────────┐    HTTP Registration    ┌─────────────┐
│  Agent  │ ──────────────────────►│ Actions API │
│         │                        │   :8083     │
└─────────┘                        └─────────────┘
     │
     │ After HTTP registration success
     │
     ▼
┌─────────┐   WebSocket Connection  ┌─────────────────┐
│  Agent  │ ──────────────────────►│ WebSocket       │
│         │                         │ Gateway :8080   │
└─────────┘                         └─────────────────┘
```

## 🔧 Quick Fix

**Update your agent code:**

```python
# Change this line in your agent:
# registration_url = "http://192.168.1.157:8080/agents/register/init"

# To this:
registration_url = "http://192.168.1.157:8083/agents/register/init"
```

## ✅ Verification

After making the change, you should see:
- ✅ No more "invalid character 'p' after top-level value" error
- ✅ Successful JSON response from registration endpoint
- ✅ Agent appears in the backend system

## 📞 Support

If you need help implementing the registration completion step or WebSocket connection, let me know!
