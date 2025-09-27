# Agent Registration Fix

## Issue Identified

The agent is trying to call the registration endpoint on the **WebSocket Gateway** (port 8080) instead of the **Actions API** (port 8083).

**Current (Incorrect) Agent Configuration:**
```
http://192.168.1.157:8080/agents/register/init
```

**Should Be:**
```
http://192.168.1.157:8083/agents/register/init
```

## Solution

### 1. Update Agent Configuration

Change the agent's registration endpoint from:
- ❌ `http://192.168.1.157:8080/agents/register/init` (WebSocket Gateway)
- ✅ `http://192.168.1.157:8083/agents/register/init` (Actions API)

### 2. Port Mapping

- **Port 8080**: WebSocket Gateway (WebSocket connections only)
- **Port 8083**: Actions API (HTTP registration endpoints)

### 3. Registration Flow

The agent should use **HTTP registration** (not WebSocket) for the initial registration:

1. **HTTP POST** to `http://192.168.1.157:8083/agents/register/init`
2. **HTTP POST** to `http://192.168.1.157:8083/agents/register/complete`

After successful HTTP registration, the agent can then connect via WebSocket to `ws://192.168.1.157:8080/ws/agent` for real-time communication.

### 4. Test Registration Endpoint

You can test the correct endpoint:

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

Expected response:
```json
{
  "registration_id": "uuid-here",
  "nonce": "base64-encoded-nonce",
  "server_time": "2025-09-26T16:16:15Z"
}
```

## Architecture Clarification

```
Agent Registration Flow:
┌─────────┐    HTTP POST     ┌─────────────┐
│  Agent  │ ────────────────►│ Actions API │
│         │                  │   :8083     │
└─────────┘                  └─────────────┘
     │
     │ After HTTP registration
     │
     ▼
┌─────────┐   WebSocket     ┌─────────────────┐
│  Agent  │ ───────────────►│ WebSocket       │
│         │                 │ Gateway :8080   │
└─────────┘                 └─────────────────┘
```

## Next Steps

1. Update agent configuration to use port 8083 for HTTP registration
2. Keep port 8080 for WebSocket connections after successful registration
3. Test the registration flow with the correct endpoints
