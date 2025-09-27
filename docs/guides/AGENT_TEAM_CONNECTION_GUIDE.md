# Agent Team Connection Guide

## Overview
This document provides step-by-step instructions for connecting an agent to the backend and completing the registration process.

## Backend Architecture

### Services
- **WebSocket Gateway**: `ws://192.168.1.157:8080/ws/agent` (WebSocket connection)
- **Actions API**: `http://192.168.1.157:8083` (HTTP registration endpoints)

### Connection Flow
The agent connects to the **WebSocket Gateway** on port 8080, then sends registration messages through the WebSocket connection. The WebSocket Gateway acts as a proxy to the Actions API.

## Step-by-Step Connection Process

### Step 1: Establish WebSocket Connection
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

### Step 2: Send Authentication Message (Optional)
If your agent requires authentication, send this message:

```json
{
  "id": "auth_req_123456789",
  "type": "request",
  "channel": "auth",
  "timestamp": 1640995200,
  "payload": "base64_encoded_auth_data",
  "headers": {}
}
```

### Step 3: Send Registration Init Message
**This is the first required registration step.**

Send this message through the WebSocket connection:

```json
{
  "id": "reg_init_123456789",
  "type": "request", 
  "channel": "agent.registration",
  "timestamp": 1640995200,
  "payload": "base64_encoded_registration_data",
  "headers": {}
}
```

**Registration Data (base64 encode this JSON)**:
```json
{
  "org_id": "default-org",
  "host_id": "your-host-id",
  "agent_pubkey": "your-base64-encoded-ed25519-public-key",
  "machine_id_hash": "your-machine-hash",
  "agent_version": "1.0.0",
  "capabilities": {},
  "platform": {
    "arch": "arm64",
    "os": "linux"
  },
  "network": {
    "interface": "eth0"
  }
}
```

### Step 4: Handle Registration Init Response
The backend will respond with:

```json
{
  "id": "reg_resp_123456789",
  "type": "response",
  "channel": "agent.registration", 
  "timestamp": 1640995200,
  "payload": "{\"registration_id\":\"uuid\",\"nonce\":\"base64-nonce\",\"server_time\":\"2025-09-27T01:24:10Z\"}",
  "headers": {}
}
```

**Extract from response**:
- `registration_id`: UUID from the registration
- `nonce`: Base64-encoded nonce
- `server_time`: Server timestamp

### Step 5: Send Registration Complete Message
**This is the second required registration step.**

Create the signature data:
```
signature_data = nonce + server_time + host_id
```

Sign the data with your Ed25519 private key:
```
signature = ed25519_sign(private_key, signature_data)
signature_base64 = base64_encode(signature)
```

Send this message:

```json
{
  "id": "reg_complete_123456789",
  "type": "request",
  "channel": "agent.registration.complete", 
  "timestamp": 1640995200,
  "payload": "base64_encoded_completion_data",
  "headers": {}
}
```

**Completion Data (base64 encode this JSON)**:
```json
{
  "registration_id": "uuid-from-step-4",
  "host_id": "your-host-id",
  "signature": "base64-encoded-signature"
}
```

### Step 6: Handle Registration Complete Response
The backend will respond with success or failure. If successful, the agent is now registered.

## Important Notes

### Timeout Behavior
- **Initial timeout**: 5 minutes to send first message
- **Subsequent timeout**: 60 seconds between messages
- **If no messages sent**: Connection will timeout and close

### Message Format
- All messages must be JSON
- `payload` field must be base64-encoded JSON
- `timestamp` should be Unix timestamp
- `id` should be unique for each message

### Key Requirements
- **Ed25519 key pair**: Generate and use consistently
- **Base64 encoding**: All binary data must be base64-encoded
- **JSON structure**: Follow exact message format
- **Two-step registration**: Must complete both init and complete steps

### Common Issues

#### Issue 1: Connection Timeout
**Symptom**: Connection closes after 5 minutes
**Cause**: No messages sent
**Solution**: Send authentication or registration message immediately after connecting

#### Issue 2: Registration Fails
**Symptom**: Registration init works, complete fails
**Cause**: Incorrect signature
**Solution**: Ensure you're signing `nonce + server_time + host_id` with the same private key

#### Issue 3: Abnormal Closure (1006)
**Symptom**: WebSocket closes with error 1006
**Cause**: Agent-side issue or network problem
**Solution**: Check agent code, ensure proper WebSocket handling

## Example Working Flow

1. **Connect**: `ws://192.168.1.157:8080/ws/agent`
2. **Send registration init**: Channel `agent.registration`
3. **Receive response**: Extract `registration_id`, `nonce`, `server_time`
4. **Send registration complete**: Channel `agent.registration.complete`
5. **Receive confirmation**: Agent is registered

## Testing

### Test Connection
```bash
# Test WebSocket endpoint
curl -I http://192.168.1.157:8080/ws/agent
# Should return 400 Bad Request (expected for WebSocket endpoint)
```

### Check Registration
```bash
# Check registered agents
curl http://192.168.1.157:8083/agents
```

## Backend Status Endpoints

- **WebSocket Gateway Health**: `http://192.168.1.157:8080/health`
- **Actions API Health**: `http://192.168.1.157:8083/healthz`
- **Registered Agents**: `http://192.168.1.157:8083/agents`

## Summary

The agent must:
1. Connect to WebSocket Gateway on port 8080
2. Send registration init message
3. Receive registration response
4. Send registration complete message with signature
5. Receive confirmation

**Key**: The agent connects to port 8080 (WebSocket Gateway) and sends registration messages through the WebSocket connection. The WebSocket Gateway proxies these to the Actions API on port 8083.
