# Agent Troubleshooting Guide

## Common Issues and Solutions

### Issue 1: Connection Timeout After 5 Minutes
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

### Issue 2: Abnormal Closure (Close Code 1006)
**Symptom**: WebSocket closes with "websocket: close 1006 (abnormal closure): unexpected EOF"

**Root Cause**: Agent-side WebSocket handling issue or network problem

**Solutions**:
1. **Check WebSocket library**: Ensure you're using a stable WebSocket library
2. **Handle reconnection**: Implement automatic reconnection logic
3. **Check network**: Ensure stable network connection to backend
4. **Error handling**: Add proper error handling for WebSocket events

**Code Example**:
```python
def on_close(ws, close_status_code, close_msg):
    print(f"Connection closed: {close_status_code} - {close_msg}")
    if close_status_code == 1006:
        print("Abnormal closure - attempting reconnection...")
        time.sleep(5)
        reconnect()
```

### Issue 3: Registration Init Works, Complete Fails
**Symptom**: Step 1 (registration init) succeeds, Step 2 (registration complete) fails with signature error

**Root Cause**: Incorrect signature calculation

**Solution**: Ensure you're signing the correct data in the correct order:
```
signature_data = nonce + server_time + host_id
```

**Code Example**:
```python
# Correct signature calculation
signature_data = nonce + server_time + host_id
signature = private_key.sign(signature_data.encode())
signature_b64 = base64.b64encode(signature).decode()
```

### Issue 4: No Registration Messages Sent
**Symptom**: Agent connects but never sends registration messages

**Root Cause**: Agent doesn't implement the registration flow

**Solution**: Implement the two-step registration process:
1. Send registration init message
2. Handle response and send registration complete message

### Issue 5: Message Format Errors
**Symptom**: Backend rejects messages with format errors

**Root Cause**: Incorrect message structure or encoding

**Solution**: Follow the exact message format:
```json
{
  "id": "unique_message_id",
  "type": "request",
  "channel": "agent.registration",
  "timestamp": unix_timestamp,
  "payload": "base64_encoded_json_data",
  "headers": {}
}
```

## Debugging Steps

### Step 1: Verify Connection
```bash
# Test WebSocket endpoint
curl -I http://192.168.1.157:8080/ws/agent
# Should return 400 Bad Request (expected)
```

### Step 2: Check Backend Status
```bash
# Check WebSocket Gateway health
curl http://192.168.1.157:8080/health

# Check Actions API health  
curl http://192.168.1.157:8083/healthz

# Check registered agents
curl http://192.168.1.157:8083/agents
```

### Step 3: Monitor Backend Logs
```bash
# Watch WebSocket Gateway logs
docker compose -f infra/compose/docker-compose.yml logs -f websocket-gateway

# Watch Actions API logs
docker compose logs -f actions-api
```

### Step 4: Test with Python Script
Run the provided test script to verify the backend is working:
```bash
python3 AGENT_CONNECTION_TEST.py
```

## Expected Behavior

### Successful Registration Flow
1. **Connect**: WebSocket connection established
2. **Send Init**: Registration init message sent
3. **Receive Response**: Backend responds with registration_id, nonce, server_time
4. **Send Complete**: Registration complete message with signature sent
5. **Receive Confirmation**: Backend confirms registration
6. **Agent Registered**: Agent appears in `/agents` endpoint

### Backend Logs (Success)
```
WebSocket connection established for agent: your-agent-id
Received registration init request: map[...]
Successfully registered agent with Actions API
Received registration complete request: map[...]
Successfully completed agent registration
```

## Current Agent Issues

Based on the logs, your agent has these issues:

### Issue A: No Messages Sent
**Current Behavior**: Agent connects but never sends any messages
**Solution**: Implement message sending immediately after connection

### Issue B: Registration Incomplete
**Current Behavior**: Registration init works once, but complete never sent
**Solution**: Implement the registration complete step with proper signature

### Issue C: Reconnection Loop
**Current Behavior**: Agent reconnects repeatedly without completing registration
**Solution**: Complete the registration process before allowing reconnection

## Testing Checklist

- [ ] Agent connects to WebSocket Gateway on port 8080
- [ ] Agent sends message within 5 seconds of connection
- [ ] Agent sends registration init message with correct format
- [ ] Agent handles registration init response
- [ ] Agent sends registration complete message with correct signature
- [ ] Agent handles registration complete response
- [ ] Agent appears in `/agents` endpoint after registration

## Key Requirements

1. **Immediate Message**: Send a message within seconds of connecting
2. **Two-Step Registration**: Complete both init and complete steps
3. **Correct Signature**: Sign `nonce + server_time + host_id`
4. **Proper Format**: Use correct JSON message structure
5. **Base64 Encoding**: Encode all binary data and payloads
6. **Error Handling**: Handle WebSocket errors and reconnection

## Summary

The main issue is that your agent connects but doesn't send the required registration messages. Implement the two-step registration process and send messages immediately after connecting to avoid timeouts.
