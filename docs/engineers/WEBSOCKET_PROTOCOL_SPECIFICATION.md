# WebSocket Protocol Specification

## Overview

This document defines the complete WebSocket communication protocol between Aegis agents and the backend gateway.

## Connection Establishment

### WebSocket URL
```
ws://backend-host:8080/ws/agent
```

### Connection Headers
```
User-Agent: Aegis-Agent/1.0
X-Agent-Id: <agent_id>
X-Agent-Public-Key: <base64_encoded_ed25519_public_key>
X-Agent-Uid: <agent_uid> (optional, for reconnections)
X-Bootstrap-Token: <bootstrap_token> (optional, for reconnections)
```

## Message Format

All messages use the SecureMessage format:

```json
{
  "id": "unique_message_id",
  "type": "request|response|heartbeat|error",
  "channel": "channel_name",
  "payload": "base64_encoded_payload",
  "timestamp": 1695326400,
  "nonce": "base64_encoded_16_byte_nonce",
  "signature": "base64_encoded_ed25519_signature",
  "headers": {}
}
```

## Authentication Protocol

### Authentication Request
**Channel**: `auth`
**Payload**: Base64-encoded JSON containing:
```json
{
  "agent_id": "aegis-agent-001",
  "public_key": "base64_encoded_ed25519_public_key",
  "timestamp": 1695326400,
  "nonce": "base64_encoded_16_byte_nonce",
  "signature": "base64_encoded_ed25519_signature"
}
```

**Signature Data**: `agent_id:public_key:timestamp:nonce`

### Authentication Response
**Channel**: `auth`
**Payload**: Base64-encoded JSON containing:
```json
{
  "success": true,
  "session_token": "jwt_session_token",
  "backend_key": "base64_encoded_backend_public_key",
  "expires_at": 1759082015,
  "message": "Authentication successful"
}
```

## Registration Protocol

### Registration Init Request
**Channel**: `agent.registration`
**Payload**: Base64-encoded JSON containing:
```json
{
  "org_id": "default-org",
  "host_id": "aegis-agent-001",
  "agent_pubkey": "base64_encoded_ed25519_public_key",
  "agent_version": "1.0.0",
  "capabilities": {},
  "platform": {"os": "linux", "arch": "arm64"},
  "network": {"interface": "eth0"}
}
```

### Registration Init Response
**Channel**: `agent.registration`
**Payload**: Base64-encoded JSON containing:
```json
{
  "registration_id": "uuid",
  "nonce": "base64_encoded_nonce",
  "server_time": "2025-09-27T02:38:04Z"
}
```

### Registration Complete Request
**Channel**: `agent.registration.complete`
**Payload**: Base64-encoded JSON containing:
```json
{
  "registration_id": "uuid",
  "host_id": "aegis-agent-001",
  "signature": "base64_encoded_ed25519_signature"
}
```

**Signature Data**: `nonce_bytes + server_time + host_id`

### Registration Complete Response
**Channel**: `agent.registration.complete`
**Payload**: Base64-encoded JSON containing:
```json
{
  "agent_uid": "uuid",
  "bootstrap_token": "bootstrap_token_string"
}
```

## Heartbeat Protocol

### Heartbeat Message
**Channel**: `agent.{agent_id}.heartbeat`
**Payload**: Base64-encoded JSON containing:
```json
{}
```

**Frequency**: Every 60 seconds
**Signature**: Required (all messages must be signed)

## Error Handling

### Error Response Format
**Channel**: `error`
**Payload**: Base64-encoded JSON containing:
```json
{
  "error": "error_type",
  "message": "Human readable error message",
  "details": "Additional error details"
}
```

### Common Error Types
- `authentication_failed`: Invalid credentials
- `registration_failed`: Registration process failed
- `signature_verification_failed`: Invalid message signature
- `channel_not_found`: Invalid channel specified
- `message_processing_error`: General processing error

## Security Considerations

### Message Signing
All messages must be signed using Ed25519:
1. Create signature data based on message type
2. Sign with agent's private key
3. Include base64-encoded signature in message

### Session Management
- Session tokens expire after 24 hours
- Agents should re-authenticate before expiration
- Failed authentication requires new registration

### Connection Security
- Use WSS (WebSocket Secure) in production
- Validate all message signatures
- Implement rate limiting on backend
- Monitor for suspicious activity

## Implementation Examples

### Go Implementation
```go
type SecureMessage struct {
    ID        string            `json:"id"`
    Type      string            `json:"type"`
    Channel   string            `json:"channel"`
    Payload   string            `json:"payload"`
    Timestamp int64             `json:"timestamp"`
    Nonce     string            `json:"nonce"`
    Signature string            `json:"signature"`
    Headers   map[string]string `json:"headers"`
}
```

### Python Implementation
```python
import websocket
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519

class WebSocketClient:
    def __init__(self, url, private_key):
        self.url = url
        self.private_key = private_key
        self.public_key = private_key.public_key()
    
    def sign_message(self, message):
        # Implementation depends on message type
        pass
```

## Testing and Debugging

### Message Validation
- Verify signature on all received messages
- Check timestamp validity (within 5 minutes)
- Validate nonce uniqueness
- Ensure proper channel routing

### Connection Testing
```bash
# Test WebSocket connection
wscat -c ws://backend-host:8080/ws/agent

# Test with headers
wscat -c ws://backend-host:8080/ws/agent \
  -H "User-Agent: Aegis-Agent/1.0" \
  -H "X-Agent-Id: test-agent"
```

### Log Analysis
Monitor logs for:
- Connection establishment
- Authentication success/failure
- Message processing errors
- Signature validation failures