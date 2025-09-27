# Agent Registration Implementation Guide

## Overview

This document provides the complete implementation details for agent registration, including the exact code, signature formats, and troubleshooting steps.

## Registration Flow

The agent registration process consists of two steps:

1. **Registration Init** - Initialize registration and receive challenge data
2. **Registration Complete** - Sign the challenge and complete registration

## Implementation

### Go Implementation

```go
package main

import (
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type RegistrationInitRequest struct {
    OrgID       string                 `json:"org_id"`
    HostID      string                 `json:"host_id"`
    AgentPubkey string                 `json:"agent_pubkey"`
    AgentVersion string                `json:"agent_version"`
    Capabilities map[string]interface{} `json:"capabilities"`
    Platform    map[string]string      `json:"platform"`
    Network     map[string]string      `json:"network"`
}

type RegistrationInitResponse struct {
    RegistrationID string `json:"registration_id"`
    Nonce          string `json:"nonce"`
    ServerTime     string `json:"server_time"`
}

type RegistrationCompleteRequest struct {
    RegistrationID string `json:"registration_id"`
    HostID         string `json:"host_id"`
    Signature      string `json:"signature"`
}

type RegistrationCompleteResponse struct {
    AgentUID       string `json:"agent_uid"`
    BootstrapToken string `json:"bootstrap_token"`
}

func (a *Agent) register() error {
    // Step 1: Registration Init
    initReq := RegistrationInitRequest{
        OrgID:        "default-org",
        HostID:       a.hostID,
        AgentPubkey:  base64.StdEncoding.EncodeToString(a.publicKey),
        AgentVersion: "1.0.0",
        Capabilities: make(map[string]interface{}),
        Platform: map[string]string{
            "os":   "linux",
            "arch": "arm64",
        },
        Network: map[string]string{
            "interface": "eth0",
        },
    }

    initResp, err := a.sendRegistrationInit(initReq)
    if err != nil {
        return fmt.Errorf("registration init failed: %w", err)
    }

    // Step 2: Registration Complete
    signature, err := a.signRegistrationComplete(initResp.Nonce, initResp.ServerTime)
    if err != nil {
        return fmt.Errorf("failed to sign registration complete: %w", err)
    }

    completeReq := RegistrationCompleteRequest{
        RegistrationID: initResp.RegistrationID,
        HostID:         a.hostID,
        Signature:      signature,
    }

    completeResp, err := a.sendRegistrationComplete(completeReq)
    if err != nil {
        return fmt.Errorf("registration complete failed: %w", err)
    }

    a.agentUID = completeResp.AgentUID
    a.bootstrapToken = completeResp.BootstrapToken

    return nil
}

func (a *Agent) signRegistrationComplete(nonce, serverTime string) (string, error) {
    // Decode the nonce from base64 to bytes
    nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
    if err != nil {
        return "", fmt.Errorf("failed to decode nonce: %w", err)
    }

    // Create signature data: nonce_bytes + server_time + host_id
    signatureData := append(nonceBytes, []byte(serverTime+a.hostID)...)

    // Sign the data
    signature := ed25519.Sign(a.privateKey, signatureData)
    
    return base64.StdEncoding.EncodeToString(signature), nil
}
```

### Python Implementation

```python
import requests
import base64
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class AgentRegistration:
    def __init__(self, host_id="test-host", org_id="test-org"):
        self.host_id = host_id
        self.org_id = org_id
        # Generate Ed25519 key pair
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
    def register_agent(self):
        """Complete two-step registration process"""
        
        # Step 1: Registration Init
        print("🔧 Step 1: Registration Init")
        init_response = requests.post(
            "http://192.168.1.157:8080/agents/register/init",
            json={
                "org_id": self.org_id,
                "host_id": self.host_id,
                "agent_pubkey": base64.b64encode(
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                ).decode(),
                "agent_version": "1.0.0",
                "capabilities": {},
                "platform": {"os": "linux", "arch": "arm64"},
                "network": {"interface": "eth0"}
            }
        )
        
        if init_response.status_code != 200:
            print(f"❌ Registration init failed: {init_response.status_code} {init_response.text}")
            return False
            
        reg_data = init_response.json()
        print(f"✅ Registration init successful: {reg_data}")
        
        # Step 2: Registration Complete
        print("🔧 Step 2: Registration Complete")
        
        # ✅ CRITICAL: Sign nonce + server_time + host_id (exactly what backend expects)
        nonce = base64.b64decode(reg_data["nonce"])
        server_time = reg_data["server_time"]
        
        # This is the EXACT format the backend expects
        data_to_sign = nonce + server_time.encode() + self.host_id.encode()
        signature = self.private_key.sign(data_to_sign)
        
        complete_response = requests.post(
            "http://192.168.1.157:8080/agents/register/complete",
            json={
                "registration_id": reg_data["registration_id"],
                "host_id": self.host_id,  # ✅ Required by backend
                "signature": base64.b64encode(signature).decode()  # ✅ Backend expects 'signature' field
            }
        )
        
        if complete_response.status_code != 200:
            print(f"❌ Registration complete failed: {complete_response.status_code} {complete_response.text}")
            return False
            
        complete_data = complete_response.json()
        print(f"✅ Registration complete successful: {complete_data}")
        
        return True
```

## Signature Verification

### Backend Verification Logic

The backend verifies signatures using this exact logic:

```go
func verifyRegistrationSignature(nonce, serverTime, hostID string, signature []byte, publicKey ed25519.PublicKey) bool {
    // Decode nonce from base64
    nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
    if err != nil {
        return false
    }
    
    // Create signature data: nonce_bytes + server_time + host_id
    signatureData := append(nonceBytes, []byte(serverTime+hostID)...)
    
    // Verify signature
    return ed25519.Verify(publicKey, signatureData, signature)
}
```

### Common Signature Mistakes

❌ **Wrong**: Signing `nonce + server_time + host_id` as strings
```python
# WRONG - This concatenates strings, not bytes
data_to_sign = nonce + server_time + host_id
```

✅ **Correct**: Decode nonce to bytes first
```python
# CORRECT - Decode nonce to bytes, then concatenate
nonce_bytes = base64.b64decode(nonce)
data_to_sign = nonce_bytes + server_time.encode() + host_id.encode()
```

## Error Handling

### Common Registration Errors

| Error Code | Error Message | Solution |
|------------|---------------|----------|
| 400 | Invalid request format | Check JSON structure and required fields |
| 401 | Signature verification failed | Verify signature data format and signing process |
| 409 | Agent already registered | Use existing agent UID or clear backend data |
| 500 | Internal server error | Check backend logs and retry |

### Debugging Registration Issues

```bash
# Test registration endpoints manually
curl -X POST http://192.168.1.157:8080/agents/register/init \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "default-org",
    "host_id": "test-agent",
    "agent_pubkey": "base64_public_key",
    "agent_version": "1.0.0",
    "capabilities": {},
    "platform": {"os": "linux", "arch": "arm64"},
    "network": {"interface": "eth0"}
  }'

# Check backend logs for registration attempts
# Look for signature verification messages
```

## Session Management

### Agent UID and Bootstrap Token

After successful registration, the agent receives:
- **Agent UID**: Unique identifier for this agent instance
- **Bootstrap Token**: Token for subsequent authentication

### Session Persistence

```go
type AgentSession struct {
    AgentUID       string    `json:"agent_uid"`
    BootstrapToken string    `json:"bootstrap_token"`
    SessionToken   string    `json:"session_token"`
    ExpiresAt      time.Time `json:"expires_at"`
}

func (a *Agent) saveSession(session AgentSession) error {
    data, err := json.Marshal(session)
    if err != nil {
        return err
    }
    return ioutil.WriteFile("/var/lib/aegis/session.json", data, 0600)
}

func (a *Agent) loadSession() (*AgentSession, error) {
    data, err := ioutil.ReadFile("/var/lib/aegis/session.json")
    if err != nil {
        return nil, err
    }
    
    var session AgentSession
    if err := json.Unmarshal(data, &session); err != nil {
        return nil, err
    }
    
    // Check if session is expired
    if time.Now().After(session.ExpiresAt) {
        return nil, fmt.Errorf("session expired")
    }
    
    return &session, nil
}
```

## Testing

### Unit Tests

```go
func TestRegistrationSignature(t *testing.T) {
    // Generate test keys
    publicKey, privateKey, err := ed25519.GenerateKey(nil)
    require.NoError(t, err)
    
    // Test data
    nonce := base64.StdEncoding.EncodeToString([]byte("test-nonce"))
    serverTime := "2025-09-27T02:38:04Z"
    hostID := "test-agent"
    
    // Sign
    signature, err := signRegistrationComplete(privateKey, nonce, serverTime, hostID)
    require.NoError(t, err)
    
    // Verify
    valid := verifyRegistrationSignature(nonce, serverTime, hostID, signature, publicKey)
    assert.True(t, valid)
}
```

### Integration Tests

```bash
# Test complete registration flow
python3 test_registration.py

# Expected output:
# 🔧 Step 1: Registration Init
# ✅ Registration init successful: {'registration_id': 'uuid', 'nonce': '...', 'server_time': '...'}
# 🔧 Step 2: Registration Complete  
# ✅ Registration complete successful: {'agent_uid': 'uuid', 'bootstrap_token': '...'}
```
