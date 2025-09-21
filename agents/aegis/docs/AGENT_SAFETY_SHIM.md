# Aegis Agent Safety Shim

## Overview

The Aegis Agent Safety Shim provides comprehensive safety mechanisms for eBPF policy enforcement, including cryptographic verification, dry-run capabilities, rollback functionality, and enhanced telemetry.

## Features

### 1. Cryptographic Verification
- **Ed25519 Signature Verification**: All policy bundles are cryptographically verified using Ed25519 signatures
- **Trust Store Management**: Centralized management of trusted signing keys with rotation support
- **Detached Signature Support**: Support for detached signatures over policy content

### 2. Dry-Run Mode
- **Verification-Only Mode**: Test policy application without making actual changes
- **Change Simulation**: Simulate what changes would be made during policy application
- **Safety Validation**: Validate policies before applying them to production systems

### 3. Rollback Capabilities
- **Automatic Snapshots**: Create snapshots before applying policies for safe rollback
- **Manual Rollback**: Rollback to previous states when issues are detected
- **Rollback Triggers**: Automatic rollback on verification or application failures

### 4. TTL and Expiry Management
- **Assignment TTL**: Time-to-live enforcement for policy assignments
- **Expiry Monitoring**: Background monitoring for expired assignments
- **Automatic Cleanup**: Clean up expired assignments automatically

### 5. Enhanced Telemetry
- **Structured Events**: JSON-structured telemetry events for all operations
- **Verification Events**: Track verification success/failure with timing
- **Enforcement Events**: Track policy enforcement with change details
- **Rollback Events**: Track rollback operations and their outcomes
- **Counter Metrics**: Track various operational metrics

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AEGIS_DRY_RUN` | Enable dry-run mode | `false` |
| `AEGIS_MTLS` | Enable mTLS for registry communication | `false` |
| `AEGIS_TRUSTSTORE` | Path to trust store file | `/etc/aegis/truststore.json` |
| `AGENT_HOST_ID` | Host identifier | Auto-generated |
| `AGENT_ID` | Agent identifier | Auto-generated |
| `AEGIS_VERBOSE` | Enable verbose logging | `false` |

### Command Line Flags

```bash
./aegis-agent --dry-run --mtls --truststore=/path/to/truststore.json --verbose
```

## Usage

### 1. Basic Operation

```bash
# Start agent in normal mode
./aegis-agent

# Start agent in dry-run mode
./aegis-agent --dry-run

# Start agent with mTLS enabled
./aegis-agent --mtls --truststore=/etc/aegis/truststore.json
```

### 2. Trust Store Management

```bash
# Initialize trust store with new key
./aegis-agent --init-truststore

# Add trusted key
./aegis-agent --add-key --key-id=backend-1 --public-key=base64-key

# Revoke key
./aegis-agent --revoke-key --key-id=backend-1
```

### 3. Rollback Operations

```bash
# List available snapshots
./aegis-agent --list-snapshots

# Rollback to specific snapshot
./aegis-agent --rollback --snapshot-id=rollback-123

# Rollback assignment
./aegis-agent --rollback-assignment --assignment-id=assign-456
```

## Safety Mechanisms

### 1. Pre-Application Validation
- Assignment structure validation
- TTL expiry checks
- Host selector matching
- Bundle signature verification

### 2. Dry-Run Verification
- Simulate policy application
- Identify potential issues
- Validate changes before application
- Generate change reports

### 3. Automatic Rollback
- Create snapshots before changes
- Monitor application success
- Automatic rollback on failure
- Manual rollback capabilities

### 4. TTL Enforcement
- Check assignment expiry
- Background monitoring
- Automatic cleanup
- Warning notifications

## Telemetry Events

### Event Types

| Event Type | Description |
|------------|-------------|
| `verify_ok` | Successful bundle verification |
| `verify_failed` | Failed bundle verification |
| `enforce_ok` | Successful policy enforcement |
| `enforce_failed` | Failed policy enforcement |
| `rollback_ok` | Successful rollback |
| `rollback_failed` | Failed rollback |
| `counter` | Counter/metric event |
| `assignment` | Assignment-related event |
| `error` | Error event |
| `warning` | Warning event |

### Event Structure

```json
{
  "id": "event-123",
  "type": "verify_ok",
  "timestamp": "2025-01-01T00:00:00Z",
  "host_id": "host-123",
  "agent_id": "agent-456",
  "message": "Bundle verification successful",
  "data": {
    "bundle_id": "bundle-789",
    "key_id": "backend-1",
    "algorithm": "Ed25519",
    "duration_ms": 150
  }
}
```

## Operations Runbook

### 1. Initial Setup

1. Generate mTLS certificates
2. Initialize trust store
3. Configure systemd service
4. Start agent in dry-run mode
5. Verify telemetry events
6. Switch to normal mode

### 2. Policy Deployment

1. Verify policy bundle signature
2. Test in dry-run mode
3. Create rollback snapshot
4. Apply policy
5. Monitor enforcement events
6. Verify success

### 3. Incident Response

1. Check telemetry events
2. Identify failed operations
3. Review rollback options
4. Execute rollback if needed
5. Investigate root cause
6. Deploy fix

### 4. Maintenance

1. Rotate signing keys
2. Update trust store
3. Clean up old snapshots
4. Monitor TTL expiry
5. Review telemetry metrics

## Security Considerations

### 1. Key Management
- Use strong key sizes (Ed25519 recommended)
- Rotate keys regularly
- Secure key storage
- Monitor key usage

### 2. Certificate Management
- Use proper certificate validation
- Monitor certificate expiry
- Implement certificate pinning
- Secure certificate storage

### 3. Access Control
- Limit agent privileges
- Use principle of least privilege
- Monitor access patterns
- Implement audit logging

### 4. Network Security
- Use mTLS for all communications
- Validate all incoming data
- Implement rate limiting
- Monitor network traffic

## Troubleshooting

### Common Issues

1. **Verification Failures**
   - Check trust store configuration
   - Verify key rotation
   - Validate bundle signatures

2. **Rollback Issues**
   - Check snapshot availability
   - Verify rollback permissions
   - Monitor rollback events

3. **TTL Problems**
   - Check system clock
   - Verify TTL configuration
   - Monitor expiry events

4. **Telemetry Issues**
   - Check event channel capacity
   - Verify telemetry configuration
   - Monitor event processing

### Debug Commands

```bash
# Enable verbose logging
AEGIS_VERBOSE=true ./aegis-agent

# Check trust store
./aegis-agent --verify-truststore

# List snapshots
./aegis-agent --list-snapshots

# Test dry-run
./aegis-agent --dry-run --test-policy=/path/to/policy.json
```

## Monitoring

### Key Metrics

- Verification success rate
- Enforcement success rate
- Rollback frequency
- TTL expiry rate
- Event processing latency

### Alerts

- Verification failures
- Enforcement failures
- Rollback operations
- TTL expiry warnings
- Telemetry errors

### Dashboards

- Policy enforcement status
- Rollback operations
- TTL monitoring
- Telemetry events
- Error rates

