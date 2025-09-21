# Real Policy Application Implementation

## Overview

This document explains how to implement real eBPF policy application without dry-run mode, integrating with the existing eBPF loaders and policy writers.

## Architecture

The real policy application follows this pipeline:

```
Policy Bundle → Verification → Snapshot → Parse → Apply eBPF Programs → Update Maps → Attach Programs → Monitor
```

## Key Components

### 1. Policy Applier (`internal/ebpf/policy_applier.go`)

The `PolicyApplier` handles the actual application of policies to the system:

- **Parse Policy Content**: Decodes and validates policy JSON from bundles
- **Apply eBPF Programs**: Loads and attaches eBPF programs to kernel hooks
- **Update Policy Maps**: Writes policy rules to eBPF maps
- **Attach to Interfaces**: Attaches programs to network interfaces and cgroups

### 2. Enhanced Loader (`internal/ebpf/loader.go`)

The main loader now integrates real policy application:

- **Dry-Run Mode**: Uses `DryRunManager` for safe testing
- **Real Mode**: Uses `PolicyApplier` for actual enforcement
- **Rollback**: Automatic rollback on failures
- **Telemetry**: Comprehensive event tracking

### 3. Policy Data Structures

```go
type PolicyData struct {
    EgressPolicies  []EgressPolicy  `json:"egress_policies"`
    IngressPolicies []IngressPolicy `json:"ingress_policies"`
    PolicyEdges     []PolicyEdge    `json:"policy_edges"`
    AllowCIDRs      []AllowCIDR     `json:"allow_cidrs"`
    Metadata        map[string]any  `json:"metadata"`
}
```

## Implementation Steps

### Step 1: Create Policy Applier

```go
// Initialize policy applier
policyApplier := NewPolicyApplier(eventEmitter)

// Set loaders (inject from main agent)
policyApplier.SetLoaders(egressLoader, ingressLoader, policyWriter)

// Apply policy
result, err := policyApplier.ApplyPolicy(ctx, assignment)
```

### Step 2: Integrate with Existing Loaders

The policy applier integrates with existing components:

- **SegEgressLoader**: For egress policy enforcement
- **SegIngressLoader**: For ingress policy enforcement  
- **PolicyWriter**: For updating eBPF maps

### Step 3: Real Policy Application

```go
// Parse policy content from bundle
policyData, err := parsePolicyContent(assignment.Bundle.Content)

// Apply eBPF programs
err = applyEBPFPrograms(ctx, policyData)

// Apply policy rules to maps
err = applyPolicyRules(ctx, policyData)

// Attach programs to interfaces
err = attachPrograms(ctx, policyData)
```

## Policy Types

### 1. Egress Policies

Control outbound traffic based on process UID/GID:

```json
{
  "id": 1,
  "process_uid": 1000,
  "process_gid": 1000,
  "allowed_ports": [80, 443, 8080],
  "blocked_ports": [22, 23, 252],
  "action": 1,
  "priority": 100
}
```

### 2. Ingress Policies

Control inbound traffic based on source IP and destination port:

```json
{
  "id": 1,
  "src_ip": 192168168,
  "src_mask": 255255255,
  "dst_port": 80,
  "protocol": 17,
  "action": 1,
  "priority": 100
}
```

### 3. Policy Edges

Define specific network flows:

```json
{
  "id": 1,
  "src_ip": 192168168,
  "dst_ip": 192168169,
  "src_port": 80,
  "dst_port": 80,
  "protocol": 17,
  "action": 1,
  "priority": 100
}
```

### 4. Allow CIDRs

Define allowed network ranges:

```json
{
  "prefix_len": 24,
  "ip": 192168168,
  "action": 1,
  "priority": 100
}
```

## Usage Examples

### Example 1: Basic Policy Application

```bash
# Build the real policy application binary
go build -o aegis-agent-real ./cmd/aegis/main_real_policy.go

# Apply a policy
./aegis-agent-real -policy=examples/example_policy.json -verbose
```

### Example 2: Programmatic Usage

```go
// Initialize components
verifier := crypto.NewVerifier("/etc/aegis/truststore.json")
eventEmitter := telemetry.NewEventEmitter(hostID, agentID)
loader := ebpf.NewLoader(verifier, eventEmitter, false) // dryRun = false

// Load assignment
assignment := &models.Assignment{
    ID: "assignment-001",
    PolicyID: "network-segmentation",
    Bundle: models.Bundle{
        Content: policyJSONBytes,
        // ... other fields
    },
}

// Apply policy (real enforcement)
ctx := context.Background()
result := loader.LoadAssignment(ctx, assignment)

if result.Success {
    log.Printf("Policy applied: %v", result.Changes)
} else {
    log.Printf("Policy failed: %v", result.Errors)
}
```

## Integration with Existing Code

### 1. SegEgressLoader Integration

```go
func (pa *PolicyApplier) applyEgressPolicies(ctx context.Context, policies []EgressPolicy) error {
    // Get the egress loader from the main agent
    egressLoader := pa.egressLoader.(*loader.SegEgressLoader)
    
    for _, policy := range policies {
        // Update egress policies map
        err := egressLoader.UpdatePolicy(ctx, policy.ID, policy)
        if err != nil {
            return err
        }
        
        // Update allowed ports
        for _, port := range policy.AllowedPorts {
            err := egressLoader.UpdateAllowedPort(ctx, port, true)
            if err != nil {
                return err
            }
        }
    }
    
    return nil
}
```

### 2. SegIngressLoader Integration

```go
func (pa *PolicyApplier) applyIngressPolicies(ctx context.Context, policies []IngressPolicy) error {
    // Get the ingress loader from the main agent
    ingressLoader := pa.ingressLoader.(*loader.SegIngressLoader)
    
    for _, policy := range policies {
        // Update ingress policies map
        err := ingressLoader.UpdatePolicy(ctx, policy.ID, policy)
        if err != nil {
            return err
        }
    }
    
    return nil
}
```

### 3. PolicyWriter Integration

```go
func (pa *PolicyApplier) applyPolicyEdges(ctx context.Context, edges []PolicyEdge) error {
    // Get the policy writer from the main agent
    policyWriter := pa.policyWriter.(*policy.Writer)
    
    // Convert to policy writer format
    policyEdges := make([]policy.PolicyEdge, len(edges))
    for i, edge := range edges {
        policyEdges[i] = policy.PolicyEdge{
            ID:         edge.ID,
            SrcIP:      edge.SrcIP,
            DstIP:      edge.DstIP,
            SrcMask:    edge.SrcMask,
            DstMask:    edge.DstMask,
            SrcPort:    edge.SrcPort,
            DstPort:    edge.DstPort,
            Protocol:   edge.Protocol,
            Action:     edge.Action,
            Priority:   edge.Priority,
            ProcessUID: edge.ProcessUID,
            ProcessGID: edge.ProcessGID,
            Timestamp:  edge.Timestamp,
        }
    }
    
    return policyWriter.WriteEdges(ctx, policyEdges)
}
```

## Safety Features

### 1. Verification Before Application

```go
// Verify bundle signature
verification, err := verifier.VerifyBundle(&assignment.Bundle)
if !verification.Valid {
    return fmt.Errorf("bundle verification failed: %s", verification.Error)
}
```

### 2. Snapshot Before Changes

```go
// Create snapshot for rollback
snapshot := rollbackMgr.CreateSnapshot(assignment.ID, map[string]any{
    "assignment_id": assignment.ID,
    "policy_id":     assignment.PolicyID,
    "created_at":    time.Now(),
})
```

### 3. Rollback on Failure

```go
if !result.Success {
    // Attempt rollback
    rollbackResult := rollbackMgr.RollbackToSnapshot(snapshot.ID)
    if rollbackResult.Success {
        log.Printf("Rollback successful")
    } else {
        log.Printf("Rollback failed: %v", rollbackResult.Errors)
    }
}
```

### 4. Comprehensive Telemetry

```go
// Emit events for all operations
eventEmitter.EmitVerifyOK(bundleID, keyID, algorithm, duration)
eventEmitter.EmitEnforceOK(assignmentID, policyID, false, changes, duration)
eventEmitter.EmitRollbackOK(rollbackID, assignmentID, reason, changes, duration)
```

## Testing Real Policy Application

### 1. Create Test Policy

```json
{
  "id": "test-assignment-001",
  "policy_id": "test-policy",
  "bundle": {
    "content": "base64-encoded-policy-json"
  }
}
```

### 2. Run with Real Application

```bash
# Build and run
go build -o aegis-agent-real ./cmd/aegis/main_real_policy.go
./aegis-agent-real -policy=test_policy.json -verbose
```

### 3. Verify Policy is Applied

```bash
# Check eBPF programs
bpftool prog list

# Check eBPF maps
bpftool map list

# Check policy enforcement
# (traffic should be filtered according to policy)
```

## Production Deployment

### 1. Systemd Service

```ini
[Unit]
Description=Aegis Agent - Real Policy Enforcement
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/aegis-agent/aegis-agent-real -policy=/etc/aegis/policy.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### 2. Configuration

```bash
# Set environment variables
export AEGIS_DRY_RUN=false
export AEGIS_TRUSTSTORE=/etc/aegis/truststore.json
export AGENT_HOST_ID=$(hostname)
```

### 3. Monitoring

```bash
# Check agent status
curl http://localhost:7070/status

# View telemetry events
journalctl -u aegis-agent -f

# Monitor eBPF programs
bpftool prog list | grep aegis
```

## Troubleshooting

### Common Issues

1. **Policy Verification Fails**
   - Check trust store configuration
   - Verify bundle signature
   - Ensure key is not revoked

2. **eBPF Program Loading Fails**
   - Check kernel version and eBPF support
   - Verify program permissions
   - Check resource limits

3. **Map Updates Fail**
   - Verify maps are pinned correctly
   - Check map permissions
   - Ensure maps exist

4. **Program Attachment Fails**
   - Check interface exists
   - Verify TC qdisc is present
   - Check cgroup mount points

### Debug Commands

```bash
# Enable verbose logging
AEGIS_VERBOSE=true ./aegis-agent-real

# Check eBPF programs
bpftool prog list

# Check eBPF maps
bpftool map list

# Check TC qdiscs
tc qdisc show

# Check cgroup mounts
mount | grep cgroup
```

## Next Steps

1. **Integrate with Existing Agent**: Connect policy applier with current loaders
2. **Add More Policy Types**: Extend support for additional policy types
3. **Performance Optimization**: Optimize map updates and program loading
4. **Monitoring Integration**: Add metrics and alerting
5. **Policy Validation**: Add more comprehensive policy validation
6. **Rollback Testing**: Test rollback scenarios thoroughly
7. **Production Hardening**: Add more safety checks and error handling

