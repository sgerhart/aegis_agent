# Cap7.10 - Real eBPF Enforcement and Host Visibility

This document describes the Cap7.10 implementation which provides real eBPF enforcement (no more simulation) and complete host visibility.

## Overview

Cap7.10 implements:
- **Real eBPF enforcement** - Policies are written to actual eBPF maps and enforced by attached programs
- **Mode switching** - Per-assignment observe (log only) vs block (drop) modes
- **Host visibility** - Process tree, exec events, sockets, and network flows
- **Enhanced telemetry** - Enforcement decisions and visibility frames

## Architecture

### eBPF Maps
- `/sys/fs/bpf/aegis/policy_edges` - Service-graph edges (src → dst tuples)
- `/sys/fs/bpf/aegis/allow_lpm4` - LPM trie for IPv4 CIDR allow/deny
- `/sys/fs/bpf/aegis/mode` - Enforcement mode (0=observe, 1=block)
- `/sys/fs/bpf/aegis/policy_stats_map` - Statistics and counters

### eBPF Programs
- `seg_ingress_tc.bpf.c` - TC ingress program for packet filtering
- `seg_egress_cgroup.bpf.c` - Cgroup egress program for connection control

### Agent Components
- `internal/ebpf/maps.go` - eBPF map management
- `internal/ebpf/attach.go` - Program attachment (TC, cgroup)
- `internal/ebpf/writer.go` - Policy application to maps
- `internal/enforce/mode.go` - Enforcement mode management
- `internal/enforce/decision.go` - Decision logic and telemetry
- `internal/visibility/` - Host visibility collection

## Features

### 1. Real eBPF Enforcement

**No more simulation** - Policies are written to actual eBPF maps in the kernel:

```go
// Write policy edge to eBPF map
err := policyEdgesMap.Put(edgeID, ebpfEdge)

// Write allow CIDR to LPM map
err := allowLPM4Map.Put(cidrKey, cidrValue)
```

**Program attachment** - eBPF programs are attached to network interfaces:

```go
// Attach TC ingress program
link, err := link.AttachTCX(link.TCXOptions{
    Program:   ingressProg,
    Interface: iface.Index,
    Attach:    ebpf.AttachTCXIngress,
})
```

### 2. Mode Switching

**Observe Mode** (mode=0):
- Programs classify packets but return ALLOW
- Emits `enforce_decision(verdict="observe_drop")` for would-be blocks
- Safe for testing and monitoring

**Block Mode** (mode=1):
- Programs return DROP where policy denies
- Actually blocks traffic
- Production enforcement

### 3. Host Visibility

**Process Information**:
- Process tree (parent/child relationships)
- Exec events (binary path, args, uid)
- Start time, state, thread count

**Network Flows**:
- Socket connections (PID ↔ IP:port)
- 5-tuple counters (packets/bytes)
- Ingress/egress direction
- Protocol and state information

**Visibility Frames**:
```json
{
  "host_id": "h-123",
  "ts": "2025-09-19T13:00:01Z",
  "procs": [
    {
      "pid": 123,
      "ppid": 1,
      "exe": "/usr/bin/sshd",
      "uid": 0,
      "args": ["-D"]
    }
  ],
  "flows": [
    {
      "pid": 123,
      "laddr": "10.0.0.10:51234",
      "raddr": "8.8.8.8:53",
      "proto": "udp",
      "dir": "egress",
      "pkts": 4,
      "bytes": 512
    }
  ]
}
```

### 4. Enhanced Telemetry

**Enforcement Events**:
- `verify_ok/failed` - Policy verification
- `apply_ok/failed` - Policy application
- `enforce_decision` - Per-packet decisions
- `rollback_ok/failed` - Rollback operations

**Decision Details**:
```json
{
  "type": "enforce_decision",
  "program": "seg_ingress_cls",
  "map": "policy_edges",
  "five_tuple": {
    "src_ip": "192.168.1.100",
    "dst_ip": "8.8.8.8",
    "src_port": 12345,
    "dst_port": 53,
    "protocol": "udp"
  },
  "verdict": "block",
  "reason": "Policy blocks this connection",
  "mode": "block"
}
```

## Usage

### CLI Flags

```bash
# Basic usage
./aegis-agent-cap7-10 --observe --verbose

# Block mode (actually blocks traffic)
./aegis-agent-cap7-10 --block --verbose

# Dry-run mode (no actual changes)
./aegis-agent-cap7-10 --dry-run --verbose

# Specific interface
./aegis-agent-cap7-10 --observe --iface=eth0 --verbose

# Skip TC or cgroup attachment
./aegis-agent-cap7-10 --observe --no-tc --no-cg --verbose

# Disable visibility collection
./aegis-agent-cap7-10 --observe --visibility=false --verbose
```

### Policy Application

The agent automatically applies a default policy that blocks 8.8.8.8:

```go
// Default policy edge
PolicyEdge{
    SrcIP:    0,           // Any source
    DstIP:    0x08080808,  // 8.8.8.8
    Action:   0,           // BLOCK
    Protocol: 6,           // TCP
}
```

### Mode Management

```go
// Set enforcement mode
modeManager.SetMode(enforce.ModeBlock)

// Check current mode
mode, err := modeManager.GetMode()

// Toggle between modes
modeManager.ToggleMode()
```

## Testing

### Test Script

Run the comprehensive test suite:

```bash
./test_cap7_10.sh
```

This tests:
1. **Observe mode** - Logs decisions but allows traffic
2. **Block mode** - Actually blocks traffic
3. **Visibility collection** - Process and flow monitoring
4. **Dry-run mode** - Simulation without changes
5. **Interface filtering** - Specific interface attachment

### Manual Testing

1. **Test observe mode**:
   ```bash
   ./aegis-agent-cap7-10 --observe --verbose
   ping 8.8.8.8  # Should work but log decisions
   ```

2. **Test block mode**:
   ```bash
   ./aegis-agent-cap7-10 --block --verbose
   ping 8.8.8.8  # Should be blocked
   ```

3. **Test visibility**:
   ```bash
   ./aegis-agent-cap7-10 --observe --visibility --verbose
   # Check logs for visibility frames
   ```

## Implementation Details

### eBPF Map Operations

**Policy Edges**:
```go
type PolicyEdge struct {
    SrcIP      uint32
    DstIP      uint32
    SrcMask    uint32
    DstMask    uint32
    SrcPort    uint16
    DstPort    uint16
    Protocol   uint8
    Action     uint8  // 0=BLOCK, 1=ALLOW, 2=LOG
    Priority   uint8
    ProcessUID uint32
    ProcessGID uint32
    Timestamp  uint64
}
```

**Allow CIDRs**:
```go
type AllowCIDR struct {
    IP        uint32
    PrefixLen uint32
    Action    uint8  // 0=BLOCK, 1=ALLOW
    Priority  uint8
    Timestamp uint64
}
```

### Program Attachment

**TC Ingress**:
```go
// Ensure clsact qdisc exists
netlink.QdiscAdd(&netlink.GenericQdisc{
    QdiscAttrs: netlink.QdiscAttrs{
        LinkIndex: iface.Index,
        Handle:    netlink.MakeHandle(0xffff, 0),
        Parent:    netlink.HANDLE_CLSACT,
    },
    QdiscType: "clsact",
})

// Attach program
link, err := link.AttachTCX(link.TCXOptions{
    Program:   ingressProg,
    Interface: iface.Index,
    Attach:    ebpf.AttachTCXIngress,
})
```

**Cgroup Egress**:
```bash
bpftool cgroup attach /sys/fs/cgroup sock_create pinned /sys/fs/bpf/aegis/seg_connect4
```

### Decision Logic

**Mode-based decisions**:
```go
switch policyAction {
case 0: // BLOCK
    if modeManager.IsObserveMode() {
        verdict = VerdictObserve
        reason = "Policy would block, but in observe mode"
    } else {
        verdict = VerdictBlock
        reason = "Policy blocks this connection"
    }
case 1: // ALLOW
    verdict = VerdictAllow
    reason = "Policy allows this connection"
}
```

## Security Considerations

1. **Mode Safety** - Default to observe mode to prevent accidental blocking
2. **Atomic Updates** - Use shadow maps and swap to avoid race conditions
3. **Rollback Support** - Automatic rollback on policy application failures
4. **Telemetry** - Comprehensive logging of all enforcement decisions
5. **Validation** - Policy validation before application

## Performance

- **eBPF Efficiency** - Kernel-space packet processing
- **Map Performance** - LPM trie for efficient CIDR matching
- **Minimal Overhead** - Only processes packets matching policy rules
- **Batched Updates** - Efficient policy application

## Troubleshooting

### Common Issues

1. **Map not found** - Ensure eBPF maps are pinned and accessible
2. **Program attachment failed** - Check interface exists and has clsact qdisc
3. **Permission denied** - Run with appropriate privileges
4. **No enforcement** - Verify mode is set to block, not observe

### Debug Commands

```bash
# Check eBPF maps
ls -la /sys/fs/bpf/aegis/

# Check attached programs
bpftool prog list

# Check TC qdiscs
tc qdisc show

# Check cgroup attachments
bpftool cgroup tree
```

## Future Enhancements

1. **NATS Integration** - Real-time telemetry publishing
2. **Backend Integration** - Policy management via API
3. **Advanced Policies** - More complex policy rules
4. **Performance Monitoring** - Detailed performance metrics
5. **Policy Templates** - Predefined policy templates

## Conclusion

Cap7.10 provides a complete eBPF enforcement solution with:
- ✅ **Real enforcement** - No more simulation
- ✅ **Mode switching** - Safe observe/block modes
- ✅ **Host visibility** - Complete process and network monitoring
- ✅ **Enhanced telemetry** - Detailed enforcement decisions
- ✅ **Production ready** - Robust error handling and rollback

This implementation bridges the gap between policy simulation and real enforcement, providing a solid foundation for production eBPF-based network security.

