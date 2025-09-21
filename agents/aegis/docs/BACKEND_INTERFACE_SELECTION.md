# Backend Interface Selection

This document describes how the Aegis agent automatically detects the interface used for backend connectivity and how the backend can specify target interfaces for policy enforcement.

## Overview

The agent uses a two-tier interface management system:

1. **Auto-Detection**: Agent automatically selects the interface used for backend connectivity
2. **Backend Control**: Backend can specify additional interfaces for policy enforcement

## Auto-Detection Logic

The agent automatically detects the best interface for backend connectivity by:

1. **Testing Connectivity**: Attempts to reach the backend URL from each available interface
2. **Interface Ranking**: Prioritizes interfaces that can successfully reach the backend
3. **Default Selection**: Uses the first interface that can reach the backend as the default

### Interface Detection Process

```go
// The agent tests each interface for backend connectivity
func (id *InterfaceDetector) testBackendConnectivity(ifaceName string) bool {
    // Parse backend URL to get host
    host := id.backendURL
    // Test connectivity using the interface
    conn, err := net.Dial("udp", host+":80")
    // Check if the connection uses the specified interface
    // Return true if interface can reach backend
}
```

## Backend Interface API

The agent exposes HTTP endpoints for the backend to manage interface assignments:

### Endpoints

#### 1. Interface Assignment
**POST** `/interfaces/assign`

Assigns interfaces for policy enforcement.

**Request:**
```json
{
  "interfaces": ["ens160", "ens161", "wlan0"],
  "mode": "block"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Interface assignment processed",
  "attached": ["ens160", "ens161"],
  "failed": ["wlan0 (not available)"],
  "assignment_id": "iface-assign-1758303007"
}
```

#### 2. Interface Status
**GET** `/interfaces/status`

Returns current interface status and availability.

**Response:**
```json
{
  "agent_uid": "agent-123",
  "host_id": "host-456",
  "default_interface": {
    "name": "ens160",
    "index": 2,
    "mac": "00:11:22:33:44:55",
    "addresses": ["192.168.1.100/24"],
    "is_up": true,
    "is_loopback": false,
    "is_backend": true,
    "is_default": true,
    "backend_reachable": true
  },
  "attached": {
    "ens160": {
      "name": "ens160",
      "index": 2,
      "is_backend": true
    }
  },
  "available": [
    {
      "name": "ens160",
      "index": 2,
      "is_up": true,
      "backend_reachable": true
    },
    {
      "name": "ens161", 
      "index": 3,
      "is_up": true,
      "backend_reachable": false
    }
  ],
  "attached_count": 1,
  "available_count": 2
}
```

#### 3. Interface Detachment
**POST** `/interfaces/detach`

Detaches from specified interfaces.

**Request:**
```json
{
  "interfaces": ["ens161", "wlan0"]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Interface detachment processed",
  "detached": ["ens161"],
  "failed": ["wlan0 (not attached)"]
}
```

## Usage Examples

### 1. Agent Startup (Auto-Detection)

```bash
# Agent automatically detects and uses the interface that can reach the backend
./aegis-agent --block --verbose

# Output:
# [main] Default interface for backend connectivity: ens160 (index 2)
# [main] Interface addresses: [192.168.1.100/24]
# [main] Attached to 1 interfaces:
# [main]   - ens160 (backend: true, addresses: [192.168.1.100/24])
```

### 2. Backend Interface Assignment

```bash
# Backend assigns additional interfaces for policy enforcement
curl -X POST http://192.168.1.100:7070/interfaces/assign \
  -H "Content-Type: application/json" \
  -d '{
    "interfaces": ["ens160", "ens161", "wlan0"],
    "mode": "block"
  }'

# Response:
# {
#   "success": true,
#   "message": "Attached to 2 interfaces, 1 failed",
#   "attached": ["ens160", "ens161"],
#   "failed": ["wlan0 (not available)"],
#   "assignment_id": "iface-assign-1758303007"
# }
```

### 3. Check Interface Status

```bash
# Check current interface status
curl http://192.168.1.100:7070/interfaces/status

# Response shows all available interfaces and current attachments
```

### 4. Detach from Interfaces

```bash
# Detach from specific interfaces
curl -X POST http://192.168.1.100:7070/interfaces/detach \
  -H "Content-Type: application/json" \
  -d '{
    "interfaces": ["ens161", "wlan0"]
  }'
```

## Configuration

### Environment Variables

- `ACTIONS_API_URL`: Backend URL for connectivity testing (default: `http://localhost:8083`)
- `AGENT_HTTP_ADDR`: Agent HTTP server address (default: `:7070`)
- `AGENT_UID`: Agent unique identifier

### Command Line Flags

- `--iface`: Override auto-detection and use specific interface
- `--no-tc`: Skip TC program attachment
- `--no-cg`: Skip cgroup program attachment

## Implementation Details

### Interface Detection Algorithm

1. **Get All Interfaces**: Enumerate all network interfaces
2. **Filter Active**: Only consider interfaces that are up and not loopback
3. **Test Connectivity**: For each interface, test if it can reach the backend
4. **Rank by Connectivity**: Sort interfaces by backend reachability
5. **Select Default**: Use the first interface that can reach the backend

### eBPF Program Attachment

The agent attaches eBPF programs to interfaces in this order:

1. **Ensure clsact qdisc**: `tc qdisc add dev <iface> clsact`
2. **Attach TC classifier**: `tc filter add dev <iface> ingress bpf obj bpf/bpf/seg_ingress_tc.o sec classifier direct-action`
3. **Attach cgroup program**: `bpftool cgroup attach /sys/fs/cgroup bpf/bpf/seg_egress_cgroup.o cgroup/connect4`

### Error Handling

- **Interface Not Available**: Logs warning and continues with other interfaces
- **Attachment Failure**: Logs error but doesn't stop agent startup
- **Backend Unreachable**: Falls back to all available interfaces
- **Partial Failures**: Reports which interfaces succeeded/failed

## Security Considerations

- **Interface Validation**: Only allows attachment to valid, available interfaces
- **Backend Authentication**: Interface API should be protected with authentication
- **Network Isolation**: Consider network segmentation for interface management
- **Audit Logging**: All interface changes are logged for audit purposes

## Troubleshooting

### Common Issues

1. **No Interface Can Reach Backend**
   - Check network connectivity
   - Verify backend URL is correct
   - Check firewall rules

2. **eBPF Attachment Fails**
   - Ensure agent has CAP_NET_ADMIN capability
   - Check if eBPF programs are compiled correctly
   - Verify interface exists and is up

3. **Backend API Not Responding**
   - Check if HTTP server is running on correct port
   - Verify agent is listening on the expected address
   - Check for network connectivity issues

### Debug Commands

```bash
# Check interface status
ip addr show

# Check eBPF programs
bpftool prog list

# Check TC filters
tc filter show dev ens160 ingress

# Check agent logs
journalctl -u aegis-agent -f

# Test backend connectivity
curl http://192.168.1.100:7070/interfaces/status
```

