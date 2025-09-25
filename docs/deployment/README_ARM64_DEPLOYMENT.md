# Aegis Agent - ARM64 Linux Deployment Guide

## Overview

This guide covers deploying the Aegis Agent on ARM64 Linux systems with **dynamic module control capabilities**, including Raspberry Pi, AWS Graviton, and other ARM-based servers. The agent now supports **real-time module management** from the backend without requiring restarts.

## Supported ARM64 Linux Distributions

### ✅ Tested Distributions
- **Ubuntu 20.04+ ARM64** (Recommended)
- **Debian 11+ ARM64** 
- **CentOS Stream 9 ARM64**
- **Rocky Linux 9 ARM64**
- **Amazon Linux 2 ARM64** (Graviton instances)

### 🔧 Requirements

#### Hardware Requirements
- **Architecture**: ARM64/AArch64 (64-bit ARM)
- **Memory**: Minimum 1GB RAM, Recommended 2GB+
- **Storage**: 500MB free space for agent and eBPF programs
- **Network**: Internet connectivity for backend registration

#### Software Requirements
- **Kernel**: Linux 4.18+ with eBPF support
- **BTF**: Kernel BTF (BPF Type Format) support
- **Capabilities**: CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_BPF
- **Tools**: clang, llvm, bpftool, jq

## Quick Start

### 1. Deploy to ARM64 Host

```bash
# Auto-detect architecture and deploy
./deploy_to_arm.sh user@your-arm-host

# Deploy to specific path
./deploy_to_arm.sh user@your-arm-host /opt/aegis
```

### 2. Test the Deployment

```bash
# Comprehensive ARM64 testing
./test_on_arm.sh user@your-arm-host
```

### 3. Start the Agent

```bash
# On the ARM64 host
sudo systemctl enable --now aegis

# Check status
sudo systemctl status aegis

# View logs
sudo journalctl -u aegis -f
```

### 4. Test Module Control

```bash
# Test module control via WebSocket
python3 test_module_control.py

# Or manually test with curl (if HTTP API available)
curl -X POST http://localhost:7070/modules/list
curl -X POST http://localhost:7070/modules/start -d '{"module_id": "analysis"}'
```

## Manual Deployment Steps

### 1. Copy ARM64 Binary

```bash
# Copy the ARM64 binary
scp agents/aegis/aegis-linux-arm64 user@arm-host:/tmp/aegis
ssh user@arm-host "sudo mv /tmp/aegis /opt/aegis/bin/aegis && sudo chmod +x /opt/aegis/bin/aegis"
```

### 2. Install Dependencies

#### Ubuntu/Debian ARM64
```bash
sudo apt-get update
sudo apt-get install -y clang llvm bpftool jq curl
```

#### CentOS/Rocky ARM64  
```bash
sudo dnf install -y clang llvm bpftool jq curl
```

### 3. Configure Environment

```bash
# Create configuration file
sudo tee /opt/aegis/config/aegis.env << EOF
AGENT_HOST_ID=$(hostname)-arm64
AEGIS_EBPF=true
AEGIS_SEGMENTATION=true
CLANG_PATH=/usr/bin/clang
BPFTOOL_PATH=/usr/sbin/bpftool
EOF
```

## ARM64-Specific Configuration

### Performance Tuning

```bash
# ARM64 optimized environment variables
export GOMAXPROCS=0                    # Use all available cores
export GOGC=100                        # Standard GC pressure  
export GOMEMLIMIT=256MiB               # Memory limit for smaller ARM systems
```

### Power Management

```bash
# For battery-powered ARM64 devices
export AEGIS_POWER_MODE=efficient      # Enable power-efficient mode
export AEGIS_CPU_LIMIT=50              # Limit CPU usage to 50%
export AEGIS_POLL_INTERVAL=60s         # Reduce polling frequency
```

## Testing on ARM64

### System Verification

```bash
# Check ARM64 architecture
uname -m                               # Should show aarch64

# Verify eBPF support
ls -la /sys/kernel/btf/vmlinux        # BTF should exist
mount | grep bpf                       # BPF filesystem mounted

# Check available tools
clang --version
bpftool version
```

### Agent Testing

```bash
# Test basic functionality
sudo /opt/aegis/bin/aegis --help

# Test dry-run mode
sudo /opt/aegis/bin/aegis --dry-run --verbose --register=false

# Test with ARM64-optimized policy
sudo /opt/aegis/bin/aegis --policy=/opt/aegis/policies/arm64_optimized.json --dry-run
```

### HTTP API Testing

```bash
# Test health endpoint
curl http://localhost:7070/healthz

# Check agent info (should show arm64)
curl http://localhost:7070/info | jq .platform

# View policy statistics
curl http://localhost:7070/policies/stats
```

## ARM64-Specific Features

### Optimized Policies

The agent includes ARM64-optimized policies:

- **Power Efficiency**: Reduced CPU overhead for battery-powered devices
- **Memory Optimization**: Lower memory footprint for resource-constrained systems  
- **Low Latency**: Optimized rule evaluation for real-time applications

### Dynamic Module Control

The agent supports **real-time module management** from the backend:

- **Available Modules**: 6 modules shipped with agent (telemetry, websocket_communication, observability, analysis, threat_intelligence, advanced_policy)
- **Backend Control**: Start/stop modules without agent restart
- **Resource Management**: Enable modules only when needed
- **Zero Downtime**: Module changes don't interrupt agent operation

#### Module Control Commands
```bash
# List all available modules
{"type": "list_modules"}

# Start a specific module
{"type": "start_module", "module_id": "analysis"}

# Stop a specific module  
{"type": "stop_module", "module_id": "threat_intelligence"}

# Get module status
{"type": "get_module_status", "module_id": "observability"}
```

### Architecture Detection

The agent automatically detects ARM64 architecture and enables optimizations:

```json
{
  "platform": "linux/arm64",
  "optimizations": {
    "power_efficient": true,
    "low_latency": true,
    "memory_optimized": true
  }
}
```

## Common ARM64 Issues and Solutions

### Issue: BTF Not Available

```bash
# Check if BTF is built into kernel
zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF
# Should show CONFIG_DEBUG_INFO_BTF=y

# Alternative: Install BTF separately (Ubuntu)
sudo apt-get install linux-tools-$(uname -r)
```

### Issue: bpftool Missing

```bash
# Ubuntu/Debian
sudo apt-get install bpftool

# CentOS/Rocky (may need EPEL)
sudo dnf install epel-release
sudo dnf install bpftool
```

### Issue: Permission Denied

```bash
# Ensure proper capabilities
sudo setcap cap_sys_admin,cap_net_admin,cap_bpf+ep /opt/aegis/bin/aegis

# Or run with systemd (recommended)
sudo systemctl start aegis
```

## Performance Monitoring

### ARM64 Metrics

```bash
# Monitor CPU usage (should be < 5%)
top -p $(pgrep aegis)

# Monitor memory usage
cat /proc/$(pgrep aegis)/status | grep -E 'VmRSS|VmSize'

# Monitor network connections
ss -tlnp | grep aegis
```

### Power Consumption (for battery-powered devices)

```bash
# Monitor CPU frequency scaling
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq

# Check thermal status
cat /sys/class/thermal/thermal_zone*/temp
```

## ARM64 Deployment Examples

### Raspberry Pi 4

```bash
# Raspberry Pi OS (64-bit)
./deploy_to_arm.sh pi@raspberrypi.local

# Test deployment
./test_on_arm.sh pi@raspberrypi.local
```

### AWS Graviton Instances

```bash
# Amazon Linux 2 ARM64
./deploy_to_arm.sh ec2-user@graviton-instance

# Ubuntu on Graviton
./deploy_to_arm.sh ubuntu@graviton-instance
```

### NVIDIA Jetson

```bash
# Jetson with JetPack
./deploy_to_arm.sh nvidia@jetson-device
```

## Security Considerations

### ARM64 Security Features

- **Pointer Authentication**: Enhanced security on newer ARM64 processors
- **Memory Tagging**: Hardware-assisted memory safety (if available)
- **Secure Boot**: Verify integrity on ARM64 systems with secure boot

### Hardening for ARM64

```bash
# Enable additional security features
echo 'kernel.yama.ptrace_scope = 1' | sudo tee -a /etc/sysctl.conf
echo 'kernel.kptr_restrict = 2' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Troubleshooting

### Debug Mode

```bash
# Enable verbose logging
sudo /opt/aegis/bin/aegis --verbose --dry-run

# Check systemd logs
sudo journalctl -u aegis -f --no-pager
```

### Performance Issues

```bash
# Check if ARM64 binary is being used
file /opt/aegis/bin/aegis
# Should show: ELF 64-bit LSB executable, ARM aarch64

# Monitor system resources
htop
iotop
```

## Support

For ARM64-specific issues:

1. Check architecture: `uname -m` should show `aarch64`
2. Verify eBPF support: `zcat /proc/config.gz | grep BPF`
3. Test with dry-run mode first
4. Monitor system resources during operation
5. Check kernel version compatibility

## ARM64 Binary Information

| Architecture | Binary Size | Go Runtime | Performance |
|--------------|-------------|------------|-------------|
| ARM64        | ~10MB       | Go 1.21+   | Optimized   |
| AMD64        | ~11MB       | Go 1.21+   | Standard    |

The ARM64 binary is optimized for:
- Lower power consumption
- Reduced memory footprint  
- Efficient instruction scheduling
- ARM-specific optimizations
