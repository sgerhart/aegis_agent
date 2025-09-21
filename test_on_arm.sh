#!/bin/bash

# Test Aegis Agent on Linux ARM64 Host
# Usage: ./test_on_arm.sh [user@host]

set -e

USER_HOST=${1:-"user@arm-host"}
REMOTE_PATH="/opt/aegis"

echo "🧪 Testing Aegis Agent on Linux ARM64 Host: $USER_HOST"

# Function to run remote command and show output
run_remote() {
    echo "🔍 Running: $1"
    ssh $USER_HOST "$1"
    echo ""
}

# Test 1: ARM64 System Information
echo "📋 Test 1: ARM64 System Check"
run_remote "echo '=== ARM64 System Information ==='"
run_remote "uname -a"
run_remote "cat /proc/cpuinfo | grep -E 'processor|model name|Architecture|CPU|Features' | head -10"
run_remote "free -h"
run_remote "df -h /"

# Test 2: Check if binary exists and is ARM64
echo "📋 Test 2: Binary Architecture Check"
run_remote "ls -la $REMOTE_PATH/bin/aegis"
run_remote "file $REMOTE_PATH/bin/aegis"
run_remote "ldd $REMOTE_PATH/bin/aegis | head -5 || echo 'Static binary'"

# Test 3: Check help output  
echo "📋 Test 3: Help Output"
run_remote "sudo $REMOTE_PATH/bin/aegis --help"

# Test 4: ARM64-specific capabilities
echo "📋 Test 4: ARM64 eBPF Capabilities"
run_remote "uname -r"
run_remote "cat /proc/version"
run_remote "ls -la /sys/kernel/btf/vmlinux || echo 'BTF not available'"
run_remote "mount | grep bpf || echo 'BPF filesystem not mounted'"
run_remote "ls -la /sys/fs/bpf/ || echo 'eBPF filesystem not available'"

# Test 5: Check required tools for ARM64
echo "📋 Test 5: Required Tools Check"
run_remote "which clang && clang --version | head -2 || echo 'clang not found'"
run_remote "which bpftool && bpftool version || echo 'bpftool not found'"
run_remote "which jq && jq --version || echo 'jq not found'"

# Test 6: Check ARM64 capabilities
echo "📋 Test 6: ARM64 Capabilities"
run_remote "sudo capsh --print | grep -E 'Current|Bounding'"
run_remote "cat /proc/sys/kernel/unprivileged_bpf_disabled || echo 'BPF setting not found'"

# Test 7: Memory and performance test
echo "📋 Test 7: ARM64 Performance Check"
run_remote "lscpu | grep -E 'Architecture|CPU|Thread|Core|MHz'"
run_remote "cat /proc/meminfo | grep -E 'MemTotal|MemFree|MemAvailable'"

# Test 8: Test dry-run mode on ARM64
echo "📋 Test 8: ARM64 Dry-Run Test (10 seconds)"
ssh $USER_HOST "cd $REMOTE_PATH && sudo timeout 10s bin/aegis --verbose --dry-run --register=false || echo 'Test completed'"

# Test 9: Test with enhanced policy
echo "📋 Test 9: ARM64 Policy Test"
cat > /tmp/arm_test_policy.json << EOF
{
  "id": "arm64-test-policy",
  "name": "ARM64 Network Policy",
  "description": "Test policy optimized for ARM64 architecture",
  "type": "network",
  "priority": 100,
  "enabled": true,
  "rules": [
    {
      "id": "arm64-test-rule",
      "action": "deny",
      "priority": 1,
      "conditions": [
        {"field": "dest_ip", "operator": "eq", "value": "1.1.1.1"},
        {"field": "protocol", "operator": "eq", "value": "tcp"}
      ],
      "metadata": {
        "description": "ARM64 test rule for Cloudflare DNS",
        "architecture": "arm64"
      }
    }
  ],
  "metadata": {
    "test": true,
    "architecture": "arm64",
    "optimized_for": "low_power"
  }
}
EOF

scp /tmp/arm_test_policy.json $USER_HOST:/tmp/
echo "🧪 Testing ARM64 policy loading (5 seconds)..."
ssh $USER_HOST "cd $REMOTE_PATH && sudo timeout 5s bin/aegis --verbose --dry-run --register=false --policy=/tmp/arm_test_policy.json || echo 'Policy test completed'"

# Test 10: ARM64 startup script test
echo "📋 Test 10: ARM64 Startup Script Test"
run_remote "sudo $REMOTE_PATH/bin/start-aegis --help || echo 'Startup script test'"

# Test 11: Check systemd service configuration
echo "📋 Test 11: Systemd Service Check"
run_remote "sudo systemctl status aegis || echo 'Service not active'"
run_remote "sudo systemctl is-enabled aegis || echo 'Service not enabled'"
run_remote "cat /etc/systemd/system/aegis.service | grep -E 'ExecStart|Environment'"

# Test 12: Network connectivity test
echo "📋 Test 12: Network Connectivity"
run_remote "ping -c 2 8.8.8.8 || echo 'External connectivity test'"
run_remote "ss -tlnp | grep :7070 || echo 'Agent port not open'"

# Test 13: ARM64 HTTP endpoints test (if service is running)
echo "📋 Test 13: HTTP Endpoints Test"
run_remote "curl -s http://localhost:7070/healthz || echo 'Agent not running on port 7070'"
run_remote "curl -s http://localhost:7070/info | jq .platform || echo 'Info endpoint not available'"

# Test 14: ARM64 specific metrics
echo "📋 Test 14: ARM64 Metrics"
run_remote "cat /proc/loadavg"
run_remote "uptime"
run_remote "cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | head -3 || echo 'Temperature sensors not available'"

echo "✅ ARM64 testing complete!"
echo ""
echo "📊 ARM64 Summary:"
ssh $USER_HOST "
echo 'Architecture:' \$(uname -m)
echo 'Kernel:' \$(uname -r)  
echo 'CPU Cores:' \$(nproc)
echo 'Memory:' \$(free -h | grep '^Mem:' | awk '{print \$2}')
echo 'Agent Binary:' \$(file $REMOTE_PATH/bin/aegis | cut -d':' -f2)
"
echo ""
echo "💡 To start the ARM64 agent service:"
echo "   ssh $USER_HOST 'sudo systemctl start aegis'"
echo ""
echo "📊 To monitor the ARM64 agent:"
echo "   ssh $USER_HOST 'sudo journalctl -u aegis -f'"
echo ""
echo "🌐 ARM64 Agent endpoints:"
echo "   - Health: curl http://[arm-host]:7070/healthz"
echo "   - Status: curl http://[arm-host]:7070/status"
echo "   - Policies: curl http://[arm-host]:7070/policies"
