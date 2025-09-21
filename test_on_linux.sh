#!/bin/bash

# Test Aegis Agent on Linux Host
# Usage: ./test_on_linux.sh [user@host]

set -e

USER_HOST=${1:-"user@linux-host"}
REMOTE_PATH="/opt/aegis"

echo "🧪 Testing Aegis Agent on Linux Host: $USER_HOST"

# Function to run remote command and show output
run_remote() {
    echo "🔍 Running: $1"
    ssh $USER_HOST "$1"
    echo ""
}

# Test 1: Check if binary exists and is executable
echo "📋 Test 1: Binary Check"
run_remote "ls -la $REMOTE_PATH/bin/aegis"

# Test 2: Check help output
echo "📋 Test 2: Help Output"
run_remote "sudo $REMOTE_PATH/bin/aegis --help"

# Test 3: Check system capabilities
echo "📋 Test 3: System Capabilities"
run_remote "uname -a"
run_remote "cat /proc/version"
run_remote "ls -la /sys/kernel/btf/vmlinux"
run_remote "which clang || echo 'clang not found'"
run_remote "which bpftool || echo 'bpftool not found'"

# Test 4: Check required capabilities
echo "📋 Test 4: Check Capabilities"
run_remote "sudo capsh --print | grep -E 'Current|Bounding'"

# Test 5: Test dry-run mode
echo "📋 Test 5: Dry-Run Test (10 seconds)"
ssh $USER_HOST "cd $REMOTE_PATH && sudo timeout 10s bin/aegis --verbose --dry-run --register=false || true"

# Test 6: Check eBPF filesystem
echo "📋 Test 6: eBPF Filesystem"
run_remote "ls -la /sys/fs/bpf/ || echo 'eBPF filesystem not available'"

# Test 7: Test policy loading
echo "📋 Test 7: Policy Test"
cat > /tmp/test_policy.json << EOF
{
  "id": "test-policy",
  "name": "Test Network Policy",
  "description": "Test policy for validation",
  "type": "network",
  "priority": 100,
  "enabled": true,
  "rules": [
    {
      "id": "test-rule",
      "action": "deny",
      "priority": 1,
      "conditions": [
        {"field": "dest_ip", "operator": "eq", "value": "1.1.1.1"},
        {"field": "protocol", "operator": "eq", "value": "tcp"}
      ],
      "metadata": {"description": "Block Cloudflare DNS for testing"}
    }
  ],
  "metadata": {"test": true}
}
EOF

scp /tmp/test_policy.json $USER_HOST:/tmp/
echo "🧪 Testing policy loading (5 seconds)..."
ssh $USER_HOST "cd $REMOTE_PATH && sudo timeout 5s bin/aegis --verbose --dry-run --register=false --policy=/tmp/test_policy.json || true"

# Test 8: Check if systemd service is properly configured
echo "📋 Test 8: Systemd Service Check"
run_remote "sudo systemctl status aegis || echo 'Service not active'"
run_remote "sudo systemctl is-enabled aegis || echo 'Service not enabled'"

# Test 9: Test HTTP endpoints (if service is running)
echo "📋 Test 9: HTTP Endpoints Test"
run_remote "curl -s http://localhost:7070/healthz || echo 'Agent not running on port 7070'"
run_remote "curl -s http://localhost:7070/info | jq . || echo 'Info endpoint not available'"

echo "✅ Testing complete!"
echo ""
echo "💡 To start the agent service:"
echo "   ssh $USER_HOST 'sudo systemctl start aegis'"
echo ""
echo "📊 To monitor the agent:"
echo "   ssh $USER_HOST 'sudo journalctl -u aegis -f'"
