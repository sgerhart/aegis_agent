#!/bin/bash

# Deploy Aegis Agent and Backend to Linux Host
# Usage: ./deploy_to_linux.sh [host_ip] [username]

set -e

# Configuration
REMOTE_HOST=${1:-192.168.193.129}
REMOTE_USER=${2:-steve}
SSH_KEY=~/.ssh/aegis_agent_key

echo "🚀 Deploying Aegis Agent to Linux Host"
echo "======================================"
echo "Host: $REMOTE_HOST"
echo "User: $REMOTE_USER"
echo "SSH Key: $SSH_KEY"

# Check if binaries exist
if [ ! -f "agents/aegis/aegis-linux-arm64" ]; then
    echo "❌ Error: agents/aegis/aegis-linux-arm64 not found"
    echo "Please run: cd agents/aegis && GOOS=linux GOARCH=arm64 go build -o aegis-linux-arm64 cmd/aegis/main_ubuntu_simple_integrated.go"
    exit 1
fi

if [ ! -f "backend/actions-api/actions-api-linux" ]; then
    echo "❌ Error: backend/actions-api/actions-api-linux not found"
    echo "Please run: cd backend/actions-api && GOOS=linux GOARCH=arm64 go build -o actions-api-linux cmd/server/main.go"
    exit 1
fi

echo -e "\n1️⃣ Stopping existing agent service:"
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "echo 'C!sco#123' | sudo -S systemctl stop aegis || true"

echo -e "\n2️⃣ Creating backup of existing binary:"
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "echo 'C!sco#123' | sudo -S cp /opt/aegis/bin/aegis /opt/aegis/bin/aegis.backup.$(date +%Y%m%d_%H%M%S) || true"

echo -e "\n3️⃣ Deploying new agent binary:"
scp -i $SSH_KEY agents/aegis/aegis-linux-arm64 $REMOTE_USER@$REMOTE_HOST:/tmp/aegis-new
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "echo 'C!sco#123' | sudo -S mv /tmp/aegis-new /opt/aegis/bin/aegis"
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "echo 'C!sco#123' | sudo -S chmod +x /opt/aegis/bin/aegis"

echo -e "\n4️⃣ Starting agent service:"
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "echo 'C!sco#123' | sudo -S systemctl start aegis"

echo -e "\n5️⃣ Checking agent status:"
sleep 3
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "echo 'C!sco#123' | sudo -S systemctl status aegis --no-pager | grep -E '(Active|Main PID)'"

echo -e "\n6️⃣ Testing agent API:"
ssh -i $SSH_KEY $REMOTE_USER@$REMOTE_HOST "curl -s http://localhost:7070/status | jq '{enforce_mode, ebpf_enabled, registered}' || echo 'Agent API not responding'"

echo -e "\n✅ Deployment complete!"
echo "Agent binary: $(du -h agents/aegis/aegis-linux-arm64 | cut -f1)"
echo "Backend binary: $(du -h backend/actions-api/actions-api-linux | cut -f1)"
