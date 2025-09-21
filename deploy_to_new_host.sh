#!/bin/bash

# Deploy Aegis Agent to New ARM64 Host
# Usage: ./deploy_to_new_host.sh [user@host]

set -e

HOST_USER=${1:-"steve@NEW_HOST_IP"}

echo "🚀 Deploying Aegis Agent to New ARM64 Host: $HOST_USER"

# Check if we have the ARM64 binary
if [ ! -f "agents/aegis/aegis-linux-arm64" ]; then
    echo "❌ ARM64 binary not found. Building it now..."
    cd agents/aegis
    GOOS=linux GOARCH=arm64 go build -o aegis-linux-arm64 cmd/aegis/main_ubuntu_simple_integrated.go
    cd ../..
    echo "✅ ARM64 binary built"
fi

echo "📦 Binary info:"
ls -la agents/aegis/aegis-linux-arm64
file agents/aegis/aegis-linux-arm64

# Test SSH connection first
echo "🔍 Testing SSH connection..."
ssh -i ~/.ssh/aegis_agent_key -o ConnectTimeout=5 $HOST_USER "echo 'SSH connection successful'"

# Deploy the binary
echo "📂 Deploying binary..."
scp -i ~/.ssh/aegis_agent_key agents/aegis/aegis-linux-arm64 $HOST_USER:/tmp/aegis

# Install and configure
echo "⚙️  Installing and configuring agent..."
ssh -i ~/.ssh/aegis_agent_key $HOST_USER "
sudo mv /tmp/aegis /opt/aegis/bin/aegis
sudo chmod +x /opt/aegis/bin/aegis
sudo chown root:root /opt/aegis/bin/aegis

# Test the binary
echo '🧪 Testing binary...'
sudo /opt/aegis/bin/aegis --help | head -5

# Enable and start the service
echo '🔧 Starting service...'
sudo systemctl daemon-reload
sudo systemctl enable aegis
sudo systemctl start aegis

# Wait for startup
sleep 5

# Check status
echo '📊 Service status:'
sudo systemctl status aegis --no-pager

echo '🌐 Testing endpoints:'
curl -s http://localhost:7070/healthz && echo ' ✅ Health OK'
curl -s http://localhost:7070/status | jq '.host_id' && echo ' ✅ Status OK'
"

# Deploy policies
echo "📋 Deploying ARM64 policies..."
scp -i ~/.ssh/aegis_agent_key policies/arm64_optimized.json $HOST_USER:/tmp/
ssh -i ~/.ssh/aegis_agent_key $HOST_USER "
sudo mv /tmp/arm64_optimized.json /opt/aegis/policies/
sudo chown root:root /opt/aegis/policies/arm64_optimized.json
"

# Deploy BPF programs if they exist
if [ -d "bpf" ]; then
    echo "🔗 Deploying BPF programs..."
    scp -i ~/.ssh/aegis_agent_key -r bpf $HOST_USER:/tmp/
    ssh -i ~/.ssh/aegis_agent_key $HOST_USER "
    sudo mv /tmp/bpf /opt/aegis/
    sudo chown -R root:root /opt/aegis/bpf
    "
fi

# Final verification
echo "✅ Running final verification..."
ssh -i ~/.ssh/aegis_agent_key $HOST_USER "
echo '=== Final Agent Status ==='
sudo systemctl is-active aegis && echo '✅ Service Active'
sudo systemctl is-enabled aegis && echo '✅ Service Enabled'
curl -s http://localhost:7070/healthz && echo ' ✅ Health endpoint OK'
echo ''
echo 'Agent logs (last 5 lines):'
sudo journalctl -u aegis --no-pager -n 5
echo ''
echo '📊 System resources:'
free -h | grep Mem
df -h / | tail -1
echo ''
echo '🎉 Deployment successful!'
echo 'Monitor with: sudo journalctl -u aegis -f'
echo 'Health: curl http://$(hostname -I | awk '{print \$1}'):7070/healthz'
echo 'Status: curl http://$(hostname -I | awk '{print \$1}'):7070/status'
"

HOST_IP=$(echo $HOST_USER | cut -d'@' -f2)
echo ""
echo "✅ Deployment complete!"
echo ""
echo "🌐 Agent endpoints:"
echo "   Health: curl http://$HOST_IP:7070/healthz"
echo "   Status: curl http://$HOST_IP:7070/status"
echo "   Policies: curl http://$HOST_IP:7070/policies"
echo ""
echo "🔧 Management commands:"
echo "   SSH: ssh -i ~/.ssh/aegis_agent_key $HOST_USER"
echo "   Logs: ssh -i ~/.ssh/aegis_agent_key $HOST_USER 'sudo journalctl -u aegis -f'"
echo "   Restart: ssh -i ~/.ssh/aegis_agent_key $HOST_USER 'sudo systemctl restart aegis'"
