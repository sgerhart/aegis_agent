#!/bin/bash

# Aegis Agent Deployment Script for Linux ARM64
set -e

echo "🚀 Deploying Aegis Agent on Linux ARM64..."

# Create agent user
if ! id "aegis" &>/dev/null; then
    echo "Creating aegis user..."
    sudo useradd -r -s /bin/false -d /opt/aegis aegis
fi

# Create directories
echo "Creating directories..."
sudo mkdir -p /opt/aegis/{bin,logs,configs}
sudo mkdir -p /var/log/aegis

# Copy binary
echo "Installing agent binary..."
sudo cp aegis-agent /opt/aegis/bin/
sudo chmod +x /opt/aegis/bin/aegis-agent

# Set ownership
sudo chown -R aegis:aegis /opt/aegis
sudo chown -R aegis:aegis /var/log/aegis

# Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/aegis-agent.service > /dev/null << 'SERVICE_EOF'
[Unit]
Description=Aegis Agent
After=network.target

[Service]
Type=simple
User=aegis
Group=aegis
WorkingDirectory=/opt/aegis
ExecStart=/opt/aegis/bin/aegis-agent --agent-id "production-agent" --backend-url "ws://192.168.1.166:8080/ws/agent" --log-level info
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Reload systemd
sudo systemctl daemon-reload

echo "✅ Aegis Agent deployed successfully!"
echo ""
echo "To start the agent:"
echo "  sudo systemctl start aegis-agent"
echo ""
echo "To enable auto-start:"
echo "  sudo systemctl enable aegis-agent"
echo ""
echo "To check status:"
echo "  sudo systemctl status aegis-agent"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u aegis-agent -f"
