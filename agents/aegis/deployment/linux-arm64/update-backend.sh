#!/bin/bash

# Aegis Agent Backend Configuration Update Script
# Usage: ./update-backend.sh <backend-ip> [port] [agent-id] [log-level]

set -e

# Default values
DEFAULT_PORT="8080"
DEFAULT_AGENT_ID="production-agent"
DEFAULT_LOG_LEVEL="info"

# Parse arguments
BACKEND_IP="$1"
BACKEND_PORT="${2:-$DEFAULT_PORT}"
AGENT_ID="${3:-$DEFAULT_AGENT_ID}"
LOG_LEVEL="${4:-$DEFAULT_LOG_LEVEL}"

# Validate arguments
if [ -z "$BACKEND_IP" ]; then
    echo "Usage: $0 <backend-ip> [port] [agent-id] [log-level]"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.166"
    echo "  $0 192.168.1.200 8080"
    echo "  $0 10.0.0.100 9090 my-agent-001"
    echo "  $0 192.168.1.166 8080 production-agent debug"
    exit 1
fi

# Build backend URL
BACKEND_URL="ws://${BACKEND_IP}:${BACKEND_PORT}/ws/agent"

echo "Updating agent configuration..."
echo "  Backend IP: $BACKEND_IP"
echo "  Backend Port: $BACKEND_PORT"
echo "  Backend URL: $BACKEND_URL"
echo "  Agent ID: $AGENT_ID"
echo "  Log Level: $LOG_LEVEL"
echo ""

# Create temporary service file
TEMP_SERVICE="/tmp/aegis-agent.service"
cat > "$TEMP_SERVICE" << EOF
[Unit]
Description=Aegis Agent
After=network.target

[Service]
Type=simple
User=aegis
Group=aegis
WorkingDirectory=/opt/aegis
ExecStart=/opt/aegis/bin/aegis-agent --agent-id "$AGENT_ID" --backend-url "$BACKEND_URL" --log-level "$LOG_LEVEL"
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Copy to systemd directory
sudo cp "$TEMP_SERVICE" /etc/systemd/system/aegis-agent.service

# Reload systemd
sudo systemctl daemon-reload

# Clean up temporary file
rm -f "$TEMP_SERVICE"

echo "✅ Configuration updated successfully!"
echo ""

# Ask if user wants to restart the agent
read -p "Do you want to restart the agent now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Restarting agent..."
    sudo systemctl restart aegis-agent
    echo "✅ Agent restarted!"
    echo ""
    echo "Check status with: sudo systemctl status aegis-agent"
    echo "View logs with: sudo journalctl -u aegis-agent -f"
else
    echo "To apply changes, restart the agent manually:"
    echo "  sudo systemctl restart aegis-agent"
fi

