#!/bin/bash

# Aegis Agent Configuration Update Script
# This script allows dynamic updating of the agent configuration

set -e

# Default values
DEFAULT_BACKEND_HOST="192.168.1.166"
DEFAULT_BACKEND_PORT="8080"
DEFAULT_AGENT_ID="production-agent"
DEFAULT_LOG_LEVEL="info"

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --backend-host HOST    Set backend host (default: $DEFAULT_BACKEND_HOST)"
    echo "  --backend-port PORT    Set backend port (default: $DEFAULT_BACKEND_PORT)"
    echo "  --agent-id ID          Set agent ID (default: $DEFAULT_AGENT_ID)"
    echo "  --log-level LEVEL      Set log level (default: $DEFAULT_LOG_LEVEL)"
    echo "  --restart              Restart the agent after updating config"
    echo "  --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --backend-host 192.168.1.200 --restart"
    echo "  $0 --backend-host 10.0.0.100 --backend-port 9090 --restart"
    echo "  $0 --agent-id my-agent-001 --log-level debug --restart"
}

# Parse command line arguments
BACKEND_HOST=""
BACKEND_PORT=""
AGENT_ID=""
LOG_LEVEL=""
RESTART=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --backend-host)
            BACKEND_HOST="$2"
            shift 2
            ;;
        --backend-port)
            BACKEND_PORT="$2"
            shift 2
            ;;
        --agent-id)
            AGENT_ID="$2"
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --restart)
            RESTART=true
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Update systemd service file
echo "Updating agent configuration..."

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
ExecStart=/opt/aegis/bin/aegis-agent --agent-id "\${AEGIS_AGENT_ID:-$DEFAULT_AGENT_ID}" --backend-url "ws://\${AEGIS_BACKEND_HOST:-$DEFAULT_BACKEND_HOST}:\${AEGIS_BACKEND_PORT:-$DEFAULT_BACKEND_PORT}/ws/agent" --log-level "\${AEGIS_LOG_LEVEL:-$DEFAULT_LOG_LEVEL}"
Environment=AEGIS_BACKEND_HOST=${BACKEND_HOST:-$DEFAULT_BACKEND_HOST}
Environment=AEGIS_BACKEND_PORT=${BACKEND_PORT:-$DEFAULT_BACKEND_PORT}
Environment=AEGIS_AGENT_ID=${AGENT_ID:-$DEFAULT_AGENT_ID}
Environment=AEGIS_LOG_LEVEL=${LOG_LEVEL:-$DEFAULT_LOG_LEVEL}
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
echo "Current configuration:"
echo "  Backend Host: ${BACKEND_HOST:-$DEFAULT_BACKEND_HOST}"
echo "  Backend Port: ${BACKEND_PORT:-$DEFAULT_BACKEND_PORT}"
echo "  Agent ID: ${AGENT_ID:-$DEFAULT_AGENT_ID}"
echo "  Log Level: ${LOG_LEVEL:-$DEFAULT_LOG_LEVEL}"
echo ""

if [ "$RESTART" = true ]; then
    echo "Restarting agent..."
    sudo systemctl restart aegis-agent
    echo "✅ Agent restarted!"
    echo ""
    echo "Check status with: sudo systemctl status aegis-agent"
    echo "View logs with: sudo journalctl -u aegis-agent -f"
else
    echo "To apply changes, restart the agent:"
    echo "  sudo systemctl restart aegis-agent"
fi

