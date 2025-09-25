# Aegis Agent Linux ARM64 Deployment Guide

## 🚀 Quick Deployment

### 1. Transfer Files to Linux Host
```bash
# Copy the deployment package to your Linux host (192.168.1.166)
scp aegis-agent-linux-arm64.tar.gz user@192.168.1.166:/tmp/
```

### 2. Extract and Deploy on Linux Host
```bash
# SSH into your Linux host
ssh user@192.168.1.166

# Extract the deployment package
cd /tmp
tar -xzf aegis-agent-linux-arm64.tar.gz
cd linux-arm64

# Make the deployment script executable
chmod +x deploy.sh

# Run the deployment script
sudo ./deploy.sh
```

### 3. Start the Agent
```bash
# Start the agent service
sudo systemctl start aegis-agent

# Enable auto-start on boot
sudo systemctl enable aegis-agent

# Check status
sudo systemctl status aegis-agent

# View logs
sudo journalctl -u aegis-agent -f
```

## 🔧 Configuration

The agent uses command-line parameters for configuration:
- **Backend URL**: `--backend-url "ws://192.168.1.166:8080/ws/agent"`
- **Agent ID**: `--agent-id "production-agent"`
- **Log Level**: `--log-level info`

### Updating Backend IP
To change the backend IP address:
```bash
# Update backend IP (and optionally port, agent-id, log-level)
sudo ./update-backend.sh 192.168.1.200

# Or with custom port
sudo ./update-backend.sh 192.168.1.200 9090

# Or with all parameters
sudo ./update-backend.sh 192.168.1.200 8080 my-agent-001 debug
```

## 📊 Monitoring

### Check Agent Status
```bash
sudo systemctl status aegis-agent
```

### View Real-time Logs
```bash
sudo journalctl -u aegis-agent -f
```

### View Recent Logs
```bash
sudo journalctl -u aegis-agent --since "1 hour ago"
```

## 🛠️ Troubleshooting

### If the agent fails to start:
1. Check the logs: `sudo journalctl -u aegis-agent -n 50`
2. Verify the backend is running: `curl http://192.168.1.166:8080/health`
3. Check network connectivity: `ping 192.168.1.166`

### If WebSocket connection fails:
1. Verify the backend WebSocket endpoint is accessible
2. Check firewall settings
3. Ensure the backend is listening on the correct port

## 🔄 Updates

To update the agent:
1. Build new binary: `GOOS=linux GOARCH=arm64 go build -o aegis-agent ./cmd/aegis/main_core.go`
2. Copy to host: `scp aegis-agent user@192.168.1.166:/tmp/`
3. On host: `sudo cp /tmp/aegis-agent /opt/aegis/bin/ && sudo systemctl restart aegis-agent`
