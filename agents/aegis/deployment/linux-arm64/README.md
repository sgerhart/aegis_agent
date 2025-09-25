# Aegis Agent - Linux ARM64 Deployment

## Quick Deploy

1. **Copy files to Linux ARM64 host:**
   ```bash
   scp -r deployment/linux-arm64/* user@linux-host:/tmp/aegis-deploy/
   ```

2. **SSH into the host and deploy:**
   ```bash
   ssh user@linux-host
   cd /tmp/aegis-deploy
   sudo ./deploy.sh
   ```

3. **Start the agent:**
   ```bash
   sudo systemctl start aegis-agent
   sudo systemctl enable aegis-agent
   ```

## Files Included

- `aegis-agent` - ARM64 binary (6.1MB)
- `deploy.sh` - Automated deployment script
- `agent-config.json` - Configuration file
- `README.md` - This guide

## Configuration

The agent is configured to:
- Connect to `ws://localhost:8080/ws/agent`
- Use agent ID: `production-agent`
- Enable telemetry and WebSocket communication modules
- Log at info level

## Management Commands

```bash
# Check status
sudo systemctl status aegis-agent

# View logs
sudo journalctl -u aegis-agent -f

# Restart agent
sudo systemctl restart aegis-agent

# Stop agent
sudo systemctl stop aegis-agent
```

## Requirements

- Linux ARM64 host
- systemd
- Network access to backend
- sudo privileges for deployment
