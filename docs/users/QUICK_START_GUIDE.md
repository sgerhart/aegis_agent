# 🚀 Aegis Agent - Quick Start Guide

## What is Aegis Agent?

Aegis Agent is a security monitoring system that protects your Linux servers by:
- **Real-time threat detection** - Monitors system activities and network traffic
- **Policy enforcement** - Automatically blocks suspicious activities
- **Secure communication** - Connects to backend via WebSocket for real-time updates

## 🎯 Getting Started (5 Minutes)

### 1. **Deploy the Agent**

```bash
# Download and install the agent
sudo systemctl start aegis-agent

# Check if it's running
sudo systemctl status aegis-agent
```

### 2. **Verify Connection**

The agent will automatically:
- ✅ Connect to the security backend
- ✅ Register itself securely
- ✅ Start monitoring your system

### 3. **Monitor Activity**

```bash
# View agent logs
sudo journalctl -u aegis-agent -f

# Check agent status
sudo systemctl is-active aegis-agent
```

## 📊 What You'll See

### ✅ **Normal Operation**
```
[websocket] Connected to backend at ws://192.168.1.157:8080/ws/agent
[enforcer] Enforcement cycle completed (maps: 3)
[websocket] Heartbeat sent successfully
```

### ⚠️ **Common Issues & Solutions**

| Issue | Solution |
|-------|----------|
| Agent won't start | Check systemd service: `sudo systemctl status aegis-agent` |
| Connection failed | Verify network connectivity to backend |
| Registration failed | Check agent configuration and backend status |

## 🔧 Configuration

The agent runs with these default settings:
- **Backend URL**: `ws://192.168.1.157:8080/ws/agent`
- **Agent ID**: `aegis-linux-service`
- **Log Level**: `info`

## 📈 Monitoring & Maintenance

### **Daily Checks**
- ✅ Agent is running: `systemctl is-active aegis-agent`
- ✅ Recent logs: `journalctl -u aegis-agent --since "1 hour ago"`

### **Weekly Checks**
- ✅ Disk space: `df -h /var/lib/aegis`
- ✅ Log rotation: Check `/var/log/aegis/`

## 🆘 Troubleshooting

### **Agent Not Starting**
```bash
# Check service status
sudo systemctl status aegis-agent

# View error logs
sudo journalctl -u aegis-agent --no-pager -n 50
```

### **Connection Issues**
```bash
# Test network connectivity
ping 192.168.1.157

# Check WebSocket endpoint
curl -I http://192.168.1.157:8080/health
```

### **Performance Issues**
```bash
# Check resource usage
top -p $(pgrep aegis-agent)

# Monitor system resources
htop
```

## 📞 Support

- **Documentation**: See `/docs/` directory for detailed guides
- **Logs**: Always check `journalctl -u aegis-agent` first
- **Backend Status**: Verify backend connectivity before troubleshooting agent

---

**🎯 You're all set!** Your system is now protected by Aegis Agent with real-time monitoring and automatic threat response.
