# 🛠️ Aegis Agent - Troubleshooting Guide

## Common Issues & Quick Fixes

### 🔴 **Agent Won't Start**

**Symptoms:**
- `systemctl status aegis-agent` shows "failed" or "inactive"
- No agent process running

**Quick Fixes:**
```bash
# 1. Check service status
sudo systemctl status aegis-agent

# 2. Restart the service
sudo systemctl restart aegis-agent

# 3. Check for errors
sudo journalctl -u aegis-agent --no-pager -n 20
```

**Common Causes:**
- Port conflicts (7070 already in use)
- Permission issues with `/var/lib/aegis`
- Corrupted configuration

### 🔴 **Connection Failed**

**Symptoms:**
- `[websocket] Failed to connect to backend`
- Agent connects but immediately disconnects

**Quick Fixes:**
```bash
# 1. Test network connectivity
ping 192.168.1.157

# 2. Check backend health
curl http://192.168.1.157:8080/health

# 3. Verify firewall settings
sudo ufw status
```

**Common Causes:**
- Network connectivity issues
- Backend server down
- Firewall blocking connections

### 🔴 **Registration Loop**

**Symptoms:**
- Multiple agent registrations in backend
- Agent keeps reconnecting
- Logs show repeated registration attempts

**Quick Fixes:**
```bash
# 1. Stop the agent
sudo systemctl stop aegis-agent

# 2. Wait 30 seconds
sleep 30

# 3. Restart the agent
sudo systemctl start aegis-agent
```

**Common Causes:**
- Session management issues (fixed in latest version)
- Backend registration conflicts

### 🔴 **High CPU/Memory Usage**

**Symptoms:**
- System slow or unresponsive
- Agent consuming excessive resources

**Quick Fixes:**
```bash
# 1. Check resource usage
top -p $(pgrep aegis-agent)

# 2. Restart agent
sudo systemctl restart aegis-agent

# 3. Monitor for improvement
htop
```

**Common Causes:**
- Memory leaks in older versions
- Excessive logging
- eBPF program issues

## 📊 Diagnostic Commands

### **System Health Check**
```bash
# Complete system check
sudo systemctl status aegis-agent
sudo journalctl -u aegis-agent --no-pager -n 50
df -h /var/lib/aegis
free -h
```

### **Network Connectivity**
```bash
# Test backend connectivity
ping 192.168.1.157
curl -I http://192.168.1.157:8080/health
telnet 192.168.1.157 8080
```

### **Agent Process Information**
```bash
# Process details
ps aux | grep aegis-agent
lsof -p $(pgrep aegis-agent)
netstat -tulpn | grep aegis
```

## 🔍 Log Analysis

### **Understanding Log Messages**

**✅ Normal Messages:**
```
[websocket] Connected to backend at ws://192.168.1.157:8080/ws/agent
[enforcer] Enforcement cycle completed (maps: 3)
[websocket] Heartbeat sent successfully
```

**⚠️ Warning Messages:**
```
[websocket] Connection failure 1, preserving session credentials
[websocket] Failed to read message: i/o timeout
```

**🔴 Error Messages:**
```
[websocket] Failed to connect to backend
[core] Agent startup failed
[registration] Registration failed: 401 signature verify failed
```

### **Log Filtering**
```bash
# Filter by component
sudo journalctl -u aegis-agent | grep "websocket"
sudo journalctl -u aegis-agent | grep "enforcer"
sudo journalctl -u aegis-agent | grep "registration"

# Filter by severity
sudo journalctl -u aegis-agent | grep -E "(ERROR|WARN)"
sudo journalctl -u aegis-agent | grep -E "(Failed|failed)"
```

## 🔧 Advanced Troubleshooting

### **Reset Agent Configuration**
```bash
# Stop agent
sudo systemctl stop aegis-agent

# Clear data directory (WARNING: This will reset agent identity)
sudo rm -rf /var/lib/aegis/*

# Restart agent (will generate new identity)
sudo systemctl start aegis-agent
```

### **Debug Mode**
```bash
# Stop service
sudo systemctl stop aegis-agent

# Run in debug mode
sudo /usr/local/bin/aegis-agent --log-level debug --backend-url ws://192.168.1.157:8080/ws/agent
```

### **Check eBPF Programs**
```bash
# List eBPF programs
sudo bpftool prog list | grep aegis

# Check eBPF maps
sudo bpftool map list | grep aegis
```

## 📞 When to Contact Support

Contact support if you experience:
- **Persistent connection failures** after network troubleshooting
- **Repeated crashes** or memory leaks
- **Performance degradation** that doesn't improve with restart
- **Security alerts** that seem incorrect

### **Information to Provide:**
1. Agent version: `aegis-agent --version`
2. System info: `uname -a`
3. Recent logs: `sudo journalctl -u aegis-agent --no-pager -n 100`
4. Network test: `ping 192.168.1.157 && curl -I http://192.168.1.157:8080/health`

---

**💡 Pro Tip:** Most issues are resolved by restarting the agent service. Always try `sudo systemctl restart aegis-agent` first!
