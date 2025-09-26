#!/bin/bash

# Check Aegis Agent Status on Linux Host  
# Copy this script to your Linux host and run it there
# Usage: sudo ./check_agent_on_host.sh

echo "🔍 Aegis Agent Status Check on $(hostname)"
echo "Architecture: $(uname -m)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
echo "Kernel: $(uname -r)"
echo "Date: $(date)"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "⚠️  This script should be run as root (sudo)"
   echo "   Some checks may fail without root privileges"
   echo ""
fi

echo "=========================================="
echo "📋 1. SYSTEM ARCHITECTURE CHECK"
echo "=========================================="
echo "Architecture: $(uname -m)"
echo "CPU Info:"
lscpu | grep -E 'Architecture|CPU|Model|Thread|Core' | head -5
echo ""
echo "Memory:"
free -h
echo ""

echo "=========================================="
echo "📋 2. AGENT BINARY CHECK"
echo "=========================================="

# Common agent locations
AGENT_PATHS=(
    "/opt/aegis/bin/aegis"
    "/usr/local/bin/aegis"
    "/usr/bin/aegis"
    "./aegis"
    "./aegis-linux-arm64"
    "./aegis-linux-amd64"
)

FOUND_AGENT=""
for path in "${AGENT_PATHS[@]}"; do
    if [ -f "$path" ]; then
        echo "✅ Found agent at: $path"
        file "$path"
        ls -la "$path"
        FOUND_AGENT="$path"
        break
    fi
done

if [ -z "$FOUND_AGENT" ]; then
    echo "❌ No agent binary found in common locations"
    echo "   Searching for aegis binaries..."
    find / -name "*aegis*" -type f -executable 2>/dev/null | head -10
fi
echo ""

echo "=========================================="
echo "📋 3. SYSTEMD SERVICE CHECK"
echo "=========================================="
systemctl status aegis 2>/dev/null || echo "❌ aegis systemd service not found or not active"
echo ""
if [ -f "/etc/systemd/system/aegis.service" ]; then
    echo "✅ Systemd service file exists:"
    cat /etc/systemd/system/aegis.service
else
    echo "❌ No systemd service file found at /etc/systemd/system/aegis.service"
fi
echo ""

echo "=========================================="
echo "📋 4. PROCESS CHECK"
echo "=========================================="
ps aux | grep -E '[a]egis|[A]EGIS' || echo "❌ No aegis processes running"
echo ""

echo "=========================================="
echo "📋 5. NETWORK PORTS CHECK"
echo "=========================================="
echo "Listening ports related to aegis:"
ss -tlnp | grep -E ':7070|:8080|:8090|aegis' || echo "❌ No aegis-related ports listening"
echo ""

echo "=========================================="
echo "📋 6. EBPF SUPPORT CHECK"
echo "=========================================="
echo "BTF Support:"
ls -la /sys/kernel/btf/vmlinux 2>/dev/null && echo "✅ BTF available" || echo "❌ BTF not available"
echo ""
echo "BPF Filesystem:"
mount | grep bpf || echo "❌ BPF filesystem not mounted"
echo ""
echo "Required tools:"
which clang >/dev/null 2>&1 && echo "✅ clang: $(which clang)" || echo "❌ clang not found"
which bpftool >/dev/null 2>&1 && echo "✅ bpftool: $(which bpftool)" || echo "❌ bpftool not found"
which jq >/dev/null 2>&1 && echo "✅ jq: $(which jq)" || echo "❌ jq not found"
echo ""

echo "=========================================="
echo "📋 7. CONFIGURATION CHECK"
echo "=========================================="
CONFIG_PATHS=(
    "/opt/aegis/config"
    "/etc/aegis"
    "/usr/local/etc/aegis"
)

for path in "${CONFIG_PATHS[@]}"; do
    if [ -d "$path" ]; then
        echo "✅ Config directory found: $path"
        ls -la "$path"
        echo ""
    fi
done
echo ""

echo "=========================================="
echo "📋 8. LOG CHECK"
echo "=========================================="
echo "Recent aegis logs from journalctl:"
journalctl -u aegis --no-pager -n 10 2>/dev/null || echo "❌ No systemd logs for aegis service"
echo ""

LOG_PATHS=(
    "/opt/aegis/logs"
    "/var/log/aegis"
    "/tmp/aegis.log"
)

for path in "${LOG_PATHS[@]}"; do
    if [ -f "$path" ] || [ -d "$path" ]; then
        echo "✅ Log location found: $path"
        if [ -f "$path" ]; then
            echo "Recent log entries:"
            tail -10 "$path" 2>/dev/null || echo "Cannot read log file"
        else
            ls -la "$path"
        fi
        echo ""
    fi
done

echo "=========================================="
echo "📋 9. CONNECTIVITY CHECK"
echo "=========================================="
echo "Testing external connectivity:"
ping -c 2 8.8.8.8 >/dev/null 2>&1 && echo "✅ External connectivity OK" || echo "❌ External connectivity failed"
echo ""

echo "Testing local HTTP endpoints:"
curl -s --max-time 3 http://localhost:7070/healthz 2>/dev/null && echo "✅ Agent HTTP endpoint responding" || echo "❌ Agent HTTP endpoint not responding"
curl -s --max-time 3 http://localhost:8083/health 2>/dev/null && echo "✅ Actions API responding" || echo "❌ Actions API not responding"
echo ""

echo "=========================================="
echo "📋 10. MANUAL AGENT TEST"
echo "=========================================="
if [ -n "$FOUND_AGENT" ]; then
    echo "Testing agent help:"
    "$FOUND_AGENT" --help 2>&1 | head -10
    echo ""
    
    echo "Testing agent version/info:"
    "$FOUND_AGENT" --version 2>&1 || echo "No version flag available"
    echo ""
    
    echo "Testing dry-run mode (5 seconds):"
    timeout 5s "$FOUND_AGENT" --dry-run --verbose --register=false 2>&1 || echo "Dry-run test completed"
else
    echo "❌ No agent binary found for manual testing"
fi
echo ""

echo "=========================================="
echo "📋 SUMMARY"
echo "=========================================="
echo "Host: $(hostname)"
echo "IP: $(hostname -I | awk '{print $1}')"
echo "Arch: $(uname -m)"
echo "Time: $(date)"
echo ""
echo "🔧 Next Steps:"
echo "1. If agent not found, deploy using: ./deploy_to_arm.sh steve@$(hostname -I | awk '{print $1}')"
echo "2. If service not running: sudo systemctl start aegis"
echo "3. If issues found, check logs: sudo journalctl -u aegis -f"
echo "4. For remote access setup SSH keys or use: ssh steve@$(hostname -I | awk '{print $1}')"
echo ""
echo "📊 Quick health check URLs:"
echo "   - Health: curl http://$(hostname -I | awk '{print $1}'):7070/healthz"
echo "   - Status: curl http://$(hostname -I | awk '{print $1}'):7070/status" 
echo "   - Info: curl http://$(hostname -I | awk '{print $1}'):7070/info"
