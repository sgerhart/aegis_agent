# 📚 Aegis Agent Documentation

Welcome to the Aegis Agent documentation! This directory contains comprehensive guides for both users and engineers.

## 🎯 Quick Navigation

### 👥 **For Users** (Easy-to-read guides)
- **[Quick Start Guide](users/QUICK_START_GUIDE.md)** - Get up and running in 5 minutes
- **[Installation Guide](users/INSTALLATION_GUIDE.md)** - Complete installation instructions
- **[Troubleshooting Guide](users/TROUBLESHOOTING_GUIDE.md)** - Common issues and solutions

### 🔧 **For Engineers** (Technical documentation)
- **[WebSocket Protocol Specification](engineers/WEBSOCKET_PROTOCOL_SPECIFICATION.md)** - Complete protocol reference
- **[Agent Registration Implementation](engineers/AGENT_REGISTRATION_IMPLEMENTATION.md)** - Registration flow and code examples
- **[Backend Team Handoff](engineers/BACKEND_TEAM_HANDOFF.md)** - Backend integration details
- **[Agent Working Example](engineers/AGENT_WORKING_EXAMPLE.md)** - Complete working code examples

## 📖 Documentation Structure

```
docs/
├── users/                    # User-friendly guides
│   ├── QUICK_START_GUIDE.md
│   ├── INSTALLATION_GUIDE.md
│   └── TROUBLESHOOTING_GUIDE.md
├── engineers/                # Technical documentation
│   ├── WEBSOCKET_PROTOCOL_SPECIFICATION.md
│   ├── AGENT_REGISTRATION_IMPLEMENTATION.md
│   ├── BACKEND_TEAM_HANDOFF.md
│   ├── AGENT_WORKING_EXAMPLE.md
│   ├── AGENT_SIGNATURE_FIX.md
│   └── AGENT_TEAM_FINAL_SOLUTION.md
├── api/                      # API references
│   └── COMPREHENSIVE_API_REFERENCE.md
├── architecture/             # System architecture
│   └── MODULAR_ARCHITECTURE_SUMMARY.md
├── deployment/               # Deployment guides
│   └── COMPREHENSIVE_DEPLOYMENT_GUIDE.md
├── testing/                  # Testing documentation
│   └── COMPREHENSIVE_TESTING_GUIDE.md
├── guides/                   # General guides
│   └── COMPREHENSIVE_AGENT_GUIDE.md
├── analysis/                 # Technical analysis
│   └── COMPREHENSIVE_TECHNICAL_ANALYSIS.md
└── summaries/                # Project summaries
    └── COMPREHENSIVE_PROJECT_SUMMARY.md
```

## 🚀 Getting Started

### **New Users**
1. Start with the [Quick Start Guide](users/QUICK_START_GUIDE.md)
2. Follow the [Installation Guide](users/INSTALLATION_GUIDE.md) if needed
3. Use the [Troubleshooting Guide](users/TROUBLESHOOTING_GUIDE.md) for issues

### **Developers**
1. Read the [WebSocket Protocol Specification](engineers/WEBSOCKET_PROTOCOL_SPECIFICATION.md)
2. Study the [Agent Registration Implementation](engineers/AGENT_REGISTRATION_IMPLEMENTATION.md)
3. Reference the [Backend Team Handoff](engineers/BACKEND_TEAM_HANDOFF.md) for integration

### **System Administrators**
1. Review the [Installation Guide](users/INSTALLATION_GUIDE.md)
2. Check the [Deployment Guide](deployment/COMPREHENSIVE_DEPLOYMENT_GUIDE.md)
3. Keep the [Troubleshooting Guide](users/TROUBLESHOOTING_GUIDE.md) handy

## 📋 Key Features

### **Security**
- **Real-time threat detection** - Monitors system activities and network traffic
- **Policy enforcement** - Automatically blocks suspicious activities
- **Secure communication** - Uses WebSocket with Ed25519 signatures
- **Session management** - Proper authentication and session handling

### **Reliability**
- **Auto-reconnection** - Handles network interruptions gracefully
- **Session persistence** - Maintains state across reconnections
- **Error recovery** - Robust error handling and recovery mechanisms
- **Health monitoring** - Continuous health checks and reporting

### **Performance**
- **Low resource usage** - Optimized for production environments
- **Efficient monitoring** - Uses eBPF for high-performance system monitoring
- **Scalable architecture** - Supports multiple agents and backend scaling

## 🔍 Common Use Cases

### **Production Deployment**
- Deploy agents on critical servers
- Monitor real-time security events
- Enforce security policies automatically

### **Development & Testing**
- Test agent functionality
- Debug communication issues
- Develop custom integrations

### **Troubleshooting**
- Diagnose connection problems
- Analyze security events
- Monitor agent performance

## 📞 Support

### **Documentation Issues**
- Check the [Troubleshooting Guide](users/TROUBLESHOOTING_GUIDE.md) first
- Review relevant technical documentation in `engineers/`
- Look for similar issues in the project history

### **Technical Questions**
- Reference the [WebSocket Protocol Specification](engineers/WEBSOCKET_PROTOCOL_SPECIFICATION.md)
- Check the [Agent Registration Implementation](engineers/AGENT_REGISTRATION_IMPLEMENTATION.md)
- Review the [Backend Team Handoff](engineers/BACKEND_TEAM_HANDOFF.md)

### **Getting Help**
1. **Check logs first**: `sudo journalctl -u aegis-agent`
2. **Review documentation**: Use this README to find relevant guides
3. **Search existing issues**: Look for similar problems in project history
4. **Contact support**: Provide logs and system information

## 🔄 Documentation Updates

This documentation is actively maintained and updated with each release. Key areas of focus:

- **User guides** - Simplified, step-by-step instructions
- **Technical specs** - Complete implementation details
- **Troubleshooting** - Common issues and solutions
- **Examples** - Working code and configuration samples

---

**📚 Happy reading!** This documentation is designed to help you get the most out of Aegis Agent, whether you're a user, developer, or system administrator.