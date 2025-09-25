#!/usr/bin/env python3
"""
Test script to demonstrate backend module control functionality.
This script simulates backend commands to control agent modules.
"""

import json
import time
import websocket
import threading

class ModuleControlTester:
    def __init__(self, backend_url="ws://192.168.1.166:8080/ws/agent"):
        self.backend_url = backend_url
        self.ws = None
        self.connected = False
        
    def connect(self):
        """Connect to the backend WebSocket"""
        try:
            self.ws = websocket.WebSocket()
            self.ws.connect(self.backend_url)
            self.connected = True
            print(f"✅ Connected to backend at {self.backend_url}")
            return True
        except Exception as e:
            print(f"❌ Failed to connect to backend: {e}")
            return False
    
    def send_command(self, command_type, **kwargs):
        """Send a module control command to the agent"""
        if not self.connected:
            print("❌ Not connected to backend")
            return None
            
        command = {
            "type": command_type,
            "timestamp": time.time(),
            **kwargs
        }
        
        try:
            self.ws.send(json.dumps(command))
            print(f"📤 Sent command: {command_type}")
            
            # Wait for response
            response = self.ws.recv()
            response_data = json.loads(response)
            print(f"📥 Response: {json.dumps(response_data, indent=2)}")
            return response_data
        except Exception as e:
            print(f"❌ Error sending command: {e}")
            return None
    
    def test_module_control(self):
        """Test various module control commands"""
        print("\n🧪 Testing Module Control Commands")
        print("=" * 50)
        
        # 1. List all modules
        print("\n1️⃣ Listing all modules...")
        self.send_command("list_modules")
        
        time.sleep(1)
        
        # 2. Get status of specific modules
        print("\n2️⃣ Getting module status...")
        for module_id in ["telemetry", "observability", "analysis", "threat_intelligence"]:
            self.send_command("get_module_status", module_id=module_id)
            time.sleep(0.5)
        
        time.sleep(1)
        
        # 3. Start a disabled module
        print("\n3️⃣ Starting analysis module...")
        self.send_command("start_module", module_id="analysis")
        
        time.sleep(2)
        
        # 4. Check status again
        print("\n4️⃣ Checking analysis module status after start...")
        self.send_command("get_module_status", module_id="analysis")
        
        time.sleep(1)
        
        # 5. Stop the module
        print("\n5️⃣ Stopping analysis module...")
        self.send_command("stop_module", module_id="analysis")
        
        time.sleep(2)
        
        # 6. Final status check
        print("\n6️⃣ Final module status check...")
        self.send_command("get_module_status", module_id="analysis")
        
        print("\n✅ Module control testing completed!")
    
    def disconnect(self):
        """Disconnect from the backend"""
        if self.ws:
            self.ws.close()
            self.connected = False
            print("🔌 Disconnected from backend")

def main():
    print("🚀 Aegis Agent Module Control Tester")
    print("=" * 50)
    
    tester = ModuleControlTester()
    
    if not tester.connect():
        return
    
    try:
        tester.test_module_control()
    except KeyboardInterrupt:
        print("\n⏹️ Test interrupted by user")
    finally:
        tester.disconnect()

if __name__ == "__main__":
    main()
