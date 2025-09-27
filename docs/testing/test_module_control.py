#!/usr/bin/env python3
"""
Test script for Aegis Agent module control functionality
Tests WebSocket communication and backend module control
"""

import asyncio
import websockets
import json
import time
import sys

# Configuration
AGENT_URL = "ws://192.168.193.129:8080/ws/agent"  # Agent WebSocket endpoint
BACKEND_URL = "ws://192.168.1.157:8080/ws/agent"  # Backend WebSocket endpoint

async def test_agent_connection():
    """Test direct connection to agent WebSocket"""
    print(f"🔌 Testing direct connection to agent at {AGENT_URL}...")
    try:
        async with websockets.connect(AGENT_URL) as websocket:
            print("✅ Connected to agent WebSocket")
            
            # Test basic ping
            await websocket.send(json.dumps({"type": "ping", "timestamp": int(time.time())}))
            response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            print(f"📡 Ping response: {response}")
            
            return True
    except Exception as e:
        print(f"❌ Failed to connect to agent: {e}")
        return False

async def test_backend_connection():
    """Test connection to backend WebSocket"""
    print(f"🔌 Testing connection to backend at {BACKEND_URL}...")
    try:
        async with websockets.connect(BACKEND_URL) as websocket:
            print("✅ Connected to backend WebSocket")
            
            # Test basic ping
            await websocket.send(json.dumps({"type": "ping", "timestamp": int(time.time())}))
            response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            print(f"📡 Ping response: {response}")
            
            return True
    except Exception as e:
        print(f"❌ Failed to connect to backend: {e}")
        return False

async def test_module_control():
    """Test module control commands"""
    print(f"🎛️ Testing module control at {BACKEND_URL}...")
    try:
        async with websockets.connect(BACKEND_URL) as websocket:
            print("✅ Connected to backend for module control")
            
            # 1. List all modules
            print("\n--- 📋 Listing all modules ---")
            await websocket.send(json.dumps({"type": "list_modules", "timestamp": int(time.time())}))
            response = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            print(f"📋 Modules: {response}")
            
            # 2. Get status of analysis module
            print("\n--- 🔍 Getting status of 'analysis' module ---")
            await websocket.send(json.dumps({"type": "get_module_status", "module_id": "analysis", "timestamp": int(time.time())}))
            response = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            print(f"🔍 Analysis status: {response}")
            
            # 3. Test starting a module
            print("\n--- ▶️ Starting 'analysis' module ---")
            await websocket.send(json.dumps({"type": "start_module", "module_id": "analysis", "timestamp": int(time.time())}))
            response = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            print(f"▶️ Start response: {response}")
            
            return True
    except Exception as e:
        print(f"❌ Module control test failed: {e}")
        return False

async def main():
    """Main test function"""
    print("🚀 Aegis Agent Module Control Test")
    print("=" * 50)
    
    # Test agent connection
    agent_ok = await test_agent_connection()
    print()
    
    # Test backend connection
    backend_ok = await test_backend_connection()
    print()
    
    # Test module control if backend is available
    if backend_ok:
        module_ok = await test_module_control()
    else:
        print("⚠️ Skipping module control test (backend not available)")
        module_ok = False
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results:")
    print(f"  Agent Connection: {'✅ PASS' if agent_ok else '❌ FAIL'}")
    print(f"  Backend Connection: {'✅ PASS' if backend_ok else '❌ FAIL'}")
    print(f"  Module Control: {'✅ PASS' if module_ok else '❌ FAIL'}")
    
    if agent_ok and backend_ok and module_ok:
        print("\n🎉 All tests passed! Agent is fully functional.")
        return 0
    else:
        print("\n⚠️ Some tests failed. Check the output above.")
        return 1

if __name__ == "__main__":
    try:
        result = asyncio.run(main())
        sys.exit(result)
    except KeyboardInterrupt:
        print("\n⏹️ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Test failed with error: {e}")
        sys.exit(1)