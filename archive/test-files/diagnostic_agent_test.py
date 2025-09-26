#!/usr/bin/env python3
"""
Agent Authentication Diagnostic Test
Helps identify why authentication is failing
"""

import asyncio
import websockets
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class DiagnosticAgent:
    def __init__(self, agent_id="diagnostic-agent-001"):
        self.agent_id = agent_id
        self.private_key, self.public_key_b64 = self.generate_keypair()
        
    def generate_keypair(self):
        """Generate Ed25519 key pair"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        public_key_b64 = base64.b64encode(public_bytes).decode('utf-8')
        
        return private_key, public_key_b64
    
    def sign_data(self, data):
        """Sign data with Ed25519 private key"""
        signature = self.private_key.sign(data.encode('utf-8'))
        return base64.b64encode(signature).decode('utf-8')

async def test_wrong_approach():
    """Test the WRONG approach that causes 'agent not authenticated'"""
    print("🧪 TEST 1: Wrong Approach (Should Fail)")
    print("=" * 50)
    
    agent = DiagnosticAgent("wrong-agent-001")
    
    try:
        headers = {
            "X-Agent-ID": agent.agent_id,
            "X-Agent-Public-Key": agent.public_key_b64,
            "User-Agent": "Aegis-Agent/1.0"
        }
        
        async with websockets.connect("ws://localhost:8080/ws/agent", additional_headers=headers) as websocket:
            print("✅ Connected")
            
            # ❌ WRONG: Send heartbeat without authenticating first
            heartbeat_msg = {
                "type": "heartbeat",
                "data": "ping"
            }
            
            print("📤 Sending heartbeat WITHOUT authentication (this should fail)...")
            await websocket.send(json.dumps(heartbeat_msg))
            
            # Wait for error response
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                print(f"📨 Response: {response}")
            except asyncio.TimeoutError:
                print("⏰ No response (connection may have closed)")
                
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print()

async def test_correct_approach():
    """Test the CORRECT approach that should work"""
    print("🧪 TEST 2: Correct Approach (Should Succeed)")
    print("=" * 50)
    
    agent = DiagnosticAgent("correct-agent-001")
    
    try:
        headers = {
            "X-Agent-ID": agent.agent_id,
            "X-Agent-Public-Key": agent.public_key_b64,
            "User-Agent": "Aegis-Agent/1.0"
        }
        
        async with websockets.connect("ws://localhost:8080/ws/agent", additional_headers=headers) as websocket:
            print("✅ Connected")
            
            # ✅ CORRECT: Send authentication first
            timestamp = int(time.time())
            nonce = base64.b64encode(b"auth_nonce_1234").decode('utf-8')
            
            # Create signature data
            signature_data = f"{agent.agent_id}:{agent.public_key_b64}:{timestamp}:{nonce}"
            signature = agent.sign_data(signature_data)
            
            auth_request = {
                "agent_id": agent.agent_id,
                "public_key": agent.public_key_b64,
                "timestamp": timestamp,
                "nonce": nonce,
                "signature": signature
            }
            
            # Wrap in SecureMessage format
            secure_message = {
                "id": f"auth_req_{timestamp}",
                "type": "request",
                "channel": "auth",
                "payload": base64.b64encode(json.dumps(auth_request).encode()).decode(),
                "timestamp": timestamp,
                "nonce": base64.b64encode(b"secure_nonce").decode(),
                "signature": "",
                "headers": {}
            }
            
            print("📤 Sending authentication request...")
            await websocket.send(json.dumps(secure_message))
            
            # Wait for authentication response
            response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            response_data = json.loads(response)
            
            # Decode response payload
            payload_data = json.loads(base64.b64decode(response_data["payload"]).decode())
            
            if payload_data.get("success"):
                print("🎉 Authentication SUCCESSFUL!")
                
                # ✅ CORRECT: Now send heartbeat after authentication
                heartbeat_message = {
                    "id": f"heartbeat_{int(time.time())}",
                    "type": "heartbeat",
                    "channel": f"agent.{agent.agent_id}.heartbeat",
                    "payload": base64.b64encode(json.dumps({"status": "alive"}).encode()).decode(),
                    "timestamp": int(time.time()),
                    "nonce": base64.b64encode(b"heartbeat_nonce").decode(),
                    "signature": "",
                    "headers": {}
                }
                
                print("📤 Sending heartbeat AFTER authentication...")
                await websocket.send(json.dumps(heartbeat_message))
                print("✅ Heartbeat sent successfully!")
                
            else:
                print(f"❌ Authentication failed: {payload_data.get('message')}")
                
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print()

async def test_wrong_message_format():
    """Test sending authentication in wrong format"""
    print("🧪 TEST 3: Wrong Message Format (Should Fail)")
    print("=" * 50)
    
    agent = DiagnosticAgent("format-agent-001")
    
    try:
        headers = {
            "X-Agent-ID": agent.agent_id,
            "X-Agent-Public-Key": agent.public_key_b64,
            "User-Agent": "Aegis-Agent/1.0"
        }
        
        async with websockets.connect("ws://localhost:8080/ws/agent", additional_headers=headers) as websocket:
            print("✅ Connected")
            
            # ❌ WRONG: Send raw authentication request (not in SecureMessage format)
            timestamp = int(time.time())
            nonce = base64.b64encode(b"auth_nonce_1234").decode('utf-8')
            
            signature_data = f"{agent.agent_id}:{agent.public_key_b64}:{timestamp}:{nonce}"
            signature = agent.sign_data(signature_data)
            
            # Direct auth request (wrong format)
            auth_request = {
                "agent_id": agent.agent_id,
                "public_key": agent.public_key_b64,
                "timestamp": timestamp,
                "nonce": nonce,
                "signature": signature
            }
            
            print("📤 Sending raw authentication request (wrong format)...")
            await websocket.send(json.dumps(auth_request))
            
            # Wait for response
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                print(f"📨 Response: {response}")
            except asyncio.TimeoutError:
                print("⏰ No response (connection may have closed)")
                
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print()

async def main():
    print("🔍 Agent Authentication Diagnostic Test")
    print("This test shows the difference between correct and incorrect approaches")
    print("=" * 70)
    print()
    
    await test_wrong_approach()
    await test_correct_approach() 
    await test_wrong_message_format()
    
    print("🏁 Diagnostic tests completed!")
    print()
    print("📋 Summary:")
    print("• Test 1: Shows what happens when you don't authenticate first")
    print("• Test 2: Shows the correct authentication flow")
    print("• Test 3: Shows what happens with wrong message format")
    print()
    print("🎯 Key Takeaway:")
    print("You MUST send authentication in SecureMessage format FIRST,")
    print("before sending any other messages!")

if __name__ == "__main__":
    asyncio.run(main())
