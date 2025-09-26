#!/usr/bin/env python3
"""
AegisFlux Agent Authentication Test
This script demonstrates working authentication with the WebSocket Gateway
"""

import asyncio
import websockets
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class AegisAgent:
    def __init__(self, agent_id="test-agent-001"):
        self.agent_id = agent_id
        self.private_key, self.public_key_b64 = self.generate_keypair()
        self.websocket = None
        self.authenticated = False
        
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
    
    async def connect(self, url="ws://localhost:8080/ws/agent"):
        """Connect to WebSocket Gateway"""
        headers = {
            "X-Agent-ID": self.agent_id,
            "X-Agent-Public-Key": self.public_key_b64,
            "User-Agent": "Aegis-Agent/1.0"
        }
        
        print(f"🔗 Connecting to {url}")
        print(f"🆔 Agent ID: {self.agent_id}")
        print(f"🔑 Public Key: {self.public_key_b64}")
        
        self.websocket = await websockets.connect(url, additional_headers=headers)
        print("✅ WebSocket connection established")
        
    async def authenticate(self):
        """Authenticate with the backend"""
        if not self.websocket:
            raise Exception("Not connected to WebSocket")
            
        # Create authentication request
        timestamp = int(time.time())
        nonce = base64.b64encode(b"auth_nonce_1234").decode('utf-8')
        
        # CRITICAL: Backend expects this exact signature data format
        signature_data = f"{self.agent_id}:{self.public_key_b64}:{timestamp}:{nonce}"
        signature = self.sign_data(signature_data)
        
        auth_request = {
            "agent_id": self.agent_id,
            "public_key": self.public_key_b64,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature
        }
        
        # Wrap in SecureMessage format (backend requirement)
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
        await self.websocket.send(json.dumps(secure_message))
        
        # Wait for response
        response = await asyncio.wait_for(self.websocket.recv(), timeout=10.0)
        response_data = json.loads(response)
        
        # Decode response payload
        payload_data = json.loads(base64.b64decode(response_data["payload"]).decode())
        
        if payload_data.get("success"):
            self.authenticated = True
            print("🎉 Authentication SUCCESSFUL!")
            print(f"📋 Session Token: {payload_data.get('session_token', 'N/A')[:50]}...")
            print(f"⏰ Expires At: {payload_data.get('expires_at', 'N/A')}")
            return True
        else:
            print(f"❌ Authentication FAILED: {payload_data.get('message', 'Unknown error')}")
            return False
    
    async def send_heartbeat(self):
        """Send heartbeat message"""
        if not self.authenticated:
            raise Exception("Not authenticated")
            
        heartbeat_message = {
            "id": f"heartbeat_{int(time.time())}",
            "type": "heartbeat",
            "channel": f"agent.{self.agent_id}.heartbeat",
            "payload": base64.b64encode(json.dumps({"status": "alive"}).encode()).decode(),
            "timestamp": int(time.time()),
            "nonce": base64.b64encode(b"heartbeat_nonce").decode(),
            "signature": "",
            "headers": {}
        }
        
        await self.websocket.send(json.dumps(heartbeat_message))
        print("💓 Heartbeat sent")
    
    async def close(self):
        """Close WebSocket connection"""
        if self.websocket:
            await self.websocket.close()
            print("🔌 Connection closed")

async def main():
    print("🚀 AegisFlux Agent Authentication Test")
    print("=" * 50)
    
    agent = AegisAgent("working-agent-001")
    
    try:
        # Connect to WebSocket Gateway
        await agent.connect()
        
        # Authenticate
        success = await agent.authenticate()
        
        if success:
            # Send heartbeat
            await agent.send_heartbeat()
            
            # Keep connection alive for testing
            print("⏳ Keeping connection alive for 5 seconds...")
            await asyncio.sleep(5)
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await agent.close()
        print("🏁 Test completed")

if __name__ == "__main__":
    asyncio.run(main())
