#!/usr/bin/env python3
"""
Agent Connection Test Script
This script demonstrates the correct way to connect and register with the backend.
"""

import json
import base64
import time
import websocket
import threading
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class AgentConnectionTest:
    def __init__(self):
        # Generate Ed25519 key pair
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Get public key as base64
        pub_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.public_key_b64 = base64.b64encode(pub_key_bytes).decode('utf-8')
        
        self.websocket = None
        self.registration_id = None
        self.nonce = None
        self.server_time = None
        
    def connect(self):
        """Connect to WebSocket Gateway"""
        print("🔌 Connecting to WebSocket Gateway...")
        
        def on_message(ws, message):
            print(f"📨 Received: {message}")
            try:
                data = json.loads(message)
                self.handle_message(data)
            except Exception as e:
                print(f"❌ Error parsing message: {e}")
        
        def on_error(ws, error):
            print(f"❌ WebSocket error: {error}")
        
        def on_close(ws, close_status_code, close_msg):
            print(f"🔌 WebSocket closed: {close_status_code} - {close_msg}")
        
        def on_open(ws):
            print("✅ WebSocket connected!")
            # Send registration init immediately
            threading.Timer(1.0, self.send_registration_init).start()
        
        self.websocket = websocket.WebSocketApp(
            "ws://192.168.1.157:8080/ws/agent",
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close
        )
        
        self.websocket.run_forever()
    
    def send_registration_init(self):
        """Send registration init message"""
        print("📤 Sending registration init...")
        
        # Registration data
        registration_data = {
            "org_id": "default-org",
            "host_id": "test-agent-python",
            "agent_pubkey": self.public_key_b64,
            "machine_id_hash": "test-machine-hash",
            "agent_version": "1.0.0",
            "capabilities": {},
            "platform": {
                "arch": "arm64",
                "os": "linux"
            },
            "network": {
                "interface": "eth0"
            }
        }
        
        # Base64 encode the registration data
        payload = base64.b64encode(json.dumps(registration_data).encode()).decode()
        
        # Create message
        message = {
            "id": f"reg_init_{int(time.time() * 1000)}",
            "type": "request",
            "channel": "agent.registration",
            "timestamp": int(time.time()),
            "payload": payload,
            "headers": {}
        }
        
        self.websocket.send(json.dumps(message))
        print(f"✅ Registration init sent: {message['id']}")
    
    def send_registration_complete(self):
        """Send registration complete message"""
        print("📤 Sending registration complete...")
        
        # Create signature data: nonce + server_time + host_id
        signature_data = self.nonce + self.server_time + "test-agent-python"
        
        # Sign the data
        signature = self.private_key.sign(signature_data.encode())
        signature_b64 = base64.b64encode(signature).decode()
        
        # Completion data
        completion_data = {
            "registration_id": self.registration_id,
            "host_id": "test-agent-python",
            "signature": signature_b64
        }
        
        # Base64 encode the completion data
        payload = base64.b64encode(json.dumps(completion_data).encode()).decode()
        
        # Create message
        message = {
            "id": f"reg_complete_{int(time.time() * 1000)}",
            "type": "request",
            "channel": "agent.registration.complete",
            "timestamp": int(time.time()),
            "payload": payload,
            "headers": {}
        }
        
        self.websocket.send(json.dumps(message))
        print(f"✅ Registration complete sent: {message['id']}")
    
    def handle_message(self, data):
        """Handle incoming messages"""
        if data.get("channel") == "agent.registration" and data.get("type") == "response":
            print("📨 Received registration init response")
            
            # Parse the payload
            payload_data = json.loads(data["payload"])
            self.registration_id = payload_data["registration_id"]
            self.nonce = payload_data["nonce"]
            self.server_time = payload_data["server_time"]
            
            print(f"📋 Registration ID: {self.registration_id}")
            print(f"📋 Nonce: {self.nonce}")
            print(f"📋 Server Time: {self.server_time}")
            
            # Send registration complete
            threading.Timer(1.0, self.send_registration_complete).start()
            
        elif data.get("channel") == "agent.registration.complete" and data.get("type") == "response":
            print("🎉 Registration completed successfully!")
            print(f"📨 Response: {data}")
            
            # Close connection after successful registration
            threading.Timer(2.0, self.websocket.close).start()
            
        else:
            print(f"📨 Unknown message: {data}")

def main():
    print("🚀 Starting Agent Connection Test")
    print("=" * 50)
    
    agent = AgentConnectionTest()
    print(f"🔑 Generated public key: {agent.public_key_b64[:20]}...")
    
    try:
        agent.connect()
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
    except Exception as e:
        print(f"❌ Test failed: {e}")
    
    print("✅ Test completed")

if __name__ == "__main__":
    main()
