package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	// Simple WebSocket test without encryption
	url := "ws://localhost:8080/ws/agent"
	
	// Create headers
	headers := http.Header{}
	headers.Set("X-Agent-ID", "simple-test-agent")
	headers.Set("X-Agent-Public-Key", "dGVzdC1wdWJsaWMta2V5") // base64 encoded test key
	headers.Set("User-Agent", "Aegis-Agent/1.0")
	
	// Connect to WebSocket
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(url, headers)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	
	log.Println("Connected to WebSocket!")
	
	// Send simple authentication message (base64 encoded payload)
	authPayloadB64 := "eyJhZ2VudF9pZCI6InNpbXBsZS10ZXN0LWFnZW50IiwicHVibGljX2tleSI6ImR0VnpjVzVwdWJsaWNLazV5IiwidGltZXN0YW1wIjoxNjk1MzI2NDAwLCJub25jZSI6InRlc3Qtbm9uY2UifQ=="
	
	authMsg := map[string]interface{}{
		"id":        "auth_001",
		"type":      "request",
		"channel":   "auth",
		"payload":   authPayloadB64, // Base64 encoded payload
		"timestamp": time.Now().Unix(),
		"nonce":     "dGVzdC1ub25jZQ==", // Base64 encoded nonce
		"signature": "dGVzdC1zaWduYXR1cmU=", // Base64 encoded signature
		"headers":   map[string]string{},
	}
	
	log.Println("Sending authentication message...")
	if err := conn.WriteJSON(authMsg); err != nil {
		log.Fatalf("Failed to send auth message: %v", err)
	}
	
	// Read response
	var response map[string]interface{}
	if err := conn.ReadJSON(&response); err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}
	
	log.Printf("Received response: %+v", response)
	
	// Pretty print the response
	responseJSON, _ := json.MarshalIndent(response, "", "  ")
	fmt.Printf("Response JSON:\n%s\n", responseJSON)
}
