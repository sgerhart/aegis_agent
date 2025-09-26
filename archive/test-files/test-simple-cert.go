package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	var (
		agentID    = flag.String("agent-id", "cert-test-agent", "Agent ID")
		backendURL = flag.String("backend-url", "wss://localhost:8080/ws/agent", "Backend WebSocket URL")
	)
	flag.Parse()

	// Create test certificates
	certPath, keyPath, caCertPath, err := createTestCertificates(*agentID)
	if err != nil {
		log.Fatalf("Failed to create test certificates: %v", err)
	}
	defer os.Remove(certPath)
	defer os.Remove(keyPath)
	defer os.Remove(caCertPath)

	fmt.Printf("Created test certificates:\n")
	fmt.Printf("  Agent Cert: %s\n", certPath)
	fmt.Printf("  Agent Key:  %s\n", keyPath)
	fmt.Printf("  CA Cert:    %s\n", caCertPath)

	// Test WebSocket connection with certificates
	fmt.Println("\n=== Testing Certificate-Based WebSocket Connection ===")
	testCertConnection(*backendURL, certPath, keyPath, caCertPath)
}

func testCertConnection(backendURL, certPath, keyPath, caCertPath string) {
	// Load certificates
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Printf("Failed to load certificate: %v", err)
		return
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Printf("Failed to read CA certificate: %v", err)
		return
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		log.Printf("Failed to parse CA certificate")
		return
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   "aegis-backend",
		MinVersion:   tls.VersionTLS12,
	}

	// Connect to WebSocket
	dialer := websocket.Dialer{
		TLSClientConfig: tlsConfig,
		HandshakeTimeout: 30 * time.Second,
	}

	headers := http.Header{}
	headers.Set("X-Agent-ID", "cert-test-agent")
	headers.Set("User-Agent", "Aegis-Agent/1.0")

	fmt.Printf("Connecting to %s with certificate authentication...\n", backendURL)
	conn, _, err := dialer.Dial(backendURL, headers)
	if err != nil {
		log.Printf("❌ Failed to connect: %v", err)
		return
	}
	defer conn.Close()

	fmt.Println("✅ Connected to WebSocket with certificate authentication!")

	// Send a test message
	testMsg := map[string]interface{}{
		"id":        "test_001",
		"type":      "event",
		"channel":   "agent.cert-test-agent.status",
		"payload":   `{"status":"online","timestamp":` + fmt.Sprintf("%d", time.Now().Unix()) + `}`,
		"timestamp": time.Now().Unix(),
		"nonce":     "test-nonce",
		"signature": "test-signature",
		"headers":   map[string]string{},
	}

	fmt.Println("Sending test message...")
	if err := conn.WriteJSON(testMsg); err != nil {
		log.Printf("❌ Failed to send message: %v", err)
		return
	}

	fmt.Println("✅ Sent test message")

	// Read response
	var response map[string]interface{}
	if err := conn.ReadJSON(&response); err != nil {
		log.Printf("❌ Failed to read response: %v", err)
		return
	}

	fmt.Printf("✅ Received response: %+v\n", response)

	// Pretty print the response
	responseJSON, _ := json.MarshalIndent(response, "", "  ")
	fmt.Printf("Response JSON:\n%s\n", responseJSON)
}

func createTestCertificates(agentID string) (string, string, string, error) {
	// Create CA certificate
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Aegis Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}

	// Save CA certificate
	caCertFile, err := os.CreateTemp("", "ca-cert.pem")
	if err != nil {
		return "", "", "", err
	}
	defer caCertFile.Close()

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if _, err := caCertFile.Write(caCertPEM); err != nil {
		return "", "", "", err
	}

	// Create agent certificate
	agentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}

	agentTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Aegis Agent"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    agentID,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}

	agentCertDER, err := x509.CreateCertificate(rand.Reader, &agentTemplate, &caTemplate, &agentKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}

	// Save agent certificate
	agentCertFile, err := os.CreateTemp("", "agent-cert.pem")
	if err != nil {
		return "", "", "", err
	}
	defer agentCertFile.Close()

	agentCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agentCertDER})
	if _, err := agentCertFile.Write(agentCertPEM); err != nil {
		return "", "", "", err
	}

	// Save agent private key
	agentKeyFile, err := os.CreateTemp("", "agent-key.pem")
	if err != nil {
		return "", "", "", err
	}
	defer agentKeyFile.Close()

	agentKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(agentKey)})
	if _, err := agentKeyFile.Write(agentKeyPEM); err != nil {
		return "", "", "", err
	}

	return agentCertFile.Name(), agentKeyFile.Name(), caCertFile.Name(), nil
}
