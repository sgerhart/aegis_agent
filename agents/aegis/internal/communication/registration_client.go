package communication

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// RegistrationClient handles the two-step agent registration process
type RegistrationClient struct {
	agentID        string
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	baseURL        string
	httpClient     *http.Client
	AgentUID       string
	BootstrapToken string
}

// RegistrationInitRequest represents the initial registration request
type RegistrationInitRequest struct {
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
	Timestamp int64  `json:"timestamp"`
}

// RegistrationInitResponse represents the initial registration response
type RegistrationInitResponse struct {
	Success       bool   `json:"success"`
	RegistrationID string `json:"registration_id"`
	Nonce         string `json:"nonce"`
	Message       string `json:"message,omitempty"`
}

// RegistrationCompleteRequest represents the completion request
type RegistrationCompleteRequest struct {
	RegistrationID string `json:"registration_id"`
	AgentID        string `json:"agent_id"`
	Nonce          string `json:"nonce"`
	Signature      string `json:"signature"`
	Timestamp      int64  `json:"timestamp"`
}

// RegistrationCompleteResponse represents the completion response
type RegistrationCompleteResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// NewRegistrationClient creates a new registration client
func NewRegistrationClient(agentID string, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, baseURL string) *RegistrationClient {
	return &RegistrationClient{
		agentID:    agentID,
		privateKey: privateKey,
		publicKey:  publicKey,
		baseURL:    baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Register performs the two-step registration process
func (rc *RegistrationClient) Register() error {
	log.Printf("[registration] Starting two-step registration process for agent %s", rc.agentID)

	// Step 1: Initialize registration
	registrationID, nonce, serverTime, hostID, err := rc.initRegistration()
	if err != nil {
		return fmt.Errorf("failed to initialize registration: %w", err)
	}

	log.Printf("[registration] Step 1 complete: registration_id=%s, nonce=%s, server_time=%s, host_id=%s", registrationID, nonce, serverTime, hostID)

	// Step 2: Complete registration
	if err := rc.completeRegistration(registrationID, nonce, serverTime, hostID); err != nil {
		return fmt.Errorf("failed to complete registration: %w", err)
	}

	log.Printf("[registration] Step 2 complete: agent %s successfully registered", rc.agentID)
	return nil
}

// initRegistration performs step 1: /agents/register/init
func (rc *RegistrationClient) initRegistration() (string, string, string, string, error) {
	// Prepare request with correct format for backend
	request := map[string]interface{}{
		"org_id":           "default-org",
		"host_id":          rc.agentID,
		"agent_pubkey":     base64.StdEncoding.EncodeToString(rc.publicKey),
		"machine_id_hash":  "agent-machine-hash",
		"agent_version":    "1.0.0",
		"capabilities":     map[string]interface{}{},
		"platform": map[string]interface{}{
			"os":   "linux",
			"arch": "arm64",
		},
		"network": map[string]interface{}{
			"interface": "eth0",
		},
	}

	// Send HTTP request
	url := fmt.Sprintf("%s/agents/register/init", rc.baseURL)
	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to marshal request: %w", err)
	}

	log.Printf("[registration] Sending init request to %s", url)
	resp, err := rc.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to send init request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to read response: %w", err)
	}

	// Check HTTP status code first
	if resp.StatusCode != 200 {
		return "", "", "", "", fmt.Errorf("init registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response - backend returns direct JSON with registration_id and nonce
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract registration_id and nonce
	registrationID, ok := response["registration_id"].(string)
	if !ok {
		return "", "", "", "", fmt.Errorf("invalid response: missing or invalid registration_id")
	}

	nonce, ok := response["nonce"].(string)
	if !ok {
		return "", "", "", "", fmt.Errorf("invalid response: missing or invalid nonce")
	}

	// Extract server_time and host_id from response
	serverTime, ok := response["server_time"].(string)
	if !ok {
		return "", "", "", "", fmt.Errorf("invalid response: missing or invalid server_time")
	}

	// Use the host_id from the request (same as agentID)
	hostID := rc.agentID

	return registrationID, nonce, serverTime, hostID, nil
}

// completeRegistration performs step 2: /agents/register/complete
func (rc *RegistrationClient) completeRegistration(registrationID, nonce, serverTime, hostID string) error {
	// Sign the nonce with server_time and host_id (backend expects this exact format)
	signature, err := rc.signNonce(nonce, serverTime, hostID)
	if err != nil {
		return fmt.Errorf("failed to sign nonce: %w", err)
	}

	log.Printf("[registration] Signing data: nonce=%s, server_time=%s, host_id=%s", nonce, serverTime, hostID)

	// Prepare request with correct format for backend (backend expects host_id and signature fields)
	request := map[string]interface{}{
		"registration_id": registrationID,
		"host_id":         hostID,  // Required by backend
		"signature":        signature, // Backend expects 'signature' field, not 'signed_nonce'
	}

	// Send HTTP request
	url := fmt.Sprintf("%s/agents/register/complete", rc.baseURL)
	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	log.Printf("[registration] Sending complete request to %s", url)
	resp, err := rc.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send complete request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check HTTP status code first
	if resp.StatusCode != 200 {
		log.Printf("[registration] Complete registration failed with status %d: %s", resp.StatusCode, string(body))
		return fmt.Errorf("complete registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("[registration] Complete registration response: %s", string(body))

	// Parse response - backend may return simple success or error message
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		// If JSON parsing fails, check if it's a simple success message
		responseText := string(body)
		if responseText == "success" || responseText == "ok" {
			return nil
		}
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Check if response indicates success
	if success, ok := response["success"].(bool); ok && success {
		return nil
	}

	// Check for alternative success indicators (agent_uid and bootstrap_token)
	if agentUID, hasUID := response["agent_uid"]; hasUID {
		if bootstrapToken, hasToken := response["bootstrap_token"]; hasToken {
			// Store the registration information
			rc.AgentUID = agentUID.(string)
			rc.BootstrapToken = bootstrapToken.(string)
			log.Printf("[registration] Registration successful - agent_uid: %v, bootstrap_token: %v", agentUID, bootstrapToken)
			return nil
		}
	}

	// If we get here, registration failed
	message := "unknown error"
	if msg, ok := response["message"].(string); ok {
		message = msg
	}
	return fmt.Errorf("complete registration failed: %s", message)
}

// signNonce signs the nonce with the agent's private key
func (rc *RegistrationClient) signNonce(nonce, serverTime, hostID string) (string, error) {
	// Decode the nonce from base64
	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Create data to sign: nonce + server_time.encode() + host_id.encode() (backend expects this exact format)
	// In Go: concatenate the raw bytes, not strings
	dataToSign := append(nonceBytes, []byte(serverTime)...)
	dataToSign = append(dataToSign, []byte(hostID)...)

	// Sign the data
	signature := ed25519.Sign(rc.privateKey, dataToSign)

	log.Printf("[registration] Data to sign (bytes): %x", dataToSign)
	log.Printf("[registration] Generated signature: %s", base64.StdEncoding.EncodeToString(signature))

	// Return base64 encoded signature
	return base64.StdEncoding.EncodeToString(signature), nil
}
