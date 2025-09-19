package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"backend/actions-api/internal/store"
	"github.com/google/uuid"
)

// RegisterInitReq represents the initial registration request with extended metadata
type RegisterInitReq struct {
	OrgID          string         `json:"org_id"`
	HostID         string         `json:"host_id"`
	AgentPubKey    string         `json:"agent_pubkey"`
	MachineIDHash  string         `json:"machine_id_hash,omitempty"`
	AgentVersion   string         `json:"agent_version,omitempty"`
	Capabilities   map[string]any `json:"capabilities,omitempty"`
	Platform       map[string]any `json:"platform,omitempty"`
	Network        map[string]any `json:"network,omitempty"`
}

// RegisterInitResp represents the response to registration init
type RegisterInitResp struct {
	RegistrationID string `json:"registration_id"`
	Nonce          string `json:"nonce"`
	ServerTime     string `json:"server_time"`
}

// RegisterCompleteReq represents the registration completion request
type RegisterCompleteReq struct {
	RegistrationID string `json:"registration_id"`
	HostID         string `json:"host_id"`
	Signature      string `json:"signature"`
}

// RegisterCompleteResp represents the response to registration completion
type RegisterCompleteResp struct {
	AgentUID       string `json:"agent_uid"`
	BootstrapToken string `json:"bootstrap_token"`
}

// AgentResponse represents an agent in API responses
type AgentResponse struct {
	AgentUID       string         `json:"agent_uid"`
	OrgID          string         `json:"org_id"`
	HostID         string         `json:"host_id"`
	Hostname       string         `json:"hostname"`
	MachineIDHash  string         `json:"machine_id_hash"`
	AgentVersion   string         `json:"agent_version"`
	Capabilities   map[string]any `json:"capabilities"`
	Platform       map[string]any `json:"platform"`
	Network        map[string]any `json:"network"`
	Labels         []string       `json:"labels"` // Converted from map[string]bool
	Note           string         `json:"note"`
	PublicKey      string         `json:"public_key"`
	RegisteredAt   time.Time      `json:"registered_at"`
	LastSeenAt     time.Time      `json:"last_seen_at"`
}

// AgentsListResponse represents the response for listing agents
type AgentsListResponse struct {
	Agents []AgentResponse `json:"agents"`
	Total  int             `json:"total"`
}

// LabelsUpdateReq represents a request to update agent labels
type LabelsUpdateReq struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

// NoteUpdateReq represents a request to update agent note
type NoteUpdateReq struct {
	Note string `json:"note"`
}

// Server represents the API server
type Server struct {
	store *store.Store
	mux   *http.ServeMux
}

// NewServer creates a new API server
func NewServer() *Server {
	return &Server{
		store: store.NewStore(),
		mux:   http.NewServeMux(),
	}
}

// PostRegisterInit handles the initial registration request
func (s *Server) PostRegisterInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterInitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.OrgID == "" || req.HostID == "" || req.AgentPubKey == "" {
		http.Error(w, "Missing required fields: org_id, host_id, agent_pubkey", http.StatusBadRequest)
		return
	}

	// Check if agent already exists
	if _, exists := s.store.GetAgentByHostID(req.HostID); exists {
		http.Error(w, fmt.Sprintf("Agent already registered with host_id: %s", req.HostID), http.StatusConflict)
		return
	}

	// Generate registration ID and nonce
	registrationID := uuid.New().String()
	nonceBytes := make([]byte, 32)
	rand.Read(nonceBytes)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	serverTime := time.Now().UTC().Format(time.RFC3339)

	// Create pending registration
	s.store.CreatePendingRegistration(
		registrationID,
		req.OrgID,
		req.HostID,
		req.MachineIDHash, // Using machine_id_hash as hostname fallback
		req.MachineIDHash,
		req.AgentVersion,
		req.AgentPubKey,
		nonce,
		serverTime,
		req.Capabilities,
		req.Platform,
		req.Network,
	)

	resp := RegisterInitResp{
		RegistrationID: registrationID,
		Nonce:          nonce,
		ServerTime:     serverTime,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// PostRegisterComplete handles the registration completion request
func (s *Server) PostRegisterComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterCompleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.RegistrationID == "" || req.HostID == "" || req.Signature == "" {
		http.Error(w, "Missing required fields: registration_id, host_id, signature", http.StatusBadRequest)
		return
	}

	// Get pending registration
	pending, exists := s.store.GetPendingRegistration(req.RegistrationID)
	if !exists {
		http.Error(w, "Registration not found or expired", http.StatusNotFound)
		return
	}

	// Check if expired
	if time.Now().After(pending.ExpiresAt) {
		s.store.DeletePendingRegistration(req.RegistrationID)
		http.Error(w, "Registration expired", http.StatusGone)
		return
	}

	// Verify signature
	if !s.verifySignature(pending, req.Signature) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Generate agent UID and bootstrap token
	agentUID := uuid.New().String()
	bootstrapToken := uuid.New().String()

	// Create agent
	_ = s.store.CreateAgent(
		agentUID,
		pending.OrgID,
		pending.HostID,
		pending.Hostname,
		pending.MachineIDHash,
		pending.AgentVersion,
		pending.PublicKey,
		pending.Capabilities,
		pending.Platform,
		pending.Network,
	)

	// Clean up pending registration
	s.store.DeletePendingRegistration(req.RegistrationID)

	resp := RegisterCompleteResp{
		AgentUID:       agentUID,
		BootstrapToken: bootstrapToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// verifySignature verifies the agent's signature
func (s *Server) verifySignature(pending *store.PendingRegistration, signature string) bool {
	// Decode the public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pending.PublicKey)
	if err != nil {
		return false
	}

	// Decode the signature
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	// Create the message that should have been signed
	nonceBytes, err := base64.StdEncoding.DecodeString(pending.Nonce)
	if err != nil {
		return false
	}
	message := append(nonceBytes, []byte(pending.ServerTime+pending.HostID)...)

	// Verify the signature
	return ed25519.Verify(ed25519.PublicKey(pubKeyBytes), message, sigBytes)
}
