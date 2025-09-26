package store

import (
	"sync"
	"time"
)

// Agent represents a registered agent with all metadata
type Agent struct {
	AgentUID       string                 `json:"agent_uid"`
	OrgID          string                 `json:"org_id"`
	HostID         string                 `json:"host_id"`
	Hostname       string                 `json:"hostname"`
	MachineIDHash  string                 `json:"machine_id_hash"`
	AgentVersion   string                 `json:"agent_version"`
	Capabilities   map[string]any         `json:"capabilities"`
	Platform       map[string]any         `json:"platform"`
	Network        map[string]any         `json:"network"`
	Labels         map[string]bool        `json:"-"` // Internal storage as map
	Note           string                 `json:"note"`
	PublicKey      string                 `json:"public_key"`
	RegisteredAt   time.Time              `json:"registered_at"`
	LastSeenAt     time.Time              `json:"last_seen_at"`
}

// PendingRegistration represents a registration in progress
type PendingRegistration struct {
	RegistrationID string                 `json:"registration_id"`
	OrgID          string                 `json:"org_id"`
	HostID         string                 `json:"host_id"`
	Hostname       string                 `json:"hostname"`
	MachineIDHash  string                 `json:"machine_id_hash"`
	AgentVersion   string                 `json:"agent_version"`
	Capabilities   map[string]any         `json:"capabilities"`
	Platform       map[string]any         `json:"platform"`
	Network        map[string]any         `json:"network"`
	PublicKey      string                 `json:"public_key"`
	Nonce          string                 `json:"nonce"`
	ServerTime     string                 `json:"server_time"`
	CreatedAt      time.Time              `json:"created_at"`
	ExpiresAt      time.Time              `json:"expires_at"`
}

// Store provides in-memory storage for agents and pending registrations
type Store struct {
	mu                sync.RWMutex
	agents            map[string]*Agent            // agent_uid -> Agent
	pendingRegistrations map[string]*PendingRegistration // registration_id -> PendingRegistration
	agentsByHostID    map[string]string            // host_id -> agent_uid
}

// NewStore creates a new in-memory store
func NewStore() *Store {
	return &Store{
		agents:               make(map[string]*Agent),
		pendingRegistrations: make(map[string]*PendingRegistration),
		agentsByHostID:       make(map[string]string),
	}
}

// CreateAgent creates a new agent from a pending registration
func (s *Store) CreateAgent(agentUID, orgID, hostID, hostname, machineIDHash, agentVersion, publicKey string, capabilities, platform, network map[string]any) *Agent {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	agent := &Agent{
		AgentUID:      agentUID,
		OrgID:         orgID,
		HostID:        hostID,
		Hostname:      hostname,
		MachineIDHash: machineIDHash,
		AgentVersion:  agentVersion,
		Capabilities:  capabilities,
		Platform:      platform,
		Network:       network,
		Labels:        make(map[string]bool),
		Note:          "",
		PublicKey:     publicKey,
		RegisteredAt:  now,
		LastSeenAt:    now,
	}

	s.agents[agentUID] = agent
	s.agentsByHostID[hostID] = agentUID
	return agent
}

// GetAgent retrieves an agent by UID
func (s *Store) GetAgent(agentUID string) (*Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, exists := s.agents[agentUID]
	return agent, exists
}

// GetAgentByHostID retrieves an agent by host ID
func (s *Store) GetAgentByHostID(hostID string) (*Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agentUID, exists := s.agentsByHostID[hostID]
	if !exists {
		return nil, false
	}
	agent, exists := s.agents[agentUID]
	return agent, exists
}

// ListAgents returns all agents with optional filtering
func (s *Store) ListAgents() []*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	agents := make([]*Agent, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, agent)
	}
	return agents
}

// UpdateAgentLabels updates agent labels
func (s *Store) UpdateAgentLabels(agentUID string, addLabels, removeLabels []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	agent, exists := s.agents[agentUID]
	if !exists {
		return ErrAgentNotFound
	}

	// Add labels
	for _, label := range addLabels {
		agent.Labels[label] = true
	}

	// Remove labels
	for _, label := range removeLabels {
		delete(agent.Labels, label)
	}

	return nil
}

// UpdateAgentNote updates agent note
func (s *Store) UpdateAgentNote(agentUID, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	agent, exists := s.agents[agentUID]
	if !exists {
		return ErrAgentNotFound
	}

	agent.Note = note
	return nil
}

// CreatePendingRegistration creates a new pending registration
func (s *Store) CreatePendingRegistration(registrationID, orgID, hostID, hostname, machineIDHash, agentVersion, publicKey, nonce, serverTime string, capabilities, platform, network map[string]any) *PendingRegistration {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	pending := &PendingRegistration{
		RegistrationID: registrationID,
		OrgID:          orgID,
		HostID:         hostID,
		Hostname:       hostname,
		MachineIDHash:  machineIDHash,
		AgentVersion:   agentVersion,
		Capabilities:   capabilities,
		Platform:       platform,
		Network:        network,
		PublicKey:      publicKey,
		Nonce:          nonce,
		ServerTime:     serverTime,
		CreatedAt:      now,
		ExpiresAt:      now.Add(5 * time.Minute), // 5 minute expiry
	}

	s.pendingRegistrations[registrationID] = pending
	return pending
}

// GetPendingRegistration retrieves a pending registration by ID
func (s *Store) GetPendingRegistration(registrationID string) (*PendingRegistration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pending, exists := s.pendingRegistrations[registrationID]
	return pending, exists
}

// DeletePendingRegistration removes a pending registration
func (s *Store) DeletePendingRegistration(registrationID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingRegistrations, registrationID)
}

// CleanupExpiredPendingRegistrations removes expired pending registrations
func (s *Store) CleanupExpiredPendingRegistrations() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	now := time.Now()
	for id, pending := range s.pendingRegistrations {
		if now.After(pending.ExpiresAt) {
			delete(s.pendingRegistrations, id)
		}
	}
}



