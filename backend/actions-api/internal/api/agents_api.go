package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"backend/actions-api/internal/store"
)

// GetAgents handles GET /agents with filtering support
func (s *Server) GetAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters for filtering
	labelFilter := r.URL.Query().Get("label")
	hostnameFilter := r.URL.Query().Get("hostname")
	hostIDFilter := r.URL.Query().Get("host_id")
	ipFilter := r.URL.Query().Get("ip")

	// Get all agents
	allAgents := s.store.ListAgents()
	var filteredAgents []*store.Agent

	// Apply filters
	for _, agent := range allAgents {
		// Label filter
		if labelFilter != "" {
			if !agent.Labels[labelFilter] {
				continue
			}
		}

		// Hostname filter (exact match)
		if hostnameFilter != "" {
			if agent.Hostname != hostnameFilter {
				continue
			}
		}

		// Host ID filter (exact match)
		if hostIDFilter != "" {
			if agent.HostID != hostIDFilter {
				continue
			}
		}

		// IP filter (search in network.ifaces.addrs)
		if ipFilter != "" {
			if !s.agentHasIP(agent, ipFilter) {
				continue
			}
		}

		filteredAgents = append(filteredAgents, agent)
	}

	// Convert to response format
	agentResponses := make([]AgentResponse, len(filteredAgents))
	for i, agent := range filteredAgents {
		agentResponses[i] = s.agentToResponse(agent)
	}

	resp := AgentsListResponse{
		Agents: agentResponses,
		Total:  len(agentResponses),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetAgent handles GET /agents/{agent_uid}
func (s *Server) GetAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract agent UID from path
	path := strings.TrimPrefix(r.URL.Path, "/agents/")
	if path == "" {
		http.Error(w, "Missing agent_uid", http.StatusBadRequest)
		return
	}

	agent, exists := s.store.GetAgent(path)
	if !exists {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	agentResp := s.agentToResponse(agent)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agentResp)
}

// UpdateAgentLabels handles PUT /agents/{agent_uid}/labels
func (s *Server) UpdateAgentLabels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract agent UID from path
	path := strings.TrimPrefix(r.URL.Path, "/agents/")
	path = strings.TrimSuffix(path, "/labels")
	if path == "" {
		http.Error(w, "Missing agent_uid", http.StatusBadRequest)
		return
	}

	var req LabelsUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate request
	if len(req.Add) == 0 && len(req.Remove) == 0 {
		http.Error(w, "No labels to add or remove", http.StatusBadRequest)
		return
	}

	// Update labels
	if err := s.store.UpdateAgentLabels(path, req.Add, req.Remove); err != nil {
		if err == store.ErrAgentNotFound {
			http.Error(w, "Agent not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return updated agent
	agent, exists := s.store.GetAgent(path)
	if !exists {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	agentResp := s.agentToResponse(agent)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agentResp)
}

// UpdateAgentNote handles PUT /agents/{agent_uid}/note
func (s *Server) UpdateAgentNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract agent UID from path
	path := strings.TrimPrefix(r.URL.Path, "/agents/")
	path = strings.TrimSuffix(path, "/note")
	if path == "" {
		http.Error(w, "Missing agent_uid", http.StatusBadRequest)
		return
	}

	var req NoteUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Update note
	if err := s.store.UpdateAgentNote(path, req.Note); err != nil {
		if err == store.ErrAgentNotFound {
			http.Error(w, "Agent not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return updated agent
	agent, exists := s.store.GetAgent(path)
	if !exists {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	agentResp := s.agentToResponse(agent)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agentResp)
}

// agentToResponse converts a store.Agent to AgentResponse
func (s *Server) agentToResponse(agent *store.Agent) AgentResponse {
	// Convert map[string]bool to []string for labels
	labels := make([]string, 0, len(agent.Labels))
	for label := range agent.Labels {
		labels = append(labels, label)
	}

	return AgentResponse{
		AgentUID:      agent.AgentUID,
		OrgID:         agent.OrgID,
		HostID:        agent.HostID,
		Hostname:      agent.Hostname,
		MachineIDHash: agent.MachineIDHash,
		AgentVersion:  agent.AgentVersion,
		Capabilities:  agent.Capabilities,
		Platform:      agent.Platform,
		Network:       agent.Network,
		Labels:        labels,
		Note:          agent.Note,
		PublicKey:     agent.PublicKey,
		RegisteredAt:  agent.RegisteredAt,
		LastSeenAt:    agent.LastSeenAt,
	}
}

// agentHasIP checks if an agent has a specific IP address in its network configuration
func (s *Server) agentHasIP(agent *store.Agent, ip string) bool {
	if agent.Network == nil {
		return false
	}

	// Look for ifaces.addrs in the network configuration
	if ifaces, ok := agent.Network["ifaces"].(map[string]any); ok {
		if addrs, ok := ifaces["addrs"].([]any); ok {
			for _, addr := range addrs {
				if addrStr, ok := addr.(string); ok {
					if addrStr == ip {
						return true
					}
				}
			}
		}
	}

	return false
}
