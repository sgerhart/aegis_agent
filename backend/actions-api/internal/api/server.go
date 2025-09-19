package api

import (
	"log"
	"net/http"
	"strings"
	"time"
)


// SetupRoutes configures all the HTTP routes
func (s *Server) SetupRoutes() {
	// Registration endpoints
	s.mux.HandleFunc("/agents/register/init", s.PostRegisterInit)
	s.mux.HandleFunc("/agents/register/complete", s.PostRegisterComplete)

	// Agents API endpoints
	s.mux.HandleFunc("/agents", s.GetAgents)
	s.mux.HandleFunc("/agents/", s.agentDispatch)

	// Health check
	s.mux.HandleFunc("/healthz", s.healthCheck)

	// Start cleanup goroutine for expired pending registrations
	go s.cleanupExpiredRegistrations()
}

// agentDispatch handles subrouter emulation for /agents/{uid}/* paths
func (s *Server) agentDispatch(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/agents/")
	
	// Split path to get agent UID and remaining path
	parts := strings.SplitN(path, "/", 2)
	agentUID := parts[0]
	
	if agentUID == "" {
		http.Error(w, "Missing agent_uid", http.StatusBadRequest)
		return
	}

	// Check if agent exists
	if _, exists := s.store.GetAgent(agentUID); !exists {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	// Route based on remaining path
	if len(parts) == 1 {
		// /agents/{uid} - GET agent details
		s.GetAgent(w, r)
		return
	}

	remainingPath := parts[1]
	switch remainingPath {
	case "labels":
		s.UpdateAgentLabels(w, r)
	case "note":
		s.UpdateAgentNote(w, r)
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

// healthCheck handles the health check endpoint
func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"actions-api"}`))
}

// cleanupExpiredRegistrations periodically cleans up expired pending registrations
func (s *Server) cleanupExpiredRegistrations() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.store.CleanupExpiredPendingRegistrations()
	}
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Handle preflight requests
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Add request logging
	log.Printf("[%s] %s %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Serve the request
	s.mux.ServeHTTP(w, r)
}

// Start starts the HTTP server
func (s *Server) Start(addr string) error {
	log.Printf("Starting actions-api server on %s", addr)
	return http.ListenAndServe(addr, s)
}
