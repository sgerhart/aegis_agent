package network

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// InterfaceAssignment represents a backend assignment of interfaces for policy enforcement
type InterfaceAssignment struct {
	AgentUID     string   `json:"agent_uid"`
	HostID       string   `json:"host_id"`
	Interfaces   []string `json:"interfaces"`   // Target interfaces for enforcement
	Mode         string   `json:"mode"`         // "observe" or "block"
	AssignmentID string   `json:"assignment_id"`
	CreatedAt    string   `json:"created_at"`
}

// InterfaceAssignmentRequest represents a request to assign interfaces
type InterfaceAssignmentRequest struct {
	Interfaces []string `json:"interfaces"`
	Mode       string   `json:"mode"`
}

// InterfaceAssignmentResponse represents the response to an interface assignment
type InterfaceAssignmentResponse struct {
	Success      bool     `json:"success"`
	Message      string   `json:"message"`
	Attached     []string `json:"attached"`     // Successfully attached interfaces
	Failed       []string `json:"failed"`       // Failed to attach interfaces
	AssignmentID string   `json:"assignment_id"`
}

// BackendInterfaceAPI handles backend interface assignment requests
type BackendInterfaceAPI struct {
	interfaceManager *InterfaceManager
	agentUID         string
	hostID           string
}

// NewBackendInterfaceAPI creates a new backend interface API
func NewBackendInterfaceAPI(interfaceManager *InterfaceManager, agentUID, hostID string) *BackendInterfaceAPI {
	return &BackendInterfaceAPI{
		interfaceManager: interfaceManager,
		agentUID:         agentUID,
		hostID:           hostID,
	}
}

// HandleInterfaceAssignment handles interface assignment requests from the backend
func (api *BackendInterfaceAPI) HandleInterfaceAssignment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req InterfaceAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate request
	if len(req.Interfaces) == 0 {
		http.Error(w, "No interfaces specified", http.StatusBadRequest)
		return
	}

	if req.Mode != "observe" && req.Mode != "block" {
		http.Error(w, "Invalid mode. Must be 'observe' or 'block'", http.StatusBadRequest)
		return
	}

	// Process interface assignment
	response := api.processInterfaceAssignment(req)

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// processInterfaceAssignment processes the interface assignment
func (api *BackendInterfaceAPI) processInterfaceAssignment(req InterfaceAssignmentRequest) InterfaceAssignmentResponse {
	response := InterfaceAssignmentResponse{
		Success:      true,
		Message:      "Interface assignment processed",
		Attached:     []string{},
		Failed:       []string{},
		AssignmentID: fmt.Sprintf("iface-assign-%d", time.Now().UnixNano()),
	}

	// Get available interfaces
	availableInterfaces, err := api.interfaceManager.GetEnforcementInterfaces()
	if err != nil {
		response.Success = false
		response.Message = fmt.Sprintf("Failed to get available interfaces: %v", err)
		return response
	}

	// Create map of available interfaces
	availableMap := make(map[string]bool)
	for _, iface := range availableInterfaces {
		availableMap[iface.Name] = true
	}

	// Process each requested interface
	for _, ifaceName := range req.Interfaces {
		// Check if interface is available
		if !availableMap[ifaceName] {
			response.Failed = append(response.Failed, fmt.Sprintf("%s (not available)", ifaceName))
			continue
		}

		// Attach to interface
		if err := api.interfaceManager.AttachToInterface(ifaceName); err != nil {
			response.Failed = append(response.Failed, fmt.Sprintf("%s (%v)", ifaceName, err))
			log.Printf("[backend-api] Failed to attach to interface %s: %v", ifaceName, err)
		} else {
			response.Attached = append(response.Attached, ifaceName)
			log.Printf("[backend-api] Successfully attached to interface %s", ifaceName)
		}
	}

	// Update success status
	if len(response.Attached) == 0 {
		response.Success = false
		response.Message = "Failed to attach to any interfaces"
	} else if len(response.Failed) > 0 {
		response.Message = fmt.Sprintf("Attached to %d interfaces, %d failed", 
			len(response.Attached), len(response.Failed))
	}

	return response
}

// HandleInterfaceStatus returns the current interface status
func (api *BackendInterfaceAPI) HandleInterfaceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get current interface status
	attached := api.interfaceManager.GetAttachedInterfaces()
	available, err := api.interfaceManager.GetEnforcementInterfaces()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get interfaces: %v", err), http.StatusInternalServerError)
		return
	}

	// Get default interface
	defaultIface, _ := api.interfaceManager.GetDefaultInterface()

	status := map[string]interface{}{
		"agent_uid":        api.agentUID,
		"host_id":          api.hostID,
		"default_interface": defaultIface,
		"attached":         attached,
		"available":        available,
		"attached_count":   len(attached),
		"available_count":  len(available),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// HandleInterfaceDetach detaches from specified interfaces
func (api *BackendInterfaceAPI) HandleInterfaceDetach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Interfaces []string `json:"interfaces"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	response := struct {
		Success bool     `json:"success"`
		Message string   `json:"message"`
		Detached []string `json:"detached"`
		Failed   []string `json:"failed"`
	}{
		Success:  true,
		Message:  "Interface detachment processed",
		Detached: []string{},
		Failed:   []string{},
	}

	// Process each interface
	for _, ifaceName := range req.Interfaces {
		if err := api.interfaceManager.DetachFromInterface(ifaceName); err != nil {
			response.Failed = append(response.Failed, fmt.Sprintf("%s (%v)", ifaceName, err))
		} else {
			response.Detached = append(response.Detached, ifaceName)
		}
	}

	if len(response.Detached) == 0 {
		response.Success = false
		response.Message = "Failed to detach from any interfaces"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// RegisterRoutes registers the interface API routes
func (api *BackendInterfaceAPI) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/interfaces/assign", api.HandleInterfaceAssignment)
	mux.HandleFunc("/interfaces/status", api.HandleInterfaceStatus)
	mux.HandleFunc("/interfaces/detach", api.HandleInterfaceDetach)
}
