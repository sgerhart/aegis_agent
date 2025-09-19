package models

import (
	"time"
)

// Assignment represents a policy assignment with enhanced safety features
type Assignment struct {
	ID          string            `json:"id"`
	HostID      string            `json:"host_id"`
	PolicyID    string            `json:"policy_id"`
	Version     string            `json:"version"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`   // TTL enforcement
	Selectors   map[string]string `json:"selectors,omitempty"`    // Host selector matching
	DryRun      bool              `json:"dry_run,omitempty"`      // Verification-only mode
	Priority    int               `json:"priority,omitempty"`     // Assignment priority
	Bundle      Bundle            `json:"bundle"`                 // Policy bundle with signature
	Metadata    map[string]any    `json:"metadata,omitempty"`     // Additional metadata
}


// AssignmentRequest represents a request to apply an assignment
type AssignmentRequest struct {
	AssignmentID string `json:"assignment_id"`
	DryRun       bool   `json:"dry_run,omitempty"`
	Force        bool   `json:"force,omitempty"` // Override safety checks
}

// AssignmentResponse represents the result of applying an assignment
type AssignmentResponse struct {
	Success     bool              `json:"success"`
	Message     string            `json:"message,omitempty"`
	Warnings    []string          `json:"warnings,omitempty"`
	Changes     []string          `json:"changes,omitempty"`     // What would change
	RollbackID  string            `json:"rollback_id,omitempty"` // For safe rollback
	Metadata    map[string]any    `json:"metadata,omitempty"`
}

// HostSelector represents criteria for matching assignments to hosts
type HostSelector struct {
	Labels     map[string]string `json:"labels,omitempty"`
	Platform   string            `json:"platform,omitempty"`
	Arch       string            `json:"arch,omitempty"`
	Kernel     string            `json:"kernel,omitempty"`
	Capabilities []string        `json:"capabilities,omitempty"`
}

// IsExpired checks if the assignment has expired
func (a *Assignment) IsExpired() bool {
	if a.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*a.ExpiresAt)
}

// MatchesHost checks if the assignment matches the given host selectors
func (a *Assignment) MatchesHost(hostInfo map[string]any) bool {
	if len(a.Selectors) == 0 {
		return true // No selectors means match all
	}

	// Check platform match
	if platform, ok := a.Selectors["platform"]; ok {
		if hostPlatform, exists := hostInfo["platform"]; !exists || hostPlatform != platform {
			return false
		}
	}

	// Check architecture match
	if arch, ok := a.Selectors["arch"]; ok {
		if hostArch, exists := hostInfo["arch"]; !exists || hostArch != arch {
			return false
		}
	}

	// Check kernel version match
	if kernel, ok := a.Selectors["kernel"]; ok {
		if hostKernel, exists := hostInfo["kernel"]; !exists || hostKernel != kernel {
			return false
		}
	}

	// Check capabilities match
	if caps, ok := a.Selectors["capabilities"]; ok {
		if hostCaps, exists := hostInfo["capabilities"]; !exists {
			return false
		} else {
			// Simple string matching for now - could be enhanced
			hostCapsStr, ok := hostCaps.(string)
			if !ok || hostCapsStr != caps {
				return false
			}
		}
	}

	return true
}

// Validate performs basic validation on the assignment
func (a *Assignment) Validate() error {
	if a.ID == "" {
		return ErrInvalidAssignment("missing ID")
	}
	if a.HostID == "" {
		return ErrInvalidAssignment("missing HostID")
	}
	if a.PolicyID == "" {
		return ErrInvalidAssignment("missing PolicyID")
	}
	if a.Version == "" {
		return ErrInvalidAssignment("missing Version")
	}
	return nil
}

// ErrInvalidAssignment represents an invalid assignment error
type ErrInvalidAssignment string

func (e ErrInvalidAssignment) Error() string {
	return "invalid assignment: " + string(e)
}
