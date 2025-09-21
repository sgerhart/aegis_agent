package enforce

import (
	"fmt"
	"log"
	"strings"
	"time"

	"agents/aegis/internal/ebpf"
)

// Mode represents the enforcement mode
type Mode uint32

const (
	ModeObserve Mode = 0 // Log decisions but allow traffic
	ModeBlock   Mode = 1 // Actually block traffic
)

// String returns a string representation of the mode
func (m Mode) String() string {
	switch m {
	case ModeObserve:
		return "observe"
	case ModeBlock:
		return "block"
	default:
		return "unknown"
	}
}

// ModeManager manages enforcement modes
type ModeManager struct {
	mapManager *ebpf.MapManager
	currentMode Mode
}

// NewModeManager creates a new mode manager
func NewModeManager(mapManager *ebpf.MapManager) *ModeManager {
	return &ModeManager{
		mapManager: mapManager,
		currentMode: ModeObserve, // Default to observe mode
	}
}

// SetMode sets the enforcement mode
func (mm *ModeManager) SetMode(mode Mode) error {
	if err := mm.mapManager.SetMode(uint32(mode)); err != nil {
		return fmt.Errorf("failed to set mode to %s: %w", mode.String(), err)
	}
	
	mm.currentMode = mode
	log.Printf("[mode] Set enforcement mode to %s", mode.String())
	return nil
}

// GetMode gets the current enforcement mode
func (mm *ModeManager) GetMode() (Mode, error) {
	mode, err := mm.mapManager.GetMode()
	if err != nil {
		return ModeObserve, fmt.Errorf("failed to get mode: %w", err)
	}
	
	mm.currentMode = Mode(mode)
	return mm.currentMode, nil
}

// IsObserveMode returns true if in observe mode
func (mm *ModeManager) IsObserveMode() bool {
	return mm.currentMode == ModeObserve
}

// IsBlockMode returns true if in block mode
func (mm *ModeManager) IsBlockMode() bool {
	return mm.currentMode == ModeBlock
}

// ToggleMode toggles between observe and block modes
func (mm *ModeManager) ToggleMode() error {
	if mm.currentMode == ModeObserve {
		return mm.SetMode(ModeBlock)
	}
	return mm.SetMode(ModeObserve)
}

// SetModeFromAssignment sets mode based on assignment configuration
func (mm *ModeManager) SetModeFromAssignment(assignmentMode string) error {
	switch strings.ToLower(assignmentMode) {
	case "observe", "log", "0":
		return mm.SetMode(ModeObserve)
	case "block", "enforce", "1":
		return mm.SetMode(ModeBlock)
	default:
		return fmt.Errorf("unknown assignment mode: %s", assignmentMode)
	}
}

// GetModeInfo returns detailed mode information
func (mm *ModeManager) GetModeInfo() ModeInfo {
	return ModeInfo{
		CurrentMode: mm.currentMode,
		ModeString:  mm.currentMode.String(),
		IsObserve:   mm.IsObserveMode(),
		IsBlock:     mm.IsBlockMode(),
		LastUpdated: time.Now(),
	}
}

// ModeInfo contains detailed mode information
type ModeInfo struct {
	CurrentMode Mode      `json:"current_mode"`
	ModeString  string    `json:"mode_string"`
	IsObserve   bool      `json:"is_observe"`
	IsBlock     bool      `json:"is_block"`
	LastUpdated time.Time `json:"last_updated"`
}

// ValidateMode validates a mode string
func ValidateMode(modeStr string) (Mode, error) {
	switch strings.ToLower(modeStr) {
	case "observe", "log", "0":
		return ModeObserve, nil
	case "block", "enforce", "1":
		return ModeBlock, nil
	default:
		return ModeObserve, fmt.Errorf("invalid mode: %s (valid: observe, block)", modeStr)
	}
}

// ModeTransition represents a mode change
type ModeTransition struct {
	FromMode   Mode      `json:"from_mode"`
	ToMode     Mode      `json:"to_mode"`
	Timestamp  time.Time `json:"timestamp"`
	Reason     string    `json:"reason,omitempty"`
	AssignmentID string  `json:"assignment_id,omitempty"`
}

// CreateModeTransition creates a mode transition record
func CreateModeTransition(from, to Mode, reason, assignmentID string) ModeTransition {
	return ModeTransition{
		FromMode:     from,
		ToMode:       to,
		Timestamp:    time.Now(),
		Reason:       reason,
		AssignmentID: assignmentID,
	}
}

// LogModeTransition logs a mode transition
func LogModeTransition(transition ModeTransition) {
	log.Printf("[mode] Transition: %s -> %s (reason: %s, assignment: %s)", 
		transition.FromMode.String(), 
		transition.ToMode.String(), 
		transition.Reason,
		transition.AssignmentID)
}
