package ebpf

import (
	"context"
	"fmt"
	"log"
	"time"

	"agents/aegis/internal/telemetry"
	"agents/aegis/pkg/models"
)

// PolicyWriter applies policy snapshots to eBPF maps
type PolicyWriter struct {
	mapManager   MapManagerInterface
	eventEmitter interface{} // *telemetry.EventEmitter or *telemetry.ConsoleEmitter
}

// NewPolicyWriter creates a new policy writer
func NewPolicyWriter(mapManager MapManagerInterface, eventEmitter interface{}) *PolicyWriter {
	return &PolicyWriter{
		mapManager:   mapManager,
		eventEmitter: eventEmitter,
	}
}

// ApplySnapshot applies a policy snapshot to eBPF maps
func (pw *PolicyWriter) ApplySnapshot(ctx context.Context, snapshot *PolicySnapshot) error {
	log.Printf("[writer] Applying policy snapshot: %s", snapshot.ID)

	// Set enforcement mode
	if err := pw.setEnforcementMode(snapshot.Mode); err != nil {
		return fmt.Errorf("failed to set enforcement mode: %w", err)
	}

	// Clear existing policies
	if err := pw.clearExistingPolicies(); err != nil {
		return fmt.Errorf("failed to clear existing policies: %w", err)
	}

	// Apply policy edges
	if len(snapshot.PolicyEdges) > 0 {
		if err := pw.applyPolicyEdges(ctx, snapshot.PolicyEdges); err != nil {
			return fmt.Errorf("failed to apply policy edges: %w", err)
		}
		log.Printf("[writer] Applied %d policy edges", len(snapshot.PolicyEdges))
	}

	// Apply allow CIDRs
	if len(snapshot.AllowCIDRs) > 0 {
		if err := pw.applyAllowCIDRs(ctx, snapshot.AllowCIDRs); err != nil {
			return fmt.Errorf("failed to apply allow CIDRs: %w", err)
		}
		log.Printf("[writer] Applied %d allow CIDRs", len(snapshot.AllowCIDRs))
	}

	// Emit success event
	if emitter, ok := pw.eventEmitter.(*telemetry.ConsoleEmitter); ok {
		emitter.Emit(telemetry.Event{
			Type: telemetry.EventTypeEnforceOK,
			Data: map[string]interface{}{
				"snapshot_id":   snapshot.ID,
				"policy_edges":  len(snapshot.PolicyEdges),
				"allow_cidrs":   len(snapshot.AllowCIDRs),
				"mode":          snapshot.Mode,
				"timestamp":     time.Now(),
			},
			Message: fmt.Sprintf("Successfully applied policy snapshot %s", snapshot.ID),
		})
	}

	log.Printf("[writer] Successfully applied policy snapshot: %s", snapshot.ID)
	return nil
}

// setEnforcementMode sets the enforcement mode
func (pw *PolicyWriter) setEnforcementMode(mode string) error {
	var modeValue uint32
	switch mode {
	case "observe", "log", "0":
		modeValue = 0
	case "block", "enforce", "1":
		modeValue = 1
	default:
		return fmt.Errorf("invalid mode: %s", mode)
	}

	if err := pw.mapManager.SetMode(modeValue); err != nil {
		return fmt.Errorf("failed to set mode: %w", err)
	}

	log.Printf("[writer] Set enforcement mode to %s (%d)", mode, modeValue)
	return nil
}

// clearExistingPolicies clears existing policies from maps
func (pw *PolicyWriter) clearExistingPolicies() error {
	if err := pw.mapManager.ClearPolicyEdges(); err != nil {
		return fmt.Errorf("failed to clear policy edges: %w", err)
	}

	if err := pw.mapManager.ClearAllowCIDRs(); err != nil {
		return fmt.Errorf("failed to clear allow CIDRs: %w", err)
	}

	log.Printf("[writer] Cleared existing policies")
	return nil
}

// applyPolicyEdges applies policy edges to the eBPF map
func (pw *PolicyWriter) applyPolicyEdges(ctx context.Context, edges []PolicyEdge) error {
	for i, edge := range edges {
		// Convert to eBPF format
		ebpfEdge := PolicyEdge{
			SrcIP:      edge.SrcIP,
			DstIP:      edge.DstIP,
			SrcMask:    edge.SrcMask,
			DstMask:    edge.DstMask,
			SrcPort:    edge.SrcPort,
			DstPort:    edge.DstPort,
			Protocol:   edge.Protocol,
			Action:     edge.Action,
			Priority:   edge.Priority,
			ProcessUID: edge.ProcessUID,
			ProcessGID: edge.ProcessGID,
			Timestamp:  uint64(time.Now().Unix()),
		}

		// Write to eBPF map
		if err := pw.mapManager.WritePolicyEdge(uint32(i+1), ebpfEdge); err != nil {
			return fmt.Errorf("failed to write policy edge %d: %w", i+1, err)
		}

		log.Printf("[writer] Applied policy edge %d: %s -> %s (action=%d)", 
			i+1, formatIP(edge.SrcIP), formatIP(edge.DstIP), edge.Action)
	}

	return nil
}

// applyAllowCIDRs applies allow CIDRs to the eBPF map
func (pw *PolicyWriter) applyAllowCIDRs(ctx context.Context, cidrs []AllowCIDR) error {
	for _, cidr := range cidrs {
		// Set timestamp
		cidr.Timestamp = uint64(time.Now().Unix())

		// Write to eBPF map
		if err := pw.mapManager.WriteAllowCIDR(cidr); err != nil {
			return fmt.Errorf("failed to write allow CIDR: %w", err)
		}

		log.Printf("[writer] Applied allow CIDR: %s/%d (action=%d)", 
			formatIP(cidr.IP), cidr.PrefixLen, cidr.Action)
	}

	return nil
}

// PolicySnapshot represents a policy snapshot to apply
type PolicySnapshot struct {
	ID           string        `json:"id"`
	Mode         string        `json:"mode"`
	PolicyEdges  []PolicyEdge  `json:"policy_edges"`
	AllowCIDRs   []AllowCIDR   `json:"allow_cidrs"`
	CreatedAt    time.Time     `json:"created_at"`
	AssignmentID string        `json:"assignment_id,omitempty"`
}

// CreateSnapshotFromAssignment creates a policy snapshot from an assignment
func CreateSnapshotFromAssignment(assignment *models.Assignment) (*PolicySnapshot, error) {
	// Parse policy content
	policyData, err := parsePolicyContent(string(assignment.Bundle.Content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy content: %w", err)
	}

	// Determine mode from assignment
	mode := "observe" // Default
	if assignment.DryRun {
		mode = "observe"
	} else {
		mode = "block"
	}

	snapshot := &PolicySnapshot{
		ID:           fmt.Sprintf("snapshot-%s-%d", assignment.ID, time.Now().Unix()),
		Mode:         mode,
		PolicyEdges:  policyData.PolicyEdges,
		AllowCIDRs:   policyData.AllowCIDRs,
		CreatedAt:    time.Now(),
		AssignmentID: assignment.ID,
	}

	return snapshot, nil
}

// parsePolicyContent parses policy content from a bundle
func parsePolicyContent(content string) (*PolicyData, error) {
	// This is a simplified parser - in practice you'd parse JSON/YAML
	// For now, we'll create a mock policy that blocks 8.8.8.8
	
	// Parse 8.8.8.8
	dstIP := uint32(8)<<24 | uint32(8)<<16 | uint32(8)<<8 | uint32(8)
	
	policyData := &PolicyData{
		PolicyEdges: []PolicyEdge{
			{
				SrcIP:      0, // Any source
				DstIP:      dstIP,
				SrcMask:    0,
				DstMask:    0xFFFFFFFF,
				SrcPort:    0,
				DstPort:    0,
				Protocol:   6, // TCP
				Action:     0, // BLOCK
				Priority:   1,
				ProcessUID: 0,
				ProcessGID: 0,
				Timestamp:  uint64(time.Now().Unix()),
			},
		},
		AllowCIDRs: []AllowCIDR{
			{
				IP:        0, // Allow all other traffic
				PrefixLen: 0,
				Action:    1, // ALLOW
				Priority:  0,
				Timestamp: uint64(time.Now().Unix()),
			},
		},
	}

	return policyData, nil
}

// PolicyData represents parsed policy data
type PolicyData struct {
	PolicyEdges []PolicyEdge `json:"policy_edges"`
	AllowCIDRs  []AllowCIDR  `json:"allow_cidrs"`
}

// getProtocolName returns the protocol name for a protocol number
func getProtocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("proto-%d", protocol)
	}
}

// RollbackSnapshot rolls back a policy snapshot
func (pw *PolicyWriter) RollbackSnapshot(ctx context.Context, snapshotID string) error {
	log.Printf("[writer] Rolling back policy snapshot: %s", snapshotID)

	// Clear all policies
	if err := pw.clearExistingPolicies(); err != nil {
		return fmt.Errorf("failed to clear policies during rollback: %w", err)
	}

	// Set to observe mode
	if err := pw.mapManager.SetMode(0); err != nil {
		return fmt.Errorf("failed to set observe mode during rollback: %w", err)
	}

	// Emit rollback event
	if emitter, ok := pw.eventEmitter.(*telemetry.ConsoleEmitter); ok {
		emitter.Emit(telemetry.Event{
			Type: telemetry.EventTypeRollbackOK,
			Data: map[string]interface{}{
				"snapshot_id": snapshotID,
				"timestamp":   time.Now(),
			},
			Message: fmt.Sprintf("Successfully rolled back policy snapshot %s", snapshotID),
		})
	}

	log.Printf("[writer] Successfully rolled back policy snapshot: %s", snapshotID)
	return nil
}
