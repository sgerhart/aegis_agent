package enforce

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"agents/aegis/internal/telemetry"
)

// Verdict represents the decision verdict
type Verdict string

const (
	VerdictAllow  Verdict = "allow"
	VerdictBlock  Verdict = "block"
	VerdictLog    Verdict = "log"
	VerdictObserve Verdict = "observe_drop" // Would block in block mode
)

// String returns a string representation of the verdict
func (v Verdict) String() string {
	return string(v)
}

// Decision represents an enforcement decision
type Decision struct {
	Timestamp    time.Time         `json:"timestamp"`
	Program      string            `json:"program"`
	Map          string            `json:"map"`
	FiveTuple    FiveTuple         `json:"five_tuple"`
	Verdict      Verdict           `json:"verdict"`
	Reason       string            `json:"reason"`
	PolicyID     string            `json:"policy_id,omitempty"`
	EdgeID       uint32            `json:"edge_id,omitempty"`
	Mode         Mode              `json:"mode"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// FiveTuple represents a network 5-tuple
type FiveTuple struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`
}

// String returns a string representation of the 5-tuple
func (ft FiveTuple) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d/%s", ft.SrcIP, ft.SrcPort, ft.DstIP, ft.DstPort, ft.Protocol)
}

// DecisionManager manages enforcement decisions and telemetry
type DecisionManager struct {
	eventEmitter *telemetry.EventEmitter
	modeManager  *ModeManager
	decisionCounts map[Verdict]int64
}

// NewDecisionManager creates a new decision manager
func NewDecisionManager(eventEmitter *telemetry.EventEmitter, modeManager *ModeManager) *DecisionManager {
	return &DecisionManager{
		eventEmitter: eventEmitter,
		modeManager:  modeManager,
		decisionCounts: make(map[Verdict]int64),
	}
}

// MakeDecision makes an enforcement decision based on policy and mode
func (dm *DecisionManager) MakeDecision(program, mapName string, fiveTuple FiveTuple, policyAction uint8, policyID string, edgeID uint32) Decision {
	decision := Decision{
		Timestamp: time.Now(),
		Program:   program,
		Map:       mapName,
		FiveTuple: fiveTuple,
		PolicyID:  policyID,
		EdgeID:    edgeID,
		Mode:      dm.modeManager.currentMode,
		Metadata:  make(map[string]interface{}),
	}

	// Determine verdict based on policy action and mode
	switch policyAction {
	case 0: // BLOCK
		if dm.modeManager.IsObserveMode() {
			decision.Verdict = VerdictObserve
			decision.Reason = "Policy would block, but in observe mode"
		} else {
			decision.Verdict = VerdictBlock
			decision.Reason = "Policy blocks this connection"
		}
	case 1: // ALLOW
		decision.Verdict = VerdictAllow
		decision.Reason = "Policy allows this connection"
	case 2: // LOG
		decision.Verdict = VerdictLog
		decision.Reason = "Policy requires logging this connection"
	default:
		decision.Verdict = VerdictAllow
		decision.Reason = "Unknown policy action, defaulting to allow"
	}

	// Update counters
	dm.decisionCounts[decision.Verdict]++

	// Emit telemetry event
	dm.emitDecisionEvent(decision)

	return decision
}

// emitDecisionEvent emits a telemetry event for the decision
func (dm *DecisionManager) emitDecisionEvent(decision Decision) {
	eventData := map[string]interface{}{
		"program":     decision.Program,
		"map":         decision.Map,
		"five_tuple":  decision.FiveTuple,
		"verdict":     decision.Verdict.String(),
		"reason":      decision.Reason,
		"policy_id":   decision.PolicyID,
		"edge_id":     decision.EdgeID,
		"mode":        decision.Mode.String(),
		"timestamp":   decision.Timestamp,
	}

	// Add metadata
	for k, v := range decision.Metadata {
		eventData[k] = v
	}

	// Emit the event
	event := telemetry.Event{
		Type:      telemetry.EventTypeEnforceDecision,
		Data:      eventData,
		Message:   fmt.Sprintf("Enforcement decision: %s %s", decision.Verdict.String(), decision.FiveTuple.String()),
	}

	dm.eventEmitter.Emit(event)
}

// GetDecisionStats returns decision statistics
func (dm *DecisionManager) GetDecisionStats() DecisionStats {
	return DecisionStats{
		TotalDecisions: dm.getTotalDecisions(),
		VerdictCounts:  dm.decisionCounts,
		LastUpdated:    time.Now(),
	}
}

// getTotalDecisions returns the total number of decisions
func (dm *DecisionManager) getTotalDecisions() int64 {
	total := int64(0)
	for _, count := range dm.decisionCounts {
		total += count
	}
	return total
}

// ResetStats resets decision statistics
func (dm *DecisionManager) ResetStats() {
	dm.decisionCounts = make(map[Verdict]int64)
	log.Printf("[decision] Reset decision statistics")
}

// DecisionStats contains decision statistics
type DecisionStats struct {
	TotalDecisions int64            `json:"total_decisions"`
	VerdictCounts  map[Verdict]int64 `json:"verdict_counts"`
	LastUpdated    time.Time        `json:"last_updated"`
}

// CreateFiveTupleFromIPs creates a FiveTuple from IP addresses and ports
func CreateFiveTupleFromIPs(srcIP, dstIP string, srcPort, dstPort uint16, protocol string) FiveTuple {
	return FiveTuple{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}
}

// CreateFiveTupleFromUint32 creates a FiveTuple from uint32 IPs
func CreateFiveTupleFromUint32(srcIP, dstIP uint32, srcPort, dstPort uint16, protocol string) FiveTuple {
	return FiveTuple{
		SrcIP:    formatIP(srcIP),
		DstIP:    formatIP(dstIP),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}
}

// formatIP formats a uint32 IP address
func formatIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", 
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}

// LogDecision logs a decision to the console
func LogDecision(decision Decision) {
	log.Printf("[decision] %s: %s %s (reason: %s)", 
		decision.Verdict.String(), 
		decision.Program, 
		decision.FiveTuple.String(), 
		decision.Reason)
}

// ToJSON converts a decision to JSON
func (d Decision) ToJSON() ([]byte, error) {
	return json.Marshal(d)
}

// FromJSON creates a decision from JSON
func FromJSON(data []byte) (Decision, error) {
	var decision Decision
	err := json.Unmarshal(data, &decision)
	return decision, err
}
