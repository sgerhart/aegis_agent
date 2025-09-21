package analysis

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"agents/aegis/internal/policy"
	"agents/aegis/internal/rollout"
	"agents/aegis/internal/telemetry"
)

// RollbackPlanner plans and executes rollbacks based on policy impact analysis
type RollbackPlanner struct {
	policySimulator    *PolicySimulator
	rollbackManager    *rollout.RollbackManager
	historyManager     *policy.PolicyHistoryManager
	auditLogger        *telemetry.AuditLogger
	mu                 sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
	running            bool
	
	// Rollback planning state
	rollbackPlans      map[string]*RollbackPlan
	activeRollbacks    map[string]*ActiveRollback
	rollbackCounter    int
	planningInterval   time.Duration
}

// RollbackPlan represents a planned rollback sequence
type RollbackPlan struct {
	ID                string                 `json:"id"`
	PolicyID          string                 `json:"policy_id"`
	PolicyName        string                 `json:"policy_name"`
	TriggerReason     RollbackTrigger        `json:"trigger_reason"`
	Priority          RollbackPriority       `json:"priority"`
	Status            RollbackStatus         `json:"status"`
	CreatedAt         time.Time              `json:"created_at"`
	PlannedAt         time.Time              `json:"planned_at"`
	ExecutedAt        time.Time              `json:"executed_at,omitempty"`
	
	// Rollback sequence
	Steps             []RollbackStep         `json:"steps"`
	EstimatedDuration time.Duration          `json:"estimated_duration"`
	SuccessProbability float64               `json:"success_probability"`
	
	// Impact analysis
	ImpactAssessment  RollbackImpact         `json:"impact_assessment"`
	RiskFactors       []RollbackRiskFactor   `json:"risk_factors"`
	
	// Dependencies
	Dependencies      []string               `json:"dependencies"`
	Prerequisites     []string               `json:"prerequisites"`
	
	// Metadata
	Metadata          map[string]interface{} `json:"metadata"`
}

// RollbackStep represents a single step in the rollback sequence
type RollbackStep struct {
	ID                string                 `json:"id"`
	Order             int                    `json:"order"`
	Type              RollbackStepType       `json:"type"`
	Description       string                 `json:"description"`
	Action            string                 `json:"action"`
	Target            string                 `json:"target"`
	Parameters        map[string]interface{} `json:"parameters"`
	EstimatedDuration time.Duration          `json:"estimated_duration"`
	SuccessCriteria   []string               `json:"success_criteria"`
	RollbackAction    string                 `json:"rollback_action,omitempty"`
	Status            RollbackStepStatus     `json:"status"`
	ExecutedAt        time.Time              `json:"executed_at,omitempty"`
	Error             string                 `json:"error,omitempty"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ActiveRollback represents a rollback currently being executed
type ActiveRollback struct {
	PlanID            string                 `json:"plan_id"`
	CurrentStep       int                    `json:"current_step"`
	Status            RollbackStatus         `json:"status"`
	StartedAt         time.Time              `json:"started_at"`
	LastUpdate        time.Time              `json:"last_update"`
	Progress          float64                `json:"progress"` // 0-1
	Error             string                 `json:"error,omitempty"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// RollbackImpact represents the impact of a rollback
type RollbackImpact struct {
	AffectedProcesses int                    `json:"affected_processes"`
	AffectedServices  int                    `json:"affected_services"`
	AffectedFiles     int                    `json:"affected_files"`
	AffectedNetworks  int                    `json:"affected_networks"`
	ConnectivityScore float64                `json:"connectivity_score"`
	DataLossRisk      bool                   `json:"data_loss_risk"`
	ServiceDowntime   time.Duration          `json:"service_downtime"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// RollbackRiskFactor represents a risk factor in rollback planning
type RollbackRiskFactor struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Severity    RiskLevel              `json:"severity"`
	Probability float64                `json:"probability"`
	Impact      string                 `json:"impact"`
	Mitigation  string                 `json:"mitigation"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Enums
type RollbackTrigger string
const (
	TriggerPolicyFailure    RollbackTrigger = "policy_failure"
	TriggerConnectivityLoss RollbackTrigger = "connectivity_loss"
	TriggerServiceFailure   RollbackTrigger = "service_failure"
	TriggerSecurityIncident RollbackTrigger = "security_incident"
	TriggerManualRequest    RollbackTrigger = "manual_request"
	TriggerScheduled        RollbackTrigger = "scheduled"
	TriggerEmergency        RollbackTrigger = "emergency"
)

type RollbackPriority string
const (
	PriorityLow       RollbackPriority = "low"
	PriorityMedium    RollbackPriority = "medium"
	PriorityHigh      RollbackPriority = "high"
	PriorityCritical  RollbackPriority = "critical"
	PriorityEmergency RollbackPriority = "emergency"
)

type RollbackStatus string
const (
	RollbackStatusPlanned    RollbackStatus = "planned"
	RollbackStatusReady      RollbackStatus = "ready"
	RollbackStatusExecuting  RollbackStatus = "executing"
	RollbackStatusCompleted  RollbackStatus = "completed"
	RollbackStatusFailed     RollbackStatus = "failed"
	RollbackStatusCancelled  RollbackStatus = "cancelled"
	RollbackStatusPaused     RollbackStatus = "paused"
)

type RollbackStepType string
const (
	StepTypePolicyRemove    RollbackStepType = "policy_remove"
	StepTypePolicyRestore   RollbackStepType = "policy_restore"
	StepTypeServiceRestart  RollbackStepType = "service_restart"
	StepTypeProcessKill     RollbackStepType = "process_kill"
	StepTypeProcessRestart  RollbackStepType = "process_restart"
	StepTypeMapRestore      RollbackStepType = "map_restore"
	StepTypeConfigRestore   RollbackStepType = "config_restore"
	StepTypeValidation      RollbackStepType = "validation"
	StepTypeNotification    RollbackStepType = "notification"
)

type RollbackStepStatus string
const (
	StepStatusPending    RollbackStepStatus = "pending"
	StepStatusExecuting  RollbackStepStatus = "executing"
	StepStatusCompleted  RollbackStepStatus = "completed"
	StepStatusFailed     RollbackStepStatus = "failed"
	StepStatusSkipped    RollbackStepStatus = "skipped"
)

// NewRollbackPlanner creates a new rollback planner
func NewRollbackPlanner(policySimulator *PolicySimulator, rollbackManager *rollout.RollbackManager, historyManager *policy.PolicyHistoryManager, auditLogger *telemetry.AuditLogger) *RollbackPlanner {
	ctx, cancel := context.WithCancel(context.Background())
	
	rp := &RollbackPlanner{
		policySimulator:   policySimulator,
		rollbackManager:   rollbackManager,
		historyManager:    historyManager,
		auditLogger:       auditLogger,
		ctx:               ctx,
		cancel:            cancel,
		rollbackPlans:     make(map[string]*RollbackPlan),
		activeRollbacks:   make(map[string]*ActiveRollback),
		planningInterval:  60 * time.Second, // Plan rollbacks every minute
	}
	
	log.Printf("[rollback_planner] Rollback planner initialized")
	return rp
}

// Start starts the rollback planner
func (rp *RollbackPlanner) Start() error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	if rp.running {
		return fmt.Errorf("rollback planner already running")
	}
	
	rp.running = true
	
	// Start planning goroutine
	go rp.planRollbacks()
	
	// Start execution goroutine
	go rp.executeRollbacks()
	
	log.Printf("[rollback_planner] Rollback planner started")
	
	// Log startup event
	rp.auditLogger.LogSystemEvent("rollback_planner_start", "Rollback planner started", map[string]interface{}{
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
		"planning_interval": rp.planningInterval.String(),
	})
	
	return nil
}

// Stop stops the rollback planner
func (rp *RollbackPlanner) Stop() error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	if !rp.running {
		return fmt.Errorf("rollback planner not running")
	}
	
	rp.cancel()
	rp.running = false
	
	log.Printf("[rollback_planner] Rollback planner stopped")
	
	// Log shutdown event
	rp.auditLogger.LogSystemEvent("rollback_planner_stop", "Rollback planner stopped", map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	
	return nil
}

// CreateRollbackPlan creates a rollback plan for a policy
func (rp *RollbackPlanner) CreateRollbackPlan(policyID, policyName string, trigger RollbackTrigger, priority RollbackPriority) (*RollbackPlan, error) {
	planID := fmt.Sprintf("rollback_%d_%s", rp.rollbackCounter, policyID)
	rp.rollbackCounter++
	
	plan := &RollbackPlan{
		ID:            planID,
		PolicyID:      policyID,
		PolicyName:    policyName,
		TriggerReason: trigger,
		Priority:      priority,
		Status:        RollbackStatusPlanned,
		CreatedAt:     time.Now(),
		Steps:         []RollbackStep{},
		Dependencies:  []string{},
		Prerequisites: []string{},
		Metadata:      make(map[string]interface{}),
	}
	
	// Generate rollback steps
	if err := rp.generateRollbackSteps(plan); err != nil {
		return nil, fmt.Errorf("failed to generate rollback steps: %w", err)
	}
	
	// Assess rollback impact
	rp.assessRollbackImpact(plan)
	
	// Identify risk factors
	rp.identifyRiskFactors(plan)
	
	// Calculate estimated duration and success probability
	rp.calculateRollbackMetrics(plan)
	
	// Store plan
	rp.mu.Lock()
	rp.rollbackPlans[planID] = plan
	rp.mu.Unlock()
	
	// Log plan creation
	rp.auditLogger.LogCustomEvent(telemetry.EventTypeRollbackEvent, telemetry.SeverityInfo,
		"Rollback plan created",
		map[string]interface{}{
			"plan_id":        planID,
			"policy_id":      policyID,
			"policy_name":    policyName,
			"trigger":        trigger,
			"priority":       priority,
			"steps_count":    len(plan.Steps),
			"estimated_duration": plan.EstimatedDuration.String(),
		})
	
	return plan, nil
}

// ExecuteRollback executes a rollback plan
func (rp *RollbackPlanner) ExecuteRollback(planID string) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	plan, exists := rp.rollbackPlans[planID]
	if !exists {
		return fmt.Errorf("rollback plan %s not found", planID)
	}
	
	if plan.Status != RollbackStatusReady {
		return fmt.Errorf("rollback plan %s is not ready for execution", planID)
	}
	
	// Create active rollback
	activeRollback := &ActiveRollback{
		PlanID:      planID,
		CurrentStep: 0,
		Status:      RollbackStatusExecuting,
		StartedAt:   time.Now(),
		LastUpdate:  time.Now(),
		Progress:    0.0,
		Metadata:    make(map[string]interface{}),
	}
	
	rp.activeRollbacks[planID] = activeRollback
	plan.Status = RollbackStatusExecuting
	plan.ExecutedAt = time.Now()
	
	// Log rollback execution start
	rp.auditLogger.LogCustomEvent(telemetry.EventTypeRollbackEvent, telemetry.SeverityInfo,
		"Rollback execution started",
		map[string]interface{}{
			"plan_id":        planID,
			"policy_id":      plan.PolicyID,
			"policy_name":    plan.PolicyName,
			"steps_count":    len(plan.Steps),
		})
	
	return nil
}

// generateRollbackSteps generates the steps for a rollback plan
func (rp *RollbackPlanner) generateRollbackSteps(plan *RollbackPlan) error {
	// Get policy history to understand what needs to be rolled back
	history := rp.historyManager.GetHistory()
	
	// Find relevant policy changes
	var relevantChanges []policy.PolicyChangeRecord
	for _, change := range history {
		if change.PolicyID == plan.PolicyID && change.Success {
			relevantChanges = append(relevantChanges, change)
		}
	}
	
	// Sort by timestamp (newest first)
	sort.Slice(relevantChanges, func(i, j int) bool {
		return relevantChanges[i].Timestamp.After(relevantChanges[j].Timestamp)
	})
	
	stepOrder := 1
	
	// Add validation step
	plan.Steps = append(plan.Steps, RollbackStep{
		ID:                fmt.Sprintf("step_%d_validation", stepOrder),
		Order:             stepOrder,
		Type:              StepTypeValidation,
		Description:       "Validate system state before rollback",
		Action:            "validate_system_state",
		Target:            "system",
		Parameters:        make(map[string]interface{}),
		EstimatedDuration: 30 * time.Second,
		SuccessCriteria:   []string{"system_healthy", "no_critical_errors"},
		Status:            StepStatusPending,
		Metadata:          make(map[string]interface{}),
	})
	stepOrder++
	
	// Add policy removal steps
	for _, change := range relevantChanges {
		if change.Action == "apply" {
			plan.Steps = append(plan.Steps, RollbackStep{
				ID:                fmt.Sprintf("step_%d_policy_remove", stepOrder),
				Order:             stepOrder,
				Type:              StepTypePolicyRemove,
				Description:       fmt.Sprintf("Remove policy %s", change.PolicyName),
				Action:            "remove_policy",
				Target:            change.PolicyID,
				Parameters:        change.PolicyData,
				EstimatedDuration: 10 * time.Second,
				SuccessCriteria:   []string{"policy_removed", "no_errors"},
				Status:            StepStatusPending,
				Metadata:          make(map[string]interface{}),
			})
			stepOrder++
		}
	}
	
	// Add map restoration steps
	plan.Steps = append(plan.Steps, RollbackStep{
		ID:                fmt.Sprintf("step_%d_map_restore", stepOrder),
		Order:             stepOrder,
		Type:              StepTypeMapRestore,
		Description:       "Restore eBPF maps to previous state",
		Action:            "restore_maps",
		Target:            "ebpf_maps",
		Parameters:        make(map[string]interface{}),
		EstimatedDuration: 15 * time.Second,
		SuccessCriteria:   []string{"maps_restored", "no_errors"},
		Status:            StepStatusPending,
		Metadata:          make(map[string]interface{}),
	})
	stepOrder++
	
	// Add service restart steps if needed
	if plan.TriggerReason == TriggerServiceFailure {
		plan.Steps = append(plan.Steps, RollbackStep{
			ID:                fmt.Sprintf("step_%d_service_restart", stepOrder),
			Order:             stepOrder,
			Type:              StepTypeServiceRestart,
			Description:       "Restart affected services",
			Action:            "restart_services",
			Target:            "affected_services",
			Parameters:        make(map[string]interface{}),
			EstimatedDuration: 60 * time.Second,
			SuccessCriteria:   []string{"services_healthy", "no_errors"},
			Status:            StepStatusPending,
			Metadata:          make(map[string]interface{}),
		})
		stepOrder++
	}
	
	// Add final validation step
	plan.Steps = append(plan.Steps, RollbackStep{
		ID:                fmt.Sprintf("step_%d_final_validation", stepOrder),
		Order:             stepOrder,
		Type:              StepTypeValidation,
		Description:       "Validate rollback completion",
		Action:            "validate_rollback",
		Target:            "system",
		Parameters:        make(map[string]interface{}),
		EstimatedDuration: 30 * time.Second,
		SuccessCriteria:   []string{"rollback_complete", "system_healthy"},
		Status:            StepStatusPending,
		Metadata:          make(map[string]interface{}),
	})
	
	return nil
}

// assessRollbackImpact assesses the impact of the rollback
func (rp *RollbackPlanner) assessRollbackImpact(plan *RollbackPlan) {
	impact := &RollbackImpact{
		AffectedProcesses: 0,
		AffectedServices:  0,
		AffectedFiles:     0,
		AffectedNetworks:  0,
		ConnectivityScore: 1.0,
		DataLossRisk:      false,
		ServiceDowntime:   0,
		Metadata:          make(map[string]interface{}),
	}
	
	// Calculate impact based on rollback steps
	for _, step := range plan.Steps {
		switch step.Type {
		case StepTypeServiceRestart:
			impact.AffectedServices++
			impact.ServiceDowntime += step.EstimatedDuration
		case StepTypeProcessKill, StepTypeProcessRestart:
			impact.AffectedProcesses++
		case StepTypeMapRestore:
			impact.AffectedNetworks++
		}
	}
	
	// Assess data loss risk
	impact.DataLossRisk = rp.assessDataLossRisk(plan)
	
	// Calculate connectivity score
	impact.ConnectivityScore = rp.calculateConnectivityScore(plan)
	
	plan.ImpactAssessment = *impact
}

// identifyRiskFactors identifies risk factors for the rollback
func (rp *RollbackPlanner) identifyRiskFactors(plan *RollbackPlan) {
	var riskFactors []RollbackRiskFactor
	
	// Service restart risks
	if rp.hasServiceRestartSteps(plan) {
		riskFactors = append(riskFactors, RollbackRiskFactor{
			Type:        "service_downtime",
			Description: "Services will be restarted during rollback",
			Severity:    RiskMedium,
			Probability: 0.8,
			Impact:      "Temporary service unavailability",
			Mitigation:  "Schedule rollback during maintenance window",
			Metadata:    make(map[string]interface{}),
		})
	}
	
	// Data loss risks
	if plan.ImpactAssessment.DataLossRisk {
		riskFactors = append(riskFactors, RollbackRiskFactor{
			Type:        "data_loss",
			Description: "Risk of data loss during rollback",
			Severity:    RiskHigh,
			Probability: 0.3,
			Impact:      "Potential data corruption or loss",
			Mitigation:  "Create data backup before rollback",
			Metadata:    make(map[string]interface{}),
		})
	}
	
	// Connectivity risks
	if plan.ImpactAssessment.ConnectivityScore < 0.7 {
		riskFactors = append(riskFactors, RollbackRiskFactor{
			Type:        "connectivity_loss",
			Description: "Risk of connectivity loss during rollback",
			Severity:    RiskHigh,
			Probability: 0.5,
			Impact:      "Services may become unreachable",
			Mitigation:  "Implement gradual rollback with monitoring",
			Metadata:    make(map[string]interface{}),
		})
	}
	
	plan.RiskFactors = riskFactors
}

// calculateRollbackMetrics calculates estimated duration and success probability
func (rp *RollbackPlanner) calculateRollbackMetrics(plan *RollbackPlan) {
	// Calculate total estimated duration
	totalDuration := time.Duration(0)
	for _, step := range plan.Steps {
		totalDuration += step.EstimatedDuration
	}
	plan.EstimatedDuration = totalDuration
	
	// Calculate success probability based on risk factors
	successProbability := 1.0
	for _, risk := range plan.RiskFactors {
		successProbability *= (1.0 - risk.Probability)
	}
	plan.SuccessProbability = successProbability
}

// planRollbacks plans rollbacks based on system state
func (rp *RollbackPlanner) planRollbacks() {
	ticker := time.NewTicker(rp.planningInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			rp.analyzeSystemState()
		case <-rp.ctx.Done():
			return
		}
	}
}

// executeRollbacks executes active rollbacks
func (rp *RollbackPlanner) executeRollbacks() {
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			rp.processActiveRollbacks()
		case <-rp.ctx.Done():
			return
		}
	}
}

// analyzeSystemState analyzes the current system state for rollback triggers
func (rp *RollbackPlanner) analyzeSystemState() {
	// Get recent policy changes
	history := rp.historyManager.GetHistory()
	
	// Check for failed policy applications
	for _, change := range history {
		if !change.Success && change.Timestamp.After(time.Now().Add(-5*time.Minute)) {
			// Create emergency rollback plan
			plan, err := rp.CreateRollbackPlan(
				change.PolicyID,
				change.PolicyName,
				TriggerPolicyFailure,
				PriorityHigh,
			)
			if err != nil {
				log.Printf("[rollback_planner] Failed to create emergency rollback plan: %v", err)
				continue
			}
			
			// Mark as ready for execution
			plan.Status = RollbackStatusReady
			
			// Log emergency rollback plan
			rp.auditLogger.LogCustomEvent(telemetry.EventTypeRollbackEvent, telemetry.SeverityWarning,
				"Emergency rollback plan created",
				map[string]interface{}{
					"plan_id":     plan.ID,
					"policy_id":   change.PolicyID,
					"policy_name": change.PolicyName,
					"reason":      "policy_failure",
				})
		}
	}
}

// processActiveRollbacks processes active rollbacks
func (rp *RollbackPlanner) processActiveRollbacks() {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	for planID, activeRollback := range rp.activeRollbacks {
		if activeRollback.Status != RollbackStatusExecuting {
			continue
		}
		
		plan, exists := rp.rollbackPlans[planID]
		if !exists {
			activeRollback.Status = RollbackStatusFailed
			activeRollback.Error = "Plan not found"
			continue
		}
		
		// Execute current step
		if activeRollback.CurrentStep < len(plan.Steps) {
			step := &plan.Steps[activeRollback.CurrentStep]
			if step.Status == StepStatusPending {
				rp.executeRollbackStep(plan, step, activeRollback)
			}
		} else {
			// All steps completed
			activeRollback.Status = RollbackStatusCompleted
			activeRollback.Progress = 1.0
			plan.Status = RollbackStatusCompleted
			
			// Log rollback completion
			rp.auditLogger.LogCustomEvent(telemetry.EventTypeRollbackEvent, telemetry.SeverityInfo,
				"Rollback completed successfully",
				map[string]interface{}{
					"plan_id":        planID,
					"policy_id":      plan.PolicyID,
					"policy_name":    plan.PolicyName,
					"duration":       time.Since(activeRollback.StartedAt).String(),
				})
		}
	}
}

// executeRollbackStep executes a single rollback step
func (rp *RollbackPlanner) executeRollbackStep(plan *RollbackPlan, step *RollbackStep, activeRollback *ActiveRollback) {
	step.Status = StepStatusExecuting
	step.ExecutedAt = time.Now()
	activeRollback.LastUpdate = time.Now()
	
	// Simulate step execution (in reality would call actual rollback actions)
	log.Printf("[rollback_planner] Executing step %d: %s", step.Order, step.Description)
	
	// Simulate execution time
	time.Sleep(step.EstimatedDuration)
	
	// Mark step as completed
	step.Status = StepStatusCompleted
	activeRollback.CurrentStep++
	activeRollback.Progress = float64(activeRollback.CurrentStep) / float64(len(plan.Steps))
	
	// Log step completion
	rp.auditLogger.LogCustomEvent(telemetry.EventTypeRollbackEvent, telemetry.SeverityInfo,
		"Rollback step completed",
		map[string]interface{}{
			"plan_id":     plan.ID,
			"step_id":     step.ID,
			"step_order":  step.Order,
			"step_type":   step.Type,
			"description": step.Description,
		})
}

// Helper methods
func (rp *RollbackPlanner) hasServiceRestartSteps(plan *RollbackPlan) bool {
	for _, step := range plan.Steps {
		if step.Type == StepTypeServiceRestart {
			return true
		}
	}
	return false
}

func (rp *RollbackPlanner) assessDataLossRisk(plan *RollbackPlan) bool {
	// Simplified risk assessment
	for _, step := range plan.Steps {
		if step.Type == StepTypeMapRestore || step.Type == StepTypeConfigRestore {
			return true
		}
	}
	return false
}

func (rp *RollbackPlanner) calculateConnectivityScore(plan *RollbackPlan) float64 {
	// Simplified connectivity score calculation
	score := 1.0
	
	// Reduce score based on risk factors
	for _, risk := range plan.RiskFactors {
		if risk.Type == "connectivity_loss" {
			score *= (1.0 - risk.Probability)
		}
	}
	
	return score
}

// Public methods for accessing rollback plans
func (rp *RollbackPlanner) GetRollbackPlan(planID string) (*RollbackPlan, error) {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	
	plan, exists := rp.rollbackPlans[planID]
	if !exists {
		return nil, fmt.Errorf("rollback plan %s not found", planID)
	}
	
	return plan, nil
}

func (rp *RollbackPlanner) GetRollbackPlans() map[string]*RollbackPlan {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	
	plans := make(map[string]*RollbackPlan)
	for id, plan := range rp.rollbackPlans {
		plans[id] = plan
	}
	
	return plans
}

func (rp *RollbackPlanner) GetActiveRollbacks() map[string]*ActiveRollback {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	
	active := make(map[string]*ActiveRollback)
	for id, rollback := range rp.activeRollbacks {
		active[id] = rollback
	}
	
	return active
}

func (rp *RollbackPlanner) GetRollbackStatistics() map[string]interface{} {
	rp.mu.RLock()
	defer rp.mu.Unlock()
	
	stats := map[string]interface{}{
		"total_plans":      len(rp.rollbackPlans),
		"active_rollbacks": len(rp.activeRollbacks),
		"planned":          0,
		"ready":            0,
		"executing":        0,
		"completed":        0,
		"failed":           0,
	}
	
	for _, plan := range rp.rollbackPlans {
		switch plan.Status {
		case RollbackStatusPlanned:
			stats["planned"] = stats["planned"].(int) + 1
		case RollbackStatusReady:
			stats["ready"] = stats["ready"].(int) + 1
		case RollbackStatusExecuting:
			stats["executing"] = stats["executing"].(int) + 1
		case RollbackStatusCompleted:
			stats["completed"] = stats["completed"].(int) + 1
		case RollbackStatusFailed:
			stats["failed"] = stats["failed"].(int) + 1
		}
	}
	
	return stats
}

// Close closes the rollback planner
func (rp *RollbackPlanner) Close() error {
	return rp.Stop()
}
