package enforcement

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"agents/aegis/internal/telemetry"
)

// EBPFManagerInterface defines the interface for eBPF operations
type EBPFManagerInterface interface {
	IsInitialized() bool
	GetMapCount() int
	GetProgramCount() int
}

// Enforcer enforces policies through eBPF
type Enforcer struct {
	ebpfManager EBPFManagerInterface
	telemetry   *telemetry.Logger
	
	// State
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.RWMutex
}

// NewEnforcer creates a new enforcer
func NewEnforcer(ebpfManager EBPFManagerInterface, telemetry *telemetry.Logger) (*Enforcer, error) {
	if ebpfManager == nil {
		return nil, fmt.Errorf("eBPF manager cannot be nil")
	}
	if telemetry == nil {
		return nil, fmt.Errorf("telemetry logger cannot be nil")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	enforcer := &Enforcer{
		ebpfManager: ebpfManager,
		telemetry:   telemetry,
		ctx:         ctx,
		cancel:      cancel,
	}
	
	log.Printf("[enforcer] Enforcer initialized")
	return enforcer, nil
}

// Start starts the enforcer
func (e *Enforcer) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	if e.running {
		return fmt.Errorf("enforcer is already running")
	}
	
	e.running = true
	log.Printf("[enforcer] Enforcer started")
	
	// Start enforcement loop
	go e.enforcementLoop()
	
	return nil
}

// Stop stops the enforcer
func (e *Enforcer) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	if !e.running {
		return fmt.Errorf("enforcer is not running")
	}
	
	e.cancel()
	e.running = false
	
	log.Printf("[enforcer] Enforcer stopped")
	return nil
}

// enforcementLoop runs the main enforcement loop
func (e *Enforcer) enforcementLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	log.Printf("[enforcer] Enforcement loop started")
	
	for {
		select {
		case <-e.ctx.Done():
			log.Printf("[enforcer] Enforcement loop stopped")
			return
		case <-ticker.C:
			if err := e.performEnforcement(); err != nil {
				log.Printf("[enforcer] Error in enforcement: %v", err)
				e.telemetry.LogError("enforcement", err.Error(), nil)
			}
		}
	}
}

// EnforcePolicies enforces all active policies
func (e *Enforcer) EnforcePolicies() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	if !e.running {
		return fmt.Errorf("enforcer is not running")
	}
	
	return e.performEnforcement()
}

// performEnforcement performs the actual enforcement
func (e *Enforcer) performEnforcement() error {
	// Check eBPF manager status
	if !e.ebpfManager.IsInitialized() {
		return fmt.Errorf("eBPF manager not initialized")
	}
	
	// Verify eBPF maps are accessible
	mapCount := e.ebpfManager.GetMapCount()
	if mapCount == 0 {
		log.Printf("[enforcer] Warning: no eBPF maps loaded")
		return nil
	}
	
	// For now, we'll just verify that the eBPF infrastructure is working
	// In production, this would:
	// 1. Check for policy violations
	// 2. Apply corrective actions
	// 3. Log enforcement events
	// 4. Update statistics
	
	log.Printf("[enforcer] Enforcement cycle completed (maps: %d)", mapCount)
	return nil
}

// IsRunning returns whether the enforcer is running
func (e *Enforcer) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// GetStatus returns the enforcer status
func (e *Enforcer) GetStatus() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	status := map[string]interface{}{
		"running":        e.running,
		"ebpf_initialized": e.ebpfManager.IsInitialized(),
		"map_count":      e.ebpfManager.GetMapCount(),
		"program_count":  e.ebpfManager.GetProgramCount(),
	}
	
	return status
}
