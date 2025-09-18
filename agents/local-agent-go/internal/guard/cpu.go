package guard

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPUGuard monitors CPU usage and triggers rollbacks
type CPUGuard struct {
	threshold    float64
	checkInterval time.Duration
	rollbackFunc func(artifactID string) error
	monitoring   map[string]*CPUMonitor
	mu           sync.RWMutex
}

// CPUMonitor tracks CPU usage for a specific artifact
type CPUMonitor struct {
	ArtifactID    string
	ProcessID     int
	CPUUsage      float64
	LastCheck     time.Time
	RollbackCount int
	IsRolledBack  bool
}

// NewCPUGuard creates a new CPU guard
func NewCPUGuard(threshold float64, checkInterval time.Duration, rollbackFunc func(artifactID string) error) *CPUGuard {
	return &CPUGuard{
		threshold:     threshold,
		checkInterval: checkInterval,
		rollbackFunc:  rollbackFunc,
		monitoring:    make(map[string]*CPUMonitor),
	}
}

// StartMonitoring starts monitoring CPU usage for an artifact
func (g *CPUGuard) StartMonitoring(ctx context.Context, artifactID string, processID int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.monitoring[artifactID] = &CPUMonitor{
		ArtifactID: artifactID,
		ProcessID:  processID,
		LastCheck:  time.Now(),
	}

	// Start monitoring goroutine
	go g.monitorCPU(ctx, artifactID)
}

// StopMonitoring stops monitoring CPU usage for an artifact
func (g *CPUGuard) StopMonitoring(artifactID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	delete(g.monitoring, artifactID)
}

// GetCPUUsage gets the current CPU usage for a process
func (g *CPUGuard) GetCPUUsage(processID int) (float64, error) {
	// Read from /proc/[pid]/stat
	statPath := fmt.Sprintf("/proc/%d/stat", processID)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read process stat: %w", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 14 {
		return 0, fmt.Errorf("invalid stat format")
	}

	// Parse utime and stime (fields 13 and 14)
	utime, err := strconv.ParseUint(fields[13], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse utime: %w", err)
	}

	stime, err := strconv.ParseUint(fields[14], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse stime: %w", err)
	}

	// Get system uptime
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, fmt.Errorf("failed to read uptime: %w", err)
	}

	uptimeFields := strings.Fields(string(uptimeData))
	if len(uptimeFields) < 1 {
		return 0, fmt.Errorf("invalid uptime format")
	}

	uptime, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse uptime: %w", err)
	}

	// Calculate CPU usage percentage
	totalTime := float64(utime + stime) / 100.0 // Convert to seconds
	cpuUsage := (totalTime / uptime) * 100.0

	return cpuUsage, nil
}

// monitorCPU continuously monitors CPU usage for an artifact
func (g *CPUGuard) monitorCPU(ctx context.Context, artifactID string) {
	ticker := time.NewTicker(g.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.checkCPUUsage(ctx, artifactID)
		}
	}
}

// checkCPUUsage checks CPU usage and triggers rollback if needed
func (g *CPUGuard) checkCPUUsage(ctx context.Context, artifactID string) {
	g.mu.RLock()
	monitor, exists := g.monitoring[artifactID]
	g.mu.RUnlock()

	if !exists || monitor.IsRolledBack {
		return
	}

	// Get current CPU usage
	cpuUsage, err := g.GetCPUUsage(monitor.ProcessID)
	if err != nil {
		// If we can't get CPU usage, assume the process is dead
		g.StopMonitoring(artifactID)
		return
	}

	// Update monitor
	g.mu.Lock()
	monitor.CPUUsage = cpuUsage
	monitor.LastCheck = time.Now()
	g.mu.Unlock()

	// Check if CPU usage exceeds threshold
	if cpuUsage > g.threshold {
		fmt.Printf("CPU usage %.2f%% exceeds threshold %.2f%% for artifact %s\n", 
			cpuUsage, g.threshold, artifactID)

		// Trigger rollback
		if g.rollbackFunc != nil {
			if err := g.rollbackFunc(artifactID); err != nil {
				fmt.Printf("Failed to rollback artifact %s: %v\n", artifactID, err)
			} else {
				g.mu.Lock()
				monitor.IsRolledBack = true
				monitor.RollbackCount++
				g.mu.Unlock()
				fmt.Printf("Successfully rolled back artifact %s\n", artifactID)
			}
		}
	}
}

// GetMonitoringStatus returns the current monitoring status
func (g *CPUGuard) GetMonitoringStatus() map[string]*CPUMonitor {
	g.mu.RLock()
	defer g.mu.RUnlock()

	status := make(map[string]*CPUMonitor)
	for k, v := range g.monitoring {
		// Create a copy to avoid race conditions
		status[k] = &CPUMonitor{
			ArtifactID:    v.ArtifactID,
			ProcessID:     v.ProcessID,
			CPUUsage:      v.CPUUsage,
			LastCheck:     v.LastCheck,
			RollbackCount: v.RollbackCount,
			IsRolledBack:  v.IsRolledBack,
		}
	}

	return status
}

// ResetMonitoring resets monitoring for an artifact (allows re-monitoring after rollback)
func (g *CPUGuard) ResetMonitoring(artifactID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if monitor, exists := g.monitoring[artifactID]; exists {
		monitor.IsRolledBack = false
		monitor.CPUUsage = 0
		monitor.LastCheck = time.Now()
	}
}
