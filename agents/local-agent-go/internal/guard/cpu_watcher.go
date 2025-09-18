package guard

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
)

// CPUWatcher monitors CPU usage and triggers rollback when threshold is exceeded
type CPUWatcher struct {
	maxCPUPercent float64
	sampleInterval time.Duration
	rollbackFunc   func(artifactID string) error
	watchers       map[string]*cpuMonitor
	mu             sync.RWMutex
	stopCh         chan struct{}
}

// cpuMonitor tracks CPU usage for a specific artifact
type cpuMonitor struct {
	artifactID    string
	pid           int
	lastCPU       float64
	avgCPU        float64
	samples       []float64
	maxSamples    int
	rollbackCount int
	lastRollback  time.Time
	stopCh        chan struct{}
}

// NewCPUWatcher creates a new CPU watcher
func NewCPUWatcher(maxCPUPercent float64, sampleInterval time.Duration, rollbackFunc func(artifactID string) error) *CPUWatcher {
	return &CPUWatcher{
		maxCPUPercent:  maxCPUPercent,
		sampleInterval: sampleInterval,
		rollbackFunc:   rollbackFunc,
		watchers:       make(map[string]*cpuMonitor),
		stopCh:         make(chan struct{}),
	}
}

// Start starts the CPU watcher
func (cw *CPUWatcher) Start(ctx context.Context) {
	go cw.run(ctx)
}

// Stop stops the CPU watcher
func (cw *CPUWatcher) Stop() {
	close(cw.stopCh)
	
	cw.mu.Lock()
	defer cw.mu.Unlock()
	
	// Stop all individual watchers
	for _, watcher := range cw.watchers {
		close(watcher.stopCh)
	}
}

// WatchArtifact starts monitoring CPU usage for a specific artifact
func (cw *CPUWatcher) WatchArtifact(artifactID string, pid int) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	
	// Stop existing watcher if any
	if existing, exists := cw.watchers[artifactID]; exists {
		close(existing.stopCh)
	}
	
	// Create new watcher
	watcher := &cpuMonitor{
		artifactID: artifactID,
		pid:        pid,
		maxSamples: 10, // Keep last 10 samples for averaging
		stopCh:     make(chan struct{}),
	}
	
	cw.watchers[artifactID] = watcher
	
	// Start monitoring this artifact
	go cw.monitorArtifact(watcher)
}

// StopWatchingArtifact stops monitoring a specific artifact
func (cw *CPUWatcher) StopWatchingArtifact(artifactID string) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	
	if watcher, exists := cw.watchers[artifactID]; exists {
		close(watcher.stopCh)
		delete(cw.watchers, artifactID)
	}
}

// run is the main watcher loop
func (cw *CPUWatcher) run(ctx context.Context) {
	ticker := time.NewTicker(cw.sampleInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-cw.stopCh:
			return
		case <-ticker.C:
			cw.checkAllArtifacts()
		}
	}
}

// checkAllArtifacts checks CPU usage for all monitored artifacts
func (cw *CPUWatcher) checkAllArtifacts() {
	cw.mu.RLock()
	watchers := make([]*cpuMonitor, 0, len(cw.watchers))
	for _, watcher := range cw.watchers {
		watchers = append(watchers, watcher)
	}
	cw.mu.RUnlock()
	
	for _, watcher := range watchers {
		cw.checkArtifact(watcher)
	}
}

// checkArtifact checks CPU usage for a specific artifact
func (cw *CPUWatcher) checkArtifact(watcher *cpuMonitor) {
	// Get current CPU usage
	cpuPercent, err := cw.getCPUPercent(watcher.pid)
	if err != nil {
		log.Printf("[cpu-watcher] failed to get CPU usage for artifact %s (pid %d): %v", 
			watcher.artifactID, watcher.pid, err)
		return
	}
	
	// Update watcher state
	watcher.lastCPU = cpuPercent
	watcher.samples = append(watcher.samples, cpuPercent)
	
	// Keep only last maxSamples
	if len(watcher.samples) > watcher.maxSamples {
		watcher.samples = watcher.samples[1:]
	}
	
	// Calculate average
	watcher.avgCPU = cw.calculateAverage(watcher.samples)
	
	// Check if threshold exceeded
	if watcher.avgCPU > cw.maxCPUPercent {
		cw.handleThresholdExceeded(watcher)
	}
}

// handleThresholdExceeded handles when CPU threshold is exceeded
func (cw *CPUWatcher) handleThresholdExceeded(watcher *cpuMonitor) {
	// Check if we should rollback (rate limiting)
	now := time.Now()
	if watcher.lastRollback.Add(5 * time.Minute).After(now) {
		log.Printf("[cpu-watcher] skipping rollback for %s (rate limited), CPU: %.2f%%", 
			watcher.artifactID, watcher.avgCPU)
		return
	}
	
	watcher.rollbackCount++
	watcher.lastRollback = now
	
	log.Printf("[cpu-watcher] CPU threshold exceeded for artifact %s: %.2f%% > %.2f%%, triggering rollback", 
		watcher.artifactID, watcher.avgCPU, cw.maxCPUPercent)
	
	// Trigger rollback
	if cw.rollbackFunc != nil {
		if err := cw.rollbackFunc(watcher.artifactID); err != nil {
			log.Printf("[cpu-watcher] rollback failed for artifact %s: %v", watcher.artifactID, err)
		} else {
			log.Printf("[cpu-watcher] rollback successful for artifact %s", watcher.artifactID)
		}
	}
}

// monitorArtifact monitors a specific artifact
func (cw *CPUWatcher) monitorArtifact(watcher *cpuMonitor) {
	ticker := time.NewTicker(cw.sampleInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-watcher.stopCh:
			return
		case <-ticker.C:
			cw.checkArtifact(watcher)
		}
	}
}

// getCPUPercent gets CPU usage percentage for a process
func (cw *CPUWatcher) getCPUPercent(pid int) (float64, error) {
	// Try to get process-specific CPU usage
	if proc, err := process.NewProcess(int32(pid)); err == nil {
		cpuPercent, err := proc.CPUPercent()
		if err == nil {
			return cpuPercent, nil
		}
	}
	
	// Fall back to system-wide CPU usage
	percentages, err := cpu.Percent(time.Second, false)
	if err != nil {
		return 0, fmt.Errorf("failed to get CPU percentage: %w", err)
	}
	
	if len(percentages) == 0 {
		return 0, fmt.Errorf("no CPU data available")
	}
	
	return percentages[0], nil
}

// calculateAverage calculates the average of CPU samples
func (cw *CPUWatcher) calculateAverage(samples []float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	
	sum := 0.0
	for _, sample := range samples {
		sum += sample
	}
	
	return sum / float64(len(samples))
}

// GetStats returns CPU watcher statistics
func (cw *CPUWatcher) GetStats() map[string]interface{} {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	
	stats := map[string]interface{}{
		"max_cpu_percent":  cw.maxCPUPercent,
		"sample_interval":  cw.sampleInterval.String(),
		"watched_artifacts": len(cw.watchers),
		"artifacts":        make(map[string]interface{}),
	}
	
	artifacts := stats["artifacts"].(map[string]interface{})
	for artifactID, watcher := range cw.watchers {
		artifacts[artifactID] = map[string]interface{}{
			"pid":            watcher.pid,
			"last_cpu":       watcher.lastCPU,
			"avg_cpu":        watcher.avgCPU,
			"rollback_count": watcher.rollbackCount,
			"last_rollback":  watcher.lastRollback,
		}
	}
	
	return stats
}

// GetArtifactStats returns stats for a specific artifact
func (cw *CPUWatcher) GetArtifactStats(artifactID string) (map[string]interface{}, error) {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	
	watcher, exists := cw.watchers[artifactID]
	if !exists {
		return nil, fmt.Errorf("artifact %s not being watched", artifactID)
	}
	
	return map[string]interface{}{
		"artifact_id":     watcher.artifactID,
		"pid":             watcher.pid,
		"last_cpu":        watcher.lastCPU,
		"avg_cpu":         watcher.avgCPU,
		"rollback_count":  watcher.rollbackCount,
		"last_rollback":   watcher.lastRollback,
		"sample_count":    len(watcher.samples),
	}, nil
}

// IsWatching returns true if an artifact is being watched
func (cw *CPUWatcher) IsWatching(artifactID string) bool {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	
	_, exists := cw.watchers[artifactID]
	return exists
}

// GetWatchedArtifacts returns list of watched artifact IDs
func (cw *CPUWatcher) GetWatchedArtifacts() []string {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	
	artifacts := make([]string, 0, len(cw.watchers))
	for artifactID := range cw.watchers {
		artifacts = append(artifacts, artifactID)
	}
	
	return artifacts
}
