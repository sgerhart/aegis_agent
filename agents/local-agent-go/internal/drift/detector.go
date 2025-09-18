package drift

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Detector handles drift detection and TTL refresh
type Detector struct {
	artifacts map[string]*ArtifactState
	mu        sync.RWMutex
}

// ArtifactState tracks the state of an artifact
type ArtifactState struct {
	ArtifactID     string
	BundlePath     string
	OriginalHash   string
	LastCheck      time.Time
	LastModified   time.Time
	TTL            time.Duration
	RefreshCount   int
	IsDrifted      bool
	LastError      string
}

// NewDetector creates a new drift detector
func NewDetector() *Detector {
	return &Detector{
		artifacts: make(map[string]*ArtifactState),
	}
}

// RegisterArtifact registers an artifact for drift detection
func (d *Detector) RegisterArtifact(artifactID, bundlePath string, ttl time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Calculate initial hash
	hash, err := d.calculateFileHash(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to calculate initial hash: %w", err)
	}

	// Get file modification time
	stat, err := os.Stat(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}

	d.artifacts[artifactID] = &ArtifactState{
		ArtifactID:   artifactID,
		BundlePath:   bundlePath,
		OriginalHash: hash,
		LastCheck:    time.Now(),
		LastModified: stat.ModTime(),
		TTL:          ttl,
		IsDrifted:    false,
	}

	return nil
}

// CheckDrift checks for drift in all registered artifacts
func (d *Detector) CheckDrift(ctx context.Context) ([]string, error) {
	d.mu.RLock()
	var driftedArtifacts []string

	for artifactID, state := range d.artifacts {
		if d.isArtifactDrifted(state) {
			driftedArtifacts = append(driftedArtifacts, artifactID)
		}
	}
	d.mu.RUnlock()

	// Update drift status
	d.mu.Lock()
	for _, artifactID := range driftedArtifacts {
		if state, exists := d.artifacts[artifactID]; exists {
			state.IsDrifted = true
			state.LastCheck = time.Now()
		}
	}
	d.mu.Unlock()

	return driftedArtifacts, nil
}

// isArtifactDrifted checks if a specific artifact has drifted
func (d *Detector) isArtifactDrifted(state *ArtifactState) bool {
	// Check if file still exists
	if _, err := os.Stat(state.BundlePath); os.IsNotExist(err) {
		return true
	}

	// Check if file has been modified
	stat, err := os.Stat(state.BundlePath)
	if err != nil {
		return true
	}

	if stat.ModTime().After(state.LastModified) {
		return true
	}

	// Check if hash has changed
	currentHash, err := d.calculateFileHash(state.BundlePath)
	if err != nil {
		return true
	}

	return currentHash != state.OriginalHash
}

// RefreshTTL refreshes the TTL for an artifact
func (d *Detector) RefreshTTL(artifactID string, newTTL time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, exists := d.artifacts[artifactID]
	if !exists {
		return fmt.Errorf("artifact %s not found", artifactID)
	}

	state.TTL = newTTL
	state.RefreshCount++
	state.LastCheck = time.Now()

	return nil
}

// ExtendTTL extends the TTL for an artifact
func (d *Detector) ExtendTTL(artifactID string, extension time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, exists := d.artifacts[artifactID]
	if !exists {
		return fmt.Errorf("artifact %s not found", artifactID)
	}

	state.TTL += extension
	state.RefreshCount++
	state.LastCheck = time.Now()

	return nil
}

// ResetDrift resets the drift status for an artifact
func (d *Detector) ResetDrift(artifactID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, exists := d.artifacts[artifactID]
	if !exists {
		return fmt.Errorf("artifact %s not found", artifactID)
	}

	// Recalculate hash
	hash, err := d.calculateFileHash(state.BundlePath)
	if err != nil {
		return fmt.Errorf("failed to recalculate hash: %w", err)
	}

	// Update file modification time
	stat, err := os.Stat(state.BundlePath)
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}

	state.OriginalHash = hash
	state.LastModified = stat.ModTime()
	state.IsDrifted = false
	state.LastCheck = time.Now()

	return nil
}

// GetArtifactState returns the current state of an artifact
func (d *Detector) GetArtifactState(artifactID string) (*ArtifactState, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	state, exists := d.artifacts[artifactID]
	if !exists {
		return nil, fmt.Errorf("artifact %s not found", artifactID)
	}

	// Return a copy to avoid race conditions
	return &ArtifactState{
		ArtifactID:   state.ArtifactID,
		BundlePath:   state.BundlePath,
		OriginalHash: state.OriginalHash,
		LastCheck:    state.LastCheck,
		LastModified: state.LastModified,
		TTL:          state.TTL,
		RefreshCount: state.RefreshCount,
		IsDrifted:    state.IsDrifted,
		LastError:    state.LastError,
	}, nil
}

// ListArtifacts returns all registered artifacts
func (d *Detector) ListArtifacts() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var artifacts []string
	for artifactID := range d.artifacts {
		artifacts = append(artifacts, artifactID)
	}

	return artifacts
}

// UnregisterArtifact removes an artifact from drift detection
func (d *Detector) UnregisterArtifact(artifactID string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.artifacts, artifactID)
}

// calculateFileHash calculates the SHA256 hash of a file
func (d *Detector) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// StartPeriodicCheck starts periodic drift checking
func (d *Detector) StartPeriodicCheck(ctx context.Context, interval time.Duration, driftCallback func(artifactID string) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			driftedArtifacts, err := d.CheckDrift(ctx)
			if err != nil {
				fmt.Printf("Error checking drift: %v\n", err)
				continue
			}

			for _, artifactID := range driftedArtifacts {
				if driftCallback != nil {
					if err := driftCallback(artifactID); err != nil {
						fmt.Printf("Error handling drift for artifact %s: %v\n", artifactID, err)
					}
				}
			}
		}
	}
}
