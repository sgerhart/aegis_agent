package rollout

import (
	"time"

	"agents/aegis/pkg/models"
)

// TTLManager handles TTL and expiry checks for assignments
type TTLManager struct {
	checkInterval time.Duration
	expiredChan   chan *models.Assignment
}

// NewTTLManager creates a new TTL manager
func NewTTLManager(checkInterval time.Duration) *TTLManager {
	return &TTLManager{
		checkInterval: checkInterval,
		expiredChan:   make(chan *models.Assignment, 100),
	}
}

// CheckExpired checks if any assignments have expired
func (tm *TTLManager) CheckExpired(assignments []*models.Assignment) []*models.Assignment {
	var expired []*models.Assignment
	
	for _, assignment := range assignments {
		if assignment.IsExpired() {
			expired = append(expired, assignment)
		}
	}
	
	return expired
}

// StartExpiryChecker starts a background goroutine to check for expired assignments
func (tm *TTLManager) StartExpiryChecker(assignments []*models.Assignment) {
	go func() {
		ticker := time.NewTicker(tm.checkInterval)
		defer ticker.Stop()
		
		for range ticker.C {
			expired := tm.CheckExpired(assignments)
			for _, assignment := range expired {
				select {
				case tm.expiredChan <- assignment:
				default:
					// Channel full, drop assignment
				}
			}
		}
	}()
}

// GetExpiredChannel returns the channel for expired assignments
func (tm *TTLManager) GetExpiredChannel() <-chan *models.Assignment {
	return tm.expiredChan
}

// Stop stops the TTL manager
func (tm *TTLManager) Stop() {
	close(tm.expiredChan)
}

// IsAssignmentExpired checks if a specific assignment is expired
func (tm *TTLManager) IsAssignmentExpired(assignment *models.Assignment) bool {
	return assignment.IsExpired()
}

// GetTimeUntilExpiry returns the time until an assignment expires
func (tm *TTLManager) GetTimeUntilExpiry(assignment *models.Assignment) time.Duration {
	if assignment.ExpiresAt == nil {
		return 0 // No expiry
	}
	
	now := time.Now()
	if now.After(*assignment.ExpiresAt) {
		return 0 // Already expired
	}
	
	return assignment.ExpiresAt.Sub(now)
}

// GetExpiringSoon returns assignments that will expire within the specified duration
func (tm *TTLManager) GetExpiringSoon(assignments []*models.Assignment, within time.Duration) []*models.Assignment {
	var expiringSoon []*models.Assignment
	
	for _, assignment := range assignments {
		if assignment.ExpiresAt == nil {
			continue
		}
		
		timeUntilExpiry := tm.GetTimeUntilExpiry(assignment)
		if timeUntilExpiry > 0 && timeUntilExpiry <= within {
			expiringSoon = append(expiringSoon, assignment)
		}
	}
	
	return expiringSoon
}

// ValidateTTL validates that a TTL is reasonable
func (tm *TTLManager) ValidateTTL(ttl time.Duration) error {
	// Minimum TTL of 1 minute
	if ttl < time.Minute {
		return ErrInvalidTTL("TTL must be at least 1 minute")
	}
	
	// Maximum TTL of 24 hours
	if ttl > 24*time.Hour {
		return ErrInvalidTTL("TTL must be at most 24 hours")
	}
	
	return nil
}

// SetAssignmentTTL sets the TTL for an assignment
func (tm *TTLManager) SetAssignmentTTL(assignment *models.Assignment, ttl time.Duration) error {
	if err := tm.ValidateTTL(ttl); err != nil {
		return err
	}
	
	expiresAt := time.Now().Add(ttl)
	assignment.ExpiresAt = &expiresAt
	
	return nil
}

// ExtendAssignmentTTL extends the TTL for an assignment
func (tm *TTLManager) ExtendAssignmentTTL(assignment *models.Assignment, extension time.Duration) error {
	if err := tm.ValidateTTL(extension); err != nil {
		return err
	}
	
	if assignment.ExpiresAt == nil {
		// No existing TTL, set new one
		return tm.SetAssignmentTTL(assignment, extension)
	}
	
	// Extend existing TTL
	newExpiry := assignment.ExpiresAt.Add(extension)
	assignment.ExpiresAt = &newExpiry
	
	return nil
}

// ErrInvalidTTL represents an invalid TTL error
type ErrInvalidTTL string

func (e ErrInvalidTTL) Error() string {
	return "invalid TTL: " + string(e)
}

