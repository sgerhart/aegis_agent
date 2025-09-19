package store

import "errors"

var (
	ErrAgentNotFound = errors.New("agent not found")
	ErrRegistrationNotFound = errors.New("registration not found")
	ErrRegistrationExpired = errors.New("registration expired")
	ErrInvalidSignature = errors.New("invalid signature")
)

