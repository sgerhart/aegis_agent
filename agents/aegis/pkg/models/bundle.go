package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Bundle represents a signed policy bundle with cryptographic verification
type Bundle struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"`      // Content hash (SHA256)
	Sig       string    `json:"sig"`       // Detached signature (base64)
	Algo      string    `json:"algo"`      // Signature algorithm (e.g., "Ed25519")
	CreatedAt time.Time `json:"created_at"`
	KeyID     string    `json:"key_id"`    // Signing key identifier
	Content   []byte    `json:"content"`   // Policy content (eBPF programs, maps, etc.)
	Size      int64     `json:"size"`      // Content size in bytes
	Version   string    `json:"version"`   // Bundle version
	Metadata  map[string]any `json:"metadata,omitempty"` // Additional metadata
}

// TrustedKey represents a trusted signing key in the trust store
type TrustedKey struct {
	KeyID     string    `json:"key_id"`     // Key identifier
	Algorithm string    `json:"algorithm"`  // Key algorithm (e.g., "Ed25519")
	PublicKey string    `json:"public_key"` // Base64 encoded public key
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// TrustStore represents the collection of trusted keys
type TrustStore struct {
	Version   string       `json:"version"`
	Keys      []TrustedKey `json:"keys"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// BundleVerification represents the result of bundle verification
type BundleVerification struct {
	Valid       bool     `json:"valid"`
	KeyID       string   `json:"key_id,omitempty"`
	Algorithm   string   `json:"algorithm,omitempty"`
	Error       string   `json:"error,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	VerifiedAt  time.Time `json:"verified_at"`
}

// CalculateHash computes the SHA256 hash of the bundle content
func (b *Bundle) CalculateHash() string {
	hash := sha256.Sum256(b.Content)
	return hex.EncodeToString(hash[:])
}

// VerifyHash checks if the stored hash matches the calculated hash
func (b *Bundle) VerifyHash() bool {
	calculated := b.CalculateHash()
	return b.Hash == calculated
}

// IsExpired checks if the bundle has expired
func (b *Bundle) IsExpired() bool {
	// For now, bundles don't expire unless explicitly set
	// This could be enhanced with TTL fields
	return false
}

// Validate performs basic validation on the bundle
func (b *Bundle) Validate() error {
	if b.ID == "" {
		return ErrInvalidBundle("missing ID")
	}
	if b.Hash == "" {
		return ErrInvalidBundle("missing Hash")
	}
	if b.Sig == "" {
		return ErrInvalidBundle("missing Signature")
	}
	if b.Algo == "" {
		return ErrInvalidBundle("missing Algorithm")
	}
	if b.KeyID == "" {
		return ErrInvalidBundle("missing KeyID")
	}
	if len(b.Content) == 0 {
		return ErrInvalidBundle("missing Content")
	}
	
	// Verify hash matches content
	if !b.VerifyHash() {
		return ErrInvalidBundle("hash mismatch")
	}
	
	return nil
}

// GetKeyByID retrieves a trusted key by its ID
func (ts *TrustStore) GetKeyByID(keyID string) *TrustedKey {
	for i := range ts.Keys {
		if ts.Keys[i].KeyID == keyID && !ts.Keys[i].Revoked {
			return &ts.Keys[i]
		}
	}
	return nil
}

// IsKeyRevoked checks if a key is revoked
func (ts *TrustStore) IsKeyRevoked(keyID string) bool {
	key := ts.GetKeyByID(keyID)
	return key == nil || key.Revoked
}

// AddKey adds a new trusted key to the store
func (ts *TrustStore) AddKey(key TrustedKey) {
	// Check if key already exists
	for i := range ts.Keys {
		if ts.Keys[i].KeyID == key.KeyID {
			ts.Keys[i] = key
			return
		}
	}
	ts.Keys = append(ts.Keys, key)
}

// RevokeKey marks a key as revoked
func (ts *TrustStore) RevokeKey(keyID string) {
	for i := range ts.Keys {
		if ts.Keys[i].KeyID == keyID {
			ts.Keys[i].Revoked = true
			break
		}
	}
}

// ErrInvalidBundle represents an invalid bundle error
type ErrInvalidBundle string

func (e ErrInvalidBundle) Error() string {
	return "invalid bundle: " + string(e)
}

