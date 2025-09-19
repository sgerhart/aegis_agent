package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"agents/aegis/pkg/models"
)

// Verifier handles cryptographic verification of policy bundles
type Verifier struct {
	trustStore *models.TrustStore
	trustPath  string
}

// NewVerifier creates a new verifier with the specified trust store
func NewVerifier(trustPath string) (*Verifier, error) {
	v := &Verifier{
		trustPath: trustPath,
	}
	
	if err := v.loadTrustStore(); err != nil {
		return nil, fmt.Errorf("failed to load trust store: %w", err)
	}
	
	return v, nil
}

// loadTrustStore loads the trust store from the specified path
func (v *Verifier) loadTrustStore() error {
	data, err := os.ReadFile(v.trustPath)
	if err != nil {
		// If file doesn't exist, create empty trust store
		if os.IsNotExist(err) {
			v.trustStore = &models.TrustStore{
				Version:   "1.0",
				Keys:      []models.TrustedKey{},
				UpdatedAt: time.Now(),
			}
			return v.saveTrustStore()
		}
		return err
	}
	
	if err := json.Unmarshal(data, v.trustStore); err != nil {
		return fmt.Errorf("failed to parse trust store: %w", err)
	}
	
	return nil
}

// saveTrustStore saves the trust store to disk
func (v *Verifier) saveTrustStore() error {
	data, err := json.MarshalIndent(v.trustStore, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal trust store: %w", err)
	}
	
	return os.WriteFile(v.trustPath, data, 0644)
}

// VerifyBundle verifies a policy bundle's signature
func (v *Verifier) VerifyBundle(bundle *models.Bundle) (*models.BundleVerification, error) {
	verification := &models.BundleVerification{
		VerifiedAt: time.Now(),
	}
	
	// Validate bundle structure
	if err := bundle.Validate(); err != nil {
		verification.Valid = false
		verification.Error = fmt.Sprintf("bundle validation failed: %v", err)
		return verification, nil
	}
	
	// Get the trusted key
	key := v.trustStore.GetKeyByID(bundle.KeyID)
	if key == nil {
		verification.Valid = false
		verification.Error = fmt.Sprintf("unknown key ID: %s", bundle.KeyID)
		return verification, nil
	}
	
	// Check if key is revoked
	if key.Revoked {
		verification.Valid = false
		verification.Error = fmt.Sprintf("key %s is revoked", bundle.KeyID)
		return verification, nil
	}
	
	// Verify algorithm matches
	if key.Algorithm != bundle.Algo {
		verification.Valid = false
		verification.Error = fmt.Sprintf("algorithm mismatch: expected %s, got %s", key.Algorithm, bundle.Algo)
		return verification, nil
	}
	
	// Decode the public key
	pubKey, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		verification.Valid = false
		verification.Error = fmt.Sprintf("failed to decode public key: %v", err)
		return verification, nil
	}
	
	// Decode the signature
	sig, err := base64.StdEncoding.DecodeString(bundle.Sig)
	if err != nil {
		verification.Valid = false
		verification.Error = fmt.Sprintf("failed to decode signature: %v", err)
		return verification, nil
	}
	
	// Verify signature based on algorithm
	switch bundle.Algo {
	case "Ed25519":
		if err := v.verifyEd25519(bundle, pubKey, sig); err != nil {
			verification.Valid = false
			verification.Error = fmt.Sprintf("Ed25519 verification failed: %v", err)
			return verification, nil
		}
	default:
		verification.Valid = false
		verification.Error = fmt.Sprintf("unsupported algorithm: %s", bundle.Algo)
		return verification, nil
	}
	
	verification.Valid = true
	verification.KeyID = bundle.KeyID
	verification.Algorithm = bundle.Algo
	
	return verification, nil
}

// verifyEd25519 verifies an Ed25519 signature
func (v *Verifier) verifyEd25519(bundle *models.Bundle, pubKey, sig []byte) error {
	// For Ed25519, we need to verify the signature against the content hash
	// The signature should be over the hash, not the raw content
	hash := sha256.Sum256(bundle.Content)
	
	// Convert public key to ed25519.PublicKey
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubKey))
	}
	
	ed25519PubKey := ed25519.PublicKey(pubKey)
	
	// Verify the signature
	if !ed25519.Verify(ed25519PubKey, hash[:], sig) {
		return fmt.Errorf("signature verification failed")
	}
	
	return nil
}

// VerifyDetachedSignature verifies a detached signature over arbitrary data
func (v *Verifier) VerifyDetachedSignature(data []byte, signature, keyID string) (*models.BundleVerification, error) {
	verification := &models.BundleVerification{
		VerifiedAt: time.Now(),
	}
	
	// Get the trusted key
	key := v.trustStore.GetKeyByID(keyID)
	if key == nil {
		verification.Valid = false
		verification.Error = fmt.Sprintf("unknown key ID: %s", keyID)
		return verification, nil
	}
	
	// Check if key is revoked
	if key.Revoked {
		verification.Valid = false
		verification.Error = fmt.Sprintf("key %s is revoked", keyID)
		return verification, nil
	}
	
	// Decode the public key
	pubKey, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		verification.Valid = false
		verification.Error = fmt.Sprintf("failed to decode public key: %v", err)
		return verification, nil
	}
	
	// Decode the signature
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		verification.Valid = false
		verification.Error = fmt.Sprintf("failed to decode signature: %v", err)
		return verification, nil
	}
	
	// Verify signature based on algorithm
	switch key.Algorithm {
	case "Ed25519":
		if err := v.verifyEd25519Detached(data, pubKey, sig); err != nil {
			verification.Valid = false
			verification.Error = fmt.Sprintf("Ed25519 verification failed: %v", err)
			return verification, nil
		}
	default:
		verification.Valid = false
		verification.Error = fmt.Sprintf("unsupported algorithm: %s", key.Algorithm)
		return verification, nil
	}
	
	verification.Valid = true
	verification.KeyID = keyID
	verification.Algorithm = key.Algorithm
	
	return verification, nil
}

// verifyEd25519Detached verifies a detached Ed25519 signature
func (v *Verifier) verifyEd25519Detached(data []byte, pubKey, sig []byte) error {
	// Convert public key to ed25519.PublicKey
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubKey))
	}
	
	ed25519PubKey := ed25519.PublicKey(pubKey)
	
	// Verify the signature over the raw data
	if !ed25519.Verify(ed25519PubKey, data, sig) {
		return fmt.Errorf("signature verification failed")
	}
	
	return nil
}

// AddTrustedKey adds a new trusted key to the trust store
func (v *Verifier) AddTrustedKey(key models.TrustedKey) error {
	v.trustStore.AddKey(key)
	return v.saveTrustStore()
}

// RevokeKey revokes a trusted key
func (v *Verifier) RevokeKey(keyID string) error {
	v.trustStore.RevokeKey(keyID)
	return v.saveTrustStore()
}

// GetTrustedKeys returns all trusted keys
func (v *Verifier) GetTrustedKeys() []models.TrustedKey {
	return v.trustStore.Keys
}

// ReloadTrustStore reloads the trust store from disk
func (v *Verifier) ReloadTrustStore() error {
	return v.loadTrustStore()
}
