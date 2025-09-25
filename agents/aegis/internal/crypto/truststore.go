package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"agents/aegis/pkg/models"
)

// TrustStoreManager handles trust store operations and key rotation
type TrustStoreManager struct {
	trustPath string
	verifier  *Verifier
}

// NewTrustStoreManager creates a new trust store manager
func NewTrustStoreManager(trustPath string) (*TrustStoreManager, error) {
	verifier, err := NewVerifier(trustPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}
	
	return &TrustStoreManager{
		trustPath: trustPath,
		verifier:  verifier,
	}, nil
}

// GenerateKeyPair generates a new Ed25519 key pair
func (tsm *TrustStoreManager) GenerateKeyPair(keyID string) (*models.TrustedKey, ed25519.PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	
	trustedKey := &models.TrustedKey{
		KeyID:     keyID,
		Algorithm: "Ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
		CreatedAt: time.Now(),
		Metadata: map[string]any{
			"generated_by": "aegis-agent",
			"key_size":     ed25519.PublicKeySize,
		},
	}
	
	return trustedKey, privKey, nil
}

// AddKey adds a new trusted key to the trust store
func (tsm *TrustStoreManager) AddKey(key models.TrustedKey) error {
	return tsm.verifier.AddTrustedKey(key)
}

// RevokeKey revokes a trusted key
func (tsm *TrustStoreManager) RevokeKey(keyID string) error {
	return tsm.verifier.RevokeKey(keyID)
}

// GetKey retrieves a trusted key by ID
func (tsm *TrustStoreManager) GetKey(keyID string) *models.TrustedKey {
	return tsm.verifier.trustStore.GetKeyByID(keyID)
}

// ListKeys returns all trusted keys
func (tsm *TrustStoreManager) ListKeys() []models.TrustedKey {
	return tsm.verifier.GetTrustedKeys()
}

// RotateKey performs key rotation by adding a new key and optionally revoking the old one
func (tsm *TrustStoreManager) RotateKey(oldKeyID, newKeyID string) (*models.TrustedKey, ed25519.PrivateKey, error) {
	// Generate new key pair
	newKey, newPrivKey, err := tsm.GenerateKeyPair(newKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new key: %w", err)
	}
	
	// Add new key to trust store
	if err := tsm.AddKey(*newKey); err != nil {
		return nil, nil, fmt.Errorf("failed to add new key: %w", err)
	}
	
	// Optionally revoke old key
	if oldKeyID != "" {
		if err := tsm.RevokeKey(oldKeyID); err != nil {
			return nil, nil, fmt.Errorf("failed to revoke old key: %w", err)
		}
	}
	
	return newKey, newPrivKey, nil
}

// ExportTrustStore exports the trust store to a file
func (tsm *TrustStoreManager) ExportTrustStore(exportPath string) error {
	data, err := json.MarshalIndent(tsm.verifier.trustStore, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal trust store: %w", err)
	}
	
	return os.WriteFile(exportPath, data, 0644)
}

// ImportTrustStore imports a trust store from a file
func (tsm *TrustStoreManager) ImportTrustStore(importPath string) error {
	data, err := os.ReadFile(importPath)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}
	
	var trustStore models.TrustStore
	if err := json.Unmarshal(data, &trustStore); err != nil {
		return fmt.Errorf("failed to parse trust store: %w", err)
	}
	
	// Validate the imported trust store
	if err := tsm.validateTrustStore(&trustStore); err != nil {
		return fmt.Errorf("invalid trust store: %w", err)
	}
	
	// Replace current trust store
	tsm.verifier.trustStore = &trustStore
	return tsm.verifier.saveTrustStore()
}

// validateTrustStore validates the structure and content of a trust store
func (tsm *TrustStoreManager) validateTrustStore(trustStore *models.TrustStore) error {
	if trustStore.Version == "" {
		return fmt.Errorf("missing version")
	}
	
	if len(trustStore.Keys) == 0 {
		return fmt.Errorf("no keys in trust store")
	}
	
	// Validate each key
	for i, key := range trustStore.Keys {
		if err := tsm.validateTrustedKey(&key); err != nil {
			return fmt.Errorf("invalid key at index %d: %w", i, err)
		}
	}
	
	return nil
}

// validateTrustedKey validates a single trusted key
func (tsm *TrustStoreManager) validateTrustedKey(key *models.TrustedKey) error {
	if key.KeyID == "" {
		return fmt.Errorf("missing key ID")
	}
	
	if key.Algorithm == "" {
		return fmt.Errorf("missing algorithm")
	}
	
	if key.PublicKey == "" {
		return fmt.Errorf("missing public key")
	}
	
	// Validate algorithm
	switch key.Algorithm {
	case "Ed25519":
		// Validate Ed25519 public key
		pubKey, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil {
			return fmt.Errorf("invalid base64 public key: %w", err)
		}
		if len(pubKey) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid Ed25519 public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubKey))
		}
	default:
		return fmt.Errorf("unsupported algorithm: %s", key.Algorithm)
	}
	
	return nil
}

// CreateInitialTrustStore creates an initial trust store with a generated key
func (tsm *TrustStoreManager) CreateInitialTrustStore() (*models.TrustedKey, ed25519.PrivateKey, error) {
	// Generate initial key pair
	key, privKey, err := tsm.GenerateKeyPair("aegis-backend-1")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate initial key: %w", err)
	}
	
	// Create initial trust store
	trustStore := &models.TrustStore{
		Version:   "1.0",
		Keys:      []models.TrustedKey{*key},
		UpdatedAt: time.Now(),
	}
	
	// Save to file
	data, err := json.MarshalIndent(trustStore, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal trust store: %w", err)
	}
	
	if err := os.WriteFile(tsm.trustPath, data, 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to save trust store: %w", err)
	}
	
	// Reload verifier
	if err := tsm.verifier.ReloadTrustStore(); err != nil {
		return nil, nil, fmt.Errorf("failed to reload trust store: %w", err)
	}
	
	return key, privKey, nil
}

// GetVerifier returns the underlying verifier
func (tsm *TrustStoreManager) GetVerifier() *Verifier {
	return tsm.verifier
}


