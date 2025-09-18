package verify

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Verifier handles signature verification using Vault or dev keys
type Verifier struct {
	vaultURL     string
	vaultToken   string
	devPubKey    *rsa.PublicKey
	lastError    string
	lastErrorTime time.Time
}

// VaultResponse represents Vault API response
type VaultResponse struct {
	Data struct {
		PublicKey string `json:"public_key"`
		KeyID     string `json:"key_id"`
	} `json:"data"`
}

// NewVerifier creates a new signature verifier
func NewVerifier(vaultURL, vaultToken, devPubKeyPath string) (*Verifier, error) {
	v := &Verifier{
		vaultURL:   vaultURL,
		vaultToken: vaultToken,
	}
	
	// Load dev public key if provided
	if devPubKeyPath != "" {
		key, err := loadPublicKey(devPubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load dev public key: %w", err)
		}
		v.devPubKey = key
	}
	
	return v, nil
}

// VerifyBundle verifies a bundle signature using Vault or dev key
func (v *Verifier) VerifyBundle(data []byte, b64sig string) error {
	// Try Vault first if configured
	if v.vaultURL != "" && v.vaultToken != "" {
		if err := v.verifyWithVault(data, b64sig); err != nil {
			v.setLastError(fmt.Sprintf("Vault verification failed: %v", err))
			// Fall back to dev key if Vault fails
			if v.devPubKey != nil {
				return v.verifyWithDevKey(data, b64sig)
			}
			return err
		}
		return nil
	}
	
	// Use dev key if no Vault configured
	if v.devPubKey != nil {
		return v.verifyWithDevKey(data, b64sig)
	}
	
	return errors.New("no verification method configured")
}

// verifyWithVault verifies signature using Vault
func (v *Verifier) verifyWithVault(data []byte, b64sig string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Get public key from Vault
	req, err := http.NewRequestWithContext(ctx, "GET", v.vaultURL+"/v1/transit/keys/aegis/public", nil)
	if err != nil {
		return fmt.Errorf("failed to create Vault request: %w", err)
	}
	
	req.Header.Set("X-Vault-Token", v.vaultToken)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call Vault API: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Vault API returned status %d", resp.StatusCode)
	}
	
	var vaultResp VaultResponse
	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return fmt.Errorf("failed to decode Vault response: %w", err)
	}
	
	// Parse public key
	block, _ := pem.Decode([]byte(vaultResp.Data.PublicKey))
	if block == nil {
		return errors.New("failed to decode PEM block")
	}
	
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("public key is not RSA")
	}
	
	// Verify signature
	return v.verifySignature(data, b64sig, rsaPubKey)
}

// verifyWithDevKey verifies signature using dev public key
func (v *Verifier) verifyWithDevKey(data []byte, b64sig string) error {
	return v.verifySignature(data, b64sig, v.devPubKey)
}

// verifySignature performs the actual signature verification
func (v *Verifier) verifySignature(data []byte, b64sig string, pubKey *rsa.PublicKey) error {
	// Decode signature
	sig, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	
	// Hash the data
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	
	// Verify signature
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash, sig)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	
	return nil
}

// loadPublicKey loads a public key from file
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}
	
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	
	return rsaPubKey, nil
}

// setLastError sets the last verification error
func (v *Verifier) setLastError(err string) {
	v.lastError = err
	v.lastErrorTime = time.Now()
}

// GetLastError returns the last verification error
func (v *Verifier) GetLastError() (string, time.Time) {
	return v.lastError, v.lastErrorTime
}

// VerifyFile verifies a file signature
func (v *Verifier) VerifyFile(filePath, b64sig string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	
	return v.VerifyBundle(data, b64sig)
}

// VerifyWithVaultAppRole verifies using Vault AppRole authentication
func (v *Verifier) VerifyWithVaultAppRole(ctx context.Context, roleID, secretID string, data []byte, b64sig string) error {
	// Authenticate with Vault using AppRole
	token, err := v.authenticateWithAppRole(ctx, roleID, secretID)
	if err != nil {
		return fmt.Errorf("AppRole authentication failed: %w", err)
	}
	
	// Create temporary verifier with token
	tempVerifier := &Verifier{
		vaultURL:   v.vaultURL,
		vaultToken: token,
		devPubKey:  v.devPubKey,
	}
	
	return tempVerifier.VerifyBundle(data, b64sig)
}

// authenticateWithAppRole authenticates with Vault using AppRole
func (v *Verifier) authenticateWithAppRole(ctx context.Context, roleID, secretID string) (string, error) {
	authData := map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	
	jsonData, err := json.Marshal(authData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth data: %w", err)
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", v.vaultURL+"/v1/auth/approle/login", strings.NewReader(string(jsonData)))
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call Vault auth API: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Vault auth API returned status %d", resp.StatusCode)
	}
	
	var authResp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("failed to decode auth response: %w", err)
	}
	
	return authResp.Auth.ClientToken, nil
}
