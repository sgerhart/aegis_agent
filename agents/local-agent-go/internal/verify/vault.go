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
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Verifier handles signature verification using Vault or development public keys
type Verifier struct {
	vaultURL    string
	vaultToken  string
	devPubKey   *rsa.PublicKey
	httpClient  *http.Client
}

// SignatureData represents the signature information from an artifact
type SignatureData struct {
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id,omitempty"`
}

// VaultSignatureResponse represents the response from Vault signature verification
type VaultSignatureResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// NewVerifier creates a new signature verifier
func NewVerifier(vaultURL, vaultToken, devPubKeyPath string) (*Verifier, error) {
	v := &Verifier{
		vaultURL:   vaultURL,
		vaultToken: vaultToken,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	// Load development public key if provided
	if devPubKeyPath != "" {
		pubKey, err := loadPublicKey(devPubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load dev public key: %w", err)
		}
		v.devPubKey = pubKey
	}

	return v, nil
}

// VerifySignature verifies a signature using either Vault or development public key
func (v *Verifier) VerifySignature(ctx context.Context, data []byte, signatureData SignatureData) error {
	// Try Vault verification first if configured
	if v.vaultURL != "" && v.vaultToken != "" {
		if err := v.verifyWithVault(ctx, data, signatureData); err == nil {
			return nil
		}
		// If Vault verification fails, fall back to dev key if available
	}

	// Fall back to development public key verification
	if v.devPubKey != nil {
		return v.verifyWithDevKey(data, signatureData)
	}

	return fmt.Errorf("no verification method available")
}

// verifyWithVault verifies signature using Vault
func (v *Verifier) verifyWithVault(ctx context.Context, data []byte, signatureData SignatureData) error {
	payload := map[string]interface{}{
		"data":      base64.StdEncoding.EncodeToString(data),
		"signature": signatureData.Signature,
		"algorithm": signatureData.Algorithm,
	}

	if signatureData.KeyID != "" {
		payload["key_id"] = signatureData.KeyID
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/v1/transit/verify/aegis-signature", v.vaultURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", v.vaultToken)
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(string(jsonData)))

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("vault verification failed with status %d", resp.StatusCode)
	}

	var result VaultSignatureResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode vault response: %w", err)
	}

	if !result.Valid {
		return fmt.Errorf("vault signature verification failed: %s", result.Error)
	}

	return nil
}

// verifyWithDevKey verifies signature using development public key
func (v *Verifier) verifyWithDevKey(data []byte, signatureData SignatureData) error {
	if v.devPubKey == nil {
		return fmt.Errorf("no development public key available")
	}

	// Decode the signature
	signature, err := base64.StdEncoding.DecodeString(signatureData.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Hash the data
	hasher := sha256.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Verify the signature
	switch signatureData.Algorithm {
	case "RSA-SHA256", "rsa-sha256":
		err = rsa.VerifyPKCS1v15(v.devPubKey, crypto.SHA256, hashed, signature)
	case "RSA-PSS", "rsa-pss":
		err = rsa.VerifyPSS(v.devPubKey, crypto.SHA256, hashed, signature, nil)
	default:
		return fmt.Errorf("unsupported signature algorithm: %s", signatureData.Algorithm)
	}

	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// loadPublicKey loads a public key from a file
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not RSA")
		}
		return rsaPub, nil
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
	}
}

// VerifyBundleSignature verifies the signature of a downloaded bundle
func (v *Verifier) VerifyBundleSignature(ctx context.Context, bundlePath string, signatureData SignatureData) error {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read bundle file: %w", err)
	}

	return v.VerifySignature(ctx, data, signatureData)
}
