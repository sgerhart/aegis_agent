package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func getKeyPath() string {
	if dataDir := os.Getenv("AEGIS_DATA_DIR"); dataDir != "" {
		return filepath.Join(dataDir, "identity.key")
	}
	return "/var/lib/aegis/identity.key"
}

func ResolveHostID() string {
	if v := os.Getenv("AGENT_HOST_ID"); v != "" { return v }
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		id := strings.TrimSpace(string(b)); if id != "" { return id }
	}
	if h, err := os.Hostname(); err == nil && h != "" { return h }
	return "host-unknown"
}

func LoadOrCreateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	keyPath := getKeyPath()
	if b, err := os.ReadFile(keyPath); err == nil && len(b) == ed25519.PrivateKeySize {
		priv := ed25519.PrivateKey(b)
		return priv.Public().(ed25519.PublicKey), priv, nil
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil { return nil, nil, err }
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { return nil, nil, err }
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil { return nil, nil, err }
	return pub, priv, nil
}

func PubKeyB64(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

func Sign(priv ed25519.PrivateKey, msg []byte) (string, error) {
	if len(priv) != ed25519.PrivateKeySize { return "", errors.New("bad key") }
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), nil
}

