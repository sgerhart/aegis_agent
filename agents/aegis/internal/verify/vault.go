package verify

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// VerifyBundle verifies base64 signature for data using a PEM-encoded RSA public key.
func VerifyBundle(pubPEM string, data []byte, b64sig string) error {
	if pubPEM == "" { return errors.New("no public key configured") }
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil { return errors.New("bad PEM public key") }
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil { return err }
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok { return errors.New("not an RSA public key") }
	sig, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil { return err }
	h := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h[:], sig)
}
