package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// verifierAlphabet is the unreserved character set RFC 7636 §4.1 allows.
const verifierAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// PKCE is a code verifier with its S256 challenge.
type PKCE struct {
	Verifier  string
	Challenge string
	Method    string
}

// NewPKCE generates a verifier of the given length (43 to 128) and its
// challenge.
func NewPKCE(length int) (*PKCE, error) {
	if length < 43 || length > 128 {
		return nil, fmt.Errorf("verifier length must be 43 to 128, got %d", length)
	}
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return nil, err
	}
	verifier := make([]byte, length)
	for i, b := range buffer {
		verifier[i] = verifierAlphabet[int(b)%len(verifierAlphabet)]
	}
	return PKCEFromVerifier(string(verifier))
}

// PKCEFromVerifier computes the S256 challenge of an existing verifier.
func PKCEFromVerifier(verifier string) (*PKCE, error) {
	if len(verifier) < 43 || len(verifier) > 128 {
		return nil, fmt.Errorf("verifier must be 43 to 128 characters, got %d", len(verifier))
	}
	for _, r := range verifier {
		if r > 127 || !containsRune(verifierAlphabet, byte(r)) {
			return nil, fmt.Errorf("verifier contains %q, which is outside [A-Za-z0-9-._~]", r)
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	return &PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		Method:    "S256",
	}, nil
}

func containsRune(alphabet string, b byte) bool {
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == b {
			return true
		}
	}
	return false
}
