package oauth

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Southclaws/oauthcli/internal/jose"
)

// DPoP holds the key a client proves possession of (RFC 9449).
type DPoP struct {
	Key crypto.Signer
	Alg string
	// Nonce is the last DPoP-Nonce the authorization server handed out, echoed
	// in the next proof to it. RFC 9449 §9 keeps resource server nonces apart,
	// because each server accepts only the nonces it issued.
	Nonce string
	// ResourceNonce is the last DPoP-Nonce a resource server handed out.
	ResourceNonce string
	// HTUOverride replaces the htu claim, for probes that send a proof for the
	// wrong URL on purpose.
	HTUOverride string
}

// NewDPoP generates a fresh P-256 key, or loads one from a PEM file.
func NewDPoP(keyPath string) (*DPoP, error) {
	if keyPath != "" {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read DPoP key: %w", err)
		}
		signer, err := jose.ParsePrivateKeyPEM(data)
		if err != nil {
			return nil, fmt.Errorf("DPoP key: %w", err)
		}
		alg, err := jose.DefaultAlg(signer)
		if err != nil {
			return nil, err
		}
		return &DPoP{Key: signer, Alg: alg}, nil
	}
	key, err := jose.GenerateES256()
	if err != nil {
		return nil, err
	}
	return &DPoP{Key: key, Alg: "ES256"}, nil
}

// DPoPFromJWK reloads a key saved in the token store.
func DPoPFromJWK(raw json.RawMessage) (*DPoP, error) {
	var jwk jose.JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("saved DPoP key: %w", err)
	}
	signer, err := jwk.Signer()
	if err != nil {
		return nil, fmt.Errorf("saved DPoP key: %w", err)
	}
	alg, err := jose.DefaultAlg(signer)
	if err != nil {
		return nil, err
	}
	return &DPoP{Key: signer, Alg: alg}, nil
}

// JWK returns the private key as a JWK document for saving.
func (d *DPoP) JWK() (json.RawMessage, error) {
	jwk, err := jose.PrivateJWK(d.Key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(jwk)
}

// Thumbprint is the jkt value a bound token carries in cnf.
func (d *DPoP) Thumbprint() (string, error) {
	public, err := jose.PublicJWK(d.Key.Public())
	if err != nil {
		return "", err
	}
	return public.Thumbprint()
}

// Proof builds the DPoP proof JWT for one request to the authorization
// server. accessToken, when set, is hashed into ath.
func (d *DPoP) Proof(method, target, accessToken string) (string, error) {
	return d.proof(method, target, accessToken, d.Nonce)
}

// ResourceProof builds the proof for a request to a protected resource, with
// the resource server's nonce.
func (d *DPoP) ResourceProof(method, target, accessToken string) (string, error) {
	return d.proof(method, target, accessToken, d.ResourceNonce)
}

func (d *DPoP) proof(method, target, accessToken, nonce string) (string, error) {
	public, err := jose.PublicJWK(d.Key.Public())
	if err != nil {
		return "", err
	}
	// htu is the URL without query and fragment (RFC 9449 §4.2).
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	u.RawQuery = ""
	u.Fragment = ""
	htu := u.String()
	if d.HTUOverride != "" {
		htu = d.HTUOverride
	}

	header := map[string]any{"typ": "dpop+jwt", "jwk": public}
	claims := map[string]any{
		"jti": jose.RandomString(16),
		"htm": strings.ToUpper(method),
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		claims["ath"] = jose.SHA256URL(accessToken)
	}
	return jose.Sign(header, claims, d.Key, d.Alg)
}
