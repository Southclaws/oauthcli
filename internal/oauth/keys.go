package oauth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/jose"
)

// KeySet is a fetched JWKS with where it came from.
type KeySet struct {
	*jose.Set
	URL      string
	Response *Response
}

// FetchKeys reads a key set from a URL or a local file.
func (c *Client) FetchKeys(ctx context.Context, source string) (*KeySet, error) {
	if !strings.Contains(source, "://") {
		data, err := os.ReadFile(source)
		if err != nil {
			return nil, fmt.Errorf("read key set %s: %w", source, err)
		}
		set, err := jose.ParseSet(data)
		if err != nil {
			return nil, err
		}
		return &KeySet{Set: set, URL: source}, nil
	}

	response, err := c.Get(ctx, source)
	if err != nil {
		return nil, err
	}
	if response.Status != 200 {
		return nil, fmt.Errorf("%w: key set %s: HTTP %d", ErrUnreachable, source, response.Status)
	}
	set, err := jose.ParseSet(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return &KeySet{Set: set, URL: source, Response: response}, nil
}

// DescribeKey converts a key into the declared output shape with its findings.
// mixedUse reports whether the set holds both signing and encryption keys,
// which makes use mandatory on every key (RFC 8414 §2).
func DescribeKey(key *jose.JWK, multiple, mixedUse, withPEM bool) cligen.Jwk {
	out := cligen.Jwk{Kty: key.Kty, Issues: []cligen.Issue{}}
	if key.Kid != "" {
		out.Kid = &key.Kid
	}
	if key.Alg != "" {
		out.Alg = &key.Alg
	}
	if key.Use != "" {
		out.Use = &key.Use
	}
	if key.Crv != "" {
		out.Crv = &key.Crv
	}
	if bits := key.Bits(); bits > 0 {
		out.Bits = &bits
	}

	if key.Kty == "" {
		out.Issues = append(out.Issues, Errorf("kty-missing", "RFC 7517 §4.1", "kty", "kty must be present in every key"))
	}
	if key.Private() {
		out.Issues = append(out.Issues, Errorf("private-key-published", "RFC 7517 §9.2, RFC 8414 §2", "d", "the key set contains private key material; this key is compromised"))
	}
	if key.Kty == "oct" {
		out.Issues = append(out.Issues, Errorf("symmetric-key-published", "RFC 7517 §9.2, RFC 8414 §2", "k", "a symmetric key is published; it lets anyone forge tokens"))
	}
	if key.Kid == "" && multiple {
		out.Issues = append(out.Issues, Warnf("kid-missing", "OpenID Connect Core 1.0 §10.1", "kid", "kid is absent from a set with several keys; a token header must then name a kid the client cannot match"))
	}
	if key.Use == "" && len(key.KeyOps) == 0 {
		if mixedUse {
			out.Issues = append(out.Issues, Errorf("use-required", "RFC 8414 §2", "use", "use is required on every key when the set holds both signing and encryption keys"))
		} else {
			out.Issues = append(out.Issues, Infof("use-missing", "RFC 7517 §4.2", "use", "neither use nor key_ops is set (optional)"))
		}
	}
	if key.Use != "" && len(key.KeyOps) > 0 {
		out.Issues = append(out.Issues, Warnf("use-and-key-ops", "RFC 7517 §4.3", "key_ops", "use and key_ops should not be used together"))
		if !useMatchesOps(key.Use, key.KeyOps) {
			out.Issues = append(out.Issues, Errorf("use-key-ops-inconsistent", "RFC 7517 §4.3", "key_ops", "use %q and key_ops %v convey different information", key.Use, key.KeyOps))
		}
	}
	if hasDuplicate(key.KeyOps) {
		out.Issues = append(out.Issues, Errorf("key-ops-duplicate", "RFC 7517 §4.3", "key_ops", "key_ops must not contain duplicate values"))
	}
	if key.Alg == "" {
		out.Issues = append(out.Issues, Infof("alg-missing", "RFC 7517 §4.4", "alg", "alg is not set (optional); clients infer it from the token header"))
	}
	if key.Kty == "RSA" && out.Bits != nil && *out.Bits < 2048 {
		out.Issues = append(out.Issues, Errorf("rsa-too-small", "RFC 7518 §3.3, §3.5", "n", "RSA key is %d bits; at least 2048 is required", *out.Bits))
	}

	thumbprint, err := key.Thumbprint()
	out.Thumbprint = thumbprint
	public, publicErr := key.Public()
	switch {
	case key.Kty == "":
	case err != nil || (publicErr != nil && strings.Contains(publicErr.Error(), "unsupported")):
		out.Issues = append(out.Issues, Warnf("key-unsupported", "RFC 7517 §5", "kty", "key type %s (curve %q) is not one this tool understands; clients ignore keys they do not understand", key.Kty, key.Crv))
	case publicErr != nil && !key.Private():
		section := "RFC 7518 §6"
		switch key.Kty {
		case "EC":
			section = "RFC 7518 §6.2.1"
		case "RSA":
			section = "RFC 7518 §6.3.1"
		}
		out.Issues = append(out.Issues, Errorf("key-unusable", section, "", "the public key cannot be reconstructed: %v", publicErr))
	}

	if certificate, err := key.Certificate(); err != nil {
		out.Issues = append(out.Issues, Errorf("x5c-invalid", "RFC 7517 §4.7", "x5c", "the x5c certificate does not parse: %v", err))
	} else if certificate != nil {
		info := cligen.CertificateInfo{
			Subject:   certificate.Subject.String(),
			Issuer:    certificate.Issuer.String(),
			NotBefore: certificate.NotBefore,
			NotAfter:  certificate.NotAfter,
			Expired:   time.Now().After(certificate.NotAfter),
		}
		serial := certificate.SerialNumber.String()
		info.SerialNumber = &serial
		out.Certificate = &info
		if info.Expired {
			out.Issues = append(out.Issues, Warnf("x5c-expired", "RFC 7517 §4.7", "x5c", "the x5c certificate expired on %s", certificate.NotAfter.Format(time.RFC3339)))
		}
		if public != nil {
			if matcher, ok := certificate.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !matcher.Equal(public) {
				out.Issues = append(out.Issues, Errorf("x5c-key-mismatch", "RFC 7517 §4.7", "x5c", "the key in the first x5c certificate does not match the key the JWK members describe"))
			}
		}
	}

	if withPEM {
		if pemText, err := key.PEM(); err == nil {
			out.Pem = &pemText
		}
	}
	return out
}

func useMatchesOps(use string, ops []string) bool {
	for _, op := range ops {
		switch op {
		case "sign", "verify":
			if use != "sig" {
				return false
			}
		case "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits":
			if use != "enc" {
				return false
			}
		}
	}
	return true
}

func hasDuplicate(items []string) bool {
	seen := map[string]bool{}
	for _, item := range items {
		if seen[item] {
			return true
		}
		seen[item] = true
	}
	return false
}

// DescribeKeySet converts a whole set, adding set-level findings.
func DescribeKeySet(set *KeySet, withPEM bool) cligen.KeySet {
	out := cligen.KeySet{URL: set.URL, Keys: []cligen.Jwk{}, Issues: []cligen.Issue{}}
	if set.Response != nil && !set.Response.IsJSON() {
		out.Issues = append(out.Issues, Infof("content-type", "RFC 7517 §8.5.1", "", "Content-Type is %q; application/jwk-set+json or application/json is the registered type", set.Response.Header.Get("Content-Type")))
	}
	switch {
	case set.MissingKeysMember:
		out.Issues = append(out.Issues, Errorf("no-keys", "RFC 7517 §5", "keys", "the document has no keys member"))
	case len(set.Keys) == 0:
		out.Issues = append(out.Issues, Warnf("no-keys", "RFC 7517 §5", "keys", "the key set is empty"))
	}
	signing, encryption := false, false
	for _, key := range set.Keys {
		switch key.Use {
		case "sig":
			signing = true
		case "enc":
			encryption = true
		}
	}
	seen := map[string][]string{}
	for i := range set.Keys {
		key := &set.Keys[i]
		if key.Kid != "" {
			seen[key.Kid] = append(seen[key.Kid], key.Kty)
		}
		out.Keys = append(out.Keys, DescribeKey(key, len(set.Keys) > 1, signing && encryption, withPEM))
	}
	for kid, types := range seen {
		if len(types) > 1 && !allDifferent(types) {
			out.Issues = append(out.Issues, Warnf("kid-duplicate", "RFC 7517 §4.5", "kid", "kid %q appears %d times with the same key type; different keys should use distinct kid values", kid, len(types)))
		}
	}
	return out
}

func allDifferent(items []string) bool {
	return !hasDuplicate(items)
}

// Verifier verifies JWTs against an issuer's key set, fetching the set once.
type Verifier struct {
	client *Client
	issuer string
	// KeysURL overrides the jwks_uri from the metadata.
	KeysURL string
	// Secret verifies HMAC-signed tokens.
	Secret []byte
	set    *KeySet
	setErr error
}

// NewVerifier prepares a verifier for issuer. The key set is fetched lazily.
func (c *Client) NewVerifier(issuer string) *Verifier {
	return &Verifier{client: c, issuer: issuer}
}

// Keys returns the key set, fetching it on first use from KeysURL or from the
// issuer's metadata.
func (v *Verifier) Keys(ctx context.Context) (*KeySet, error) {
	if v.set != nil || v.setErr != nil {
		return v.set, v.setErr
	}
	source := v.KeysURL
	if source == "" {
		if v.issuer == "" {
			v.setErr = errors.New("no issuer to fetch keys from")
			return nil, v.setErr
		}
		metadata, err := v.client.FetchMetadata(ctx, v.issuer, "auto")
		if err != nil {
			v.setErr = err
			return nil, err
		}
		source = metadata.String("jwks_uri")
		if source == "" {
			v.setErr = fmt.Errorf("%s advertises no jwks_uri", v.issuer)
			return nil, v.setErr
		}
	}
	v.set, v.setErr = v.client.FetchKeys(ctx, source)
	return v.set, v.setErr
}

// Verify checks the signature of a parsed token and reports where the key
// came from. The result never carries an error for an unsigned token; that
// is a finding for the caller to grade.
func (v *Verifier) Verify(ctx context.Context, token *jose.JWS) cligen.Signature {
	alg := token.Alg()
	out := cligen.Signature{Status: "unverified"}
	if alg != "" {
		out.Alg = &alg
	}
	if kid := token.Kid(); kid != "" {
		out.Kid = &kid
	}
	if alg == "" || alg == "none" {
		out.Status = "unsigned"
		return out
	}

	if strings.HasPrefix(alg, "HS") {
		if len(v.Secret) == 0 {
			out.Error = Ptr("an HMAC-signed token needs --secret to verify")
			return out
		}
		if err := token.Verify(v.Secret); err != nil {
			out.Status = "invalid"
			out.Error = Ptr(err.Error())
			return out
		}
		out.Status = "verified"
		out.KeySource = Ptr("shared secret")
		return out
	}

	set, err := v.Keys(ctx)
	if err != nil {
		out.Error = Ptr(err.Error())
		return out
	}
	candidates := set.Candidates(token.Kid(), alg)
	if len(candidates) == 0 {
		out.Error = Ptr(fmt.Sprintf("no key in %s matches kid %q and alg %s", set.URL, token.Kid(), alg))
		return out
	}
	var lastErr error
	for _, key := range candidates {
		public, err := key.Public()
		if err != nil {
			lastErr = fmt.Errorf("key %q is unusable: %w", key.Kid, err)
			continue
		}
		if err := token.Verify(public); err != nil {
			lastErr = err
			continue
		}
		out.Status = "verified"
		how := "kid " + key.Kid
		if key.Kid == "" {
			how = "a key without kid"
		}
		if token.Kid() == "" && len(candidates) > 1 {
			how += " (token has no kid; matched by trial)"
		}
		out.KeySource = Ptr(fmt.Sprintf("%s from %s", how, set.URL))
		return out
	}
	out.Status = "invalid"
	out.Error = Ptr(fmt.Sprintf("%v (tried %d key(s))", lastErr, len(candidates)))
	out.KeySource = Ptr(set.URL)
	return out
}
