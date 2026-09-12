// Package jose implements the parts of JWS, JWT and JWK that an OAuth client
// and validator need: decoding compact tokens, verifying and producing
// signatures with the algorithms the RFCs register, and reading key sets.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

// JWS is a decoded compact serialization.
type JWS struct {
	Header    map[string]any
	Claims    map[string]any
	RawHeader []byte
	RawClaims []byte
	Signature []byte
	// SigningInput is the "header.payload" text the signature covers.
	SigningInput string
}

// ErrNotJWT reports that a token is not three base64url segments.
var ErrNotJWT = errors.New("not a JWT")

// Parse decodes a compact JWS without verifying it. Claims that are not a
// JSON object are an error; an unsigned token (alg none) parses with an empty
// signature.
func Parse(token string) (*JWS, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrNotJWT
	}

	header, err := decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrNotJWT, err)
	}
	claims, err := decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %w", ErrNotJWT, err)
	}
	signature, err := decode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %w", ErrNotJWT, err)
	}

	jws := &JWS{RawHeader: header, RawClaims: claims, Signature: signature, SigningInput: parts[0] + "." + parts[1]}
	if err := json.Unmarshal(header, &jws.Header); err != nil {
		return nil, fmt.Errorf("%w: header is not a JSON object", ErrNotJWT)
	}
	if err := json.Unmarshal(claims, &jws.Claims); err != nil {
		return nil, fmt.Errorf("%w: payload is not a JSON object", ErrNotJWT)
	}
	return jws, nil
}

// Alg is the alg header, or "" when absent.
func (j *JWS) Alg() string { return j.headerString("alg") }

// Kid is the kid header, or "".
func (j *JWS) Kid() string { return j.headerString("kid") }

// Typ is the typ header, or "".
func (j *JWS) Typ() string { return j.headerString("typ") }

func (j *JWS) headerString(name string) string {
	value, _ := j.Header[name].(string)
	return value
}

// String returns a string claim, or "".
func (j *JWS) String(name string) string {
	value, _ := j.Claims[name].(string)
	return value
}

// Time returns a NumericDate claim. ok is false when absent or not numeric.
func (j *JWS) Time(name string) (time.Time, bool) {
	switch value := j.Claims[name].(type) {
	case float64:
		seconds, fraction := int64(value), value-float64(int64(value))
		return time.Unix(seconds, int64(fraction*1e9)), true
	case json.Number:
		f, err := value.Float64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(int64(f), 0), true
	}
	return time.Time{}, false
}

// Strings returns a claim that is a string or an array of strings, as the aud
// claim is defined.
func (j *JWS) Strings(name string) []string {
	switch value := j.Claims[name].(type) {
	case string:
		return []string{value}
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Verify checks the signature with key, which must match alg. HMAC algorithms
// take a []byte secret.
func (j *JWS) Verify(key any) error {
	alg := j.Alg()
	if alg == "" || alg == "none" {
		return errors.New("token is unsigned (alg none)")
	}
	if len(j.Signature) == 0 {
		return errors.New("token has an empty signature")
	}

	hash, err := hashFor(alg)
	if err != nil {
		return err
	}
	digest := hash.New()
	digest.Write([]byte(j.SigningInput))
	sum := digest.Sum(nil)

	switch {
	case strings.HasPrefix(alg, "HS"):
		secret, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("%s needs a shared secret", alg)
		}
		mac := hmac.New(hash.New, secret)
		mac.Write([]byte(j.SigningInput))
		if !hmac.Equal(mac.Sum(nil), j.Signature) {
			return errors.New("HMAC does not match")
		}
		return nil

	case strings.HasPrefix(alg, "RS"):
		public, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s needs an RSA public key, got %T", alg, key)
		}
		return rsa.VerifyPKCS1v15(public, hash, sum, j.Signature)

	case strings.HasPrefix(alg, "PS"):
		public, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s needs an RSA public key, got %T", alg, key)
		}
		return rsa.VerifyPSS(public, hash, sum, j.Signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})

	case strings.HasPrefix(alg, "ES"):
		public, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s needs an EC public key, got %T", alg, key)
		}
		size := (public.Curve.Params().BitSize + 7) / 8
		if len(j.Signature) != 2*size {
			return fmt.Errorf("signature is %d bytes, want %d for %s", len(j.Signature), 2*size, alg)
		}
		r := new(big.Int).SetBytes(j.Signature[:size])
		s := new(big.Int).SetBytes(j.Signature[size:])
		if !ecdsa.Verify(public, sum, r, s) {
			return errors.New("ECDSA signature does not verify")
		}
		return nil

	case alg == "EdDSA":
		public, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("EdDSA needs an Ed25519 public key, got %T", key)
		}
		if !ed25519.Verify(public, []byte(j.SigningInput), j.Signature) {
			return errors.New("EdDSA signature does not verify")
		}
		return nil
	}

	return fmt.Errorf("unsupported algorithm %q", alg)
}

// hashFor returns the digest an algorithm uses. EdDSA hashes internally, so it
// is given SHA-512 only to satisfy the caller's pre-hash; the verifier ignores
// the digest for it.
func hashFor(alg string) (crypto.Hash, error) {
	switch alg {
	case "HS256", "RS256", "PS256", "ES256":
		return crypto.SHA256, nil
	case "HS384", "RS384", "PS384", "ES384":
		return crypto.SHA384, nil
	case "HS512", "RS512", "PS512", "ES512", "EdDSA":
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported algorithm %q", alg)
}

// Sign produces a compact JWS over claims with the given header, using signer
// and alg. The alg header is set from alg; typ and kid come from header.
func Sign(header map[string]any, claims map[string]any, signer crypto.Signer, alg string) (string, error) {
	if header == nil {
		header = map[string]any{}
	}
	header["alg"] = alg

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := encode(headerJSON) + "." + encode(claimsJSON)

	signature, err := sign([]byte(input), signer, alg)
	if err != nil {
		return "", err
	}
	return input + "." + encode(signature), nil
}

func sign(input []byte, signer crypto.Signer, alg string) ([]byte, error) {
	switch {
	case strings.HasPrefix(alg, "HS"):
		secret, ok := signer.(hmacSigner)
		if !ok {
			return nil, fmt.Errorf("%s needs a shared secret", alg)
		}
		hash, err := hashFor(alg)
		if err != nil {
			return nil, err
		}
		mac := hmac.New(hash.New, secret)
		mac.Write(input)
		return mac.Sum(nil), nil

	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		hash, err := hashFor(alg)
		if err != nil {
			return nil, err
		}
		digest := hash.New()
		digest.Write(input)
		if strings.HasPrefix(alg, "PS") {
			return signer.Sign(rand.Reader, digest.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
		}
		return signer.Sign(rand.Reader, digest.Sum(nil), hash)

	case strings.HasPrefix(alg, "ES"):
		private, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s needs an EC private key, got %T", alg, signer)
		}
		hash, err := hashFor(alg)
		if err != nil {
			return nil, err
		}
		digest := hash.New()
		digest.Write(input)
		r, s, err := ecdsa.Sign(rand.Reader, private, digest.Sum(nil))
		if err != nil {
			return nil, err
		}
		size := (private.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil

	case alg == "EdDSA":
		return signer.Sign(rand.Reader, input, crypto.Hash(0))
	}
	return nil, fmt.Errorf("unsupported algorithm %q", alg)
}

// hmacSigner lets a shared secret travel through the crypto.Signer parameter
// of Sign, so client_secret_jwt uses the same code path as private_key_jwt.
type hmacSigner []byte

func (s hmacSigner) Public() crypto.PublicKey { return nil }
func (s hmacSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	mac := hmac.New(sha256.New, s)
	mac.Write(digest)
	return mac.Sum(nil), nil
}

// HMACSigner wraps a shared secret for Sign with an HS* algorithm.
func HMACSigner(secret []byte) crypto.Signer { return hmacSigner(secret) }

// DefaultAlg picks the conventional algorithm for a key: RS256, ES256/384/512
// by curve, or EdDSA.
func DefaultAlg(key crypto.Signer) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return "RS256", nil
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return "ES256", nil
		case 384:
			return "ES384", nil
		case 521:
			return "ES512", nil
		}
		return "", fmt.Errorf("unsupported curve %s", k.Curve.Params().Name)
	case ed25519.PrivateKey:
		return "EdDSA", nil
	case hmacSigner:
		return "HS256", nil
	}
	return "", fmt.Errorf("unsupported key type %T", key)
}

// SHA256URL returns the base64url SHA-256 of text, the form the at_hash, c_hash
// and DPoP ath claims use.
func SHA256URL(text string) string {
	sum := sha256.Sum256([]byte(text))
	return encode(sum[:])
}

// HalfHash returns the left half of the hash of text using the digest of alg,
// base64url encoded, as OpenID Connect defines at_hash and c_hash.
func HalfHash(text, alg string) (string, error) {
	hash, err := hashFor(alg)
	if err != nil {
		return "", err
	}
	var sum []byte
	switch hash {
	case crypto.SHA256:
		s := sha256.Sum256([]byte(text))
		sum = s[:]
	case crypto.SHA384:
		s := sha512.Sum384([]byte(text))
		sum = s[:]
	default:
		s := sha512.Sum512([]byte(text))
		sum = s[:]
	}
	return encode(sum[:len(sum)/2]), nil
}

// RandomString returns n bytes of randomness as base64url text, for state,
// nonce, jti and PKCE verifiers.
func RandomString(n int) string {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return encode(buffer)
}

func decode(segment string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(segment, "="))
}

func encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Encode is base64url without padding.
func Encode(data []byte) string { return encode(data) }

// EncodeStd is standard base64 with padding, the form HTTP Basic uses.
func EncodeStd(data []byte) string { return base64.StdEncoding.EncodeToString(data) }
