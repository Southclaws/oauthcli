package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// JWK is a JSON Web Key. Only the members needed to identify a key and
// reconstruct its public part are typed; Extra keeps everything else so a
// document can be shown as the server sent it.
type JWK struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	Use    string   `json:"use,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`
	D      string   `json:"d,omitempty"`
	K      string   `json:"k,omitempty"`
	P      string   `json:"p,omitempty"`
	Q      string   `json:"q,omitempty"`
	DP     string   `json:"dp,omitempty"`
	DQ     string   `json:"dq,omitempty"`
	QI     string   `json:"qi,omitempty"`
	X5C    []string `json:"x5c,omitempty"`
	X5T    string   `json:"x5t,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}

// Set is a JSON Web Key Set.
type Set struct {
	Keys []JWK `json:"keys"`
	// MissingKeysMember records that the document had no keys member at all,
	// which RFC 7517 §5 forbids; an empty array is a different condition.
	MissingKeysMember bool `json:"-"`
	// RawKeys keeps every key as sent, so members the typed JWK drops (such
	// as x5c chains beyond the leaf) can still be inspected.
	RawKeys []map[string]any `json:"-"`
}

// ParseSet decodes a key set document.
func ParseSet(data []byte) (*Set, error) {
	var set Set
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("key set is not valid JSON: %w", err)
	}
	var raw struct {
		Keys *[]map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err == nil {
		set.MissingKeysMember = raw.Keys == nil
		if raw.Keys != nil {
			set.RawKeys = *raw.Keys
		}
	}
	return &set, nil
}

// Find returns the key that matches kid, or the only key when kid is empty
// and the set has one key, or the first key compatible with alg.
func (s *Set) Find(kid, alg string) (*JWK, string) {
	candidates := s.Candidates(kid, alg)
	switch {
	case len(candidates) == 0:
		return nil, ""
	case kid != "":
		return candidates[0], "kid " + kid
	case len(candidates) == 1:
		return candidates[0], "the only compatible key"
	default:
		return candidates[0], "the first compatible key (token has no kid)"
	}
}

// Candidates lists every key that could verify a token with the given kid and
// alg. RFC 7517 §5.1 gives the order of a set no meaning, so a verifier must
// try each one before declaring a signature invalid.
func (s *Set) Candidates(kid, alg string) []*JWK {
	if kid != "" {
		for i := range s.Keys {
			if s.Keys[i].Kid == kid {
				return []*JWK{&s.Keys[i]}
			}
		}
		return nil
	}
	var candidates []*JWK
	for i := range s.Keys {
		key := &s.Keys[i]
		if key.Use == "enc" {
			continue
		}
		if alg != "" && key.Alg != "" && key.Alg != alg {
			continue
		}
		if alg != "" && !key.compatible(alg) {
			continue
		}
		candidates = append(candidates, key)
	}
	return candidates
}

func (k *JWK) compatible(alg string) bool {
	switch k.Kty {
	case "RSA":
		return len(alg) == 5 && (alg[:2] == "RS" || alg[:2] == "PS")
	case "EC":
		return len(alg) == 5 && alg[:2] == "ES"
	case "OKP":
		return alg == "EdDSA"
	case "oct":
		return len(alg) == 5 && alg[:2] == "HS"
	}
	return false
}

// Private reports whether the key carries private material. A published key
// set must never contain such a key.
func (k *JWK) Private() bool {
	return k.D != "" || k.K != "" || k.P != "" || k.Q != ""
}

// Public reconstructs the public key.
func (k *JWK) Public() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := decodeBig(k.N)
		if err != nil {
			return nil, fmt.Errorf("n: %w", err)
		}
		e, err := decodeBig(k.E)
		if err != nil {
			return nil, fmt.Errorf("e: %w", err)
		}
		if !e.IsInt64() || e.Int64() > 1<<31 {
			return nil, errors.New("exponent out of range")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil

	case "EC":
		curve, err := curveFor(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := decode(k.X)
		if err != nil {
			return nil, fmt.Errorf("x: %w", err)
		}
		y, err := decode(k.Y)
		if err != nil {
			return nil, fmt.Errorf("y: %w", err)
		}
		point := append([]byte{4}, x...)
		point = append(point, y...)
		public, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("point is not on the curve: %w", err)
		}
		return public, nil

	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		x, err := decode(k.X)
		if err != nil {
			return nil, fmt.Errorf("x: %w", err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("Ed25519 key is %d bytes, want %d", len(x), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(x), nil

	case "oct":
		return decode(k.K)
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

// Bits is the key size in bits, or 0 when it cannot be determined.
func (k *JWK) Bits() int {
	switch k.Kty {
	case "RSA":
		n, err := decodeBig(k.N)
		if err != nil {
			return 0
		}
		return n.BitLen()
	case "EC":
		curve, err := curveFor(k.Crv)
		if err != nil {
			return 0
		}
		return curve.Params().BitSize
	case "OKP":
		return 256
	case "oct":
		raw, err := decode(k.K)
		if err != nil {
			return 0
		}
		return len(raw) * 8
	}
	return 0
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint, base64url encoded. It hashes
// the required public members in lexicographic order with no whitespace.
func (k *JWK) Thumbprint() (string, error) {
	var canonical string
	switch k.Kty {
	case "RSA":
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
	case "OKP":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, k.Crv, k.X)
	case "oct":
		canonical = fmt.Sprintf(`{"k":%q,"kty":"oct"}`, k.K)
	default:
		return "", fmt.Errorf("unsupported key type %q", k.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return encode(sum[:]), nil
}

// PEM returns the public key in SubjectPublicKeyInfo PEM form.
func (k *JWK) PEM() (string, error) {
	public, err := k.Public()
	if err != nil {
		return "", err
	}
	if _, ok := public.([]byte); ok {
		return "", errors.New("a symmetric key has no PEM form")
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// Certificate returns the leaf certificate of the x5c chain, when present.
func (k *JWK) Certificate() (*x509.Certificate, error) {
	if len(k.X5C) == 0 {
		return nil, nil
	}
	der, err := base64.StdEncoding.DecodeString(k.X5C[0])
	if err != nil {
		return nil, fmt.Errorf("x5c[0]: %w", err)
	}
	return x509.ParseCertificate(der)
}

// PublicJWK builds the JWK of a public key, for embedding in a DPoP proof or a
// client's key set.
func PublicJWK(public crypto.PublicKey) (*JWK, error) {
	switch key := public.(type) {
	case *rsa.PublicKey:
		return &JWK{Kty: "RSA", N: encode(key.N.Bytes()), E: encode(big.NewInt(int64(key.E)).Bytes())}, nil
	case *ecdsa.PublicKey:
		point, err := key.Bytes()
		if err != nil {
			return nil, err
		}
		size := (len(point) - 1) / 2
		return &JWK{Kty: "EC", Crv: curveName(key.Curve), X: encode(point[1 : 1+size]), Y: encode(point[1+size:])}, nil
	case ed25519.PublicKey:
		return &JWK{Kty: "OKP", Crv: "Ed25519", X: encode(key)}, nil
	}
	return nil, fmt.Errorf("unsupported public key %T", public)
}

// PrivateJWK serialises a private key as a JWK, so a DPoP key can be kept in
// the token store and reloaded for later requests.
func PrivateJWK(signer crypto.Signer) (*JWK, error) {
	switch key := signer.(type) {
	case *ecdsa.PrivateKey:
		public, err := PublicJWK(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		d, err := key.Bytes()
		if err != nil {
			return nil, err
		}
		public.D = encode(d)
		return public, nil
	case *rsa.PrivateKey:
		public, err := PublicJWK(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		public.D = encode(key.D.Bytes())
		public.P = encode(key.Primes[0].Bytes())
		public.Q = encode(key.Primes[1].Bytes())
		key.Precompute()
		public.DP = encode(key.Precomputed.Dp.Bytes())
		public.DQ = encode(key.Precomputed.Dq.Bytes())
		public.QI = encode(key.Precomputed.Qinv.Bytes())
		return public, nil
	case ed25519.PrivateKey:
		public, err := PublicJWK(key.Public())
		if err != nil {
			return nil, err
		}
		public.D = encode(key.Seed())
		return public, nil
	}
	return nil, fmt.Errorf("unsupported private key %T", signer)
}

// Signer reconstructs a private key from a JWK that carries private members.
func (k *JWK) Signer() (crypto.Signer, error) {
	if !k.Private() {
		return nil, errors.New("key has no private members")
	}
	switch k.Kty {
	case "EC":
		curve, err := curveFor(k.Crv)
		if err != nil {
			return nil, err
		}
		d, err := decode(k.D)
		if err != nil {
			return nil, fmt.Errorf("d: %w", err)
		}
		return ecdsa.ParseRawPrivateKey(curve, d)
	case "RSA":
		public, err := k.Public()
		if err != nil {
			return nil, err
		}
		d, err := decodeBig(k.D)
		if err != nil {
			return nil, fmt.Errorf("d: %w", err)
		}
		p, err := decodeBig(k.P)
		if err != nil {
			return nil, fmt.Errorf("p: %w", err)
		}
		q, err := decodeBig(k.Q)
		if err != nil {
			return nil, fmt.Errorf("q: %w", err)
		}
		private := &rsa.PrivateKey{PublicKey: *public.(*rsa.PublicKey), D: d, Primes: []*big.Int{p, q}}
		private.Precompute()
		return private, private.Validate()
	case "OKP":
		seed, err := decode(k.D)
		if err != nil {
			return nil, fmt.Errorf("d: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("Ed25519 seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

// ParsePrivateKeyPEM reads a PKCS #8, PKCS #1 or SEC 1 private key.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("no private key found in PEM data")
		}
		switch block.Type {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			signer, ok := key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("unsupported key type %T", key)
			}
			return signer, nil
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		}
	}
}

// GenerateES256 creates a fresh P-256 key, the algorithm every DPoP server
// must support.
func GenerateES256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func curveFor(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("unsupported curve %q", name)
}

func curveName(curve elliptic.Curve) string {
	switch curve.Params().BitSize {
	case 256:
		return "P-256"
	case 384:
		return "P-384"
	case 521:
		return "P-521"
	}
	return curve.Params().Name
}

func decodeBig(segment string) (*big.Int, error) {
	if segment == "" {
		return nil, errors.New("missing")
	}
	raw, err := decode(segment)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}
