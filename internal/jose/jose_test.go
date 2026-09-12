package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestSignAndVerifyRoundTrips(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]any{"sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}

	token, err := Sign(map[string]any{"typ": "JWT", "kid": "k1"}, claims, rsaKey, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(token)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Alg() != "RS256" || parsed.Kid() != "k1" || parsed.String("sub") != "alice" {
		t.Fatalf("header/claims did not round trip: %+v %+v", parsed.Header, parsed.Claims)
	}
	if err := parsed.Verify(&rsaKey.PublicKey); err != nil {
		t.Fatalf("RS256 verify: %v", err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := parsed.Verify(&other.PublicKey); err == nil {
		t.Fatal("RS256 verified with the wrong key")
	}

	token, err = Sign(nil, claims, rsaKey, "PS256")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ = Parse(token)
	if err := parsed.Verify(&rsaKey.PublicKey); err != nil {
		t.Fatalf("PS256 verify: %v", err)
	}

	token, err = Sign(nil, claims, ecKey, "ES256")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ = Parse(token)
	if err := parsed.Verify(&ecKey.PublicKey); err != nil {
		t.Fatalf("ES256 verify: %v", err)
	}
	if len(parsed.Signature) != 64 {
		t.Fatalf("ES256 signature is %d bytes, want 64 (raw r||s)", len(parsed.Signature))
	}

	token, err = Sign(nil, claims, edKey, "EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ = Parse(token)
	if err := parsed.Verify(edKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("EdDSA verify: %v", err)
	}

	token, err = Sign(nil, claims, HMACSigner([]byte("secret")), "HS256")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ = Parse(token)
	if err := parsed.Verify([]byte("secret")); err != nil {
		t.Fatalf("HS256 verify: %v", err)
	}
	if err := parsed.Verify([]byte("wrong")); err == nil {
		t.Fatal("HS256 verified with the wrong secret")
	}
}

// The example key of RFC 7638 §3.1 has a known thumbprint.
func TestThumbprintMatchesRFC7638(t *testing.T) {
	key := JWK{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
	}
	thumbprint, err := key.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if thumbprint != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %q does not match RFC 7638", thumbprint)
	}
	if key.Bits() != 2048 {
		t.Fatalf("bits %d, want 2048", key.Bits())
	}
}

func TestJWKRoundTripsThroughPublicAndPrivateForms(t *testing.T) {
	ecKey, err := GenerateES256()
	if err != nil {
		t.Fatal(err)
	}
	private, err := PrivateJWK(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	if !private.Private() {
		t.Fatal("private JWK reports no private members")
	}
	signer, err := private.Signer()
	if err != nil {
		t.Fatal(err)
	}
	restored := signer.(*ecdsa.PrivateKey)
	if !restored.PublicKey.Equal(&ecKey.PublicKey) {
		t.Fatal("restored key differs")
	}

	public, err := PublicJWK(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if public.Private() {
		t.Fatal("public JWK carries private members")
	}
	reconstructed, err := public.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !reconstructed.(*ecdsa.PublicKey).Equal(&ecKey.PublicKey) {
		t.Fatal("public key did not round trip")
	}
	if _, err := public.PEM(); err != nil {
		t.Fatal(err)
	}
}

func TestSetFindPrefersKidThenCompatibility(t *testing.T) {
	set := &Set{Keys: []JWK{
		{Kty: "RSA", Kid: "a", Alg: "RS256", N: "AQAB", E: "AQAB"},
		{Kty: "EC", Kid: "b", Crv: "P-256", Use: "sig"},
		{Kty: "RSA", Kid: "enc", Use: "enc"},
	}}
	if key, _ := set.Find("b", ""); key == nil || key.Kid != "b" {
		t.Fatal("kid lookup failed")
	}
	if key, _ := set.Find("missing", ""); key != nil {
		t.Fatal("unknown kid must not fall back")
	}
	if key, _ := set.Find("", "ES256"); key == nil || key.Kid != "b" {
		t.Fatal("alg compatibility lookup failed")
	}
	if key, _ := set.Find("", "RS256"); key == nil || key.Kid != "a" {
		t.Fatal("RS256 should select the RSA signing key, not the encryption key")
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := ParsePrivateKeyPEM(pkcs8); err != nil {
		t.Fatalf("PKCS8: %v", err)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	signer, err := ParsePrivateKeyPEM(pkcs1)
	if err != nil {
		t.Fatalf("PKCS1: %v", err)
	}
	if alg, _ := DefaultAlg(signer); alg != "RS256" {
		t.Fatalf("default alg for RSA is %q, want RS256", alg)
	}
	if _, err := ParsePrivateKeyPEM([]byte("not pem")); err == nil {
		t.Fatal("garbage must not parse")
	}
}

func TestParseRejectsNonJWTs(t *testing.T) {
	for _, text := range []string{"", "opaque-token", "a.b", "a.b.c.d", "!!!.!!!.!!!"} {
		if _, err := Parse(text); err == nil {
			t.Errorf("%q parsed as a JWT", text)
		}
	}
	if _, err := Parse("eyJhbGciOiJub25lIn0.e30."); err != nil {
		t.Fatalf("alg none token with empty signature should parse: %v", err)
	}
}

func TestHalfHash(t *testing.T) {
	// at_hash example from OpenID Connect Core §A.3 is not normative; check the
	// shape: 16 bytes base64url for SHA-256.
	hash, err := HalfHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y", "RS256")
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 22 {
		t.Fatalf("at_hash %q has length %d, want 22", hash, len(hash))
	}
}
