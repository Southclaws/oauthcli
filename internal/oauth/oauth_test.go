package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Southclaws/oauthcli/internal/cligen"
)

func TestNormalizeIssuer(t *testing.T) {
	cases := map[string]string{
		"auth.example.com":          "https://auth.example.com",
		"https://auth.example.com/": "https://auth.example.com",
		"https://a.example.com/t/":  "https://a.example.com/t",
		"http://127.0.0.1:8080":     "http://127.0.0.1:8080",
	}
	for in, want := range cases {
		got, err := NormalizeIssuer(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
	if _, err := NormalizeIssuer(""); err == nil {
		t.Fatal("empty issuer must fail")
	}
}

// RFC 8414 §3 inserts the well-known path after the host; OpenID appends it.
func TestWellKnownURLsHandleIssuerPaths(t *testing.T) {
	plain := WellKnownURLs("https://a.example.com", KindOAuth)
	if len(plain) != 1 || plain[0] != "https://a.example.com/.well-known/oauth-authorization-server" {
		t.Fatalf("plain issuer: %v", plain)
	}
	oauth := WellKnownURLs("https://a.example.com/tenant", KindOAuth)
	if oauth[0] != "https://a.example.com/.well-known/oauth-authorization-server/tenant" || oauth[1] != "https://a.example.com/tenant/.well-known/oauth-authorization-server" {
		t.Fatalf("RFC 8414 order: %v", oauth)
	}
	openid := WellKnownURLs("https://a.example.com/tenant", KindOpenID)
	if openid[0] != "https://a.example.com/tenant/.well-known/openid-configuration" {
		t.Fatalf("OpenID order: %v", openid)
	}
}

func TestPKCE(t *testing.T) {
	pair, err := NewPKCE(64)
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Verifier) != 64 || pair.Method != "S256" {
		t.Fatalf("unexpected pair %+v", pair)
	}
	again, err := PKCEFromVerifier(pair.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	if again.Challenge != pair.Challenge {
		t.Fatal("challenge is not deterministic")
	}
	// RFC 7636 Appendix B example.
	example, err := PKCEFromVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if err != nil {
		t.Fatal(err)
	}
	if example.Challenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %q does not match RFC 7636 appendix B", example.Challenge)
	}
	if _, err := NewPKCE(10); err == nil {
		t.Fatal("short verifier must be rejected")
	}
	if _, err := PKCEFromVerifier(strings.Repeat("a", 43) + "!"); err == nil {
		t.Fatal("verifier outside the alphabet must be rejected")
	}
}

func TestParseChallenge(t *testing.T) {
	challenge := ParseChallenge(`Bearer realm="api", error="invalid_token", error_description="expired, sorry", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"`)
	if challenge == nil || challenge.Scheme != "Bearer" {
		t.Fatalf("scheme: %+v", challenge)
	}
	if challenge.Params["error"] != "invalid_token" || challenge.Params["error_description"] != "expired, sorry" {
		t.Fatalf("params: %+v", challenge.Params)
	}
	if !strings.HasSuffix(challenge.Params["resource_metadata"], "oauth-protected-resource") {
		t.Fatalf("resource_metadata: %+v", challenge.Params)
	}
	if ParseChallenge("") != nil {
		t.Fatal("empty header must yield nil")
	}
}

func hasCode(issues []cligen.Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestMetadataValidateFindsTheClassicProblems(t *testing.T) {
	m := &Metadata{
		Issuer: "https://a.example.com",
		Kind:   KindOpenID,
		Raw: map[string]any{
			"issuer":                                "https://other.example.com",
			"authorization_endpoint":                "http://a.example.com/authorize",
			"token_endpoint":                        "https://a.example.com/token#frag",
			"grant_types_supported":                 []any{"authorization_code", "implicit", "password"},
			"response_types_supported":              []any{"code", "token"},
			"code_challenge_methods_supported":      []any{"plain"},
			"id_token_signing_alg_values_supported": []any{"HS256"},
		},
	}
	issues := m.Validate(false)
	for _, code := range []string{
		"issuer-mismatch", "endpoint-not-https", "endpoint-fragment", "jwks-uri-missing",
		"pkce-no-s256", "pkce-plain", "implicit-grant", "password-grant", "implicit-response-type",
		"subject-types-missing", "id-token-no-rs256", "scopes-missing",
	} {
		if !hasCode(issues, code) {
			t.Errorf("expected finding %s; got %v", code, codes(issues))
		}
	}

	clean := &Metadata{
		Issuer: "https://a.example.com",
		Kind:   KindOAuth,
		Raw: map[string]any{
			"issuer":                           "https://a.example.com",
			"authorization_endpoint":           "https://a.example.com/authorize",
			"token_endpoint":                   "https://a.example.com/token",
			"jwks_uri":                         "https://a.example.com/jwks",
			"scopes_supported":                 []any{"read"},
			"response_types_supported":         []any{"code"},
			"grant_types_supported":            []any{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported": []any{"S256"},
		},
	}
	if issues := clean.Validate(false); len(issues) != 0 {
		t.Fatalf("clean document has findings: %v", codes(issues))
	}
	if !clean.Capabilities()[1].Supported {
		t.Fatal("authorization_code capability should be supported")
	}
}

func codes(issues []cligen.Issue) []string {
	out := make([]string, 0, len(issues))
	for _, issue := range issues {
		out = append(out, issue.Code)
	}
	return out
}

func TestParseTokenResponseChecksRFC6749Requirements(t *testing.T) {
	response := &Response{
		Status: 200,
		Header: http.Header{"Content-Type": {"text/plain"}},
		Body:   []byte(`{"access_token":"abc","refresh_token":"r"}`),
	}
	result, err := ParseTokenResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"token-type-missing", "cache-control", "content-type", "expires-in-missing"} {
		if !hasCode(result.Issues, code) {
			t.Errorf("expected %s; got %v", code, codes(result.Issues))
		}
	}
	good := &Response{
		Status: 200,
		Header: http.Header{"Content-Type": {"application/json;charset=UTF-8"}, "Cache-Control": {"no-store"}, "Pragma": {"no-cache"}},
		Body:   []byte(`{"access_token":"abc","token_type":"Bearer","expires_in":3600,"scope":"read"}`),
	}
	result, err = ParseTokenResponse(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("good response has findings: %v", codes(result.Issues))
	}
	if result.ExpiresIn != 3600 || result.TokenType != "Bearer" {
		t.Fatalf("fields: %+v", result)
	}
}

func TestClientRefusesPlainHTTPExceptLoopback(t *testing.T) {
	client, err := NewClient(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), "http://example.com/x"); err == nil || !strings.Contains(err.Error(), "refusing plain http") {
		t.Fatalf("expected a plain http refusal, got %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	response, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("loopback http should be allowed: %v", err)
	}
	if !response.IsJSON() || response.Status != 200 {
		t.Fatalf("unexpected response %+v", response)
	}
}

func TestCredentialsResolveAndApply(t *testing.T) {
	c := &Credentials{ClientID: "app", ClientSecret: "s3cret"}
	method, err := c.Resolve([]string{"client_secret_post"})
	if err != nil || method != AuthPost {
		t.Fatalf("advertised post: %s %v", method, err)
	}
	method, _ = c.Resolve(nil)
	if method != AuthBasic {
		t.Fatalf("default with a secret should be basic, got %s", method)
	}
	public := &Credentials{ClientID: "app"}
	if method, _ := public.Resolve([]string{"none"}); method != AuthNone {
		t.Fatalf("public client should resolve to none, got %s", method)
	}
	forced := &Credentials{ClientID: "app", Method: AuthPrivateKeyJWT}
	if _, err := forced.Resolve(nil); err == nil {
		t.Fatal("private_key_jwt without a key must fail")
	}

	headers := http.Header{}
	form := map[string][]string{}
	if err := c.Apply(AuthBasic, form, headers, "https://a.example.com/token"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(headers.Get("Authorization"), "Basic ") {
		t.Fatalf("basic header: %q", headers.Get("Authorization"))
	}
	form = map[string][]string{}
	if err := c.Apply(AuthSecretJWT, form, http.Header{}, "https://a.example.com/token"); err != nil {
		t.Fatal(err)
	}
	if form["client_assertion_type"][0] != clientAssertionType || form["client_assertion"][0] == "" {
		t.Fatalf("client_secret_jwt form: %v", form)
	}
}

func TestDPoPProofShape(t *testing.T) {
	dpop, err := NewDPoP("")
	if err != nil {
		t.Fatal(err)
	}
	dpop.Nonce = "n1"
	proof, err := dpop.Proof("POST", "https://a.example.com/token?x=1#y", "tok")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof is not a compact JWS: %s", proof)
	}
	saved, err := dpop.JWK()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DPoPFromJWK(saved)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := dpop.Thumbprint()
	b, _ := restored.Thumbprint()
	if a != b {
		t.Fatal("thumbprint changed across save and restore")
	}
}

func TestParseCallback(t *testing.T) {
	cb, err := ParseCallback("http://127.0.0.1:8085/callback?code=abc&state=xyz&iss=https%3A%2F%2Fa.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cb.Code != "abc" || cb.State != "xyz" || cb.Issuer != "https://a.example.com" {
		t.Fatalf("callback: %+v", cb)
	}
	cb, _ = ParseCallback("just-a-code")
	if cb.Code != "just-a-code" {
		t.Fatalf("bare code: %+v", cb)
	}
	cb, _ = ParseCallback("http://127.0.0.1/cb#code=frag&state=s")
	if cb.Code != "frag" {
		t.Fatalf("fragment response: %+v", cb)
	}
	if _, err := ValidateCallback(&Callback{Code: "c", State: "other"}, "expected", "https://a", false); err == nil {
		t.Fatal("state mismatch must fail")
	}
	if _, err := ValidateCallback(&Callback{Error: "access_denied"}, "", "", false); err == nil {
		t.Fatal("error response must fail")
	}
	issues, err := ValidateCallback(&Callback{Code: "c", State: "s"}, "s", "https://a", true)
	if err != nil || !hasCode(issues, "iss-missing") {
		t.Fatalf("missing iss when advertised should be a finding: %v %v", codes(issues), err)
	}
}

func TestValidateCIMD(t *testing.T) {
	issues := ValidateCIMDURL("http://app.example.com")
	if !hasCode(issues, "client-id-not-https") || !hasCode(issues, "client-id-no-path") {
		t.Fatalf("URL findings: %v", codes(issues))
	}
	document := map[string]any{
		"client_id":                  "https://app.example.com/other",
		"token_endpoint_auth_method": "client_secret_basic",
		"client_secret":              "x",
	}
	issues = ValidateCIMD("https://app.example.com/client.json", document)
	for _, code := range []string{"client-id-mismatch", "shared-secret-auth", "client-secret-published", "redirect-uris-missing"} {
		if !hasCode(issues, code) {
			t.Errorf("expected %s; got %v", code, codes(issues))
		}
	}
	template := CIMDTemplate("https://app.example.com/client.json", "app", []string{"https://app.example.com/cb"}, nil, "none", "")
	if issues := ValidateCIMD("https://app.example.com/client.json", template); HasErrors(issues) {
		t.Fatalf("template has errors: %v", codes(issues))
	}
}
