package conformance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/oauth"
)

func audit(t *testing.T, f *fakeAS, credentials bool, register bool) cligen.ConformanceReport {
	t.Helper()
	client, err := oauth.NewClient(oauth.Options{AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Issuer: f.issuer(), AllowHTTP: true, Register: register, Negative: true, Resources: []string{"https://api.example.com"}, RedirectURI: "http://127.0.0.1/callback", Scopes: []string{"openid"}}
	if credentials {
		opts.Credentials = &oauth.Credentials{ClientID: "app", ClientSecret: "s3cret"}
		opts.RefreshToken = "refresh-token"
	} else {
		opts.Credentials = &oauth.Credentials{ClientID: "app"}
	}
	report, err := New(client, opts).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func verdict(report cligen.ConformanceReport, id string) string {
	for _, spec := range report.Specs {
		if spec.ID == id {
			return spec.Verdict
		}
	}
	return "missing"
}

func check(report cligen.ConformanceReport, id string) *cligen.Check {
	for _, spec := range report.Specs {
		for i := range spec.Checks {
			if spec.Checks[i].ID == id {
				return &spec.Checks[i]
			}
		}
	}
	return nil
}

func configuredAudit(t *testing.T, credentials, register bool, configure func(*fakeAS)) cligen.ConformanceReport {
	t.Helper()
	f := newFakeAS()
	defer f.server.Close()
	configure(f)
	return audit(t, f, credentials, register)
}

func requireCheckStatus(t *testing.T, report cligen.ConformanceReport, id, want string) *cligen.Check {
	t.Helper()
	c := check(report, id)
	if c == nil || c.Status != want {
		t.Fatalf("%s status: %+v; want %s", id, c, want)
	}
	return c
}

func TestSpecVerdictDistinguishesPartialEvidence(t *testing.T) {
	tests := []struct {
		name   string
		checks []cligen.Check
		want   string
	}{
		{name: "nothing exercised", want: NotTested},
		{name: "only skipped", checks: []cligen.Check{{Status: Skip}}, want: NotTested},
		{name: "fully exercised", checks: []cligen.Check{{Status: Pass}, {Status: Warn}}, want: Conformant},
		{name: "mixed evidence", checks: []cligen.Check{{Status: Pass}, {Status: Untested}}, want: PartiallyTested},
		{name: "warning and unknown", checks: []cligen.Check{{Status: Warn}, {Status: Untested}}, want: PartiallyTested},
		{name: "known failure wins", checks: []cligen.Check{{Status: Fail}, {Status: Untested}}, want: NonConformant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (&Spec{Checks: tt.checks}).Verdict(); got != tt.want {
				t.Fatalf("verdict %q, want %q", got, tt.want)
			}
		})
	}

	supported := false
	if got := (&Spec{supported: &supported, Checks: []cligen.Check{{Status: Pass}, {Status: Fail}}}).Verdict(); got != NotSupported {
		t.Fatalf("an unimplemented optional specification must be not-supported, got %q", got)
	}
}

func TestConformantServerPassesEverything(t *testing.T) {
	f := newFakeAS()
	defer f.server.Close()
	report := audit(t, f, true, true)

	if !report.Passed {
		for _, spec := range report.Specs {
			for _, c := range spec.Checks {
				if c.Status == Fail {
					t.Errorf("%s failed: %s", c.ID, deref(c.Detail))
				}
			}
		}
		t.Fatal("a conformant server must pass")
	}
	for _, id := range []string{"rfc8414", "oidc-discovery", "rfc7517", "rfc6749", "rfc7636", "oauth2.1", "rfc9068", "rfc6750", "rfc7662", "rfc7009", "rfc8628", "rfc9126", "rfc9449", "rfc8707", "rfc8693", "rfc7591", "rfc9207"} {
		if v := verdict(report, id); v != Conformant {
			t.Errorf("%s verdict %s, want conformant", id, v)
		}
	}
	for _, id := range []string{"rfc8705", "rfc9101", "rfc9396", "cimd", "rfc9728"} {
		if v := verdict(report, id); v != NotSupported {
			t.Errorf("%s verdict %s, want not-supported", id, v)
		}
	}
	if v := verdict(report, "tls"); v != NotTested {
		t.Errorf("tls on loopback http should be not-tested, got %s", v)
	}
	if c := check(report, "rfc9449.bound"); c == nil || c.Status != Pass {
		t.Errorf("DPoP binding check: %+v", c)
	}
	if c := check(report, "rfc7009.effective"); c == nil || c.Status != Pass {
		t.Errorf("revocation should introspect as inactive: %+v", c)
	}
	if c := check(report, "rfc7591.delete"); c == nil || c.Status != Pass {
		t.Errorf("registered probe client should be deleted: %+v", c)
	}
	if report.Credentials == nil || !*report.Credentials {
		t.Error("report should record that credentials were used")
	}
}

func TestBrokenServerIsCaught(t *testing.T) {
	f := newFakeAS()
	defer f.server.Close()
	f.omitNoStore = true
	f.plainPKCE = true
	f.openRedirect = true
	f.leakPrivateKey = true
	f.acceptAnyGrant = true
	f.ignoreResource = true
	report := audit(t, f, true, false)

	if report.Passed {
		t.Fatal("a broken server must not pass")
	}
	expectations := map[string]string{
		"rfc6749.no-store":              Fail,
		"rfc6749.unsupported-grant":     Fail,
		"rfc7517.private-key-published": Fail,
		"rfc7636.no-plain":              Skip,
		"oauth2.1.redirect-exact":       Fail,
		"rfc7591.register":              Untested,
	}
	for id, want := range expectations {
		c := check(report, id)
		if c == nil {
			t.Errorf("check %s missing", id)
			continue
		}
		if c.Status != want {
			t.Errorf("%s status %s, want %s (%s)", id, c.Status, want, deref(c.Detail))
		}
	}
	if v := verdict(report, "rfc8707"); v != NotSupported {
		t.Errorf("ignored resource parameter should read as not supported, got %s", v)
	}
	if verdict(report, "rfc7517") != NonConformant {
		t.Error("leaked private key must make the key set non-conformant")
	}
}

func TestAnonymousAuditMarksCredentialChecksUntested(t *testing.T) {
	f := newFakeAS()
	defer f.server.Close()
	report := audit(t, f, false, false)
	if c := check(report, "rfc6749.client-credentials"); c == nil || c.Status != Untested {
		t.Fatalf("client credentials should be untested without a secret: %+v", c)
	}
	if v := verdict(report, "rfc9068"); v != NotTested {
		t.Fatalf("JWT access tokens should be not-tested, got %s", v)
	}
	if c := check(report, "rfc7636.unsupported-method"); c == nil || c.Status != Pass {
		t.Fatalf("PKCE method probe with a registered redirect URI: %+v", c)
	}
	if v := verdict(report, "rfc6749"); v != PartiallyTested {
		t.Fatalf("anonymous core audit should preserve its untested credential checks, got %s", v)
	}
	if report.Summary.PartiallyTested == 0 {
		t.Fatal("summary should count partially tested specifications")
	}
	if report.Summary.Untested == 0 {
		t.Fatal("summary should count untested checks")
	}
}

func TestOnlyAndSkipFilterSpecifications(t *testing.T) {
	f := newFakeAS()
	defer f.server.Close()
	client, _ := oauth.NewClient(oauth.Options{AllowHTTP: true})
	report, err := New(client, Options{Issuer: f.issuer(), AllowHTTP: true, Only: []string{"rfc8414", "RFC7517"}}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Specs) != 2 {
		t.Fatalf("want 2 specs, got %d", len(report.Specs))
	}
	report, _ = New(client, Options{Issuer: f.issuer(), AllowHTTP: true, Skip: []string{"rfc8414"}}).Run(context.Background())
	if verdict(report, "rfc8414") != "missing" {
		t.Fatal("skipped spec should be absent")
	}
}

func TestDPoPChecks(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*fakeAS)
		want      map[string]string
	}{
		{
			name:      "nonce challenge is answered",
			configure: func(f *fakeAS) { f.nonce = "server-nonce" },
			want:      map[string]string{"rfc9449.bound": Pass, "rfc9449.nonce": Pass},
		},
		{
			name:      "bound JWT requires confirmation thumbprint",
			configure: func(f *fakeAS) { f.omitDPoPJKT = true },
			want:      map[string]string{"rfc9449.jkt": Fail},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := configuredAudit(t, true, false, tt.configure)
			for id, status := range tt.want {
				requireCheckStatus(t, report, id, status)
			}
		})
	}
}

func TestOAuth21UsesRFC8414DefaultGrantTypes(t *testing.T) {
	report := configuredAudit(t, false, false, func(f *fakeAS) { f.omitGrantTypes = true })
	c := requireCheckStatus(t, report, "oauth2.1.no-implicit", Warn)
	if c.Detail == nil || !strings.Contains(*c.Detail, "default of authorization_code and implicit") {
		t.Fatalf("missing grant_types_supported must apply the RFC 8414 default: %+v", c)
	}
}

func TestOAuth21OwnsAuthorizationEndpointCORS(t *testing.T) {
	report := configuredAudit(t, false, false, func(f *fakeAS) { f.authzCORS = true })
	if c := check(report, "rfc6749.authz-no-cors"); c != nil {
		t.Fatalf("RFC 6749 must not own the OAuth 2.1 CORS check: %+v", c)
	}
	requireCheckStatus(t, report, "oauth2.1.authz-no-cors", Fail)
}

func TestAuthorizationProbesRequireRegisteredRedirectURI(t *testing.T) {
	f := newFakeAS()
	defer f.server.Close()
	client, err := oauth.NewClient(oauth.Options{AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	report, err := New(client, Options{
		Issuer:      f.issuer(),
		AllowHTTP:   true,
		Credentials: &oauth.Credentials{ClientID: "app", ClientSecret: "s3cret"},
		Only:        []string{"rfc7636", "oauth2.1", "rfc9126"},
	}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"rfc7636.unsupported-method", "oauth2.1.pkce-enforced", "oauth2.1.redirect-exact", "rfc9126.push"} {
		if c := check(report, id); c == nil || c.Status != Untested {
			t.Errorf("%s should be untested without a registered redirect URI: %+v", id, c)
		}
	}
	for _, id := range []string{"rfc7636", "oauth2.1", "rfc9126"} {
		if got := verdict(report, id); got != PartiallyTested {
			t.Errorf("%s verdict %s, want partially-tested", id, got)
		}
	}
}

func TestAnonymousIntrospectionIsNonConformant(t *testing.T) {
	report := configuredAudit(t, true, false, func(f *fakeAS) { f.anonymousIntrospect = true })
	requireCheckStatus(t, report, "rfc7662.authenticated", Fail)
}

func TestOpenIDFallbackDoesNotClaimRFC8414Support(t *testing.T) {
	report := configuredAudit(t, false, false, func(f *fakeAS) { f.noOAuthMetadata = true })
	if got := verdict(report, "rfc8414"); got != NotSupported {
		t.Fatalf("an OpenID-only discovery document must not make RFC 8414 conformant, got %s", got)
	}
	if c := check(report, "rfc8414.advertised"); c == nil || c.Status != Skip {
		t.Fatalf("RFC 8414 absence should be an unsupported capability, not a failed check: %+v", c)
	}
}

func TestSignedMetadataIsUntestedUntilVerified(t *testing.T) {
	report := configuredAudit(t, false, false, func(f *fakeAS) { f.signedMetadata = true })
	requireCheckStatus(t, report, "rfc8414.signed", Untested)
	if got := verdict(report, "rfc8414"); got != PartiallyTested {
		t.Fatalf("unverified signed metadata should make the RFC 8414 verdict partial, got %s", got)
	}
}

func TestExpiredSuppliedTokenDoesNotCondemnIssuer(t *testing.T) {
	f := newFakeAS()
	defer f.server.Close()
	token := f.mint("app", "openid", "", -time.Hour)
	client, err := oauth.NewClient(oauth.Options{AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	report, err := New(client, Options{Issuer: f.issuer(), AllowHTTP: true, Token: token, Only: []string{"rfc9068"}}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c := check(report, "rfc9068.not-expired"); c == nil || c.Status != Warn {
		t.Fatalf("a stale caller-supplied token is not an issuer conformance failure: %+v", c)
	}
	if got := verdict(report, "rfc9068"); got != Conformant {
		t.Fatalf("a valid-profile but stale supplied token should not make the issuer non-conformant, got %s", got)
	}
}

func TestImmediateRevocationPropagationIsNotAConfirmedFailure(t *testing.T) {
	report := configuredAudit(t, true, false, func(f *fakeAS) { f.ignoreRevocation = true })
	requireCheckStatus(t, report, "rfc7009.effective", Warn)
	requireCheckStatus(t, report, "rfc7009.hint-fallback", Untested)
}
