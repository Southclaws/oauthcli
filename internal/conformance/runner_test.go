package conformance

import (
	"context"
	"testing"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/oauth"
)

func audit(t *testing.T, f *fakeAS, credentials bool, register bool) cligen.ConformanceReport {
	t.Helper()
	client, err := oauth.NewClient(oauth.Options{AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Issuer: f.issuer(), AllowHTTP: true, Register: register, Negative: true, Resources: []string{"https://api.example.com"}}
	if credentials {
		opts.Credentials = &oauth.Credentials{ClientID: "app", ClientSecret: "s3cret"}
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
		"rfc7591.register":              Skip,
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
	if c := check(report, "rfc7636.enforced"); c == nil || c.Status != Pass {
		t.Fatalf("PKCE enforcement probe needs only a client id: %+v", c)
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

func TestDPoPNonceChallengeIsAnswered(t *testing.T) {
	f := newFakeAS()
	defer f.server.Close()
	f.nonce = "server-nonce"
	report := audit(t, f, true, false)
	if c := check(report, "rfc9449.bound"); c == nil || c.Status != Pass {
		t.Fatalf("DPoP with a nonce challenge: %+v", c)
	}
	if c := check(report, "rfc9449.nonce"); c == nil || c.Status != Pass {
		t.Fatalf("nonce check: %+v", c)
	}
}
