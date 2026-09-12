package conformance

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Southclaws/oauthcli/internal/oauth"
)

func (r *Runner) checkMetadata(ctx context.Context) {
	s := r.spec("rfc8414", "Authorization Server Metadata (RFC 8414)", "https://www.rfc-editor.org/rfc/rfc8414")
	if r.Metadata == nil {
		s.supportedIf(false, "no metadata document at any well-known location")
		s.fail("found", "metadata document is published", "§3", fmt.Sprintf("neither %s nor %s answered with a JSON document; %s",
			strings.Join(oauth.WellKnownURLs(r.Options.Issuer, oauth.KindOAuth), " or "),
			strings.Join(oauth.WellKnownURLs(r.Options.Issuer, oauth.KindOpenID), " or "), oauth.MultiTenantHint))
		return
	}
	m := r.Metadata
	issues := m.Validate(r.Options.AllowHTTP)

	switch {
	case m.Kind != oauth.KindOAuth:
		s.warn("found", "metadata document is published", "§3", "only the OpenID Connect discovery document exists; the RFC 8414 location "+strings.Join(oauth.WellKnownURLs(r.Options.Issuer, oauth.KindOAuth), " or ")+" answers 404")
	case m.URL != oauth.WellKnownURLs(r.Options.Issuer, oauth.KindOAuth)[0]:
		s.warn("found", "metadata document is published", "§3.1", fmt.Sprintf("the document is at %s, but RFC 8414 inserts /.well-known/ between the host and the path; the compliant location %s answers 404", m.URL, oauth.WellKnownURLs(r.Options.Issuer, oauth.KindOAuth)[0]))
	default:
		s.pass("found", "metadata document is published", "§3", m.URL)
	}
	if m.Response != nil {
		s.requirement(m.Response.Status == 200, Fail, "status", "well-known request answers 200", "§3.2", fmt.Sprintf("HTTP %d in %s", m.Response.Status, m.Response.Elapsed.Round(time.Millisecond)), fmt.Sprintf("HTTP %d", m.Response.Status))
	}
	s.fromIssues(issues, "content-type", "content-type", "response is application/json", "§3.2", m.Response.Header.Get("Content-Type"))
	s.fromIssues(issues, "issuer-missing", "issuer", "issuer is present", "§2", m.String("issuer"))
	if !s.fromIssuesAny(issues, []string{"issuer-mismatch", "issuer-trailing-slash"}, "issuer-match", "issuer is identical to the URL the document was fetched for", "§3.3") {
		s.pass("issuer-match", "issuer is identical to the URL the document was fetched for", "§3.3", "")
	}
	s.fromIssues(issues, "issuer-not-https", "issuer-https", "issuer uses https", "§2", "")
	s.fromIssues(issues, "issuer-has-query", "issuer-clean", "issuer has no query or fragment", "§2", "")
	s.fromIssues(issues, "response-types-missing", "response-types", "response_types_supported is present", "§2", strings.Join(m.Strings("response_types_supported"), ", "))
	s.fromIssues(issues, "response-types-inconsistent", "response-types-consistent", "response types agree with grant types", "RFC 7591 §2", "")
	s.fromIssues(issues, "token-endpoint-missing", "token-endpoint", "token_endpoint is present", "§2", m.String("token_endpoint"))
	s.fromIssues(issues, "authorization-endpoint-missing", "authorization-endpoint", "authorization_endpoint is present when needed", "§2", m.String("authorization_endpoint"))
	if m.String("jwks_uri") != "" {
		s.pass("jwks-uri", "jwks_uri is advertised", "§2", m.String("jwks_uri"))
	} else {
		s.skip("jwks-uri", "jwks_uri is advertised", "§2", "not advertised (optional in RFC 8414)")
	}
	s.fromIssues(issues, "scopes-missing", "scopes", "scopes_supported is advertised", "§2", strings.Join(m.Strings("scopes_supported"), " "))
	s.fromIssues(issues, "empty-array", "no-empty-arrays", "claims with zero elements are omitted", "§3.2", "")
	endpointOK := true
	for _, issue := range issues {
		if issue.Code == "endpoint-not-https" || issue.Code == "endpoint-invalid" || issue.Code == "endpoint-fragment" {
			endpointOK = false
			check := issueCheck(s, issue, "endpoint-"+*issue.Field, "endpoint URL is valid https: "+*issue.Field)
			s.add(check)
		}
	}
	if endpointOK {
		s.pass("endpoints-https", "every endpoint is an https URL without a fragment", "RFC 6749 §3.1, §3.2; OAuth 2.1 §1.5", fmt.Sprintf("%d endpoints", len(m.Endpoints())))
	}
	s.fromIssues(issues, "auth-methods-unknown", "auth-methods", "token endpoint authentication methods are registered values", "§2", strings.Join(m.TokenAuthMethods(), ", "))
	s.fromIssues(issues, "auth-algs-missing", "auth-algs", "signing algorithms are advertised for JWT client authentication", "§2", "")
	s.fromIssues(issues, "auth-alg-none", "auth-alg-none", "client authentication signing algorithms exclude none", "§2", "")
	if m.Has("signed_metadata") {
		s.pass("signed", "signed_metadata is published", "§2.1", "present; signature not verified by this tool")
	} else {
		s.skip("signed", "signed_metadata is published", "§2.1", "not published (optional)")
	}
	s.supportedIf(true, "")
}

func (r *Runner) checkOpenIDDiscovery(ctx context.Context) {
	s := r.spec("oidc-discovery", "OpenID Connect Discovery 1.0", "https://openid.net/specs/openid-connect-discovery-1_0.html")
	doc := r.OpenID
	if r.Metadata != nil && r.Metadata.Kind == oauth.KindOpenID {
		doc = r.Metadata
	}
	if doc == nil {
		s.supportedIf(false, "no openid-configuration document")
		if r.Metadata != nil {
			s.skip("found", "openid-configuration is published", "§4", strings.Join(oauth.WellKnownURLs(r.Options.Issuer, oauth.KindOpenID), " or ")+" answers 404")
		}
		return
	}
	s.supportedIf(true, "")
	s.pass("found", "openid-configuration is published", "§4", doc.URL)
	issues := doc.Validate(r.Options.AllowHTTP)
	if !s.fromIssuesAny(issues, []string{"issuer-mismatch", "issuer-trailing-slash"}, "issuer-match", "issuer is identical to the discovery URL", "§4.3") {
		s.pass("issuer-match", "issuer is identical to the discovery URL", "§4.3", doc.String("issuer"))
	}
	s.fromIssues(issues, "subject-types-missing", "subject-types", "subject_types_supported is present", "§3", strings.Join(doc.Strings("subject_types_supported"), ", "))
	s.fromIssues(issues, "id-token-algs-missing", "id-token-algs", "id_token_signing_alg_values_supported is present", "§3", strings.Join(doc.Strings("id_token_signing_alg_values_supported"), ", "))
	s.fromIssues(issues, "id-token-no-rs256", "id-token-rs256", "RS256 is supported for ID tokens", "§3", "")
	s.fromIssues(issues, "jwks-uri-missing", "jwks-uri", "jwks_uri is present", "§3", doc.String("jwks_uri"))
	s.fromIssues(issues, "userinfo-missing", "userinfo", "userinfo_endpoint is advertised", "§3", doc.String("userinfo_endpoint"))
	s.fromIssues(issues, "openid-scope-missing", "openid-scope", "the openid scope is advertised", "§3", "")
	s.fromIssues(issues, "claims-not-advertised", "claims", "claims_supported is advertised", "§3", strings.Join(doc.Strings("claims_supported"), " "))
	if r.OpenID != nil && r.Metadata != nil && r.Metadata.Kind == oauth.KindOAuth {
		diff := differingMembers(r.Metadata.Raw, r.OpenID.Raw)
		s.requirement(len(diff) == 0, Warn, "consistent", "RFC 8414 and OpenID documents agree", "RFC 9068 §4", "the two documents carry the same values", "members differ between the two documents: "+strings.Join(diff, ", "))
	}
}

// differingMembers lists members present in both documents with different
// values.
func differingMembers(a, b map[string]any) []string {
	var out []string
	for name, va := range a {
		vb, ok := b[name]
		if !ok {
			continue
		}
		if fmt.Sprint(va) != fmt.Sprint(vb) {
			out = append(out, name)
		}
	}
	return out
}

func (r *Runner) checkTransport(ctx context.Context) {
	s := r.spec("tls", "Transport security (RFC 6749 §3.1, OAuth 2.1 §1.5, BCP 195)", "https://www.rfc-editor.org/rfc/rfc9700#section-2.6")
	issuerURL, err := url.Parse(r.Options.Issuer)
	if err != nil {
		s.fail("issuer-url", "issuer is a URL", "", err.Error())
		return
	}
	loopback := oauth.IsLoopback(issuerURL.Hostname())
	if issuerURL.Scheme != "https" && loopback {
		s.skip("https", "issuer uses https", "RFC 6749 §3.1, §3.2; OAuth 2.1 §1.5", "plain http on a loopback address is accepted for local testing")
	} else {
		s.requirement(issuerURL.Scheme == "https", Fail, "https", "issuer uses https", "RFC 6749 §3.1, §3.2; OAuth 2.1 §1.5", issuerURL.Scheme+" scheme", "the issuer is plain http")
	}

	var state *tls.ConnectionState
	var response *oauth.Response
	if r.Metadata != nil && r.Metadata.Response != nil {
		response = r.Metadata.Response
		state = response.TLS
	}
	if state == nil {
		if loopback {
			s.skip("version", "TLS 1.2 or newer", "BCP 195 (RFC 8996)", "no TLS on loopback")
		} else {
			s.untested("version", "TLS 1.2 or newer", "BCP 195 (RFC 8996)", "no TLS connection to inspect")
		}
		return
	}
	s.supportedIf(true, "")
	s.requirement(state.Version >= tls.VersionTLS12, Fail, "version", "TLS 1.2 or newer", "BCP 195 (RFC 8996) via OAuth 2.1 §1.5", tls.VersionName(state.Version)+" with "+tls.CipherSuiteName(state.CipherSuite), "negotiated "+tls.VersionName(state.Version)+"; TLS 1.0 and 1.1 must not be used")
	if state.Version == tls.VersionTLS12 {
		s.warn("tls13", "TLS 1.3 is offered", "BCP 195 (RFC 9325 §3.1.1)", "the server negotiated TLS 1.2; TLS 1.3 is recommended")
	} else {
		s.pass("tls13", "TLS 1.3 is offered", "BCP 195 (RFC 9325 §3.1.1)", tls.VersionName(state.Version))
	}
	if r.Options.Insecure {
		s.skip("certificate", "certificate chain verifies", "RFC 6749 §10.9, OAuth 2.1 §1.5", "verification disabled with --insecure")
	} else {
		s.pass("certificate", "certificate chain verifies", "RFC 6749 §10.9, OAuth 2.1 §1.5", certificateSummary(state))
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		remaining := time.Until(leaf.NotAfter)
		s.requirement(remaining > 14*24*time.Hour, Warn, "certificate-expiry", "certificate is not about to expire", "", fmt.Sprintf("valid until %s", leaf.NotAfter.Format("2006-01-02")), fmt.Sprintf("expires in %s", remaining.Round(time.Hour)))
	}
	if hsts := response.Header.Get("Strict-Transport-Security"); hsts != "" {
		s.pass("hsts", "Strict-Transport-Security header is sent", "RFC 6797 (not an OAuth requirement)", hsts)
	} else {
		s.skip("hsts", "Strict-Transport-Security header is sent", "RFC 6797 (not an OAuth requirement)", "no HSTS header; no OAuth specification requires one")
	}
}

func certificateSummary(state *tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return "no certificate"
	}
	leaf := state.PeerCertificates[0]
	return fmt.Sprintf("%s, issued by %s", leaf.Subject.CommonName, leaf.Issuer.CommonName)
}

func (r *Runner) checkKeys(ctx context.Context) {
	s := r.spec("rfc7517", "JSON Web Key Set (RFC 7517)", "https://www.rfc-editor.org/rfc/rfc7517")
	if r.Metadata == nil {
		s.untested("reachable", "jwks_uri is reachable", "", "no metadata document")
		return
	}
	jwksURI := r.Metadata.String("jwks_uri")
	if jwksURI == "" {
		s.supportedIf(false, "no jwks_uri advertised")
		return
	}
	s.supportedIf(true, "")
	if r.Keys == nil {
		set, err := r.Client.FetchKeys(ctx, jwksURI)
		if err != nil {
			s.fail("reachable", "jwks_uri is reachable", "§5", describeErr(err))
			return
		}
		r.Keys = set
	}
	described := oauth.DescribeKeySet(r.Keys, false)
	s.pass("reachable", "jwks_uri is reachable", "§5", fmt.Sprintf("%d key(s) at %s", len(r.Keys.Keys), jwksURI))
	s.fromIssues(described.Issues, "content-type", "content-type", "key set is served with a registered JSON media type", "§8.5.1", r.Keys.Response.Header.Get("Content-Type"))
	s.fromIssues(described.Issues, "no-keys", "keys-member", "document has a non-empty keys member", "§5", "")
	s.fromIssues(described.Issues, "kid-duplicate", "kid-unique", "key identifiers are distinct", "§4.5", "")

	perKey := map[string]string{
		"private-key-published":    Fail,
		"symmetric-key-published":  Fail,
		"kty-missing":              Fail,
		"rsa-too-small":            Fail,
		"key-unusable":             Fail,
		"x5c-invalid":              Fail,
		"x5c-key-mismatch":         Fail,
		"use-required":             Fail,
		"use-key-ops-inconsistent": Fail,
		"key-ops-duplicate":        Fail,
		"kid-missing":              Warn,
		"key-unsupported":          Warn,
		"use-and-key-ops":          Warn,
		"x5c-expired":              Warn,
	}
	titles := map[string]string{
		"private-key-published":    "no private key material is published",
		"symmetric-key-published":  "no symmetric key is published",
		"kty-missing":              "every key has kty",
		"rsa-too-small":            "RSA keys are at least 2048 bits",
		"key-unusable":             "every key can be reconstructed",
		"x5c-invalid":              "x5c certificates parse",
		"x5c-key-mismatch":         "x5c leaf certificate matches the key",
		"use-required":             "use is present when the set mixes signing and encryption keys",
		"use-key-ops-inconsistent": "use and key_ops agree",
		"key-ops-duplicate":        "key_ops has no duplicates",
		"kid-missing":              "every key has a kid",
		"key-unsupported":          "every key type is one clients understand",
		"use-and-key-ops":          "use and key_ops are not both present",
		"x5c-expired":              "x5c certificates are current",
	}
	sections := map[string]string{
		"private-key-published": "§9.2", "symmetric-key-published": "§9.2", "kty-missing": "§4.1", "rsa-too-small": "RFC 7518 §3.3",
		"key-unusable": "§4", "x5c-invalid": "§4.7", "x5c-key-mismatch": "§4.7", "use-required": "RFC 8414 §2",
		"use-key-ops-inconsistent": "§4.3", "key-ops-duplicate": "§4.3", "kid-missing": "OpenID Connect Core 1.0 §10.1",
		"key-unsupported": "§5", "use-and-key-ops": "§4.3", "x5c-expired": "§4.7",
	}
	found := map[string]string{}
	for _, key := range described.Keys {
		for _, issue := range key.Issues {
			if _, graded := perKey[issue.Code]; graded && found[issue.Code] == "" {
				found[issue.Code] = issue.Message
			}
		}
	}
	for _, code := range []string{"private-key-published", "symmetric-key-published", "kty-missing", "key-unusable", "key-unsupported", "rsa-too-small", "kid-missing", "use-required", "use-and-key-ops", "use-key-ops-inconsistent", "key-ops-duplicate", "x5c-invalid", "x5c-key-mismatch", "x5c-expired"} {
		if message, ok := found[code]; ok {
			s.check(perKey[code], code, titles[code], sections[code], message)
		} else if code != "x5c-invalid" && code != "x5c-key-mismatch" && code != "x5c-expired" && code != "use-and-key-ops" && code != "use-key-ops-inconsistent" && code != "key-ops-duplicate" && code != "use-required" {
			s.pass(code, titles[code], sections[code], "")
		}
	}
	if r.Keys.Response != nil {
		cache := r.Keys.Response.Header.Get("Cache-Control")
		openID := r.OpenID != nil || r.Metadata.Kind == oauth.KindOpenID
		switch {
		case cache != "":
			s.pass("cacheable", "key set response has Cache-Control", "OpenID Connect Core 1.0 §10.2.1", cache)
		case openID:
			s.warn("cacheable", "key set response has Cache-Control", "OpenID Connect Core 1.0 §10.2.1", "no Cache-Control header; Core recommends a max-age so clients know how long to keep keys")
		default:
			s.skip("cacheable", "key set response has Cache-Control", "OpenID Connect Core 1.0 §10.2.1", "no Cache-Control header (only OpenID Connect recommends one)")
		}
	}
}
