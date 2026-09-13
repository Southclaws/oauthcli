package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/Southclaws/oauthcli/internal/cligen"
)

// Well-known document kinds, as reported by discover.
const (
	KindOAuth      = "oauth-authorization-server"
	KindOpenID     = "openid-configuration"
	KindResource   = "oauth-protected-resource"
	KindJWKS       = "jwks"
	KindFederation = "openid-federation"
	KindCredential = "openid-credential-issuer"
)

// ErrNoMetadata reports that no metadata document was found for an issuer.
var ErrNoMetadata = errors.New("no metadata document found")

// NormalizeIssuer accepts a bare host or a URL and returns an https URL with
// no trailing slash, the form an issuer identifier takes.
func NormalizeIssuer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("no issuer given: pass ISSUER_URL, --issuer, OAUTH_ISSUER or a profile")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("issuer %q is not a URL: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("issuer %q has no host", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// WellKnownURLs returns the candidate locations of a document for an issuer.
//
// RFC 8414 §3 inserts the well-known path between the host and the issuer
// path; OpenID Connect Discovery appends it. For an issuer without a path
// the two agree and one URL is returned.
func WellKnownURLs(issuer, suffix string) []string {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil
	}
	path := strings.TrimRight(u.Path, "/")
	base := u.Scheme + "://" + u.Host

	inserted := base + "/.well-known/" + suffix + path
	appended := base + path + "/.well-known/" + suffix
	if path == "" || inserted == appended {
		return []string{appended}
	}
	if suffix == KindOpenID {
		return []string{appended, inserted}
	}
	return []string{inserted, appended}
}

// Metadata is an authorization server metadata document with typed access to
// the members the tool acts on. Raw keeps the whole document.
type Metadata struct {
	Raw  map[string]any
	URL  string
	Kind string
	// Issuer is the issuer the document was fetched for, not the one it
	// claims; Validate compares the two.
	Issuer   string
	Response *Response
}

// String returns a string member, or "".
func (m *Metadata) String(name string) string {
	if m == nil || m.Raw == nil {
		return ""
	}
	value, _ := m.Raw[name].(string)
	return value
}

// Strings returns an array-of-strings member.
func (m *Metadata) Strings(name string) []string {
	if m == nil || m.Raw == nil {
		return nil
	}
	items, _ := m.Raw[name].([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Bool returns a boolean member; ok is false when absent or not a boolean.
func (m *Metadata) Bool(name string) (value, ok bool) {
	if m == nil || m.Raw == nil {
		return false, false
	}
	value, ok = m.Raw[name].(bool)
	return value, ok
}

// Has reports whether a member is present.
func (m *Metadata) Has(name string) bool {
	if m == nil || m.Raw == nil {
		return false
	}
	_, ok := m.Raw[name]
	return ok
}

// Contains reports whether an array member includes value.
func (m *Metadata) Contains(name, value string) bool {
	for _, item := range m.Strings(name) {
		if item == value {
			return true
		}
	}
	return false
}

// GrantTypes returns grant_types_supported, applying the RFC 8414 default.
func (m *Metadata) GrantTypes() []string {
	if m.Has("grant_types_supported") {
		return m.Strings("grant_types_supported")
	}
	return []string{"authorization_code", "implicit"}
}

// TokenAuthMethods returns token_endpoint_auth_methods_supported with the
// RFC 8414 default.
func (m *Metadata) TokenAuthMethods() []string {
	if m.Has("token_endpoint_auth_methods_supported") {
		return m.Strings("token_endpoint_auth_methods_supported")
	}
	return []string{"client_secret_basic"}
}

// Endpoint members, in the order they are shown.
var endpointMembers = []string{
	"authorization_endpoint",
	"token_endpoint",
	"userinfo_endpoint",
	"jwks_uri",
	"registration_endpoint",
	"introspection_endpoint",
	"revocation_endpoint",
	"device_authorization_endpoint",
	"pushed_authorization_request_endpoint",
	"end_session_endpoint",
	"check_session_iframe",
	"backchannel_authentication_endpoint",
}

// Endpoints lists the endpoint members present in the document.
func (m *Metadata) Endpoints() []cligen.Endpoint {
	var out []cligen.Endpoint
	for _, name := range endpointMembers {
		if value := m.String(name); value != "" {
			out = append(out, cligen.Endpoint{Name: name, URL: value})
		}
	}
	return out
}

// FetchMetadata fetches the metadata document of an issuer. kind selects
// "oauth", "openid" or "auto", which tries RFC 8414 first and falls back to
// OpenID Connect Discovery.
func (c *Client) FetchMetadata(ctx context.Context, issuer, kind string) (*Metadata, error) {
	var suffixes []string
	switch kind {
	case "oauth":
		suffixes = []string{KindOAuth}
	case "openid":
		suffixes = []string{KindOpenID}
	default:
		suffixes = []string{KindOAuth, KindOpenID}
	}

	var lastErr error
	for _, suffix := range suffixes {
		for _, candidate := range WellKnownURLs(issuer, suffix) {
			response, err := c.Get(ctx, candidate)
			if err != nil {
				lastErr = err
				continue
			}
			if response.Status == 404 {
				lastErr = fmt.Errorf("%s: HTTP 404", candidate)
				continue
			}
			if response.Status != 200 {
				lastErr = fmt.Errorf("%s: HTTP %d", candidate, response.Status)
				continue
			}
			document, err := response.JSON()
			if err != nil {
				lastErr = fmt.Errorf("%s: %w", candidate, err)
				continue
			}
			return &Metadata{Raw: document, URL: candidate, Kind: suffix, Issuer: issuer, Response: response}, nil
		}
	}
	if lastErr != nil && errors.Is(lastErr, ErrUnreachable) {
		return nil, lastErr
	}
	return nil, fmt.Errorf("%w for %s: %v; %s", ErrNoMetadata, issuer, lastErr, MultiTenantHint)
}

// MultiTenantHint explains the most common reason a reachable host publishes
// no metadata: the issuer is a tenant-specific host or path, not the site.
const MultiTenantHint = "a multi-tenant authorization server publishes metadata only at each tenant's issuer, which is often a tenant-specific host such as https://api.<tenant>.example.com or a path such as https://example.com/<tenant>; point at the issuer the server's tokens name in iss"

// Validate applies the RFC 8414 and OpenID Connect Discovery rules to a
// metadata document and reports every finding.
func (m *Metadata) Validate(allowHTTP bool) []cligen.Issue {
	var issues []cligen.Issue
	const rfc8414 = "RFC 8414 §2"
	const openIDDiscovery = "OpenID Connect Discovery 1.0 §3"
	issuerSection := metadataSection(m.Kind, rfc8414, openIDDiscovery)

	if m.Response != nil {
		switch {
		case m.Kind == KindOpenID && m.Response.ContentType() != "application/json":
			issues = append(issues, Errorf("content-type", "OpenID Connect Discovery 1.0 §4.2", "", "response Content-Type is %q; the document must be returned as application/json", m.Response.Header.Get("Content-Type")))
		case !m.Response.IsJSON():
			issues = append(issues, Errorf("content-type", "RFC 8414 §3.2", "", "response Content-Type is %q, want application/json", m.Response.Header.Get("Content-Type")))
		}
	}

	claimed := m.String("issuer")
	switch {
	case claimed == "":
		issues = append(issues, Errorf("issuer-missing", issuerSection, "issuer", "issuer is required"))
	case claimed == m.Issuer:
	case strings.TrimRight(claimed, "/") == strings.TrimRight(m.Issuer, "/"):
		issues = append(issues, Warnf("issuer-trailing-slash", m.issuerRuleSection(), "issuer", "issuer is %q but the document was fetched for %q; they differ only by a trailing slash, and a client configured without the slash must reject the document", claimed, m.Issuer))
	default:
		issues = append(issues, Errorf("issuer-mismatch", m.issuerRuleSection(), "issuer", "issuer is %q but the document was fetched for %q; a client must reject this", claimed, m.Issuer))
	}
	if claimed != "" {
		if u, err := url.Parse(claimed); err == nil {
			if u.Scheme != "https" && !(allowHTTP || IsLoopback(u.Hostname())) {
				issues = append(issues, Errorf("issuer-not-https", rfc8414, "issuer", "issuer must use https"))
			}
			if u.RawQuery != "" || u.Fragment != "" {
				issues = append(issues, Errorf("issuer-has-query", rfc8414, "issuer", "issuer must not have a query or fragment component"))
			}
		}
	}

	for _, endpoint := range m.Endpoints() {
		u, err := url.Parse(endpoint.URL)
		if err != nil || u.Host == "" {
			issues = append(issues, Errorf("endpoint-invalid", rfc8414, endpoint.Name, "%s is not an absolute URL: %q", endpoint.Name, endpoint.URL))
			continue
		}
		httpsSpec, fragmentSpec, fragmentLevel := endpointSpecs(endpoint.Name)
		if u.Scheme != "https" && !(allowHTTP || IsLoopback(u.Hostname())) {
			issues = append(issues, Errorf("endpoint-not-https", httpsSpec, endpoint.Name, "%s must use https: %s", endpoint.Name, endpoint.URL))
		}
		if u.Fragment != "" {
			issues = append(issues, fieldIssue(fragmentLevel, "endpoint-fragment", endpoint.Name, fragmentSpec, fmt.Sprintf("%s must not include a fragment", endpoint.Name)))
		}
	}

	emptyArraySection := "RFC 8414 §3.2"
	if m.Kind == KindOpenID {
		emptyArraySection = "OpenID Connect Discovery 1.0 §4.2"
	}
	for name, value := range m.Raw {
		if items, ok := value.([]any); ok && len(items) == 0 {
			issues = append(issues, Errorf("empty-array", emptyArraySection, name, "%s is an empty array; claims with zero elements must be omitted", name))
		}
	}

	grants := m.GrantTypes()
	usesAuthorization := contains(grants, "authorization_code") || contains(grants, "implicit")
	if usesAuthorization && m.String("authorization_endpoint") == "" {
		issues = append(issues, Errorf("authorization-endpoint-missing", rfc8414, "authorization_endpoint", "authorization_endpoint is required when the authorization code grant is supported"))
	}
	if !(len(grants) == 1 && grants[0] == "implicit") && m.String("token_endpoint") == "" {
		issues = append(issues, Errorf("token-endpoint-missing", rfc8414, "token_endpoint", "token_endpoint is required unless only the implicit grant is supported"))
	}
	if !m.Has("response_types_supported") {
		responseTypesSection := metadataSection(m.Kind, rfc8414, openIDDiscovery)
		issues = append(issues, Errorf("response-types-missing", responseTypesSection, "response_types_supported", "response_types_supported is required"))
	} else if contains(grants, "authorization_code") && !containsResponseType(m.Strings("response_types_supported"), "code") {
		issues = append(issues, Warnf("response-types-inconsistent", "RFC 7591 §2", "response_types_supported", "authorization_code is supported but no response type includes code"))
	}
	if m.String("jwks_uri") == "" {
		if m.Kind == KindOpenID {
			issues = append(issues, Errorf("jwks-uri-missing", "OpenID Connect Discovery 1.0 §3", "jwks_uri", "jwks_uri is required by OpenID Connect Discovery"))
		} else {
			issues = append(issues, Infof("jwks-uri-missing", rfc8414, "jwks_uri", "jwks_uri is not advertised (optional); clients cannot verify JWT tokens without it"))
		}
	}
	if !m.Has("scopes_supported") {
		scopesSection := metadataSection(m.Kind, rfc8414, openIDDiscovery)
		issues = append(issues, Warnf("scopes-missing", scopesSection, "scopes_supported", "scopes_supported is recommended"))
	}
	if !m.Has("code_challenge_methods_supported") {
		issues = append(issues, Warnf("pkce-not-advertised", "RFC 8414 §2, RFC 9700 §2.1.1", "code_challenge_methods_supported", "code_challenge_methods_supported is absent, which RFC 8414 reads as no PKCE support; publishing it is recommended"))
	} else {
		methods := m.Strings("code_challenge_methods_supported")
		if !contains(methods, "S256") {
			issues = append(issues, Errorf("pkce-no-s256", "RFC 7636 §4.2, OAuth 2.1 §4.1.1", "code_challenge_methods_supported", "S256 is mandatory to implement on the server; advertised: %s", strings.Join(methods, ", ")))
		}
		if contains(methods, "plain") {
			issues = append(issues, Infof("pkce-plain", "RFC 7636 §7.2, RFC 9700 §2.1.1", "code_challenge_methods_supported", "the plain code challenge method is advertised; clients should use S256, but a server may offer plain for constrained clients"))
		}
	}
	if m.Has("grant_types_supported") && contains(grants, "implicit") {
		issues = append(issues, Warnf("implicit-grant", "OAuth 2.1 §10.1, RFC 9700 §2.1.2", "grant_types_supported", "the implicit grant is advertised; OAuth 2.1 omits it and RFC 9700 says clients should not use it"))
	}
	if contains(grants, "password") {
		issues = append(issues, Errorf("password-grant", "RFC 9700 §2.4, OAuth 2.1 §10.1", "grant_types_supported", "the resource owner password credentials grant is advertised; RFC 9700 says it must not be used"))
	}
	for _, responseType := range m.Strings("response_types_supported") {
		if contains(strings.Fields(responseType), "token") {
			issues = append(issues, Warnf("implicit-response-type", "OAuth 2.1 §10.1, RFC 9700 §2.1.2", "response_types_supported", "response type %q returns an access token from the authorization endpoint; OAuth 2.1 no longer defines it", responseType))
			break
		}
	}
	if !anyKnownAuthMethod(m.TokenAuthMethods()) {
		issues = append(issues, Warnf("auth-methods-unknown", rfc8414, "token_endpoint_auth_methods_supported", "no registered token endpoint authentication method is advertised: %s", strings.Join(m.TokenAuthMethods(), ", ")))
	}
	for _, endpoint := range []string{"token", "revocation", "introspection"} {
		methodsMember := endpoint + "_endpoint_auth_methods_supported"
		algsMember := endpoint + "_endpoint_auth_signing_alg_values_supported"
		methods := m.Strings(methodsMember)
		if endpoint == "token" {
			methods = m.TokenAuthMethods()
		}
		if (contains(methods, "private_key_jwt") || contains(methods, "client_secret_jwt")) && !m.Has(algsMember) {
			issues = append(issues, Errorf("auth-algs-missing", rfc8414, algsMember, "%s must be present when %s includes private_key_jwt or client_secret_jwt", algsMember, methodsMember))
		}
		if contains(m.Strings(algsMember), "none") {
			issues = append(issues, Errorf("auth-alg-none", rfc8414, algsMember, "the value none must not be used in %s", algsMember))
		}
	}
	if m.String("introspection_endpoint") != "" && m.Has("introspection_endpoint_auth_methods_supported") && contains(m.Strings("introspection_endpoint_auth_methods_supported"), "none") {
		issues = append(issues, Warnf("introspection-unauthenticated", "RFC 7662 §2.1", "introspection_endpoint_auth_methods_supported", "introspection permits unauthenticated calls, which lets anyone probe token validity"))
	}
	if m.String("pushed_authorization_request_endpoint") == "" {
		if required, _ := m.Bool("require_pushed_authorization_requests"); required {
			issues = append(issues, Errorf("par-required-no-endpoint", "RFC 9126 §5", "require_pushed_authorization_requests", "pushed authorization requests are required but no endpoint is advertised"))
		}
	}

	if m.Kind == KindOpenID {
		const oidc = "OpenID Connect Discovery 1.0 §3"
		if m.String("authorization_endpoint") == "" {
			issues = append(issues, Errorf("authorization-endpoint-required", oidc, "authorization_endpoint", "authorization_endpoint is required in an OpenID Connect discovery document"))
		}
		if m.String("registration_endpoint") == "" {
			issues = append(issues, Warnf("registration-endpoint-missing", oidc, "registration_endpoint", "registration_endpoint is recommended"))
		} else {
			responseTypes := m.Strings("response_types_supported")
			for _, want := range []string{"code", "id_token", "id_token token"} {
				if !contains(responseTypes, want) {
					issues = append(issues, Errorf("dynamic-response-types", oidc, "response_types_supported", "a dynamic OpenID provider must support the response types code, id_token and \"id_token token\"; advertised: %s", strings.Join(responseTypes, ", ")))
					break
				}
			}
			if m.Has("grant_types_supported") && (!contains(m.GrantTypes(), "authorization_code") || !contains(m.GrantTypes(), "implicit")) {
				issues = append(issues, Errorf("dynamic-grant-types", oidc, "grant_types_supported", "a dynamic OpenID provider must support the authorization_code and implicit grant types; advertised: %s", strings.Join(m.GrantTypes(), ", ")))
			}
		}
		if !m.Has("subject_types_supported") {
			issues = append(issues, Errorf("subject-types-missing", oidc, "subject_types_supported", "subject_types_supported is required"))
		}
		algs := m.Strings("id_token_signing_alg_values_supported")
		if !m.Has("id_token_signing_alg_values_supported") {
			issues = append(issues, Errorf("id-token-algs-missing", oidc, "id_token_signing_alg_values_supported", "id_token_signing_alg_values_supported is required"))
		} else if !contains(algs, "RS256") {
			issues = append(issues, Errorf("id-token-no-rs256", oidc, "id_token_signing_alg_values_supported", "the algorithm RS256 must be included; advertised: %s. This applies to ID token signing only; access tokens signed with another algorithm are unaffected", strings.Join(algs, ", ")))
		}
		if m.String("userinfo_endpoint") == "" {
			issues = append(issues, Warnf("userinfo-missing", oidc, "userinfo_endpoint", "userinfo_endpoint is recommended"))
		}
		if !m.Has("claims_supported") {
			issues = append(issues, Warnf("claims-not-advertised", oidc, "claims_supported", "claims_supported is recommended"))
		}
		if !m.Contains("scopes_supported", "openid") && m.Has("scopes_supported") {
			issues = append(issues, Warnf("openid-scope-missing", oidc, "scopes_supported", "scopes_supported does not list openid; a server may omit supported scopes, but an OpenID provider is expected to advertise it"))
		}
	}

	return issues
}

func metadataSection(kind, oauthSection, openIDSection string) string {
	if kind == KindOpenID {
		return openIDSection
	}
	return oauthSection
}

// issuerRuleSection names the text that requires the issuer to be identical
// to the URL the document was fetched for.
func (m *Metadata) issuerRuleSection() string {
	if m.Kind == KindOpenID {
		return "OpenID Connect Discovery 1.0 §4.3"
	}
	return "RFC 8414 §3.3"
}

// endpointSpecs names the text that requires https and forbids a fragment for
// an endpoint. RFC 6749 covers only its own two endpoints; jwks_uri has its
// own rule in RFC 8414; every other protocol URL falls under OAuth 2.1 §1.5,
// where the fragment rule is not stated, so it is graded as a warning.
func endpointSpecs(name string) (httpsSpec, fragmentSpec, fragmentLevel string) {
	switch name {
	case "authorization_endpoint":
		return "RFC 6749 §3.1", "RFC 6749 §3.1", "error"
	case "token_endpoint":
		return "RFC 6749 §3.2", "RFC 6749 §3.2", "error"
	case "jwks_uri":
		return "RFC 8414 §2", "RFC 8414 §2", "warning"
	default:
		return "OAuth 2.1 §1.5", "OAuth 2.1 §1.5", "warning"
	}
}

var registeredAuthMethods = []string{"client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none", "tls_client_auth", "self_signed_tls_client_auth"}

func anyKnownAuthMethod(methods []string) bool {
	for _, method := range methods {
		if contains(registeredAuthMethods, method) {
			return true
		}
	}
	return false
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

// containsResponseType reports whether any space-separated response type
// includes the given token, so "code id_token" counts for "code".
func containsResponseType(types []string, want string) bool {
	for _, t := range types {
		for _, part := range strings.Fields(t) {
			if part == want {
				return true
			}
		}
	}
	return false
}

// capabilityRule decides one row of the capability table from metadata.
type capabilityRule struct {
	ID    string
	Title string
	Spec  string
	Check func(m *Metadata) (bool, string)
}

func member(name string) func(*Metadata) (bool, string) {
	return func(m *Metadata) (bool, string) {
		value := m.String(name)
		return value != "", value
	}
}

func grant(name string) func(*Metadata) (bool, string) {
	return func(m *Metadata) (bool, string) {
		return contains(m.GrantTypes(), name), name
	}
}

func boolMember(name string) func(*Metadata) (bool, string) {
	return func(m *Metadata) (bool, string) {
		value, ok := m.Bool(name)
		if !ok {
			return false, name + " not advertised"
		}
		return value, fmt.Sprintf("%s: %t", name, value)
	}
}

func listMember(name string) func(*Metadata) (bool, string) {
	return func(m *Metadata) (bool, string) {
		values := m.Strings(name)
		return len(values) > 0, strings.Join(values, ", ")
	}
}

var capabilityRules = []capabilityRule{
	{"oidc", "OpenID Connect", "OpenID Connect Core 1.0", func(m *Metadata) (bool, string) {
		ok := m.Kind == KindOpenID || m.Contains("scopes_supported", "openid") || m.Has("id_token_signing_alg_values_supported")
		return ok, m.String("userinfo_endpoint")
	}},
	{"authorization_code", "Authorization code grant", "RFC 6749 §4.1", grant("authorization_code")},
	{"client_credentials", "Client credentials grant", "RFC 6749 §4.4", grant("client_credentials")},
	{"refresh_token", "Refresh tokens", "RFC 6749 §6", grant("refresh_token")},
	{"pkce", "PKCE", "RFC 7636", listMember("code_challenge_methods_supported")},
	{"introspection", "Token introspection", "RFC 7662", member("introspection_endpoint")},
	{"revocation", "Token revocation", "RFC 7009", member("revocation_endpoint")},
	{"userinfo", "UserInfo endpoint", "OpenID Connect Core 1.0 §5.3", member("userinfo_endpoint")},
	{"dcr", "Dynamic client registration", "RFC 7591", member("registration_endpoint")},
	{"device", "Device authorization grant", "RFC 8628", member("device_authorization_endpoint")},
	{"par", "Pushed authorization requests", "RFC 9126", member("pushed_authorization_request_endpoint")},
	{"jar", "JWT-secured authorization requests", "RFC 9101", func(m *Metadata) (bool, string) {
		value, ok := m.Bool("request_parameter_supported")
		uri, _ := m.Bool("request_uri_parameter_supported")
		if !ok && !m.Has("request_uri_parameter_supported") {
			return false, "not advertised"
		}
		return value || uri, fmt.Sprintf("request: %t, request_uri: %t", value, uri)
	}},
	{"dpop", "Demonstrating proof of possession", "RFC 9449", listMember("dpop_signing_alg_values_supported")},
	{"mtls", "Mutual TLS client authentication", "RFC 8705", func(m *Metadata) (bool, string) {
		bound, _ := m.Bool("tls_client_certificate_bound_access_tokens")
		methods := m.TokenAuthMethods()
		ok := bound || contains(methods, "tls_client_auth") || contains(methods, "self_signed_tls_client_auth") || m.Has("mtls_endpoint_aliases")
		return ok, fmt.Sprintf("certificate-bound tokens: %t", bound)
	}},
	{"private_key_jwt", "JWT client authentication", "RFC 7523 §2.2", func(m *Metadata) (bool, string) {
		methods := m.TokenAuthMethods()
		ok := contains(methods, "private_key_jwt") || contains(methods, "client_secret_jwt")
		return ok, strings.Join(methods, ", ")
	}},
	{"jwt_bearer", "JWT bearer grant", "RFC 7523 §2.1", grant("urn:ietf:params:oauth:grant-type:jwt-bearer")},
	{"token_exchange", "Token exchange", "RFC 8693", grant("urn:ietf:params:oauth:grant-type:token-exchange")},
	{"ciba", "Client-initiated backchannel authentication", "OpenID CIBA Core 1.0", member("backchannel_authentication_endpoint")},
	{"iss_param", "Issuer identification in authorization responses", "RFC 9207", boolMember("authorization_response_iss_parameter_supported")},
	{"jarm", "JWT-secured authorization responses", "OpenID JARM", listMember("authorization_signing_alg_values_supported")},
	{"cimd", "Client ID metadata documents", "draft-ietf-oauth-client-id-metadata-document", boolMember("client_id_metadata_document_supported")},
	{"signed_metadata", "Signed metadata", "RFC 8414 §2.1", member("signed_metadata")},
	{"rp_logout", "RP-initiated logout", "OpenID Connect RP-Initiated Logout 1.0", member("end_session_endpoint")},
	{"rar", "Rich authorization requests", "RFC 9396", listMember("authorization_details_types_supported")},
}

// Capabilities decides every capability row from the metadata.
func (m *Metadata) Capabilities() []cligen.Capability {
	out := make([]cligen.Capability, 0, len(capabilityRules))
	for _, rule := range capabilityRules {
		supported, detail := rule.Check(m)
		capability := cligen.Capability{ID: rule.ID, Title: rule.Title, Spec: rule.Spec, Supported: supported}
		if detail != "" {
			capability.Detail = &detail
		}
		out = append(out, capability)
	}
	return out
}

// SortedKeys lists the members of a document in order, for stable output.
func SortedKeys(document map[string]any) []string {
	keys := make([]string, 0, len(document))
	for key := range document {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
