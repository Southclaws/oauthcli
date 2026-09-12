package conformance

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Southclaws/oauthcli/internal/oauth"
)

// authorizeProbe is one GET to the authorization endpoint, redirect not
// followed, and where the server sent the browser.
type authorizeProbe struct {
	Status   int
	Location *url.URL
	Header   http.Header
	// Error is the error parameter of a redirect back to the client.
	Error string
	// State is the state parameter echoed in the redirect.
	State string
	// ToClient reports whether the redirect targets the given redirect URI.
	ToClient bool
	// Body is the first line of the response body, for a 4xx without a
	// redirect, where it usually names the parameter the server disliked.
	Body string
	Err  error
}

func (r *Runner) probeAuthorize(ctx context.Context, params url.Values, redirectURI string, extraHeaders http.Header) authorizeProbe {
	endpoint := r.Metadata.String("authorization_endpoint")
	u, err := url.Parse(endpoint)
	if err != nil {
		return authorizeProbe{Err: err}
	}
	query := u.Query()
	for name, items := range params {
		for _, item := range items {
			query.Add(name, item)
		}
	}
	u.RawQuery = query.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return authorizeProbe{Err: err}
	}
	req.Header.Set("Accept", "text/html,application/json")
	for name, values := range extraHeaders {
		req.Header[name] = values
	}
	response, err := r.Client.Do(ctx, req)
	if err != nil {
		return authorizeProbe{Err: err}
	}
	probe := authorizeProbe{Status: response.Status, Header: response.Header, Body: firstLine(response)}
	if location := response.Header.Get("Location"); location != "" {
		if target, err := u.Parse(location); err == nil {
			probe.Location = target
			values := target.Query()
			if fragment, err := url.ParseQuery(target.Fragment); err == nil {
				for name, items := range fragment {
					values[name] = items
				}
			}
			probe.Error = values.Get("error")
			probe.State = values.Get("state")
			if redirect, err := url.Parse(redirectURI); err == nil && redirectURI != "" {
				probe.ToClient = target.Scheme == redirect.Scheme && target.Host == redirect.Host && strings.TrimRight(target.Path, "/") == strings.TrimRight(redirect.Path, "/")
			}
		}
	}
	return probe
}

func (p authorizeProbe) summary() string {
	if p.Err != nil {
		return p.Err.Error()
	}
	if p.Location == nil {
		if p.Status >= 400 && p.Body != "" {
			return fmt.Sprintf("HTTP %d with no redirect; body %s", p.Status, p.Body)
		}
		return fmt.Sprintf("HTTP %d with no redirect", p.Status)
	}
	target := *p.Location
	target.RawQuery = ""
	target.Fragment = ""
	if p.Error != "" {
		return fmt.Sprintf("HTTP %d redirect to %s with error=%s", p.Status, target.String(), p.Error)
	}
	return fmt.Sprintf("HTTP %d redirect to %s", p.Status, target.String())
}

// probeRedirectURI is the redirect URI used for authorization probes: the
// configured one, or a loopback default that a registered client is likely
// to accept.
func (r *Runner) probeRedirectURI() string {
	if r.Options.RedirectURI != "" {
		return r.Options.RedirectURI
	}
	return "http://127.0.0.1/callback"
}

// registeredErrorCodes are the token endpoint error codes RFC 6749 §5.2
// defines.
var registeredErrorCodes = []string{"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope"}

// oauthErrorOrUntested grades a request that should have produced an OAuth
// error: a transport failure is not a finding about the server.
func oauthErrorOf(err error) (*oauth.Error, bool) {
	var oauthErr *oauth.Error
	if errors.As(err, &oauthErr) {
		return oauthErr, true
	}
	return nil, false
}

func (r *Runner) checkCore(ctx context.Context) {
	s := r.spec("rfc6749", "OAuth 2.0 core endpoints (RFC 6749)", "https://www.rfc-editor.org/rfc/rfc6749")
	if r.Metadata == nil {
		s.untested("token-endpoint", "token endpoint answers", "", "no metadata document")
		return
	}
	s.supportedIf(true, "")
	tokenEndpoint := r.Metadata.String("token_endpoint")

	if tokenEndpoint != "" {
		// An empty POST must produce a JSON error document with a 400 or 401.
		response, err := r.Client.PostForm(ctx, tokenEndpoint, url.Values{}, nil)
		if err != nil {
			s.untested("token-error-shape", "token endpoint error responses are RFC 6749 §5.2 JSON", "§5.2", describeErr(err))
		} else {
			oauthErr := oauth.ParseError(response)
			isJSON := response.IsJSON() && !strings.HasPrefix(oauthErr.Code, "http_")
			s.requirement(response.Status == 400 || response.Status == 401, Fail, "token-error-status", "token endpoint answers 400 or 401 to a malformed request", "§5.2", fmt.Sprintf("HTTP %d", response.Status), fmt.Sprintf("an empty POST answered HTTP %d", response.Status))
			s.requirement(isJSON, Fail, "token-error-shape", "token endpoint error responses are RFC 6749 §5.2 JSON", "§5.2", fmt.Sprintf("error=%s", oauthErr.Code), fmt.Sprintf("the error body is %s, not an application/json document with an error member", firstLine(response)))
			if isJSON {
				s.requirement(contains(registeredErrorCodes, oauthErr.Code), Warn, "token-error-code", "error code is a registered value", "§5.2", oauthErr.Code, fmt.Sprintf("error code %q is not one RFC 6749 §5.2 defines", oauthErr.Code))
			}
		}

		// RFC 6749 §4.4.2 and §3.2.1: the client credentials grant is for
		// confidential clients, which must authenticate.
		anonymous, err := r.Client.PostForm(ctx, tokenEndpoint, url.Values{"grant_type": {oauth.GrantClientCredentials}}, nil)
		if err == nil {
			s.requirement(anonymous.Status >= 400, Fail, "client-credentials-authenticated", "client credentials grant without client authentication is refused", "§4.4.2, §3.2.1", fmt.Sprintf("HTTP %d %s", anonymous.Status, oauth.ParseError(anonymous).Code), fmt.Sprintf("HTTP %d: a token may have been issued to an unauthenticated caller", anonymous.Status))
		}
	}

	if authorize := r.Metadata.String("authorization_endpoint"); authorize != "" {
		probe := r.probeAuthorize(ctx, url.Values{}, "", nil)
		switch {
		case probe.Err != nil:
			s.untested("authz-bad-request", "authorization endpoint handles a request with no parameters", "§3.1.1, §4.1.2.1", probe.Err.Error())
		case probe.Status == 405:
			s.fail("authz-bad-request", "authorization endpoint handles a request with no parameters", "§3.1", "HTTP 405; the authorization endpoint must support GET")
		case probe.Status >= 500:
			s.fail("authz-bad-request", "authorization endpoint handles a request with no parameters", "§3.1.1, §4.1.2.1", fmt.Sprintf("HTTP %d; a request without response_type must produce an error response, not a server failure", probe.Status))
		case probe.Location != nil && probe.Status >= 300 && probe.Status < 400 && probe.Error == "":
			s.warn("authz-bad-request", "authorization endpoint handles a request with no parameters", "§4.1.2.1", "the server redirected a request with no client_id and no redirect_uri: "+probe.summary())
		default:
			s.pass("authz-bad-request", "authorization endpoint handles a request with no parameters", "§3.1.1, §4.1.2.1", probe.summary())
		}

		// OAuth 2.1 §3.1: CORS must not be supported at the authorization
		// endpoint, because it is meant for the browser's navigation only.
		cors := r.probeAuthorize(ctx, url.Values{}, "", http.Header{"Origin": {"https://oauthcli.invalid"}})
		if cors.Err == nil {
			allow := cors.Header.Get("Access-Control-Allow-Origin")
			s.requirement(allow == "", Fail, "authz-no-cors", "authorization endpoint does not answer CORS requests", "OAuth 2.1 §3.1", "", fmt.Sprintf("Access-Control-Allow-Origin: %s", allow))
		}
	}

	if !r.hasCredentials() {
		s.untested("client-credentials", "client credentials grant issues a token", "§4.4", "needs --client-id and --client-secret")
		return
	}
	if !contains(r.Metadata.GrantTypes(), oauth.GrantClientCredentials) {
		s.skip("client-credentials", "client credentials grant issues a token", "§4.4", "client_credentials is not in grant_types_supported")
		return
	}
	result, err := r.obtainToken(ctx, nil)
	if err != nil {
		if oauthErr, ok := oauthErrorOf(err); ok {
			r.clientRecognised = oauthErr.Code != "invalid_client"
			if oauthErr.Code == "invalid_client" || oauthErr.Code == "unauthorized_client" {
				r.grantUnavailable = "the client credentials grant is not available to this client (" + oauthErr.Code + ")"
				s.untested("client-credentials", "client credentials grant issues a token", "§4.4", "the server refused the credentials given: "+oauthErr.Error()+"; check the client id, secret and --auth-method")
			} else {
				s.fail("client-credentials", "client credentials grant issues a token", "§4.4", "the server answered "+oauthErr.Error())
			}
		} else {
			s.untested("client-credentials", "client credentials grant issues a token", "§4.4", describeErr(err))
		}
		return
	}
	r.clientRecognised = true
	s.pass("client-credentials", "client credentials grant issues a token", "§4.4", fmt.Sprintf("token_type=%s, authenticated with %s", result.TokenType, result.AuthMethod))
	s.fromIssues(result.Issues, "token-type-missing", "token-type", "token response carries token_type", "§5.1", result.TokenType)
	s.fromIssues(result.Issues, "cache-control", "no-store", "token response carries Cache-Control: no-store", "§5.1", result.Response.Header.Get("Cache-Control"))
	s.fromIssues(result.Issues, "pragma", "pragma", "token response carries Pragma: no-cache", "§5.1", result.Response.Header.Get("Pragma"))
	s.fromIssues(result.Issues, "content-type", "json", "token response is application/json", "§5.1", result.Response.Header.Get("Content-Type"))
	s.fromIssues(result.Issues, "expires-in-missing", "expires-in", "token response carries expires_in", "§5.1", fmt.Sprintf("%d seconds", result.ExpiresIn))
	s.fromIssues(result.Issues, "expires-in-type", "expires-in-number", "expires_in is a JSON number", "§5.1", "")
	s.fromIssues(result.Issues, "expires-in-invalid", "expires-in-valid", "expires_in is positive", "§5.1", "")
	s.fromIssues(result.Issues, "refresh-token-for-client", "no-refresh-for-client", "no refresh token for the client credentials grant", "§4.4.3", "")

	base := func() oauth.TokenRequest {
		return oauth.TokenRequest{
			Endpoint:    tokenEndpoint,
			Grant:       oauth.GrantClientCredentials,
			Credentials: r.Options.Credentials,
			Advertised:  r.Metadata.TokenAuthMethods(),
			Scopes:      r.Options.Scopes,
			Audience:    r.Options.Audience,
			Resources:   r.Options.Resources,
		}
	}

	// RFC 6749 §3.2: unrecognised parameters must be ignored.
	extra := base()
	extra.Params = url.Values{"oauthcli_unknown_parameter": {"1"}}
	if _, err := r.Client.Token(ctx, extra); err != nil {
		if oauthErr, ok := oauthErrorOf(err); ok {
			s.fail("ignores-unknown-params", "unrecognised request parameters are ignored", "§3.2", "the request was rejected: "+oauthErr.Error())
		} else {
			s.untested("ignores-unknown-params", "unrecognised request parameters are ignored", "§3.2", describeErr(err))
		}
	} else {
		s.pass("ignores-unknown-params", "unrecognised request parameters are ignored", "§3.2", "a token was issued with an unknown parameter present")
	}

	// RFC 6749 §3.2: a parameter included more than once is invalid.
	duplicate := base()
	duplicate.Params = url.Values{"grant_type": {oauth.GrantClientCredentials}}
	_, err = r.Client.Token(ctx, duplicate)
	switch oauthErr, ok := oauthErrorOf(err); {
	case err == nil:
		s.fail("rejects-duplicate-params", "a repeated parameter is rejected with invalid_request", "§3.2, §5.2", "a token was issued for a request with grant_type twice")
	case ok && oauthErr.Code == "invalid_request":
		s.pass("rejects-duplicate-params", "a repeated parameter is rejected with invalid_request", "§3.2, §5.2", "HTTP 400 invalid_request")
	case ok:
		s.warn("rejects-duplicate-params", "a repeated parameter is rejected with invalid_request", "§3.2, §5.2", "rejected with "+oauthErr.Code+" instead of invalid_request")
	default:
		s.untested("rejects-duplicate-params", "a repeated parameter is rejected with invalid_request", "§3.2", describeErr(err))
	}

	// A grant type the server cannot know must produce unsupported_grant_type.
	bogus := base()
	bogus.Grant = "urn:oauthcli:grant-type:does-not-exist"
	bogusResult, err := r.Client.Token(ctx, bogus)
	switch oauthErr, ok := oauthErrorOf(err); {
	case err == nil:
		s.fail("unsupported-grant", "unknown grant type is rejected with unsupported_grant_type", "§5.2", fmt.Sprintf("the server issued a %s token for an unknown grant type", bogusResult.TokenType))
	case ok && oauthErr.Code == "unsupported_grant_type":
		s.pass("unsupported-grant", "unknown grant type is rejected with unsupported_grant_type", "§5.2", fmt.Sprintf("HTTP %d unsupported_grant_type", oauthErr.Status))
	case ok && (oauthErr.Code == "invalid_request" || oauthErr.Code == "invalid_grant" || oauthErr.Code == "unauthorized_client"):
		s.warn("unsupported-grant", "unknown grant type is rejected with unsupported_grant_type", "§5.2", fmt.Sprintf("rejected with %s instead of unsupported_grant_type", oauthErr.Code))
	case ok:
		s.fail("unsupported-grant", "unknown grant type is rejected with unsupported_grant_type", "§5.2", "rejected with an unregistered error code: "+oauthErr.Error())
	default:
		s.untested("unsupported-grant", "unknown grant type is rejected with unsupported_grant_type", "§5.2", describeErr(err))
	}

	// A scope the server cannot know: invalid_scope, or success with the
	// granted scope echoed back so the client can see what it got.
	scoped := base()
	scoped.Scopes = append(append([]string{}, r.Options.Scopes...), "oauthcli:scope:does-not-exist")
	scopedResult, err := r.Client.Token(ctx, scoped)
	switch oauthErr, ok := oauthErrorOf(err); {
	case err == nil && scopedResult.Scope != "" && !strings.Contains(scopedResult.Scope, "oauthcli:scope:does-not-exist"):
		s.pass("invalid-scope", "unknown scope is rejected or narrowed", "§3.3, §5.2", "granted scope was narrowed to "+scopedResult.Scope)
	case err == nil && scopedResult.Scope == "":
		s.fail("invalid-scope", "unknown scope is rejected or narrowed", "§3.3, §5.2", "the request succeeded and the response carries no scope; when the granted scope differs from the request the scope parameter is required")
	case err == nil:
		s.warn("invalid-scope", "unknown scope is rejected or narrowed", "§3.3, §5.2", "the server accepted an unknown scope string: "+scopedResult.Scope+" (scope strings are server-defined, so this is allowed but unusual)")
	case ok && oauthErr.Code == "invalid_scope":
		s.pass("invalid-scope", "unknown scope is rejected or narrowed", "§3.3, §5.2", "HTTP 400 invalid_scope")
	case ok:
		s.warn("invalid-scope", "unknown scope is rejected or narrowed", "§3.3, §5.2", "rejected with "+oauthErr.Code+" instead of invalid_scope")
	default:
		s.untested("invalid-scope", "unknown scope is rejected or narrowed", "§3.3", describeErr(err))
	}

	if r.Options.Negative {
		wrong := *r.Options.Credentials
		wrong.ClientSecret = "oauthcli-wrong-secret-" + oauth.NewState()
		wrong.Key = nil
		if wrong.Method == oauth.AuthPrivateKeyJWT {
			wrong.Method = oauth.AuthBasic
		}
		request := base()
		request.Credentials = &wrong
		_, err := r.Client.Token(ctx, request)
		method, _ := wrong.Resolve(r.Metadata.TokenAuthMethods())
		switch oauthErr, ok := oauthErrorOf(err); {
		case err == nil:
			s.fail("invalid-client", "wrong client secret is rejected with invalid_client", "§5.2", "the server issued a token for a wrong secret")
		case ok && oauthErr.Code == "invalid_client":
			s.pass("invalid-client", "wrong client secret is rejected with invalid_client", "§5.2", fmt.Sprintf("HTTP %d invalid_client", oauthErr.Status))
			if method == oauth.AuthBasic {
				challenge := ""
				if oauthErr.Header != nil {
					challenge = oauthErr.Header.Get("WWW-Authenticate")
				}
				ok := oauthErr.Status == 401 && strings.HasPrefix(strings.ToLower(challenge), "basic")
				s.requirement(ok, Fail, "invalid-client-401", "invalid_client for Basic authentication answers 401 with WWW-Authenticate: Basic", "§5.2", fmt.Sprintf("HTTP 401, WWW-Authenticate: %s", challenge), fmt.Sprintf("HTTP %d, WWW-Authenticate %q", oauthErr.Status, challenge))
			} else {
				s.requirement(oauthErr.Status == 401 || oauthErr.Status == 400, Fail, "invalid-client-401", "invalid_client uses status 400 or 401", "§5.2", fmt.Sprintf("HTTP %d", oauthErr.Status), fmt.Sprintf("HTTP %d", oauthErr.Status))
			}
		case ok:
			s.warn("invalid-client", "wrong client secret is rejected with invalid_client", "§5.2", "rejected with "+oauthErr.Code+" instead of invalid_client")
		default:
			s.untested("invalid-client", "wrong client secret is rejected with invalid_client", "§5.2", describeErr(err))
		}
	} else {
		s.skip("invalid-client", "wrong client secret is rejected with invalid_client", "§5.2", "pass --negative to send a wrong secret")
	}

	if r.Options.RefreshToken != "" && contains(r.Metadata.GrantTypes(), oauth.GrantRefreshToken) {
		refreshed, err := r.Client.Token(ctx, oauth.TokenRequest{
			Endpoint:    tokenEndpoint,
			Grant:       oauth.GrantRefreshToken,
			Credentials: r.Options.Credentials,
			Advertised:  r.Metadata.TokenAuthMethods(),
			Params:      url.Values{"refresh_token": {r.Options.RefreshToken}},
		})
		switch oauthErr, ok := oauthErrorOf(err); {
		case err == nil:
			s.pass("refresh", "refresh_token grant issues a new access token", "§6", fmt.Sprintf("token_type=%s", refreshed.TokenType))
			r.refreshed = refreshed
		case ok && oauthErr.Code == "invalid_grant":
			s.untested("refresh", "refresh_token grant issues a new access token", "§6", "the refresh token given was refused as invalid_grant; it may be expired or belong to another client")
		default:
			s.fail("refresh", "refresh_token grant issues a new access token", "§6", describeErr(err))
		}
	} else if contains(r.Metadata.GrantTypes(), oauth.GrantRefreshToken) {
		s.untested("refresh", "refresh_token grant issues a new access token", "§6", "pass --refresh-token to exercise it")
	}
}

func firstLine(response *oauth.Response) string {
	body := strings.TrimSpace(string(response.Body))
	if line, _, ok := strings.Cut(body, "\n"); ok {
		body = line
	}
	if len(body) > 80 {
		body = body[:80] + "…"
	}
	if body == "" {
		return fmt.Sprintf("an empty %s body", response.ContentType())
	}
	return fmt.Sprintf("%q (%s)", body, response.ContentType())
}

func (r *Runner) checkPKCE(ctx context.Context) {
	s := r.spec("rfc7636", "Proof Key for Code Exchange (RFC 7636)", "https://www.rfc-editor.org/rfc/rfc7636")
	if r.Metadata == nil {
		s.untested("advertised", "code_challenge_methods_supported is advertised", "", "no metadata document")
		return
	}
	methods := r.Metadata.Strings("code_challenge_methods_supported")
	advertised := len(methods) > 0
	s.requirement(advertised, Warn, "advertised", "code_challenge_methods_supported is advertised", "RFC 8414 §2, RFC 9700 §2.1.1", strings.Join(methods, ", "), "not advertised; RFC 8414 reads that as no PKCE support and RFC 9700 recommends publishing it")
	if advertised {
		s.supportedIf(true, "")
		s.requirement(contains(methods, "S256"), Fail, "s256", "S256 is supported", "§4.2", "", "only "+strings.Join(methods, ", ")+" advertised; S256 is mandatory to implement")
		if contains(methods, "plain") {
			s.skip("no-plain", "plain is not offered", "§7.2, RFC 9700 §2.1.1", "plain is advertised; the specifications only tell clients to prefer S256, so a server may offer it")
		} else {
			s.pass("no-plain", "plain is not offered", "§7.2, RFC 9700 §2.1.1", "")
		}
	}

	clientID := r.clientID()
	authorize := r.Metadata.String("authorization_endpoint")
	if clientID == "" || authorize == "" {
		s.untested("enforced", "authorization request without PKCE is rejected", "OAuth 2.1 §4.1.2.1, §7.5.1.1", "needs --client-id to send a probe")
		return
	}
	redirect := r.probeRedirectURI()
	probe := r.probeAuthorize(ctx, url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirect},
		"state":         {oauth.NewState()},
		"scope":         {strings.Join(r.Options.Scopes, " ")},
	}, redirect, nil)
	const enforcedSection = "OAuth 2.1 §4.1.2.1, §7.5.1.1"
	switch {
	case probe.Err != nil:
		s.untested("enforced", "authorization request without PKCE is rejected", enforcedSection, probe.Err.Error())
	case probe.ToClient && probe.Error != "":
		s.pass("enforced", "authorization request without PKCE is rejected", enforcedSection, probe.summary())
	case probe.Status == 400 || probe.Status == 401:
		s.untested("enforced", "authorization request without PKCE is rejected", enforcedSection, probe.summary()+"; the client or the redirect URI "+redirect+" may be unknown to the server, so this says nothing about PKCE")
	case probe.Status == 200 || (probe.Status >= 300 && probe.Status < 400 && !probe.ToClient):
		s.warn("enforced", "authorization request without PKCE is rejected", enforcedSection, "the request proceeded to a login page ("+probe.summary()+"); PKCE is not enforced at the authorization endpoint, though OAuth 2.1 permits confidential clients to omit it and a server may enforce it at the token endpoint")
	default:
		s.warn("enforced", "authorization request without PKCE is rejected", enforcedSection, probe.summary())
	}

	// RFC 7636 §4.4.1: an unsupported transformation must be rejected with
	// invalid_request.
	unsupported := r.probeAuthorize(ctx, url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"state":                 {oauth.NewState()},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"oauthcli-bogus"},
	}, redirect, nil)
	switch {
	case unsupported.Err != nil:
		s.untested("unsupported-method", "unknown code_challenge_method is rejected with invalid_request", "§4.4.1", unsupported.Err.Error())
	case unsupported.ToClient && unsupported.Error == "invalid_request":
		s.pass("unsupported-method", "unknown code_challenge_method is rejected with invalid_request", "§4.4.1", unsupported.summary())
	case unsupported.ToClient && unsupported.Error != "":
		s.warn("unsupported-method", "unknown code_challenge_method is rejected with invalid_request", "§4.4.1", "rejected with error="+unsupported.Error+" instead of invalid_request")
	case unsupported.Status == 400 || unsupported.Status == 401:
		s.untested("unsupported-method", "unknown code_challenge_method is rejected with invalid_request", "§4.4.1", unsupported.summary()+"; the client or redirect URI may be unknown to the server")
	default:
		s.fail("unsupported-method", "unknown code_challenge_method is rejected with invalid_request", "§4.4.1", "the request proceeded: "+unsupported.summary())
	}
}

func (r *Runner) checkOAuth21(ctx context.Context) {
	s := r.spec("oauth2.1", "OAuth 2.1 (draft-ietf-oauth-v2-1)", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1")
	if r.Metadata == nil {
		s.untested("grants", "removed grant types are not offered", "", "no metadata document")
		return
	}
	s.supportedIf(true, "")
	grants := r.Metadata.GrantTypes()
	if r.Metadata.Has("grant_types_supported") {
		s.requirement(!contains(grants, "implicit"), Warn, "no-implicit", "implicit grant is not offered", "§10.1, RFC 9700 §2.1.2", "", "grant_types_supported includes implicit, which OAuth 2.1 omits and RFC 9700 says clients should not use")
	} else {
		s.skip("no-implicit", "implicit grant is not offered", "§10.1", "grant_types_supported is absent, so the RFC 8414 default applies and nothing was advertised")
	}
	s.requirement(!contains(grants, "password"), Fail, "no-password", "password grant is not offered", "§10.1, RFC 9700 §2.4", "", "grant_types_supported includes password, which RFC 9700 says must not be used")
	implicitResponse := false
	for _, responseType := range r.Metadata.Strings("response_types_supported") {
		if contains(strings.Fields(responseType), "token") {
			implicitResponse = true
		}
	}
	s.requirement(!implicitResponse, Warn, "no-token-response", "no response type returns an access token from the authorization endpoint", "§10.1, RFC 9700 §2.1.2", "", "response_types_supported includes token")
	methods := r.Metadata.Strings("code_challenge_methods_supported")
	switch {
	case len(methods) == 0:
		s.warn("pkce", "PKCE with S256 is advertised", "§4.1.1, RFC 9700 §2.1.1", "code_challenge_methods_supported is absent; publishing it is recommended so clients can detect PKCE support")
	case !contains(methods, "S256"):
		s.fail("pkce", "PKCE with S256 is advertised", "§4.1.1, RFC 7636 §4.2", "S256 is mandatory to implement but only "+strings.Join(methods, ", ")+" is advertised")
	default:
		s.pass("pkce", "PKCE with S256 is advertised", "§4.1.1", strings.Join(methods, ", "))
	}
	if r.Metadata.Has("grant_types_supported") {
		s.pass("grants-advertised", "grant_types_supported is advertised", "RFC 8414 §2", strings.Join(grants, ", "))
	} else {
		s.warn("grants-advertised", "grant_types_supported is advertised", "RFC 8414 §2", "absent, so the default of authorization_code and implicit applies")
	}

	clientID := r.clientID()
	authorize := r.Metadata.String("authorization_endpoint")
	const redirectSection = "§2.3.1, §4.1.1; RFC 6749 §4.1.2.1"
	if clientID == "" || authorize == "" {
		s.untested("redirect-exact", "redirect URI is matched exactly", redirectSection, "needs --client-id to send a probe")
	} else {
		// RFC 6749 §4.1.2.1: an invalid redirect URI must never be redirected
		// to, while §3.1.1 says an unsupported response type is reported by
		// redirecting to a valid one. Sending both together makes the probe
		// conclusive: a server that accepts the derived URI reveals it by
		// redirecting there with unsupported_response_type.
		registered := r.probeRedirectURI()
		bogus := strings.TrimRight(registered, "/") + "/oauthcli-open-redirect-probe"
		probe := r.probeAuthorize(ctx, url.Values{
			"response_type": {"oauthcli-invalid"},
			"client_id":     {clientID},
			"redirect_uri":  {bogus},
			"state":         {oauth.NewState()},
		}, bogus, nil)
		switch {
		case probe.Err != nil:
			s.untested("redirect-exact", "redirect URI is matched exactly", redirectSection, probe.Err.Error())
		case probe.ToClient:
			s.fail("redirect-exact", "redirect URI is matched exactly", redirectSection, "the server redirected to an unregistered URI derived from the registered one: "+probe.summary())
		default:
			s.pass("redirect-exact", "redirect URI is matched exactly", redirectSection, "an unregistered redirect URI was not followed: "+probe.summary())
		}

		// RFC 6749 §3.1.1 and §4.1.2.1: an unsupported response type is
		// reported to the registered redirect URI, with state echoed. Only a
		// redirect URI the user configured can be relied on to be registered.
		if r.Options.RedirectURI != "" {
			state := oauth.NewState()
			echo := r.probeAuthorize(ctx, url.Values{
				"response_type": {"oauthcli-invalid"},
				"client_id":     {clientID},
				"redirect_uri":  {registered},
				"state":         {state},
			}, registered, nil)
			switch {
			case echo.Err != nil:
				s.untested("error-redirect", "unsupported response type is reported to the redirect URI with state", "RFC 6749 §3.1.1, §4.1.2.1", echo.Err.Error())
			case echo.ToClient && (echo.Error == "unsupported_response_type" || echo.Error == "invalid_request") && echo.State == state:
				s.pass("error-redirect", "unsupported response type is reported to the redirect URI with state", "RFC 6749 §3.1.1, §4.1.2.1", echo.summary())
			case echo.ToClient && echo.Error != "":
				s.warn("error-redirect", "unsupported response type is reported to the redirect URI with state", "RFC 6749 §3.1.1, §4.1.2.1", fmt.Sprintf("redirected with error=%s and state echoed=%t", echo.Error, echo.State == state))
			default:
				s.warn("error-redirect", "unsupported response type is reported to the redirect URI with state", "RFC 6749 §3.1.1, §4.1.2.1", "no error redirect: "+echo.summary()+" (the redirect URI may not be registered for this client)")
			}
		}
	}

	if r.refreshed != nil {
		rotated := r.refreshed.RefreshToken != "" && r.refreshed.RefreshToken != r.Options.RefreshToken
		s.requirement(rotated, Warn, "refresh-rotation", "refresh tokens rotate on use", "§4.3.1", "a new refresh token was issued", "the same refresh token was returned; public clients must get rotation or sender-constrained tokens")
	} else if contains(grants, oauth.GrantRefreshToken) {
		s.untested("refresh-rotation", "refresh tokens rotate on use", "§4.3.1", "pass --refresh-token to test rotation")
	}

	if r.Obtained != nil {
		s.pass("bearer-header", "access tokens are usable in the Authorization header", "§5.1.1", "token_type="+r.Obtained.TokenType)
		if userinfo := r.Metadata.String("userinfo_endpoint"); userinfo != "" {
			target := userinfo
			if strings.Contains(target, "?") {
				target += "&access_token=" + url.QueryEscape(r.Obtained.AccessToken)
			} else {
				target += "?access_token=" + url.QueryEscape(r.Obtained.AccessToken)
			}
			if response, err := r.Client.Get(ctx, target); err == nil {
				s.requirement(response.Status != 200, Fail, "no-query-token", "a token in the query string is ignored by the resource server", "§5.1", fmt.Sprintf("HTTP %d", response.Status), "the UserInfo endpoint accepted an access token from the query string")
			}
		}
	}
}

func (r *Runner) checkBearer(ctx context.Context) {
	s := r.spec("rfc6750", "Bearer token usage (RFC 6750)", "https://www.rfc-editor.org/rfc/rfc6750")
	if r.Metadata == nil {
		s.untested("challenge", "protected endpoint answers with a Bearer challenge", "", "no metadata document")
		return
	}
	endpoint := r.Metadata.String("userinfo_endpoint")
	if endpoint == "" {
		s.supportedIf(false, "no protected endpoint (userinfo_endpoint) to probe")
		return
	}
	s.supportedIf(true, "")

	response, err := r.Client.Get(ctx, endpoint)
	if err != nil {
		s.untested("challenge", "protected endpoint answers with a Bearer challenge", "§3", describeErr(err))
		return
	}
	challenge := oauth.ParseChallenge(response.Header.Get("WWW-Authenticate"))
	hasBearer := challenge != nil && strings.EqualFold(challenge.Scheme, "Bearer")
	s.requirement(hasBearer, Fail, "challenge", "request without a token answers with WWW-Authenticate: Bearer", "§3", response.Header.Get("WWW-Authenticate"), fmt.Sprintf("HTTP %d with WWW-Authenticate %q", response.Status, response.Header.Get("WWW-Authenticate")))
	s.requirement(response.Status == 401, Warn, "unauthenticated-401", "request without a token answers 401", "§3.1", "HTTP 401", fmt.Sprintf("HTTP %d; 401 is the usual status for a missing token", response.Status))
	if challenge != nil {
		s.requirement(challenge.Params["error"] == "", Warn, "no-error-without-token", "challenge without a token carries no error code", "§3.1", "", "error="+challenge.Params["error"]+"; a request with no token should not get an error code")
		s.requirement(len(challenge.Params) > 0, Fail, "challenge-params", "Bearer challenge carries at least one parameter", "§3", "", "the challenge is a bare scheme with no realm, scope or error parameter")
	}

	invalid, err := r.Client.Bearer(ctx, http.MethodGet, endpoint, "oauthcli-invalid-token-"+oauth.NewState(), nil)
	if err != nil {
		s.untested("invalid-token", "invalid token answers 401 invalid_token", "§3.1", describeErr(err))
		return
	}
	invalidChallenge := oauth.ParseChallenge(invalid.Header.Get("WWW-Authenticate"))
	code := ""
	if invalidChallenge != nil {
		code = invalidChallenge.Params["error"]
	}
	switch {
	case invalidChallenge == nil || !strings.EqualFold(invalidChallenge.Scheme, "Bearer"):
		s.fail("invalid-token", "invalid token answers 401 invalid_token", "§3", fmt.Sprintf("HTTP %d with no Bearer challenge; WWW-Authenticate is required on every failed request", invalid.Status))
	case invalid.Status == 401 && code == "invalid_token":
		s.pass("invalid-token", "invalid token answers 401 invalid_token", "§3.1", invalid.Header.Get("WWW-Authenticate"))
	default:
		s.warn("invalid-token", "invalid token answers 401 invalid_token", "§3.1", fmt.Sprintf("HTTP %d with error=%q; 401 and invalid_token are what §3.1 recommends", invalid.Status, code))
	}
	if invalidChallenge != nil && invalidChallenge.Params["resource_metadata"] != "" {
		s.pass("resource-metadata", "challenge points at protected resource metadata", "RFC 9728 §5.1", invalidChallenge.Params["resource_metadata"])
	} else {
		s.skip("resource-metadata", "challenge points at protected resource metadata", "RFC 9728 §5.1", "no resource_metadata parameter (optional)")
	}
}

func (r *Runner) checkOpenIDCore(ctx context.Context) {
	s := r.spec("oidc-core", "OpenID Connect Core 1.0", "https://openid.net/specs/openid-connect-core-1_0.html")
	doc := r.OpenID
	if r.Metadata != nil && r.Metadata.Kind == oauth.KindOpenID {
		doc = r.Metadata
	}
	if r.Metadata == nil {
		s.untested("provider", "issuer is an OpenID provider", "", "no metadata document")
		return
	}
	isProvider := doc != nil || r.Metadata.Contains("scopes_supported", "openid") || r.Metadata.Has("id_token_signing_alg_values_supported")
	s.supportedIf(isProvider, "no openid-configuration, openid scope or ID token algorithms advertised")
	if !isProvider {
		return
	}
	source := r.Metadata
	if doc != nil {
		source = doc
	}
	s.pass("provider", "issuer is an OpenID provider", "§1", "openid-configuration or ID token support is advertised")
	s.requirement(source.String("authorization_endpoint") != "", Fail, "authorization-endpoint", "authorization_endpoint is present", "§3.1.2", source.String("authorization_endpoint"), "missing")
	s.requirement(source.String("jwks_uri") != "", Fail, "jwks", "ID token signing keys are published", "§10.1", source.String("jwks_uri"), "no jwks_uri")
	algs := source.Strings("id_token_signing_alg_values_supported")
	s.requirement(!contains(algs, "none") || len(algs) > 1, Fail, "no-alg-none-only", "ID tokens are signed", "§2", strings.Join(algs, ", "), "only alg none is advertised; ID tokens must be signed")
	s.requirement(!contains(algs, "none"), Warn, "no-alg-none", "alg none is not offered for ID tokens", "§3.1.3.7", "", "none is advertised; a client must never accept it for the code flow")
	if !contains(source.Strings("subject_types_supported"), "public") && !contains(source.Strings("subject_types_supported"), "pairwise") {
		s.warn("subject-types", "subject types are public or pairwise", "§8", "advertised: "+strings.Join(source.Strings("subject_types_supported"), ", "))
	} else {
		s.pass("subject-types", "subject types are public or pairwise", "§8", strings.Join(source.Strings("subject_types_supported"), ", "))
	}

	userinfo := source.String("userinfo_endpoint")
	if userinfo == "" {
		s.warn("userinfo", "userinfo_endpoint is advertised", "§5.3", "absent (recommended)")
		return
	}
	s.pass("userinfo", "userinfo_endpoint is advertised", "§5.3", userinfo)
	if u, err := url.Parse(userinfo); err == nil {
		s.requirement(u.Scheme == "https" || oauth.IsLoopback(u.Hostname()), Fail, "userinfo-https", "userinfo_endpoint uses https", "§5.3", "", userinfo)
	}
	token := r.Options.Token
	if token == "" && r.Obtained != nil && strings.Contains(" "+r.Obtained.Scope+" ", " openid ") {
		token = r.Obtained.AccessToken
	}
	if token == "" {
		s.untested("userinfo-sub", "UserInfo returns a sub claim", "§5.3.2", "needs a token with the openid scope (pass --token or add openid to --scope)")
		return
	}
	claims, _, err := r.Client.UserInfo(ctx, userinfo, token, nil)
	if err != nil {
		s.fail("userinfo-sub", "UserInfo returns a sub claim", "§5.3.2", describeErr(err))
		return
	}
	sub, _ := claims["sub"].(string)
	s.requirement(sub != "", Fail, "userinfo-sub", "UserInfo returns a sub claim", "§5.3.2", "sub="+sub, "the response has no sub")
}
