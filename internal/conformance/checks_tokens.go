package conformance

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Southclaws/oauthcli/internal/oauth"
)

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func (r *Runner) checkJWTAccessTokens(ctx context.Context) {
	s := r.spec("rfc9068", "JWT profile for access tokens (RFC 9068)", "https://www.rfc-editor.org/rfc/rfc9068")
	if r.Metadata == nil {
		s.untested("jwt", "access tokens are JWTs", "", "no metadata document")
		return
	}
	token := r.validationToken(ctx)
	if token == "" {
		s.untested("jwt", "access tokens are JWTs", "", "needs credentials or --token")
		return
	}
	verifier := r.Client.NewVerifier(r.Options.Issuer)
	if r.Keys != nil {
		verifier.KeysURL = r.Keys.URL
	}
	info, jws := oauth.Inspect(ctx, token, oauth.InspectOptions{Verifier: verifier, ExpectedIssuer: r.Options.Issuer, AccessToken: true})
	if jws == nil {
		s.supportedIf(false, "access tokens are opaque")
		s.skip("jwt", "access tokens are JWTs", "§2", "the access token is opaque; introspection is the way to learn about it")
		return
	}
	typ := jws.Typ()
	atJWT := strings.EqualFold(typ, "at+jwt") || strings.EqualFold(typ, "application/at+jwt")
	if !atJWT {
		s.supportedIf(false, "the access token is a JWT but does not declare typ at+jwt, so the profile is not implemented")
		s.skip("typ", "header typ is at+jwt", "§2.1", fmt.Sprintf("typ is %q; a JWT access token following RFC 9068 must declare at+jwt", typ))
		return
	}
	s.supportedIf(true, "")
	s.pass("jwt", "access tokens are JWTs", "§2", fmt.Sprintf("alg=%s kid=%s", jws.Alg(), jws.Kid()))
	s.pass("typ", "header typ is at+jwt", "§2.1", typ)
	s.requirement(jws.Alg() != "none" && jws.Alg() != "", Fail, "signed", "token is signed", "§2.1, §4", jws.Alg(), "alg none")
	if info.Signature != nil {
		switch info.Signature.Status {
		case "verified":
			s.pass("signature", "signature verifies against jwks_uri", "§4", *info.Signature.KeySource)
		case "invalid":
			s.fail("signature", "signature verifies against jwks_uri", "§4", *info.Signature.Error)
		default:
			s.warn("signature", "signature verifies against jwks_uri", "§4", deref(info.Signature.Error))
		}
	}
	for _, claim := range []string{"iss", "exp", "aud", "sub", "client_id", "iat", "jti"} {
		_, ok := jws.Claims[claim]
		s.requirement(ok, Fail, "claim-"+claim, "claim "+claim+" is present", "§2.2", fmt.Sprint(jws.Claims[claim]), "missing (REQUIRED)")
	}
	s.fromIssues(info.Issues, "claim-not-numeric", "numeric-dates", "exp and iat are NumericDate values", "RFC 7519 §4.1.4, §4.1.6", "")
	s.fromIssues(info.Issues, "aud-type", "aud-type", "aud is a string or an array of strings", "RFC 7519 §4.1.3", "")
	if !s.fromIssuesAny(info.Issues, []string{"issuer-mismatch", "issuer-trailing-slash"}, "iss", "iss exactly matches the issuer", "§4") {
		s.pass("iss", "iss exactly matches the issuer", "§4", jws.String("iss"))
	}
	s.requirement(!info.Timing.Expired, Fail, "not-expired", "token is not expired", "§4", deref(info.Timing.ExpiresIn)+" remaining", "expired")
	if info.Timing.Lifetime != nil {
		s.pass("lifetime", "token lifetime", "", *info.Timing.Lifetime)
	}
}

func (r *Runner) checkIntrospection(ctx context.Context) {
	s := r.spec("rfc7662", "Token introspection (RFC 7662)", "https://www.rfc-editor.org/rfc/rfc7662")
	if r.Metadata == nil {
		s.untested("advertised", "introspection_endpoint is advertised", "", "no metadata document")
		return
	}
	endpoint := r.Metadata.String("introspection_endpoint")
	s.supportedIf(endpoint != "", "no introspection_endpoint advertised")
	if endpoint == "" {
		return
	}
	s.pass("advertised", "introspection_endpoint is advertised", "RFC 8414 §2", endpoint)
	advertised := r.Metadata.Strings("introspection_endpoint_auth_methods_supported")

	// RFC 7662 §2.1 and §4: the endpoint must require authorization. A bare
	// {"active": false} to an anonymous caller reveals nothing, so it is
	// graded as uncertain rather than as a violation.
	anonymous, err := r.Client.PostForm(ctx, endpoint, url.Values{"token": {"oauthcli-probe"}}, nil)
	if err == nil {
		document, _ := anonymous.JSON()
		active, _ := document["active"].(bool)
		switch {
		case anonymous.Status == 400 || anonymous.Status == 401 || anonymous.Status == 403:
			s.pass("authenticated", "unauthenticated introspection is refused", "§2.1, §4", fmt.Sprintf("HTTP %d", anonymous.Status))
		case anonymous.Status == 200 && document != nil && !active && len(document) == 1:
			s.warn("authenticated", "unauthenticated introspection is refused", "§2.1, §4", "an anonymous call answered active=false rather than an authentication error; nothing leaked, but the endpoint should require credentials")
		default:
			s.fail("authenticated", "unauthenticated introspection is refused", "§2.1, §4", fmt.Sprintf("HTTP %d with %d member(s); anyone can probe token validity", anonymous.Status, len(document)))
		}
	}

	if !r.hasCredentials() {
		s.untested("active", "introspection of a live token reports active", "§2.2", "needs credentials")
		return
	}
	if r.grantUnavailable != "" && r.Options.Token == "" {
		s.untested("active", "introspection of a live token reports active", "§2.2", r.grantUnavailable+"; pass --token to introspect one")
		return
	}
	token := r.validationToken(ctx)
	if token == "" {
		s.untested("active", "introspection of a live token reports active", "§2.2", "no token to introspect")
		return
	}
	response, raw, err := r.Client.Introspect(ctx, endpoint, token, "access_token", r.Options.Credentials, advertised)
	if err != nil {
		if oauthErr, ok := oauthErrorOf(err); ok && (oauthErr.Status == 401 || oauthErr.Status == 403) {
			s.skip("active", "introspection of a live token reports active", "§2.2", "the client is not authorized to introspect (§4 lets a server require separate resource credentials): "+oauthErr.Error())
			return
		}
		s.fail("active", "introspection of a live token reports active", "§2.2", describeErr(err))
		return
	}
	active, _ := response["active"].(bool)
	_, hasActive := response["active"]
	s.requirement(hasActive, Fail, "active-member", "introspection response carries the active member", "§2.2", "", "active is missing (REQUIRED)")
	if r.Options.Token == "" {
		s.requirement(active, Warn, "active", "introspection of a live token reports active", "§2.2", "active=true", "active is false for a token that was just issued to this client; the server may not allow this client to introspect its own tokens (§2.2)")
	} else {
		s.requirement(active, Warn, "active", "introspection of a live token reports active", "§2.2", "active=true", "active is false for the token given; it may be expired, revoked, or not introspectable by this client")
	}
	s.requirement(raw.IsJSON(), Fail, "json", "introspection response is application/json", "§2.2", raw.Header.Get("Content-Type"), raw.Header.Get("Content-Type"))
	if active {
		present := []string{}
		for _, claim := range []string{"scope", "client_id", "exp", "sub", "iss", "token_type"} {
			if _, ok := response[claim]; ok {
				present = append(present, claim)
			}
		}
		s.pass("optional-members", "optional members returned for an active token", "§2.2", strings.Join(present, ", "))
		if clientID, _ := response["client_id"].(string); clientID != "" && r.Options.Token == "" {
			s.requirement(clientID == r.Options.Credentials.ClientID, Warn, "client-id-match", "introspection client_id matches the client the token was issued to", "§2.2", clientID, fmt.Sprintf("client_id is %q, want %q", clientID, r.Options.Credentials.ClientID))
		}

		// RFC 7662 §2.1: when the hint does not find the token, the server
		// must extend its search to every token type it supports.
		hinted, _, err := r.Client.Introspect(ctx, endpoint, token, "refresh_token", r.Options.Credentials, advertised)
		if err != nil {
			s.warn("hint-fallback", "a wrong token_type_hint still finds the token", "§2.1", describeErr(err))
		} else {
			hintedActive, _ := hinted["active"].(bool)
			s.requirement(hintedActive, Fail, "hint-fallback", "a wrong token_type_hint still finds the token", "§2.1", "active=true with token_type_hint=refresh_token", "the token was not found with token_type_hint=refresh_token; the search must extend across all token types")
		}
	}

	garbage, _, err := r.Client.Introspect(ctx, endpoint, "oauthcli-not-a-token-"+oauth.NewState(), "", r.Options.Credentials, advertised)
	if err != nil {
		s.fail("inactive", "introspection of an unknown token reports active false", "§2.2, §2.3", "the server answered an error instead of active=false: "+describeErr(err))
	} else {
		inactive, ok := garbage["active"].(bool)
		s.requirement(ok && !inactive, Fail, "inactive", "introspection of an unknown token reports active false", "§2.2, §2.3", "active=false", fmt.Sprintf("active is %v", garbage["active"]))
		s.requirement(len(garbage) == 1, Warn, "inactive-minimal", "inactive response carries no other members", "§2.2", "", fmt.Sprintf("%d members returned for an unknown token", len(garbage)))
	}
}

func (r *Runner) checkRevocation(ctx context.Context) {
	s := r.spec("rfc7009", "Token revocation (RFC 7009)", "https://www.rfc-editor.org/rfc/rfc7009")
	if r.Metadata == nil {
		s.untested("advertised", "revocation_endpoint is advertised", "", "no metadata document")
		return
	}
	endpoint := r.Metadata.String("revocation_endpoint")
	s.supportedIf(endpoint != "", "no revocation_endpoint advertised")
	if endpoint == "" {
		return
	}
	s.pass("advertised", "revocation_endpoint is advertised", "RFC 8414 §2", endpoint)
	if !r.hasCredentials() {
		s.untested("revoke", "revoking an issued token answers 200", "§2.2", "needs credentials")
		return
	}
	if r.grantUnavailable != "" {
		s.untested("revoke", "revoking an issued token answers 200", "§2.2", r.grantUnavailable+", so there is no token of the tool's own to revoke")
		return
	}
	advertised := r.Metadata.Strings("revocation_endpoint_auth_methods_supported")

	// RFC 7009 §2.2: an invalid token is not an error; §2.2.1 lets a server
	// answer 503 when it cannot process the request yet.
	garbage, err := r.Client.Revoke(ctx, endpoint, "oauthcli-not-a-token-"+oauth.NewState(), "", r.Options.Credentials, advertised)
	switch {
	case err != nil:
		s.untested("invalid-ok", "revoking an unknown token answers 200", "§2.2", describeErr(err))
	case garbage.Status == 503:
		s.untested("invalid-ok", "revoking an unknown token answers 200", "§2.2.1", "HTTP 503; the server asked the client to retry later")
	default:
		s.requirement(garbage.Status == 200, Fail, "invalid-ok", "revoking an unknown token answers 200", "§2.2", "HTTP 200", fmt.Sprintf("HTTP %d; an invalid token must not be an error", garbage.Status))
	}

	// Only a token the audit obtained itself is revoked; a user's token is
	// never touched.
	fresh, err := r.Client.Token(ctx, oauth.TokenRequest{
		Endpoint:    r.Metadata.String("token_endpoint"),
		Grant:       oauth.GrantClientCredentials,
		Credentials: r.Options.Credentials,
		Advertised:  r.Metadata.TokenAuthMethods(),
		Scopes:      r.Options.Scopes,
		Audience:    r.Options.Audience,
		Resources:   r.Options.Resources,
	})
	if err != nil {
		s.untested("revoke", "revoking an issued token answers 200", "§2.2", "could not obtain a token to revoke: "+describeErr(err))
		return
	}
	response, err := r.Client.Revoke(ctx, endpoint, fresh.AccessToken, "access_token", r.Options.Credentials, advertised)
	if err != nil {
		s.untested("revoke", "revoking an issued token answers 200", "§2.2", describeErr(err))
		return
	}
	revoked := response.Status == 200
	switch {
	case revoked:
		s.pass("revoke", "revoking an issued token answers 200", "§2.2", "HTTP 200")
	case response.Status == 503:
		s.untested("revoke", "revoking an issued token answers 200", "§2.2.1", "HTTP 503; the server asked the client to retry later")
	case oauth.ParseError(response).Code == "unsupported_token_type":
		s.warn("revoke", "revoking an issued token answers 200", "§2, §2.2.1", "the server does not revoke access tokens (unsupported_token_type); RFC 7009 only requires refresh token revocation and recommends access tokens")
	default:
		s.fail("revoke", "revoking an issued token answers 200", "§2.2", fmt.Sprintf("HTTP %d %s", response.Status, oauth.ParseError(response).Code))
	}

	if !revoked {
		return
	}
	if introspection := r.Metadata.String("introspection_endpoint"); introspection != "" {
		after, _, err := r.Client.Introspect(ctx, introspection, fresh.AccessToken, "access_token", r.Options.Credentials, r.Metadata.Strings("introspection_endpoint_auth_methods_supported"))
		if err != nil {
			s.warn("effective", "revoked token introspects as inactive", "§2.1, RFC 7662 §4", describeErr(err))
		} else {
			active, _ := after["active"].(bool)
			s.requirement(!active, Fail, "effective", "revoked token introspects as inactive", "§2.1, RFC 7662 §4", "active=false after revocation", "the token is still active after revocation; invalidation must take place immediately")
		}

		// RFC 7009 §2.1: a wrong hint must not stop the server finding the
		// token.
		second, err := r.Client.Token(ctx, oauth.TokenRequest{Endpoint: r.Metadata.String("token_endpoint"), Grant: oauth.GrantClientCredentials, Credentials: r.Options.Credentials, Advertised: r.Metadata.TokenAuthMethods(), Scopes: r.Options.Scopes, Audience: r.Options.Audience, Resources: r.Options.Resources})
		if err == nil {
			if hinted, err := r.Client.Revoke(ctx, endpoint, second.AccessToken, "refresh_token", r.Options.Credentials, advertised); err == nil && hinted.Status == 200 {
				check, _, err := r.Client.Introspect(ctx, introspection, second.AccessToken, "access_token", r.Options.Credentials, r.Metadata.Strings("introspection_endpoint_auth_methods_supported"))
				if err == nil {
					active, _ := check["active"].(bool)
					s.requirement(!active, Fail, "hint-fallback", "a wrong token_type_hint still revokes the token", "§2.1", "revoked with token_type_hint=refresh_token", "the token stayed active when revoked with token_type_hint=refresh_token; the search must extend across all token types")
				}
			}
		}
	} else if r.Metadata.String("userinfo_endpoint") != "" && strings.Contains(" "+fresh.Scope+" ", " openid ") {
		_, response, err := r.Client.UserInfo(ctx, r.Metadata.String("userinfo_endpoint"), fresh.AccessToken, nil)
		if err == nil {
			s.fail("effective", "revoked token is refused by protected endpoints", "§2.1", "UserInfo still accepts the revoked token")
		} else if response != nil {
			s.pass("effective", "revoked token is refused by protected endpoints", "§2.1", fmt.Sprintf("UserInfo answered HTTP %d", response.Status))
		}
	} else {
		s.skip("effective", "revoked token introspects as inactive", "§2.1", "no introspection endpoint to confirm with")
	}
}

func (r *Runner) checkDevice(ctx context.Context) {
	s := r.spec("rfc8628", "Device authorization grant (RFC 8628)", "https://www.rfc-editor.org/rfc/rfc8628")
	if r.Metadata == nil {
		s.untested("advertised", "device_authorization_endpoint is advertised", "", "no metadata document")
		return
	}
	endpoint := r.Metadata.String("device_authorization_endpoint")
	s.supportedIf(endpoint != "", "no device_authorization_endpoint advertised")
	if endpoint == "" {
		return
	}
	s.pass("advertised", "device_authorization_endpoint is advertised", "RFC 8414 §2", endpoint)
	s.requirement(contains(r.Metadata.GrantTypes(), oauth.GrantDeviceCode), Warn, "grant-advertised", "device_code grant is in grant_types_supported", "§4", "", "the endpoint is advertised but the grant type is not")

	anonymous, err := r.Client.PostForm(ctx, endpoint, url.Values{}, nil)
	if err == nil {
		oauthErr := oauth.ParseError(anonymous)
		hasCode := !strings.HasPrefix(oauthErr.Code, "http_")
		s.requirement((anonymous.Status == 400 || anonymous.Status == 401) && hasCode, Fail, "error-shape", "request without a client is rejected with an RFC 6749 §5.2 error", "§3.1, §3.2", fmt.Sprintf("HTTP %d %s", anonymous.Status, oauthErr.Code), fmt.Sprintf("HTTP %d with body %s", anonymous.Status, firstLine(anonymous)))
	}
	if r.clientID() == "" || r.Options.Offline {
		s.untested("response", "device authorization response has the required members", "§3.2", "needs --client-id")
		return
	}
	credentials := r.Options.Credentials
	auth, err := r.Client.DeviceAuthorize(ctx, endpoint, credentials, r.Metadata.TokenAuthMethods(), r.Options.Scopes, r.Options.Audience, r.Options.Resources, nil)
	if err != nil {
		oauthErr, ok := oauthErrorOf(err)
		switch {
		case ok && oauthErr.Code == "invalid_client" && r.clientRecognised:
			s.fail("client-auth", "device endpoint accepts the client authentication the token endpoint accepts", "§3.1, RFC 6749 §3.2.1", "the token endpoint recognised the client but the device endpoint answered invalid_client with the same credentials; client authentication must work as at the token endpoint")
			return
		case ok && (oauthErr.Code == "unauthorized_client" || oauthErr.Code == "invalid_client" || oauthErr.Code == "invalid_scope"):
			s.skip("response", "device authorization response has the required members", "§3.2", "the client cannot use the device grant with this configuration: "+oauthErr.Error())
			return
		case ok:
			s.fail("response", "device authorization response has the required members", "§3.2", oauthErr.Error())
			return
		default:
			s.untested("response", "device authorization response has the required members", "§3.2", describeErr(err))
			return
		}
	}
	s.pass("response", "device authorization response has the required members", "§3.2", fmt.Sprintf("user_code=%s expires_in=%d interval=%d", auth.UserCode, auth.ExpiresIn, auth.Interval))
	s.fromIssues(auth.Issues, "device-code-missing", "device-code", "device_code is present", "§3.2", "")
	s.fromIssues(auth.Issues, "user-code-missing", "user-code", "user_code is present", "§3.2", auth.UserCode)
	s.fromIssues(auth.Issues, "verification-uri-missing", "verification-uri", "verification_uri is present", "§3.2", auth.VerificationURI)
	s.fromIssues(auth.Issues, "verification-uri-misspelt", "verification-uri-name", "verification_uri is spelt as the RFC defines", "§3.2", "")
	s.fromIssues(auth.Issues, "expires-in-missing", "expires-in", "expires_in is present", "§3.2", fmt.Sprint(auth.ExpiresIn))
	s.fromIssues(auth.Issues, "content-type", "json", "device authorization response is application/json", "§3.2", "")
	s.fromIssues(auth.Issues, "user-code-in-uri", "user-code-separate", "verification_uri does not embed the user code", "§3.3", "")
	s.fromIssues(auth.Issues, "verification-uri-complete-absent", "verification-uri-complete", "verification_uri_complete is offered", "§3.2", auth.VerificationURIComplete)

	// One poll before anyone could have approved must say authorization_pending.
	_, err = r.Client.Token(ctx, oauth.TokenRequest{
		Endpoint:    r.Metadata.String("token_endpoint"),
		Grant:       oauth.GrantDeviceCode,
		Credentials: credentials,
		Advertised:  r.Metadata.TokenAuthMethods(),
		Params:      url.Values{"device_code": {auth.DeviceCode}},
	})
	switch oauthErr, ok := oauthErrorOf(err); {
	case err == nil:
		s.fail("pending", "polling before approval answers authorization_pending", "§3.5", "the token endpoint issued a token before the user approved")
	case ok && (oauthErr.Code == "authorization_pending" || oauthErr.Code == "slow_down"):
		s.pass("pending", "polling before approval answers authorization_pending", "§3.5", oauthErr.Code)
	case ok:
		s.fail("pending", "polling before approval answers authorization_pending", "§3.5", oauthErr.Error())
	default:
		s.untested("pending", "polling before approval answers authorization_pending", "§3.5", describeErr(err))
	}
}

func (r *Runner) checkPAR(ctx context.Context) {
	s := r.spec("rfc9126", "Pushed authorization requests (RFC 9126)", "https://www.rfc-editor.org/rfc/rfc9126")
	if r.Metadata == nil {
		s.untested("advertised", "pushed_authorization_request_endpoint is advertised", "", "no metadata document")
		return
	}
	endpoint := r.Metadata.String("pushed_authorization_request_endpoint")
	s.supportedIf(endpoint != "", "no pushed_authorization_request_endpoint advertised")
	if endpoint == "" {
		return
	}
	s.pass("advertised", "pushed_authorization_request_endpoint is advertised", "§5", endpoint)
	if u, err := url.Parse(endpoint); err == nil {
		if u.Scheme != "https" && oauth.IsLoopback(u.Hostname()) {
			s.skip("https", "PAR endpoint uses https", "§2", "plain http on loopback")
		} else {
			s.requirement(u.Scheme == "https", Fail, "https", "PAR endpoint uses https", "§2", "", endpoint)
		}
	}
	required, _ := r.Metadata.Bool("require_pushed_authorization_requests")
	if required {
		s.pass("required", "pushed authorization requests are required", "§5", "require_pushed_authorization_requests: true")
	} else {
		s.skip("required", "pushed authorization requests are required", "§5", "optional for clients")
	}

	if !r.hasCredentials() {
		s.untested("push", "pushing a request returns a request_uri", "§2.2", "needs credentials")
		return
	}
	pkce, _ := oauth.NewPKCE(64)
	request := &oauth.AuthorizationRequest{
		Endpoint:    r.Metadata.String("authorization_endpoint"),
		ClientID:    r.Options.Credentials.ClientID,
		RedirectURI: r.probeRedirectURI(),
		Scopes:      r.Options.Scopes,
		State:       oauth.NewState(),
		PKCE:        pkce,
	}

	// RFC 9126 §2.1 step 2: request_uri must be rejected, and the check is
	// only reached once the client has authenticated (step 1), so the probe
	// carries valid credentials and an otherwise valid request.
	form := request.Values()
	form.Set("request_uri", "urn:ietf:params:oauth:request_uri:oauthcli")
	headers := map[string][]string{}
	if method, err := r.Options.Credentials.Resolve(r.Metadata.TokenAuthMethods()); err == nil {
		_ = r.Options.Credentials.Apply(method, form, headers, endpoint)
	}
	response, err := r.Client.PostForm(ctx, endpoint, form, headers)
	if err == nil {
		oauthErr := oauth.ParseError(response)
		switch {
		case response.Status == 400 && oauthErr.Code == "invalid_request":
			s.pass("rejects-request-uri", "PAR endpoint rejects a request_uri parameter", "§2.1", "HTTP 400 invalid_request")
		case response.Status == 400 || response.Status == 401:
			s.warn("rejects-request-uri", "PAR endpoint rejects a request_uri parameter", "§2.1", fmt.Sprintf("rejected with HTTP %d %s; §2.3 names invalid_request for this", response.Status, oauthErr.Code))
		default:
			s.fail("rejects-request-uri", "PAR endpoint rejects a request_uri parameter", "§2.1", fmt.Sprintf("HTTP %d; a request carrying request_uri must be rejected", response.Status))
		}
	}

	requestURI, expiresIn, issues, err := r.Client.Push(ctx, endpoint, request, r.Options.Credentials, r.Metadata.TokenAuthMethods(), nil)
	if err != nil {
		if oauthErr, ok := oauthErrorOf(err); ok && (oauthErr.Code == "invalid_request" || oauthErr.Code == "invalid_client" || oauthErr.Code == "unauthorized_client") && strings.Contains(strings.ToLower(oauthErr.Description), "redirect") {
			s.skip("push", "pushing a request returns a request_uri", "§2.2", "the probe redirect URI is not registered for the client: "+oauthErr.Error())
			return
		}
		s.fail("push", "pushing a request returns a request_uri", "§2.2", describeErr(err))
		return
	}
	s.pass("push", "pushing a request returns a request_uri", "§2.2", fmt.Sprintf("%s (expires in %ds)", requestURI, expiresIn))
	s.fromIssues(issues, "par-status", "status", "PAR response status is 201", "§2.2", "HTTP 201")
	s.fromIssues(issues, "par-content-type", "json", "PAR response is application/json", "§2.2", "")
	s.fromIssues(issues, "par-request-uri-form", "request-uri-form", "request_uri uses the urn:ietf:params:oauth:request_uri: form", "§2.2", requestURI)
	s.fromIssues(issues, "par-expires-in", "expires-in", "PAR response includes expires_in", "§2.2", fmt.Sprintf("%d", expiresIn))
}

func (r *Runner) checkDPoP(ctx context.Context) {
	s := r.spec("rfc9449", "Demonstrating proof of possession (RFC 9449)", "https://www.rfc-editor.org/rfc/rfc9449")
	if r.Metadata == nil {
		s.untested("advertised", "dpop_signing_alg_values_supported is advertised", "", "no metadata document")
		return
	}
	algs := r.Metadata.Strings("dpop_signing_alg_values_supported")
	s.supportedIf(len(algs) > 0, "dpop_signing_alg_values_supported is not advertised")
	if len(algs) == 0 {
		return
	}
	s.pass("advertised", "dpop_signing_alg_values_supported is advertised", "§5.1", strings.Join(algs, ", "))
	s.requirement(!contains(algs, "none") && !containsPrefix(algs, "HS"), Fail, "asymmetric", "only asymmetric algorithms are offered", "§4.2, §11.6", "", "none or an HMAC algorithm is advertised; DPoP proofs must use asymmetric keys")
	if !r.hasCredentials() {
		s.untested("bound", "token request with a DPoP proof yields a DPoP-bound token", "§5", "needs credentials")
		return
	}
	if r.grantUnavailable != "" {
		s.untested("bound", "token request with a DPoP proof yields a DPoP-bound token", "§5", r.grantUnavailable)
		return
	}
	dpop, err := oauth.NewDPoP(r.Options.DPoPKey)
	if err != nil {
		s.fail("bound", "token request with a DPoP proof yields a DPoP-bound token", "§5", describeErr(err))
		return
	}
	if !contains(algs, dpop.Alg) && len(algs) > 0 {
		s.skip("bound", "token request with a DPoP proof yields a DPoP-bound token", "§5", fmt.Sprintf("the server offers %s but the probe key uses %s; pass --dpop-key with a matching key", strings.Join(algs, ", "), dpop.Alg))
		return
	}
	result, err := r.obtainToken(ctx, dpop)
	if err != nil {
		s.fail("bound", "token request with a DPoP proof yields a DPoP-bound token", "§5", describeErr(err))
		return
	}
	bound := strings.EqualFold(result.TokenType, "DPoP")
	s.requirement(bound, Warn, "bound", "token request with a DPoP proof yields a DPoP-bound token", "§5", "token_type=DPoP", fmt.Sprintf("token_type is %q; the server chose to issue a Bearer token, which §5 permits", result.TokenType))
	if dpop.Nonce != "" {
		s.pass("nonce", "server issues DPoP nonces", "§8", "a DPoP-Nonce was supplied and honoured")
	} else {
		s.skip("nonce", "server issues DPoP nonces", "§8", "no DPoP-Nonce header (optional)")
	}
	_, jws := oauth.Inspect(ctx, result.AccessToken, oauth.InspectOptions{})
	switch {
	case !bound:
		s.skip("jkt", "JWT access token carries cnf.jkt of the proof key", "§6.1", "the token is not DPoP-bound")
	case jws == nil:
		s.skip("jkt", "JWT access token carries cnf.jkt of the proof key", "§6.1", "the access token is opaque; the binding may be exposed through introspection (§6.2)")
	default:
		cnf, _ := jws.Claims["cnf"].(map[string]any)
		jkt, _ := cnf["jkt"].(string)
		thumbprint, _ := dpop.Thumbprint()
		switch {
		case jkt == "":
			s.warn("jkt", "JWT access token carries cnf.jkt of the proof key", "§6.1", "the bound token has no cnf.jkt; the binding may be exposed through introspection instead (§6.2)")
		default:
			s.requirement(jkt == thumbprint, Fail, "jkt", "JWT access token carries cnf.jkt of the proof key", "§6.1", jkt, fmt.Sprintf("cnf.jkt is %q, want %q", jkt, thumbprint))
		}
	}

	// RFC 9449 §5: an invalid proof must be refused with invalid_dpop_proof.
	broken, _ := oauth.NewDPoP(r.Options.DPoPKey)
	broken.Alg = dpop.Alg
	broken.HTUOverride = "https://oauthcli.invalid/not-the-token-endpoint"
	broken.Nonce = dpop.Nonce
	_, err = r.Client.Token(ctx, oauth.TokenRequest{
		Endpoint:    r.Metadata.String("token_endpoint"),
		Grant:       oauth.GrantClientCredentials,
		Credentials: r.Options.Credentials,
		Advertised:  r.Metadata.TokenAuthMethods(),
		Scopes:      r.Options.Scopes,
		DPoP:        broken,
	})
	switch oauthErr, ok := oauthErrorOf(err); {
	case err == nil:
		s.fail("invalid-proof", "a proof for the wrong URL is refused with invalid_dpop_proof", "§5", "a token was issued for a proof whose htu names another server")
	case ok && oauthErr.Code == "invalid_dpop_proof":
		s.pass("invalid-proof", "a proof for the wrong URL is refused with invalid_dpop_proof", "§5", "invalid_dpop_proof")
	case ok:
		s.warn("invalid-proof", "a proof for the wrong URL is refused with invalid_dpop_proof", "§5", "refused with "+oauthErr.Code+" instead of invalid_dpop_proof")
	default:
		s.untested("invalid-proof", "a proof for the wrong URL is refused with invalid_dpop_proof", "§5", describeErr(err))
	}
}

func containsPrefix(items []string, prefix string) bool {
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}

func (r *Runner) checkResourceIndicators(ctx context.Context) {
	s := r.spec("rfc8707", "Resource indicators (RFC 8707)", "https://www.rfc-editor.org/rfc/rfc8707")
	if r.Metadata == nil {
		s.untested("accepted", "resource parameter is understood", "", "no metadata document")
		return
	}
	if !r.hasCredentials() {
		s.untested("accepted", "resource parameter is understood", "§2", "needs credentials")
		return
	}
	if r.grantUnavailable != "" {
		s.untested("accepted", "resource parameter is understood", "§2", r.grantUnavailable)
		return
	}
	const probeResource = "https://oauthcli.invalid/resource-that-does-not-exist"
	request := oauth.TokenRequest{
		Endpoint:    r.Metadata.String("token_endpoint"),
		Grant:       oauth.GrantClientCredentials,
		Credentials: r.Options.Credentials,
		Advertised:  r.Metadata.TokenAuthMethods(),
		Scopes:      r.Options.Scopes,
		Resources:   []string{probeResource},
	}
	result, err := r.Client.Token(ctx, request)
	switch oauthErr, ok := oauthErrorOf(err); {
	case err == nil:
		// RFC 8707 §2.2 leaves acceptable resources to server policy, so a
		// token for an unknown resource is compliant when it is audience
		// restricted to it; only a token that ignores the value shows the
		// parameter is not implemented.
		_, jws := oauth.Inspect(ctx, result.AccessToken, oauth.InspectOptions{})
		switch {
		case jws != nil && contains(jws.Strings("aud"), probeResource):
			s.supportedIf(true, "")
			s.pass("accepted", "resource parameter is understood", "§2", "a token audience-restricted to the requested resource was issued")
		case jws != nil:
			s.supportedIf(false, "the resource parameter is ignored")
			s.skip("accepted", "resource parameter is understood", "§2", fmt.Sprintf("a token was issued for an unknown resource with aud %v; the parameter is ignored", jws.Strings("aud")))
		default:
			s.untested("accepted", "resource parameter is understood", "§2", "a token was issued for an unknown resource, but it is opaque so the audience cannot be inspected")
		}
	case ok && oauthErr.Code == "invalid_target":
		s.supportedIf(true, "")
		s.pass("accepted", "resource parameter is understood", "§2, §2.1", "an unknown resource is rejected with invalid_target")
	case ok:
		s.supportedIf(true, "")
		s.warn("accepted", "resource parameter is understood", "§2, §2.1", "an unknown resource was rejected with "+oauthErr.Code+" instead of invalid_target")
	default:
		s.untested("accepted", "resource parameter is understood", "§2", describeErr(err))
		return
	}

	// RFC 8707 §2: a resource value must not carry a fragment, and a
	// malformed value is invalid_target.
	request.Resources = []string{"https://oauthcli.invalid/resource#fragment"}
	_, err = r.Client.Token(ctx, request)
	switch oauthErr, ok := oauthErrorOf(err); {
	case err == nil:
		s.warn("malformed", "resource value with a fragment is rejected", "§2", "a token was issued for a resource value carrying a fragment")
	case ok && oauthErr.Code == "invalid_target":
		s.pass("malformed", "resource value with a fragment is rejected", "§2", "invalid_target")
	case ok:
		s.warn("malformed", "resource value with a fragment is rejected", "§2", "rejected with "+oauthErr.Code+" instead of invalid_target")
	}

	if len(r.Options.Resources) > 0 && r.Obtained != nil {
		_, jws := oauth.Inspect(ctx, r.Obtained.AccessToken, oauth.InspectOptions{})
		if jws != nil {
			audiences := jws.Strings("aud")
			ok := false
			for _, resource := range r.Options.Resources {
				if contains(audiences, resource) {
					ok = true
				}
			}
			s.requirement(ok, Warn, "audience", "requested resource appears in aud", "§2", strings.Join(audiences, ", "), fmt.Sprintf("aud is %v; the requested resource is not in it (a server may map the value to another identifier)", audiences))
		}
	}
}

func (r *Runner) checkJWTClientAuth(ctx context.Context) {
	s := r.spec("rfc7523", "JWT client authentication and authorization grant (RFC 7523)", "https://www.rfc-editor.org/rfc/rfc7523")
	if r.Metadata == nil {
		s.untested("advertised", "private_key_jwt or client_secret_jwt is advertised", "", "no metadata document")
		return
	}
	methods := r.Metadata.TokenAuthMethods()
	auth := contains(methods, oauth.AuthPrivateKeyJWT) || contains(methods, oauth.AuthSecretJWT)
	bearer := contains(r.Metadata.GrantTypes(), oauth.GrantJWTBearer)
	s.supportedIf(auth || bearer, "neither JWT client authentication nor the jwt-bearer grant is advertised")
	if !auth && !bearer {
		return
	}
	s.requirement(auth, Skip, "advertised", "private_key_jwt or client_secret_jwt is advertised", "§2.2", strings.Join(methods, ", "), "not advertised")
	s.requirement(bearer, Skip, "bearer-grant", "jwt-bearer grant is advertised", "§2.1", "", "not advertised")
	if algs := r.Metadata.Strings("token_endpoint_auth_signing_alg_values_supported"); len(algs) > 0 {
		s.requirement(!contains(algs, "none"), Fail, "alg-none", "assertion algorithms exclude none", "RFC 8414 §2", strings.Join(algs, ", "), "none is advertised")
	}
	if !r.hasCredentials() || r.Options.Credentials.Key == nil {
		s.untested("assertion", "client authenticates with a signed assertion", "§2.2", "pass --client-key to authenticate with private_key_jwt")
		return
	}
	credentials := *r.Options.Credentials
	credentials.Method = oauth.AuthPrivateKeyJWT
	result, err := r.Client.Token(ctx, oauth.TokenRequest{
		Endpoint:    r.Metadata.String("token_endpoint"),
		Grant:       oauth.GrantClientCredentials,
		Credentials: &credentials,
		Scopes:      r.Options.Scopes,
	})
	if err != nil {
		if oauthErr, ok := oauthErrorOf(err); ok && oauthErr.Code == "invalid_client" {
			s.warn("assertion", "client authenticates with a signed assertion", "§2.2, §3.2", "the assertion was refused with invalid_client; the key may not be registered for this client")
		} else {
			s.fail("assertion", "client authenticates with a signed assertion", "§2.2", describeErr(err))
		}
		return
	}
	s.pass("assertion", "client authenticates with a signed assertion", "§2.2", "token_type="+result.TokenType)

	if r.Options.Negative {
		// RFC 7523 §3 items 3, 4 and 9, §3.2: an assertion with the wrong
		// audience, an expired assertion, and a bad signature must each be
		// refused with invalid_client.
		for _, probe := range []struct {
			id, title string
			mutate    func(c *oauth.Credentials)
		}{
			{"rejects-wrong-aud", "assertion with a wrong audience is rejected with invalid_client", func(c *oauth.Credentials) { c.AssertionAudience = "https://oauthcli.invalid/not-the-server" }},
			{"rejects-expired", "expired assertion is rejected with invalid_client", func(c *oauth.Credentials) { c.AssertionLifetime = -oauth.AssertionDefaultLifetime }},
		} {
			bad := credentials
			probe.mutate(&bad)
			_, err := r.Client.Token(ctx, oauth.TokenRequest{Endpoint: r.Metadata.String("token_endpoint"), Grant: oauth.GrantClientCredentials, Credentials: &bad, Scopes: r.Options.Scopes})
			switch oauthErr, ok := oauthErrorOf(err); {
			case err == nil:
				s.fail(probe.id, probe.title, "§3, §3.2", "a token was issued")
			case ok && oauthErr.Code == "invalid_client":
				s.pass(probe.id, probe.title, "§3, §3.2", "invalid_client")
			case ok:
				s.warn(probe.id, probe.title, "§3.2", "rejected with "+oauthErr.Code+" instead of invalid_client")
			default:
				s.untested(probe.id, probe.title, "§3", describeErr(err))
			}
		}
	}
}

func (r *Runner) checkTokenExchange(ctx context.Context) {
	s := r.spec("rfc8693", "Token exchange (RFC 8693)", "https://www.rfc-editor.org/rfc/rfc8693")
	if r.Metadata == nil {
		s.untested("advertised", "token-exchange grant is advertised", "", "no metadata document")
		return
	}
	advertised := contains(r.Metadata.GrantTypes(), oauth.GrantTokenExchange)
	s.supportedIf(advertised, "the token-exchange grant is not advertised")
	if !advertised {
		return
	}
	s.pass("advertised", "token-exchange grant is advertised", "§2.1", oauth.GrantTokenExchange)
	if !r.hasCredentials() || r.Obtained == nil {
		detail := "needs credentials"
		if r.grantUnavailable != "" {
			detail = r.grantUnavailable + ", so there is no subject token to exchange"
		}
		s.untested("exchange", "exchanging an access token is accepted or refused with an OAuth error", "§2.2", detail)
		return
	}
	exchange := func(subject string) (*oauth.TokenResult, error) {
		return r.Client.Token(ctx, oauth.TokenRequest{
			Endpoint:    r.Metadata.String("token_endpoint"),
			Grant:       oauth.GrantTokenExchange,
			Credentials: r.Options.Credentials,
			Advertised:  r.Metadata.TokenAuthMethods(),
			Params: url.Values{
				"subject_token":      {subject},
				"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			},
		})
	}
	result, err := exchange(r.Obtained.AccessToken)
	switch oauthErr, ok := oauthErrorOf(err); {
	case err == nil:
		issued, _ := result.Raw["issued_token_type"].(string)
		s.pass("exchange", "exchanging an access token is accepted or refused with an OAuth error", "§2.2", "exchanged; issued_token_type="+issued)
		s.requirement(issued != "", Fail, "issued-token-type", "response carries issued_token_type", "§2.2.1", issued, "missing (REQUIRED)")
		s.fromIssues(result.Issues, "access-token-missing", "access-token", "response carries access_token", "§2.2.1", "")
		s.fromIssues(result.Issues, "token-type-missing", "token-type", "response carries token_type", "§2.2.1", result.TokenType)
		s.fromIssues(result.Issues, "expires-in-missing", "expires-in", "response carries expires_in", "§2.2.1", fmt.Sprint(result.ExpiresIn))
	case ok && oauthErr.Code == "unsupported_grant_type":
		s.fail("exchange", "exchanging an access token is accepted or refused with an OAuth error", "§2.2", "the grant is advertised but the token endpoint answers unsupported_grant_type")
	case ok && (oauthErr.Code == "invalid_request" || oauthErr.Code == "invalid_target"):
		s.pass("exchange", "exchanging an access token is accepted or refused with an OAuth error", "§2.2.2", "refused with "+oauthErr.Code+", which §2.2.2 defines for this")
	case ok:
		s.warn("exchange", "exchanging an access token is accepted or refused with an OAuth error", "§2.2.2", "refused with "+oauthErr.Code+"; §2.2.2 names invalid_request and invalid_target, though other codes may be used")
	default:
		s.untested("exchange", "exchanging an access token is accepted or refused with an OAuth error", "§2.2", describeErr(err))
		return
	}

	// RFC 8693 §2.2.2: an unusable subject token must produce invalid_request.
	_, err = exchange("oauthcli-not-a-token-" + oauth.NewState())
	switch oauthErr, ok := oauthErrorOf(err); {
	case err == nil:
		s.fail("invalid-subject", "an unusable subject token is refused with invalid_request", "§2.2.2", "a token was issued for a garbage subject token")
	case ok && oauthErr.Code == "invalid_request":
		s.pass("invalid-subject", "an unusable subject token is refused with invalid_request", "§2.2.2", "invalid_request")
	case ok:
		s.warn("invalid-subject", "an unusable subject token is refused with invalid_request", "§2.2.2", "refused with "+oauthErr.Code+" instead of invalid_request")
	default:
		s.untested("invalid-subject", "an unusable subject token is refused with invalid_request", "§2.2.2", describeErr(err))
	}
}

func (r *Runner) checkRegistration(ctx context.Context) {
	s := r.spec("rfc7591", "Dynamic client registration (RFC 7591, RFC 7592)", "https://www.rfc-editor.org/rfc/rfc7591")
	if r.Metadata == nil {
		s.untested("advertised", "registration_endpoint is advertised", "", "no metadata document")
		return
	}
	endpoint := r.Metadata.String("registration_endpoint")
	s.supportedIf(endpoint != "", "no registration_endpoint advertised")
	if endpoint == "" {
		return
	}
	s.pass("advertised", "registration_endpoint is advertised", "RFC 8414 §2", endpoint)

	if !r.Options.Register {
		s.skip("register", "registering a client returns 201 with client_id", "§3.2.1", "pass --register to create and delete a throwaway client")
		return
	}

	// An invalid document should produce an RFC 7591 §3.2.2 error, but a
	// server may substitute a valid value and register the client anyway; if
	// it does, the client is removed again.
	response, err := r.Client.PostJSON(ctx, "POST", endpoint, map[string]any{"redirect_uris": "not-an-array"}, authHeader(r.Options.InitialToken))
	if err == nil {
		oauthErr := oauth.ParseError(response)
		switch {
		case response.Status == 400:
			s.pass("error-shape", "invalid registration is rejected with 400", "§3.2.2", oauthErr.Code)
			s.requirement(contains([]string{"invalid_client_metadata", "invalid_redirect_uri", "invalid_software_statement", "unapproved_software_statement"}, oauthErr.Code), Warn, "error-code", "registration error uses a registered code", "§3.2.2", oauthErr.Code, fmt.Sprintf("error code %q is not one §3.2.2 defines", oauthErr.Code))
		case response.Status == 401 || response.Status == 403:
			s.pass("error-shape", "invalid registration is rejected with 400", "§3, §3.2.2", fmt.Sprintf("HTTP %d: registration needs an initial access token", response.Status))
		case response.Status == 201:
			s.warn("error-shape", "invalid registration is rejected with 400", "§3.2.1, §3.2.2", "the server registered a client from a malformed document, which §3.2.1 permits by substitution")
			if created, err := oauth.ParseTokenlessRegistration(response); err == nil && created.RegistrationClientURI != "" {
				_, _ = r.Client.DeleteClient(ctx, created.RegistrationClientURI, created.RegistrationAccessToken)
			}
		default:
			s.fail("error-shape", "invalid registration is rejected with 400", "§3.2.2", fmt.Sprintf("HTTP %d", response.Status))
		}
		if response.Status == 401 || response.Status == 403 {
			s.skip("protected", "open registration is allowed", "§3", fmt.Sprintf("HTTP %d: the endpoint requires an initial access token, which §3 permits (MAY)", response.Status))
		} else {
			s.pass("protected", "open registration is allowed", "§3", "registration requests without authorization are accepted, as §3 recommends (SHOULD)")
		}
	}

	registration, err := r.Client.Register(ctx, endpoint, map[string]any{
		"client_name":                "oauthcli conformance probe",
		"redirect_uris":              []string{"http://127.0.0.1/oauthcli-callback"},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}, r.Options.InitialToken)
	if err != nil {
		if oauthErr, ok := oauthErrorOf(err); ok && (oauthErr.Status == 401 || oauthErr.Status == 403) && r.Options.InitialToken == "" {
			s.untested("register", "registering a client returns 201 with client_id", "§3.2.1", "the endpoint requires an initial access token; pass --initial-token")
			return
		}
		s.fail("register", "registering a client returns 201 with client_id", "§3.2.1", describeErr(err))
		return
	}
	s.pass("register", "registering a client returns 201 with client_id", "§3.2.1", "client_id="+registration.ClientID)
	s.fromIssues(registration.Issues, "client-id-missing", "client-id", "registration response carries client_id", "§3.2.1", registration.ClientID)
	s.fromIssues(registration.Issues, "content-type", "json", "registration response is application/json", "§3.2", "")
	s.fromIssues(registration.Issues, "registration-status", "status", "registration answers 201 Created", "§3.2.1", "HTTP 201")
	s.fromIssues(registration.Issues, "secret-expiry-missing", "secret-expiry", "client_secret_expires_at accompanies a secret", "§3.2.1", "")
	s.fromIssues(registration.Issues, "management-pair", "management-pair", "registration_client_uri and registration_access_token come together", "RFC 7592 §3", "")
	dropped := 0
	for _, issue := range registration.Issues {
		if issue.Code == "metadata-dropped" {
			dropped++
		}
	}
	s.requirement(dropped == 0, Warn, "echo", "every registered value is echoed back", "§3.2.1", "", fmt.Sprintf("%d requested members are missing from the response", dropped))

	if registration.RegistrationClientURI == "" {
		s.skip("read", "client configuration can be read (RFC 7592)", "RFC 7592 §2.1", "no registration_client_uri returned, so the probe client "+registration.ClientID+" cannot be deleted and stays registered")
		return
	}
	s.fromIssues(registration.Issues, "management-uri-not-https", "management-https", "registration_client_uri uses https", "RFC 7592 §2", registration.RegistrationClientURI)
	read, err := r.Client.ReadClient(ctx, registration.RegistrationClientURI, registration.RegistrationAccessToken)
	if err != nil {
		s.fail("read", "client configuration can be read (RFC 7592)", "RFC 7592 §2.1", describeErr(err))
	} else {
		s.requirement(read.ClientID == registration.ClientID, Fail, "read", "client configuration can be read (RFC 7592)", "RFC 7592 §2.1", "client_id matches", "client_id differs between registration and read")
		s.fromIssues(read.Issues, "content-type", "read-json", "client configuration is returned as application/json", "RFC 7592 §2.1", "")
	}
	badToken, err := r.Client.ReadClient(ctx, registration.RegistrationClientURI, "oauthcli-wrong-"+oauth.NewState())
	if oauthErr, ok := oauthErrorOf(err); err == nil {
		s.fail("read-auth", "a wrong registration access token is refused", "RFC 7592 §2.1", "the configuration was returned for a wrong token")
	} else if ok {
		challenge := ""
		if oauthErr.Header != nil {
			challenge = oauthErr.Header.Get("WWW-Authenticate")
		}
		s.requirement(oauthErr.Status == 401 && strings.HasPrefix(strings.ToLower(challenge), "bearer"), Warn, "read-auth", "a wrong registration access token is refused with 401 and a Bearer challenge", "RFC 7592 §2.1, RFC 6750 §3", fmt.Sprintf("HTTP %d", oauthErr.Status), fmt.Sprintf("HTTP %d with WWW-Authenticate %q; RFC 6750 asks for 401 and a Bearer challenge", oauthErr.Status, challenge))
	}
	_ = badToken
	status, err := r.Client.DeleteClient(ctx, registration.RegistrationClientURI, registration.RegistrationAccessToken)
	switch {
	case err != nil:
		s.fail("delete", "client can be deprovisioned (RFC 7592)", "RFC 7592 §2.3", describeErr(err)+"; the probe client "+registration.ClientID+" was left behind")
		return
	case status == 204:
		s.pass("delete", "client can be deprovisioned (RFC 7592)", "RFC 7592 §2.3", "HTTP 204; the probe client was deleted")
	default:
		s.warn("delete", "client can be deprovisioned (RFC 7592)", "RFC 7592 §2.3", fmt.Sprintf("HTTP %d; a successful deprovisioning must answer 204", status))
	}
	if _, err := r.Client.ReadClient(ctx, registration.RegistrationClientURI, registration.RegistrationAccessToken); err == nil {
		s.fail("delete-effective", "a deleted client can no longer be read", "RFC 7592 §2.1, §2.3", "the configuration is still readable after deletion")
	} else if oauthErr, ok := oauthErrorOf(err); ok {
		s.requirement(oauthErr.Status == 401, Warn, "delete-effective", "a deleted client can no longer be read", "RFC 7592 §2.1", "HTTP 401", fmt.Sprintf("HTTP %d; §2.1 says a client that does not exist answers 401", oauthErr.Status))
	}
}

func authHeader(token string) map[string][]string {
	if token == "" {
		return nil
	}
	return map[string][]string{"Authorization": {"Bearer " + token}}
}

func (r *Runner) checkProtectedResource(ctx context.Context) {
	s := r.spec("rfc9728", "Protected resource metadata (RFC 9728)", "https://www.rfc-editor.org/rfc/rfc9728")
	resources := r.Options.ResourceURLs
	if len(resources) == 0 {
		metadata, err := r.Client.FetchResourceMetadata(ctx, r.Options.Issuer)
		if err != nil {
			s.supportedIf(false, "the issuer publishes no protected resource metadata and no --resource-url was given")
			return
		}
		s.supportedIf(true, "")
		r.gradeResource(s, metadata)
		return
	}
	s.supportedIf(true, "")
	for _, resource := range resources {
		metadata, err := r.Client.FetchResourceMetadata(ctx, resource)
		if err != nil {
			s.fail("found", "resource publishes metadata: "+resource, "§3", describeErr(err))
			continue
		}
		r.gradeResource(s, metadata)
	}
}

func (r *Runner) gradeResource(s *Spec, metadata *oauth.ResourceMetadata) {
	issues := metadata.Validate(r.Options.AllowHTTP)
	s.fromIssues(issues, "location-appended", "found", "resource publishes metadata at the inserted well-known location: "+metadata.Resource, "§3, §3.1", metadata.URL)
	s.fromIssues(issues, "content-type", "content-type", "metadata is application/json", "§3.2", "")
	s.fromIssues(issues, "resource-missing", "resource", "resource member is present", "§2", metadata.String("resource"))
	if !s.fromIssuesAny(issues, []string{"resource-mismatch", "resource-trailing-slash"}, "resource-match", "resource is identical to the URL it was fetched for", "§3.3") {
		s.pass("resource-match", "resource is identical to the URL it was fetched for", "§3.3", "")
	}
	s.fromIssues(issues, "resource-not-https", "resource-https", "resource identifier uses https", "§1.2", "")
	s.fromIssues(issues, "resource-has-fragment", "resource-no-fragment", "resource identifier has no fragment", "§1.2", "")
	s.fromIssues(issues, "resource-has-query", "resource-no-query", "resource identifier has no query component", "§1.2", "")
	s.fromIssues(issues, "authorization-server-invalid", "authorization-servers-valid", "authorization servers are https issuer identifiers", "RFC 8414 §2", strings.Join(metadata.Strings("authorization_servers"), ", "))
	s.fromIssues(issues, "empty-array", "no-empty-arrays", "parameters with zero values are omitted", "§3.2", "")
	s.fromIssues(issues, "jwks-not-https", "jwks-https", "jwks_uri uses https", "§2", "")
	s.fromIssues(issues, "signing-alg-none", "signing-alg-none", "resource_signing_alg_values_supported excludes none", "§2", "")
	s.fromIssues(issues, "scopes-missing", "scopes", "scopes_supported is advertised", "§2", strings.Join(metadata.Strings("scopes_supported"), " "))
	s.fromIssues(issues, "resource-name-missing", "resource-name", "resource_name is advertised", "§2", metadata.String("resource_name"))
	s.fromIssues(issues, "bearer-query", "no-bearer-query", "tokens are not accepted in the query string", "OAuth 2.1 §5.1", "")
	servers := metadata.Strings("authorization_servers")
	switch {
	case !metadata.Has("authorization_servers"):
		s.skip("lists-issuer", "resource lists the audited issuer as an authorization server", "§2", "authorization_servers is absent (optional)")
	case contains(servers, r.Options.Issuer) || contains(servers, r.Options.Issuer+"/"):
		s.pass("lists-issuer", "resource lists the audited issuer as an authorization server", "§2", strings.Join(servers, ", "))
	default:
		s.skip("lists-issuer", "resource lists the audited issuer as an authorization server", "§2", "the audited issuer is not listed; a resource may omit servers it supports")
	}
}

func (r *Runner) checkIssuerParameter(ctx context.Context) {
	s := r.spec("rfc9207", "Issuer identification in authorization responses (RFC 9207)", "https://www.rfc-editor.org/rfc/rfc9207")
	if r.Metadata == nil {
		s.untested("advertised", "authorization_response_iss_parameter_supported is true", "", "no metadata document")
		return
	}
	value, ok := r.Metadata.Bool("authorization_response_iss_parameter_supported")
	s.supportedIf(ok && value, "authorization_response_iss_parameter_supported is not advertised as true")
	if !(ok && value) {
		return
	}
	s.pass("advertised", "authorization_response_iss_parameter_supported is true", "§3", "mix-up attacks are mitigated for clients that check iss")

	// RFC 9207 §2: every authorization response, errors included, must carry
	// iss equal to the issuer. An error redirect to the registered redirect
	// URI shows it without a login.
	if r.clientID() == "" || r.Options.RedirectURI == "" || r.Metadata.String("authorization_endpoint") == "" {
		s.untested("iss-in-error", "error responses carry iss equal to the issuer", "§2, §2.3", "needs --client-id and a registered --redirect-uri")
		return
	}
	probe := r.probeAuthorize(ctx, url.Values{
		"response_type": {"oauthcli-invalid"},
		"client_id":     {r.clientID()},
		"redirect_uri":  {r.Options.RedirectURI},
		"state":         {oauth.NewState()},
	}, r.Options.RedirectURI, nil)
	switch {
	case probe.Err != nil || !probe.ToClient || probe.Error == "":
		s.untested("iss-in-error", "error responses carry iss equal to the issuer", "§2, §2.3", "the server did not redirect an error to the redirect URI: "+probe.summary())
	default:
		iss := probe.Location.Query().Get("iss")
		s.requirement(iss == r.Metadata.String("issuer"), Fail, "iss-in-error", "error responses carry iss equal to the issuer", "§2, §2.3", "iss="+iss, fmt.Sprintf("iss is %q, want %q", iss, r.Metadata.String("issuer")))
	}
}

func (r *Runner) checkMTLS(ctx context.Context) {
	supported, detail := false, ""
	if r.Metadata != nil {
		bound, _ := r.Metadata.Bool("tls_client_certificate_bound_access_tokens")
		methods := r.Metadata.TokenAuthMethods()
		supported = bound || contains(methods, "tls_client_auth") || contains(methods, "self_signed_tls_client_auth") || r.Metadata.Has("mtls_endpoint_aliases")
		detail = fmt.Sprintf("certificate-bound tokens: %t; methods: %s", bound, strings.Join(methods, ", "))
	}
	r.advertisedOnly("rfc8705", "Mutual TLS client authentication (RFC 8705)", "https://www.rfc-editor.org/rfc/rfc8705", supported, detail)
}

func (r *Runner) checkJAR(ctx context.Context) {
	supported, detail := false, ""
	if r.Metadata != nil {
		request, _ := r.Metadata.Bool("request_parameter_supported")
		requestURI, _ := r.Metadata.Bool("request_uri_parameter_supported")
		supported = request || requestURI
		detail = fmt.Sprintf("request: %t, request_uri: %t, algorithms: %s", request, requestURI, strings.Join(r.Metadata.Strings("request_object_signing_alg_values_supported"), ", "))
	}
	r.advertisedOnly("rfc9101", "JWT-secured authorization requests (RFC 9101)", "https://www.rfc-editor.org/rfc/rfc9101", supported, detail)
}

func (r *Runner) checkRAR(ctx context.Context) {
	supported, detail := false, ""
	if r.Metadata != nil {
		types := r.Metadata.Strings("authorization_details_types_supported")
		supported = len(types) > 0
		detail = strings.Join(types, ", ")
	}
	r.advertisedOnly("rfc9396", "Rich authorization requests (RFC 9396)", "https://www.rfc-editor.org/rfc/rfc9396", supported, detail)
}

func (r *Runner) checkCIMD(ctx context.Context) {
	supported := false
	if r.Metadata != nil {
		supported, _ = r.Metadata.Bool("client_id_metadata_document_supported")
	}
	r.advertisedOnly("cimd", "Client ID metadata documents (draft-ietf-oauth-client-id-metadata-document)", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document", supported, "client_id_metadata_document_supported: true")
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
