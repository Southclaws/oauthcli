package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/config"
	"github.com/Southclaws/oauthcli/internal/jose"
	"github.com/Southclaws/oauthcli/internal/oauth"
	"github.com/Southclaws/oauthcli/internal/render"
)

// tokenGet obtains a token with a non-interactive grant.
func tokenGet(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.TokenGetParams) (cligen.TokenResponse, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	issuer, err := s.issuer("")
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	metadata, err := s.metadataFor(ctx, issuer)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	credentials, err := s.credentials()
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	extra, err := parseParams(p.Param)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	params := url.Values(extra)

	grant := string(p.Grant)
	switch grant {
	case "password":
		if p.Username == "" || p.Password == "" {
			return cligen.TokenResponse{}, errors.New("the password grant needs --username and --password")
		}
		params.Set("username", p.Username)
		params.Set("password", p.Password)
		s.Err.Warnf("the password grant is removed by OAuth 2.1; use it only against legacy servers")
	case "refresh_token":
		token := p.RefreshToken
		if token == "" {
			saved, err := s.savedToken()
			if err != nil || saved.RefreshToken == "" {
				return cligen.TokenResponse{}, fmt.Errorf("%w: the refresh_token grant needs --refresh-token or a saved token with one", ErrNotFound)
			}
			token = saved.RefreshToken
		}
		params.Set("refresh_token", token)
	case "jwt-bearer":
		if p.Assertion == "" {
			return cligen.TokenResponse{}, errors.New("the jwt-bearer grant needs --assertion")
		}
		grant = oauth.GrantJWTBearer
		params.Set("assertion", p.Assertion)
	case "token-exchange":
		if p.SubjectToken == "" {
			return cligen.TokenResponse{}, errors.New("the token-exchange grant needs --subject-token")
		}
		grant = oauth.GrantTokenExchange
		params.Set("subject_token", p.SubjectToken)
		params.Set("subject_token_type", p.SubjectTokenType)
		if p.ActorToken != "" {
			params.Set("actor_token", p.ActorToken)
			params.Set("actor_token_type", p.ActorTokenType)
		}
		if p.RequestedTokenType != "" {
			params.Set("requested_token_type", p.RequestedTokenType)
		}
	}
	if !containsString(metadata.GrantTypes(), grant) && s.Verbose >= 0 {
		s.Err.Warnf("grant %s is not in grant_types_supported (%s); trying anyway", grant, strings.Join(metadata.GrantTypes(), ", "))
	}

	dpop, err := s.dpop()
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	result, err := s.Client.Token(ctx, oauth.TokenRequest{
		Endpoint:    metadata.String("token_endpoint"),
		Grant:       grant,
		Credentials: credentials,
		Advertised:  metadata.TokenAuthMethods(),
		Scopes:      s.Settings.Scopes,
		Audience:    s.Settings.Audience,
		Resources:   s.Settings.Resources,
		Params:      params,
		DPoP:        dpop,
	})
	if err != nil {
		return cligen.TokenResponse{}, oauthError(err)
	}
	return s.finishToken(ctx, result, issuer, metadata, dpop, p.Save, p.NoVerify, string(p.Format), "")
}

// tokenRefresh refreshes a token.
func tokenRefresh(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.TokenRefreshParams) (cligen.TokenResponse, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	refreshToken := p.RefreshToken
	var saved *config.Token
	if refreshToken == "-" {
		refreshToken, err = readAllTrim(s.in)
		if err != nil {
			return cligen.TokenResponse{}, err
		}
	}
	if refreshToken == "" {
		saved, err = s.savedToken()
		if err != nil {
			return cligen.TokenResponse{}, fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		if saved.RefreshToken == "" {
			return cligen.TokenResponse{}, fmt.Errorf("%w: the saved token has no refresh token", ErrNotFound)
		}
		refreshToken = saved.RefreshToken
		if s.Settings.Issuer == "" {
			s.Settings.Issuer = saved.Issuer
		}
		if s.Settings.Client.ID == "" {
			s.Settings.Client.ID = saved.ClientID
		}
	}
	issuer, err := s.issuer("")
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	metadata, err := s.metadataFor(ctx, issuer)
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	credentials, err := s.credentials()
	if err != nil {
		return cligen.TokenResponse{}, err
	}
	var dpop *oauth.DPoP
	if saved != nil && len(saved.DPoPKey) > 0 {
		dpop, err = oauth.DPoPFromJWK(saved.DPoPKey)
		if err != nil {
			return cligen.TokenResponse{}, err
		}
	} else if dpop, err = s.dpop(); err != nil {
		return cligen.TokenResponse{}, err
	}

	result, err := s.Client.Token(ctx, oauth.TokenRequest{
		Endpoint:    metadata.String("token_endpoint"),
		Grant:       oauth.GrantRefreshToken,
		Credentials: credentials,
		Advertised:  metadata.TokenAuthMethods(),
		Scopes:      s.Settings.Scopes,
		Params:      url.Values{"refresh_token": {refreshToken}},
		DPoP:        dpop,
	})
	if err != nil {
		return cligen.TokenResponse{}, oauthError(err)
	}
	if result.RefreshToken == "" {
		result.Issues = append(result.Issues, oauth.Infof("refresh-not-rotated", "OAuth 2.1 §4.3.1", "refresh_token", "no new refresh token was issued; the old one stays valid"))
	} else if result.RefreshToken == refreshToken {
		result.Issues = append(result.Issues, oauth.Warnf("refresh-same", "OAuth 2.1 §4.3.1", "refresh_token", "the same refresh token was returned; rotation is not in effect"))
	} else {
		result.Issues = append(result.Issues, oauth.Infof("refresh-rotated", "OAuth 2.1 §4.3.1", "refresh_token", "the refresh token was rotated"))
	}
	return s.finishToken(ctx, result, issuer, metadata, dpop, p.Save, p.NoVerify, string(p.Format), "")
}

// finishToken decodes, verifies, saves and renders a token response.
func (s *session) finishToken(ctx context.Context, result *oauth.TokenResult, issuer string, metadata *oauth.Metadata, dpop *oauth.DPoP, save, noVerify bool, format, nonce string) (cligen.TokenResponse, error) {
	response := cligen.TokenResponse{
		TokenType:   result.TokenType,
		AccessToken: result.AccessToken,
		Raw:         cligen.Document(result.Raw),
		Issues:      result.Issues,
	}
	if result.ExpiresIn > 0 {
		response.ExpiresIn = &result.ExpiresIn
		response.ExpiresAt = &result.ExpiresAt
	}
	if result.RefreshToken != "" {
		response.RefreshToken = &result.RefreshToken
	}
	if result.IDToken != "" {
		response.IDToken = &result.IDToken
	}
	if result.Scope != "" {
		response.Scope = &result.Scope
	}
	if dpop != nil {
		if thumbprint, err := dpop.Thumbprint(); err == nil {
			response.DpopThumbprint = &thumbprint
		}
	}

	var verifier *oauth.Verifier
	if !noVerify {
		verifier = s.Client.NewVerifier(issuer)
		if metadata != nil {
			verifier.KeysURL = metadata.String("jwks_uri")
		}
	}
	access, jws := oauth.Inspect(ctx, result.AccessToken, oauth.InspectOptions{Verifier: verifier, AccessToken: true})
	if jws != nil {
		response.AccessTokenInfo = &access
	}
	if result.IDToken != "" {
		id, _ := oauth.Inspect(ctx, result.IDToken, oauth.InspectOptions{
			Verifier:         verifier,
			IDToken:          true,
			ExpectedIssuer:   issuer,
			ExpectedAudience: s.Settings.Client.ID,
			Nonce:            nonce,
		})
		response.IDTokenInfo = &id
		if jws != nil && id.Claims != nil {
			if claims, ok := (*id.Claims).(map[string]any); ok {
				if atHash, ok := claims["at_hash"].(string); ok {
					if alg, ok := (*id.Header).(map[string]any)["alg"].(string); ok {
						want, err := jose.HalfHash(result.AccessToken, alg)
						if err == nil && want != atHash {
							response.Issues = append(response.Issues, oauth.Errorf("at-hash-mismatch", "OpenID Connect Core 1.0 §3.3.2.11", "at_hash", "at_hash does not match the access token"))
						}
					}
				}
			}
		}
	}

	if save {
		if err := s.saveToken(result, issuer, dpop); err != nil {
			return response, err
		}
		response.Saved = oauth.Ptr(true)
	}

	var verdict error
	if response.IDTokenInfo != nil && oauth.HasErrors(response.IDTokenInfo.Issues) {
		verdict = fmt.Errorf("%w: the ID token failed validation", ErrInvalidToken)
	}
	if machineReadable(format) {
		return response, s.fail(format, response, verdict)
	}
	if format == "plain" {
		fmt.Fprintln(s.Out.Raw(), result.AccessToken)
		return response, verdict
	}
	s.renderTokenResponse(response)
	return response, verdict
}

func (s *session) renderTokenResponse(response cligen.TokenResponse) {
	out := s.Out
	subtitle := response.TokenType
	if response.ExpiresIn != nil {
		subtitle += fmt.Sprintf(" · expires in %s", render.Duration(time.Duration(*response.ExpiresIn)*time.Second))
	}
	if response.Saved != nil && *response.Saved {
		subtitle += " · saved"
	}
	out.Title("Token response", subtitle)

	fields := []render.Field{}
	if response.Scope != nil {
		fields = append(fields, render.F("Scope", *response.Scope))
	}
	if response.ExpiresAt != nil {
		fields = append(fields, render.F("Expires", response.ExpiresAt.Local().Format(time.RFC3339)))
	}
	if response.DpopThumbprint != nil {
		fields = append(fields, render.F("DPoP jkt", *response.DpopThumbprint))
	}
	fields = append(fields, render.FS("Access token", response.AccessToken, out.T.Styles.Code))
	if response.RefreshToken != nil {
		fields = append(fields, render.FS("Refresh token", *response.RefreshToken, out.T.Styles.Code))
	}
	if response.IDToken != nil {
		fields = append(fields, render.FS("ID token", *response.IDToken, out.T.Styles.Code))
	}
	out.KV(fields)

	if response.AccessTokenInfo != nil {
		out.Section("Access token")
		s.renderTokenInfo(*response.AccessTokenInfo)
	}
	if response.IDTokenInfo != nil {
		out.Section("ID token")
		s.renderTokenInfo(*response.IDTokenInfo)
	}
	if len(response.Issues) > 0 {
		out.Section("Findings  " + out.T.Styles.Faint.Render(issueSummary(response.Issues)))
		s.printIssues(out, response.Issues)
	}
}

// renderTokenInfo prints a decoded token: signature, timing, then claims.
func (s *session) renderTokenInfo(info cligen.TokenInfo) {
	out := s.Out
	if info.Kind == "opaque" {
		out.Notef("the token is opaque (not a JWT); use `oauthcli token introspect` to ask the server about it")
		return
	}
	fields := []render.Field{}
	if info.Signature != nil {
		text := info.Signature.Status
		if info.Signature.Alg != nil {
			text = fmt.Sprintf("%s (%s", text, *info.Signature.Alg)
			if info.Signature.Kid != nil {
				text += ", kid " + *info.Signature.Kid
			}
			text += ")"
		}
		if info.Signature.KeySource != nil {
			text += " · " + *info.Signature.KeySource
		}
		if info.Signature.Error != nil {
			text += " · " + *info.Signature.Error
		}
		_, style := out.Status(info.Signature.Status)
		fields = append(fields, render.FS("Signature", text, style))
	}
	if info.Timing != nil {
		if info.Timing.IssuedAt != nil {
			fields = append(fields, render.F("Issued", fmt.Sprintf("%s (%s ago)", info.Timing.IssuedAt.Local().Format(time.RFC3339), render.Duration(time.Since(*info.Timing.IssuedAt)))))
		}
		if info.Timing.NotBefore != nil {
			fields = append(fields, render.F("Not before", info.Timing.NotBefore.Local().Format(time.RFC3339)))
		}
		if info.Timing.ExpiresAt != nil {
			style := out.T.Styles.Good
			label := "in " + deref(info.Timing.ExpiresIn, "")
			if info.Timing.Expired {
				style = out.T.Styles.Bad
				label = "expired " + strings.TrimPrefix(deref(info.Timing.ExpiresIn, ""), "-") + " ago"
			}
			fields = append(fields, render.FS("Expires", fmt.Sprintf("%s (%s)", info.Timing.ExpiresAt.Local().Format(time.RFC3339), label), style))
		}
		if info.Timing.Lifetime != nil {
			fields = append(fields, render.F("Lifetime", *info.Timing.Lifetime))
		}
	}
	out.KV(fields)

	if info.Header != nil {
		if header, ok := (*info.Header).(map[string]any); ok {
			out.Println(out.T.Styles.Faint.Render("header"))
			renderClaims(out, header)
		}
	}
	if info.Claims != nil {
		if claims, ok := (*info.Claims).(map[string]any); ok {
			out.Println(out.T.Styles.Faint.Render("claims"))
			renderClaims(out, claims)
		}
	}
	if len(info.Issues) > 0 {
		out.Println()
		s.printIssues(out, info.Issues)
	}
}

var timeClaims = map[string]bool{"exp": true, "iat": true, "nbf": true, "auth_time": true, "updated_at": true}

func renderClaims(out *render.Printer, claims map[string]any) {
	fields := make([]render.Field, 0, len(claims))
	for _, name := range oauth.SortedKeys(claims) {
		value := claims[name]
		text := formatClaim(value)
		if timeClaims[name] {
			if seconds, ok := numeric(value); ok {
				at := time.Unix(int64(seconds), 0)
				text = fmt.Sprintf("%s  %s", text, out.T.Styles.Faint.Render(at.Local().Format(time.RFC3339)))
			}
		}
		fields = append(fields, render.F(name, text))
	}
	out.KV(fields)
}

func formatClaim(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprint(v)
	case json.Number:
		return v.String()
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, formatClaim(item))
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		encoded, _ := json.Marshal(v)
		return string(encoded)
	case nil:
		return "null"
	default:
		return fmt.Sprint(v)
	}
}

func numeric(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}

// tokenInspect decodes a token and verifies it.
func tokenInspect(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.TokenInspectParams) (cligen.TokenInfo, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.TokenInfo{}, err
	}
	token, saved, err := s.token(p.Token)
	if err != nil {
		return cligen.TokenInfo{}, err
	}
	info, jws := inspectWithSession(ctx, s, token, saved, p.Secret, p.Keys, p.NoVerify, p.IdToken)

	format := string(p.Format)
	if machineReadable(format) {
		return info, s.fail(format, info, inspectVerdict(info))
	}
	out := s.Out
	if jws == nil {
		out.Title("Opaque token", fmt.Sprintf("%d characters", len(token)))
	} else {
		out.Title("JWT", fmt.Sprintf("%s · %s", jws.Alg(), deref(oauth.Ptr(jws.Typ()), "no typ")))
	}
	s.renderTokenInfo(info)
	return info, inspectVerdict(info)
}

// inspectVerdict is the exit-code error for a decoded token: invalid when the
// signature fails or the token is expired.
func inspectVerdict(info cligen.TokenInfo) error {
	if info.Signature != nil && info.Signature.Status == "invalid" {
		return fmt.Errorf("%w: signature verification failed", ErrInvalidToken)
	}
	if info.Timing != nil && info.Timing.Expired {
		return fmt.Errorf("%w: the token is expired", ErrInvalidToken)
	}
	return nil
}

// inspectWithSession decodes a token with the verifier the session can build:
// from --keys, from the iss claim, or from the configured issuer.
func inspectWithSession(ctx context.Context, s *session, token string, saved *config.Token, secret, keys string, noVerify, idToken bool) (cligen.TokenInfo, *jose.JWS) {
	var verifier *oauth.Verifier
	expectedIssuer := s.Settings.Issuer
	if saved != nil && expectedIssuer == "" {
		expectedIssuer = saved.Issuer
	}
	if !noVerify {
		issuer := expectedIssuer
		if parsed, err := jose.Parse(token); err == nil && parsed.String("iss") != "" && issuer == "" {
			issuer = parsed.String("iss")
		}
		if normalized, err := oauth.NormalizeIssuer(issuer); err == nil {
			issuer = normalized
		}
		verifier = s.Client.NewVerifier(issuer)
		verifier.KeysURL = keys
		if secret != "" {
			verifier.Secret = []byte(secret)
		}
	}
	opts := oauth.InspectOptions{Verifier: verifier, IDToken: idToken, AccessToken: !idToken}
	if normalized, err := oauth.NormalizeIssuer(expectedIssuer); err == nil {
		opts.ExpectedIssuer = normalized
	}
	if idToken {
		opts.ExpectedAudience = s.Settings.Client.ID
	}
	return oauth.Inspect(ctx, token, opts)
}

// tokenIntrospect asks the server about a token.
func tokenIntrospect(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.TokenIntrospectParams) (cligen.IntrospectionReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.IntrospectionReport{}, err
	}
	token, saved, err := s.token(p.Token)
	if err != nil {
		return cligen.IntrospectionReport{}, err
	}
	issuer, metadata, err := s.issuerForToken(ctx, saved)
	if err != nil {
		return cligen.IntrospectionReport{}, err
	}
	credentials, err := s.credentials()
	if err != nil {
		return cligen.IntrospectionReport{}, err
	}
	endpoint := metadata.String("introspection_endpoint")
	if endpoint == "" {
		return cligen.IntrospectionReport{}, fmt.Errorf("%w: %s advertises no introspection_endpoint", ErrNotFound, issuer)
	}
	response, raw, err := s.Client.Introspect(ctx, endpoint, token, string(p.Hint), credentials, metadata.Strings("introspection_endpoint_auth_methods_supported"))
	if err != nil {
		return cligen.IntrospectionReport{Endpoint: endpoint}, oauthError(err)
	}
	active, _ := response["active"].(bool)
	report := cligen.IntrospectionReport{Endpoint: endpoint, Active: active, Response: cligen.Document(response), Issues: []cligen.Issue{}}
	if _, ok := response["active"]; !ok {
		report.Issues = append(report.Issues, oauth.Errorf("active-missing", "RFC 7662 §2.2", "active", "the response has no active member"))
	}
	if !raw.IsJSON() {
		report.Issues = append(report.Issues, oauth.Errorf("content-type", "RFC 7662 §2.2", "", "Content-Type is %q, want application/json", raw.Header.Get("Content-Type")))
	}
	if jws, err := jose.Parse(token); err == nil && active {
		for _, claim := range []string{"sub", "client_id", "iss", "exp"} {
			if tokenValue, ok := jws.Claims[claim]; ok {
				if introspected, ok := response[claim]; ok && formatClaim(tokenValue) != formatClaim(introspected) {
					report.Issues = append(report.Issues, oauth.Warnf("claim-differs", "RFC 7662 §2.2", claim, "%s is %v in the token but %v in the introspection response", claim, formatClaim(tokenValue), formatClaim(introspected)))
				}
			}
		}
	}

	if machineReadable(string(p.Format)) {
		if !active {
			return report, s.fail(string(p.Format), report, fmt.Errorf("%w: the server reports the token inactive", ErrInvalidToken))
		}
		return report, nil
	}
	out := s.Out
	status := "active"
	if !active {
		status = "inactive"
	}
	out.Title("Introspection", endpoint)
	glyph, style := out.Status(map[bool]string{true: "pass", false: "fail"}[active])
	out.Printf("%s %s\n", style.Render(glyph), style.Render(status))
	out.Println()
	renderClaims(out, response)
	if len(report.Issues) > 0 {
		out.Println()
		s.printIssues(out, report.Issues)
	}
	if !active {
		return report, fmt.Errorf("%w: the server reports the token inactive", ErrInvalidToken)
	}
	return report, nil
}

// issuerForToken resolves the issuer for a token operation: the configured
// one, or the one the saved token came from.
func (s *session) issuerForToken(ctx context.Context, saved *config.Token) (string, *oauth.Metadata, error) {
	raw := s.Settings.Issuer
	if raw == "" && saved != nil {
		raw = saved.Issuer
		if s.Settings.Client.ID == "" {
			s.Settings.Client.ID = saved.ClientID
		}
	}
	issuer, err := s.issuer(raw)
	if err != nil {
		return "", nil, err
	}
	metadata, err := s.metadataFor(ctx, issuer)
	return issuer, metadata, err
}

// tokenRevoke revokes a token.
func tokenRevoke(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.TokenRevokeParams) (cligen.RevocationReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.RevocationReport{}, err
	}
	token, saved, err := s.token(p.Token)
	if err != nil {
		return cligen.RevocationReport{}, err
	}
	issuer, metadata, err := s.issuerForToken(ctx, saved)
	if err != nil {
		return cligen.RevocationReport{}, err
	}
	credentials, err := s.credentials()
	if err != nil {
		return cligen.RevocationReport{}, err
	}
	endpoint := metadata.String("revocation_endpoint")
	if endpoint == "" {
		return cligen.RevocationReport{}, fmt.Errorf("%w: %s advertises no revocation_endpoint", ErrNotFound, issuer)
	}
	response, err := s.Client.Revoke(ctx, endpoint, token, string(p.Hint), credentials, metadata.Strings("revocation_endpoint_auth_methods_supported"))
	if err != nil {
		return cligen.RevocationReport{Endpoint: endpoint}, err
	}
	report := cligen.RevocationReport{Endpoint: endpoint, HTTPStatus: response.Status, Ok: response.Status == 200, Issues: []cligen.Issue{}}
	if response.Status != 200 {
		oauthErr := oauth.ParseError(response)
		report.Issues = append(report.Issues, oauth.Errorf("revocation-failed", "RFC 7009 §2.2", "", "%v", oauthErr))
	}
	if p.Verify && report.Ok {
		if introspection := metadata.String("introspection_endpoint"); introspection != "" {
			after, _, err := s.Client.Introspect(ctx, introspection, token, string(p.Hint), credentials, metadata.Strings("introspection_endpoint_auth_methods_supported"))
			if err != nil {
				report.Issues = append(report.Issues, oauth.Warnf("verify-failed", "RFC 7662", "", "could not introspect after revocation: %v", err))
			} else {
				active, _ := after["active"].(bool)
				report.VerifiedInactive = oauth.Ptr(!active)
				if active {
					report.Issues = append(report.Issues, oauth.Errorf("still-active", "RFC 7009 §2", "", "the token is still active after revocation"))
				}
			}
		} else {
			report.Issues = append(report.Issues, oauth.Infof("no-introspection", "RFC 7662", "", "no introspection endpoint to verify with"))
		}
	}
	if p.Forget && saved != nil {
		store, err := s.store()
		if err == nil && store.Delete(s.Profile) {
			_ = store.Save()
		}
	}

	if machineReadable(string(p.Format)) {
		return report, s.fail(string(p.Format), report, revocationVerdict(report))
	}
	out := s.Out
	if report.Ok {
		out.Okf("revoked (HTTP %d) at %s", report.HTTPStatus, endpoint)
	} else {
		out.Errorf("revocation answered HTTP %d", report.HTTPStatus)
	}
	if report.VerifiedInactive != nil {
		if *report.VerifiedInactive {
			out.Okf("introspection confirms the token is inactive")
		} else {
			out.Errorf("introspection still reports the token active")
		}
	}
	if p.Forget && saved != nil {
		out.Notef("forgot the saved token for profile %q", config.Key(s.Profile))
	}
	s.printIssues(out, report.Issues)
	return report, revocationVerdict(report)
}

func revocationVerdict(report cligen.RevocationReport) error {
	if !report.Ok {
		return fmt.Errorf("%w: revocation failed", ErrOAuth)
	}
	if report.VerifiedInactive != nil && !*report.VerifiedInactive {
		return fmt.Errorf("%w: the token is still active", ErrFailed)
	}
	return nil
}

// tokenExpect asserts facts about a token.
func tokenExpect(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.TokenExpectParams) (cligen.ExpectationReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.ExpectationReport{}, err
	}
	token, saved, err := s.token(p.Token)
	if err != nil {
		return cligen.ExpectationReport{}, err
	}
	info, jws := inspectWithSession(ctx, s, token, saved, "", "", p.NoVerify, false)
	report := cligen.ExpectationReport{Passed: true, Checks: []cligen.Expectation{}, Token: info}

	add := func(rule string, ok bool, expected, actual string) {
		check := cligen.Expectation{Rule: rule, Ok: ok}
		if expected != "" {
			check.Expected = &expected
		}
		if actual != "" {
			check.Actual = &actual
		}
		report.Checks = append(report.Checks, check)
		if !ok {
			report.Passed = false
		}
	}

	if jws == nil {
		add("token is a JWT", false, "a JWT", "an opaque token")
	} else {
		if !p.NoVerify {
			verified := info.Signature != nil && info.Signature.Status == "verified"
			detail := ""
			if info.Signature != nil && info.Signature.Error != nil {
				detail = *info.Signature.Error
			}
			add("signature verifies", verified, "verified", deref(oauth.Ptr(detail), info.Signature.Status))
		}
		if !p.AllowExpired {
			add("token is not expired", !info.Timing.Expired, "", deref(info.Timing.ExpiresIn, "no exp"))
		}
		if p.MinTtl > 0 {
			remaining := time.Duration(0)
			if info.Timing.ExpiresAt != nil {
				remaining = time.Until(*info.Timing.ExpiresAt)
			}
			add(fmt.Sprintf("remaining lifetime is at least %s", render.Duration(p.MinTtl)), remaining >= p.MinTtl, render.Duration(p.MinTtl), render.Duration(remaining))
		}
		if p.MaxTtl > 0 {
			lifetime := time.Duration(0)
			if info.Timing.ExpiresAt != nil && info.Timing.IssuedAt != nil {
				lifetime = info.Timing.ExpiresAt.Sub(*info.Timing.IssuedAt)
			}
			add(fmt.Sprintf("total lifetime is at most %s", render.Duration(p.MaxTtl)), lifetime > 0 && lifetime <= p.MaxTtl, render.Duration(p.MaxTtl), render.Duration(lifetime))
		}
		if p.Sub != "" {
			add("sub equals "+p.Sub, jws.String("sub") == p.Sub, p.Sub, jws.String("sub"))
		}
		iss := p.Iss
		if iss == "" && s.Settings.Issuer != "" {
			iss, _ = oauth.NormalizeIssuer(s.Settings.Issuer)
		}
		if iss != "" {
			add("iss equals "+iss, strings.TrimRight(jws.String("iss"), "/") == strings.TrimRight(iss, "/"), iss, jws.String("iss"))
		}
		for _, audience := range p.Aud {
			add("aud includes "+audience, containsString(jws.Strings("aud"), audience), audience, strings.Join(jws.Strings("aud"), ", "))
		}
		if p.Alg != "" {
			add("alg is "+p.Alg, jws.Alg() == p.Alg, p.Alg, jws.Alg())
		}
		if p.Typ != "" {
			add("typ is "+p.Typ, strings.EqualFold(jws.Typ(), p.Typ), p.Typ, jws.Typ())
		}
		if len(p.ScopeIncludes) > 0 {
			granted := strings.Fields(jws.String("scope"))
			if scp := jws.Strings("scp"); len(scp) > 0 {
				granted = append(granted, scp...)
			}
			for _, scope := range p.ScopeIncludes {
				add("scope includes "+scope, containsString(granted, scope), scope, strings.Join(granted, " "))
			}
		}
		for _, name := range p.Has {
			_, ok := jws.Claims[name]
			add("claim "+name+" is present", ok, "present", map[bool]string{true: "present", false: "absent"}[ok])
		}
		for _, name := range p.Missing {
			_, ok := jws.Claims[name]
			add("claim "+name+" is absent", !ok, "absent", map[bool]string{true: "present", false: "absent"}[ok])
		}
		for _, expectation := range p.Claim {
			rule, ok, expected, actual, err := evaluateClaim(jws, expectation)
			if err != nil {
				return report, err
			}
			add(rule, ok, expected, actual)
		}
	}

	if p.Active {
		issuer, metadata, err := s.issuerForToken(ctx, saved)
		if err != nil {
			return report, err
		}
		credentials, err := s.credentials()
		if err != nil {
			return report, err
		}
		endpoint := metadata.String("introspection_endpoint")
		if endpoint == "" {
			add("introspection reports active", false, "active", issuer+" advertises no introspection endpoint")
		} else {
			response, _, err := s.Client.Introspect(ctx, endpoint, token, "", credentials, metadata.Strings("introspection_endpoint_auth_methods_supported"))
			if err != nil {
				add("introspection reports active", false, "active", err.Error())
			} else {
				active, _ := response["active"].(bool)
				add("introspection reports active", active, "active", fmt.Sprintf("active=%v", active))
			}
		}
	}

	format := string(p.Format)
	if !machineReadable(format) && !p.Quiet {
		out := s.Out
		for _, check := range report.Checks {
			status := "pass"
			if !check.Ok {
				status = "fail"
			}
			line := check.Rule
			if !check.Ok && check.Actual != nil {
				line += out.T.Styles.Faint.Render("  got " + *check.Actual)
			}
			out.Statusf(status, "%s", line)
		}
		out.Println()
		if report.Passed {
			out.Okf("%d expectation(s) hold", len(report.Checks))
		} else {
			failed := 0
			for _, check := range report.Checks {
				if !check.Ok {
					failed++
				}
			}
			out.Errorf("%d of %d expectation(s) failed", failed, len(report.Checks))
		}
	}
	if !report.Passed {
		return report, s.fail(format, report, fmt.Errorf("%w: an expectation did not hold", ErrFailed))
	}
	return report, nil
}

// evaluateClaim applies one --claim expression: name=value, name~regex or
// name+=member.
func evaluateClaim(jws *jose.JWS, expression string) (rule string, ok bool, expected, actual string, err error) {
	switch {
	case strings.Contains(expression, "+="):
		name, member, _ := strings.Cut(expression, "+=")
		values := jws.Strings(name)
		return fmt.Sprintf("claim %s includes %s", name, member), containsString(values, member), member, strings.Join(values, ", "), nil
	case strings.Contains(expression, "~"):
		name, pattern, _ := strings.Cut(expression, "~")
		re, err := regexp.Compile(pattern)
		if err != nil {
			return "", false, "", "", fmt.Errorf("--claim %s: %w", expression, err)
		}
		value := formatClaim(jws.Claims[name])
		return fmt.Sprintf("claim %s matches /%s/", name, pattern), re.MatchString(value), pattern, value, nil
	case strings.Contains(expression, "="):
		name, want, _ := strings.Cut(expression, "=")
		value := formatClaim(jws.Claims[name])
		if _, present := jws.Claims[name]; !present {
			value = "(absent)"
		}
		return fmt.Sprintf("claim %s equals %s", name, want), value == want, want, value, nil
	}
	return "", false, "", "", fmt.Errorf("--claim %q must be name=value, name~regex or name+=member", expression)
}

// tokenStatus lists saved tokens.
func tokenStatus(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.TokenStatusParams) (cligen.TokenStatusList, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return nil, err
	}
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	list := cligen.TokenStatusList{}
	for _, name := range store.Names() {
		token := store.Tokens[name]
		status := cligen.TokenStatus{
			Profile:         name,
			Expired:         token.Expired(),
			HasRefreshToken: token.RefreshToken != "",
			HasIDToken:      token.IDToken != "",
			Dpop:            len(token.DPoPKey) > 0,
		}
		if token.Issuer != "" {
			status.Issuer = &token.Issuer
		}
		if token.ClientID != "" {
			status.ClientID = &token.ClientID
		}
		if token.TokenType != "" {
			status.TokenType = &token.TokenType
		}
		if token.Scope != "" {
			status.Scope = &token.Scope
		}
		if !token.ObtainedAt.IsZero() {
			status.ObtainedAt = &token.ObtainedAt
		}
		if !token.ExpiresAt.IsZero() {
			status.ExpiresAt = &token.ExpiresAt
			status.ExpiresIn = oauth.Ptr(render.Duration(time.Until(token.ExpiresAt)))
		}
		if jws, err := jose.Parse(token.AccessToken); err == nil && jws.String("sub") != "" {
			status.Subject = oauth.Ptr(jws.String("sub"))
		} else if jws, err := jose.Parse(token.IDToken); err == nil && jws.String("sub") != "" {
			status.Subject = oauth.Ptr(jws.String("sub"))
		}
		list = append(list, status)
	}

	format := string(p.Format)
	if machineReadable(format) {
		return list, nil
	}
	rows := make([][]string, 0, len(list))
	for _, status := range list {
		expiry := "-"
		if status.ExpiresIn != nil {
			expiry = *status.ExpiresIn
			if status.Expired {
				expiry = "expired " + strings.TrimPrefix(expiry, "-") + " ago"
			}
		}
		rows = append(rows, []string{status.Profile, deref(status.Issuer, "-"), deref(status.Subject, "-"), deref(status.Scope, "-"), expiry, yesNo(status.HasRefreshToken), yesNo(status.Dpop)})
	}
	if format == "plain" {
		s.Out.Plain(rows)
		return list, nil
	}
	if len(list) == 0 {
		s.Out.Notef("no saved tokens in %s; obtain one with `oauthcli token get --save` or `oauthcli flow code`", store.SourcePath())
		return list, nil
	}
	s.Out.Title("Saved tokens", store.SourcePath())
	s.Out.Table([]string{"PROFILE", "ISSUER", "SUBJECT", "SCOPE", "EXPIRES", "REFRESH", "DPOP"}, rows)
	return list, nil
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "-"
}

// tokenClear deletes saved tokens.
func tokenClear(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.TokenClearParams) error {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return err
	}
	store, err := s.store()
	if err != nil {
		return err
	}
	if p.All {
		count := len(store.Tokens)
		store.Tokens = map[string]*config.Token{}
		if err := store.Save(); err != nil {
			return err
		}
		s.Out.Okf("forgot %d saved token(s)", count)
		return nil
	}
	if !store.Delete(s.Profile) {
		return fmt.Errorf("%w: no saved token for profile %q", ErrNotFound, config.Key(s.Profile))
	}
	if err := store.Save(); err != nil {
		return err
	}
	s.Out.Okf("forgot the saved token for profile %q", config.Key(s.Profile))
	return nil
}

// userinfo calls the UserInfo endpoint.
func userinfo(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.UserinfoParams) (cligen.UserInfoReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.UserInfoReport{}, err
	}
	token, saved, err := s.token(p.Token)
	if err != nil {
		return cligen.UserInfoReport{}, err
	}
	issuer, metadata, err := s.issuerForToken(ctx, saved)
	if err != nil {
		return cligen.UserInfoReport{}, err
	}
	endpoint := metadata.String("userinfo_endpoint")
	if endpoint == "" {
		return cligen.UserInfoReport{}, fmt.Errorf("%w: %s advertises no userinfo_endpoint", ErrNotFound, issuer)
	}
	var dpop *oauth.DPoP
	if saved != nil && len(saved.DPoPKey) > 0 {
		dpop, err = oauth.DPoPFromJWK(saved.DPoPKey)
		if err != nil {
			return cligen.UserInfoReport{}, err
		}
	}
	claims, _, err := s.Client.UserInfo(ctx, endpoint, token, dpop)
	if err != nil {
		return cligen.UserInfoReport{Endpoint: endpoint}, oauthError(err)
	}
	report := cligen.UserInfoReport{Endpoint: endpoint, Claims: cligen.Document(claims), Issues: []cligen.Issue{}}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		report.Issues = append(report.Issues, oauth.Errorf("sub-missing", "OpenID Connect Core 1.0 §5.3.2", "sub", "the response has no sub"))
	} else {
		report.Sub = &sub
	}
	if saved != nil && saved.IDToken != "" {
		if idToken, err := jose.Parse(saved.IDToken); err == nil && idToken.String("sub") != "" && idToken.String("sub") != sub {
			report.Issues = append(report.Issues, oauth.Errorf("sub-mismatch", "OpenID Connect Core 1.0 §5.3.2", "sub", "UserInfo sub %q differs from the ID token sub %q; the client must reject this", sub, idToken.String("sub")))
		}
	}
	if p.ExpectSub != "" && sub != p.ExpectSub {
		report.Issues = append(report.Issues, oauth.Errorf("sub-unexpected", "", "sub", "sub is %q, want %q", sub, p.ExpectSub))
	}

	if machineReadable(string(p.Format)) {
		if oauth.HasErrors(report.Issues) {
			return report, s.fail(string(p.Format), report, fmt.Errorf("%w: UserInfo validation failed", ErrFailed))
		}
		return report, nil
	}
	out := s.Out
	out.Title("UserInfo", endpoint)
	renderClaims(out, claims)
	if len(report.Issues) > 0 {
		out.Println()
		s.printIssues(out, report.Issues)
	}
	if oauth.HasErrors(report.Issues) {
		return report, fmt.Errorf("%w: UserInfo validation failed", ErrFailed)
	}
	return report, nil
}

// pkce generates or completes a PKCE pair.
func pkce(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.PkceParams) (cligen.PkceResult, error) {
	streams := newOutput(cmd, commandIO)
	var pair *oauth.PKCE
	var err error
	if p.Verifier != "" {
		pair, err = oauth.PKCEFromVerifier(p.Verifier)
	} else {
		pair, err = oauth.NewPKCE(p.Length)
	}
	if err != nil {
		return cligen.PkceResult{}, err
	}
	result := cligen.PkceResult{Verifier: pair.Verifier, Challenge: pair.Challenge, Method: pair.Method}
	switch string(p.Format) {
	case "json", "yaml":
	case "plain":
		streams.Out.Plain([][]string{{pair.Verifier, pair.Challenge}})
	default:
		streams.Out.KV([]render.Field{
			render.F("code_verifier", pair.Verifier),
			render.F("code_challenge", pair.Challenge),
			render.F("code_challenge_method", pair.Method),
		})
	}
	return result, nil
}

// sortedIssues orders findings by severity for display.
func sortedIssues(issues []cligen.Issue) []cligen.Issue {
	rank := map[string]int{"error": 0, "warning": 1, "info": 2}
	out := append([]cligen.Issue{}, issues...)
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}
