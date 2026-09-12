package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Southclaws/oauthcli/internal/cligen"
)

// Grant type identifiers.
const (
	GrantClientCredentials = "client_credentials"
	GrantPassword          = "password"
	GrantRefreshToken      = "refresh_token"
	GrantAuthorizationCode = "authorization_code"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// TokenRequest is one call to the token endpoint.
type TokenRequest struct {
	Endpoint    string
	Grant       string
	Credentials *Credentials
	// Advertised is token_endpoint_auth_methods_supported, for auto.
	Advertised []string
	Scopes     []string
	Audience   string
	Resources  []string
	// Params are the grant-specific parameters: code, code_verifier,
	// refresh_token, username, password, assertion, subject_token...
	Params url.Values
	DPoP   *DPoP
}

// TokenResult is a parsed token response with the checks that apply to it.
type TokenResult struct {
	Raw          map[string]any
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	ExpiresAt    time.Time
	RefreshToken string
	IDToken      string
	Scope        string
	Response     *Response
	Issues       []cligen.Issue
	// AuthMethod is the client authentication method that was used.
	AuthMethod string
}

// Token calls the token endpoint. An OAuth error response is returned as
// *Error. A DPoP nonce challenge is answered once, transparently.
func (c *Client) Token(ctx context.Context, req TokenRequest) (*TokenResult, error) {
	if req.Endpoint == "" {
		return nil, errors.New("the server advertises no token_endpoint")
	}
	if req.Credentials == nil {
		req.Credentials = &Credentials{}
	}
	method, err := req.Credentials.Resolve(req.Advertised)
	if err != nil {
		return nil, err
	}

	build := func() (url.Values, http.Header, error) {
		form := url.Values{}
		form.Set("grant_type", req.Grant)
		if len(req.Scopes) > 0 {
			form.Set("scope", strings.Join(req.Scopes, " "))
		}
		if req.Audience != "" {
			form.Set("audience", req.Audience)
		}
		for _, resource := range req.Resources {
			form.Add("resource", resource)
		}
		for name, values := range req.Params {
			for _, value := range values {
				form.Add(name, value)
			}
		}
		headers := http.Header{}
		if method == AuthNone && req.Credentials.ClientID == "" {
			// A public client with no id at all is only valid for grants
			// that carry their own identity, such as device polling with a
			// pre-set client_id parameter.
		} else if err := req.Credentials.Apply(method, form, headers, req.Endpoint); err != nil {
			return nil, nil, err
		}
		if req.DPoP != nil {
			proof, err := req.DPoP.Proof(http.MethodPost, req.Endpoint, "")
			if err != nil {
				return nil, nil, err
			}
			headers.Set("DPoP", proof)
		}
		return form, headers, nil
	}

	form, headers, err := build()
	if err != nil {
		return nil, err
	}
	response, err := c.PostForm(ctx, req.Endpoint, form, headers)
	if err != nil {
		return nil, err
	}

	// RFC 9449 §8: a server that wants a nonce answers 400 use_dpop_nonce with
	// the nonce in a header; the request is repeated once with it.
	if req.DPoP != nil && response.Status == 400 {
		if oauthErr := ParseError(response); oauthErr.Code == "use_dpop_nonce" && response.Header.Get("DPoP-Nonce") != "" {
			req.DPoP.Nonce = response.Header.Get("DPoP-Nonce")
			form, headers, err = build()
			if err != nil {
				return nil, err
			}
			response, err = c.PostForm(ctx, req.Endpoint, form, headers)
			if err != nil {
				return nil, err
			}
		}
	}
	if nonce := response.Header.Get("DPoP-Nonce"); nonce != "" && req.DPoP != nil {
		req.DPoP.Nonce = nonce
	}

	if response.Status < 200 || response.Status >= 300 {
		return nil, ParseError(response)
	}

	result, err := ParseTokenResponse(response)
	if err != nil {
		return nil, err
	}
	result.AuthMethod = method
	if req.DPoP != nil && !strings.EqualFold(result.TokenType, "DPoP") {
		result.Issues = append(result.Issues, Warnf("dpop-not-bound", "RFC 9449 §5", "token_type", "a DPoP proof was sent but token_type is %q, so the token is not sender-constrained", result.TokenType))
	}
	if req.Grant == GrantClientCredentials && result.RefreshToken != "" {
		result.Issues = append(result.Issues, Warnf("refresh-token-for-client", "RFC 6749 §4.4.3", "refresh_token", "a refresh token should not be issued for the client credentials grant"))
	}
	return result, nil
}

// ParseTokenResponse decodes a successful token response and checks the
// RFC 6749 §5.1 requirements on it.
func ParseTokenResponse(response *Response) (*TokenResult, error) {
	document, err := response.JSON()
	if err != nil {
		return nil, fmt.Errorf("token response: %w", err)
	}
	result := &TokenResult{Raw: document, Response: response, Issues: []cligen.Issue{}}
	result.AccessToken, _ = document["access_token"].(string)
	result.TokenType, _ = document["token_type"].(string)
	result.RefreshToken, _ = document["refresh_token"].(string)
	result.IDToken, _ = document["id_token"].(string)
	result.Scope, _ = document["scope"].(string)
	result.ExpiresIn = numberField(document, "expires_in")
	if result.ExpiresIn > 0 {
		result.ExpiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	}

	const rfc6749 = "RFC 6749 §5.1"
	if result.AccessToken == "" {
		result.Issues = append(result.Issues, Errorf("access-token-missing", rfc6749, "access_token", "the response has no access_token"))
	}
	if result.TokenType == "" {
		result.Issues = append(result.Issues, Errorf("token-type-missing", rfc6749, "token_type", "token_type is required"))
	} else if !strings.EqualFold(result.TokenType, "Bearer") && !strings.EqualFold(result.TokenType, "DPoP") && !strings.EqualFold(result.TokenType, "N_A") {
		result.Issues = append(result.Issues, Warnf("token-type-unknown", "RFC 6749 §7.1", "token_type", "token_type %q is not Bearer or DPoP", result.TokenType))
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Cache-Control")), "no-store") {
		result.Issues = append(result.Issues, Errorf("cache-control", "RFC 6749 §5.1, OAuth 2.1 §3.2.3", "", "the response must carry Cache-Control: no-store; got %q", response.Header.Get("Cache-Control")))
	}
	if !strings.EqualFold(response.Header.Get("Pragma"), "no-cache") {
		result.Issues = append(result.Issues, Warnf("pragma", "RFC 6749 §5.1", "", "the response lacks Pragma: no-cache, which RFC 6749 requires and OAuth 2.1 drops"))
	}
	if !response.IsJSON() {
		result.Issues = append(result.Issues, Errorf("content-type", rfc6749, "", "the response Content-Type is %q, want application/json", response.Header.Get("Content-Type")))
	}
	if _, ok := document["expires_in"]; !ok {
		result.Issues = append(result.Issues, Warnf("expires-in-missing", rfc6749, "expires_in", "expires_in is recommended"))
	} else if _, isString := document["expires_in"].(string); isString {
		result.Issues = append(result.Issues, Errorf("expires-in-type", rfc6749, "expires_in", "expires_in is a JSON string; numerical values must be JSON numbers"))
	} else if result.ExpiresIn <= 0 {
		result.Issues = append(result.Issues, Errorf("expires-in-invalid", rfc6749, "expires_in", "expires_in is %v, want a positive number of seconds", document["expires_in"]))
	}
	if result.Scope == "" {
		result.Issues = append(result.Issues, Infof("scope-not-echoed", "RFC 6749 §5.1", "scope", "scope is not in the response; it is required when the granted scope differs from the request"))
	}
	return result, nil
}

// numberField reads an integer that a server may have sent as a number or as
// a string, which some do.
func numberField(document map[string]any, name string) int {
	switch value := document[name].(type) {
	case json.Number:
		n, _ := value.Int64()
		return int(n)
	case float64:
		return int(value)
	case string:
		n, _ := strconv.Atoi(value)
		return n
	}
	return 0
}

// Introspect calls the introspection endpoint (RFC 7662).
func (c *Client) Introspect(ctx context.Context, endpoint, token, hint string, credentials *Credentials, advertised []string) (map[string]any, *Response, error) {
	if endpoint == "" {
		return nil, nil, errors.New("the server advertises no introspection_endpoint")
	}
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	headers := http.Header{}
	if credentials != nil && credentials.ClientID != "" {
		method, err := credentials.Resolve(advertised)
		if err != nil {
			return nil, nil, err
		}
		if err := credentials.Apply(method, form, headers, endpoint); err != nil {
			return nil, nil, err
		}
	}
	response, err := c.PostForm(ctx, endpoint, form, headers)
	if err != nil {
		return nil, nil, err
	}
	if response.Status != 200 {
		return nil, response, ParseError(response)
	}
	document, err := response.JSON()
	if err != nil {
		return nil, response, fmt.Errorf("introspection response: %w", err)
	}
	return document, response, nil
}

// Revoke calls the revocation endpoint (RFC 7009).
func (c *Client) Revoke(ctx context.Context, endpoint, token, hint string, credentials *Credentials, advertised []string) (*Response, error) {
	if endpoint == "" {
		return nil, errors.New("the server advertises no revocation_endpoint")
	}
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	headers := http.Header{}
	if credentials != nil && credentials.ClientID != "" {
		method, err := credentials.Resolve(advertised)
		if err != nil {
			return nil, err
		}
		if err := credentials.Apply(method, form, headers, endpoint); err != nil {
			return nil, err
		}
	}
	return c.PostForm(ctx, endpoint, form, headers)
}

// Bearer sends a request with an access token, as Bearer or DPoP depending
// on whether a DPoP key is given. The DPoP nonce challenge of a resource
// server (401 with DPoP-Nonce) is answered once.
func (c *Client) Bearer(ctx context.Context, method, target, accessToken string, dpop *DPoP) (*Response, error) {
	send := func() (*Response, error) {
		req, err := http.NewRequest(method, target, nil)
		if err != nil {
			return nil, err
		}
		if dpop != nil {
			proof, err := dpop.ResourceProof(method, target, accessToken)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "DPoP "+accessToken)
			req.Header.Set("DPoP", proof)
		} else {
			req.Header.Set("Authorization", "Bearer "+accessToken)
		}
		return c.Do(ctx, req)
	}
	response, err := send()
	if err != nil {
		return nil, err
	}
	if dpop != nil {
		nonce := response.Header.Get("DPoP-Nonce")
		challenge := ParseChallenge(response.Header.Get("WWW-Authenticate"))
		wantsNonce := response.Status == 401 && nonce != "" && (challenge == nil || challenge.Params["error"] == "" || challenge.Params["error"] == "use_dpop_nonce")
		if wantsNonce && dpop.ResourceNonce != nonce {
			dpop.ResourceNonce = nonce
			return send()
		}
		if nonce != "" {
			dpop.ResourceNonce = nonce
		}
	}
	return response, nil
}

// UserInfo calls the UserInfo endpoint and returns the claims.
func (c *Client) UserInfo(ctx context.Context, endpoint, accessToken string, dpop *DPoP) (map[string]any, *Response, error) {
	if endpoint == "" {
		return nil, nil, errors.New("the server advertises no userinfo_endpoint")
	}
	response, err := c.Bearer(ctx, http.MethodGet, endpoint, accessToken, dpop)
	if err != nil {
		return nil, nil, err
	}
	if response.Status != 200 {
		return nil, response, challengeError(response)
	}
	if response.ContentType() == "application/jwt" {
		return nil, response, errors.New("the UserInfo response is a signed JWT, which this tool does not decode yet")
	}
	document, err := response.JSON()
	if err != nil {
		return nil, response, fmt.Errorf("userinfo response: %w", err)
	}
	return document, response, nil
}

// challengeError turns a protected resource's error into an *Error, reading
// the WWW-Authenticate challenge when the body is not an OAuth error document.
func challengeError(response *Response) error {
	e := ParseError(response)
	if strings.HasPrefix(e.Code, "http_") {
		if challenge := ParseChallenge(response.Header.Get("WWW-Authenticate")); challenge != nil {
			if code := challenge.Params["error"]; code != "" {
				e.Code = code
				e.Description = challenge.Params["error_description"]
			}
		}
	}
	return e
}
