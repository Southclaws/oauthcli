package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Southclaws/oauthcli/internal/cligen"
)

// DeviceAuthorization is the response of the device authorization endpoint
// (RFC 8628 §3.2).
type DeviceAuthorization struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int
	Interval                int
	Raw                     map[string]any
	Issues                  []cligen.Issue
}

// DeviceAuthorize starts the device flow.
func (c *Client) DeviceAuthorize(ctx context.Context, endpoint string, credentials *Credentials, advertised []string, scopes []string, audience string, resources []string, extra url.Values) (*DeviceAuthorization, error) {
	if endpoint == "" {
		return nil, errors.New("the server advertises no device_authorization_endpoint")
	}
	form := url.Values{}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	if audience != "" {
		form.Set("audience", audience)
	}
	for _, resource := range resources {
		form.Add("resource", resource)
	}
	for name, items := range extra {
		for _, item := range items {
			form.Add(name, item)
		}
	}
	headers := http.Header{}
	method, err := credentials.Resolve(advertised)
	if err != nil {
		return nil, err
	}
	if err := credentials.Apply(method, form, headers, endpoint); err != nil {
		return nil, err
	}
	response, err := c.PostForm(ctx, endpoint, form, headers)
	if err != nil {
		return nil, err
	}
	if response.Status != 200 {
		return nil, ParseError(response)
	}
	document, err := response.JSON()
	if err != nil {
		return nil, fmt.Errorf("device authorization response: %w", err)
	}

	out := &DeviceAuthorization{Raw: document, Issues: []cligen.Issue{}}
	out.DeviceCode, _ = document["device_code"].(string)
	out.UserCode, _ = document["user_code"].(string)
	out.VerificationURI, _ = document["verification_uri"].(string)
	out.VerificationURIComplete, _ = document["verification_uri_complete"].(string)
	out.ExpiresIn = numberField(document, "expires_in")
	out.Interval = numberField(document, "interval")
	if out.Interval <= 0 {
		out.Interval = 5
	}

	const spec = "RFC 8628 §3.2"
	if out.DeviceCode == "" {
		out.Issues = append(out.Issues, Errorf("device-code-missing", spec, "device_code", "device_code is required"))
	}
	if out.UserCode == "" {
		out.Issues = append(out.Issues, Errorf("user-code-missing", spec, "user_code", "user_code is required"))
	}
	if out.VerificationURI == "" {
		// Some servers spell it verification_url; accept it with a finding.
		if alt, _ := document["verification_url"].(string); alt != "" {
			out.VerificationURI = alt
			out.Issues = append(out.Issues, Errorf("verification-uri-misspelt", spec, "verification_url", "the response uses verification_url; the member is verification_uri"))
		} else {
			out.Issues = append(out.Issues, Errorf("verification-uri-missing", spec, "verification_uri", "verification_uri is required"))
		}
	}
	if out.ExpiresIn <= 0 {
		out.Issues = append(out.Issues, Errorf("expires-in-missing", spec, "expires_in", "expires_in is required and must be positive"))
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Cache-Control")), "no-store") {
		out.Issues = append(out.Issues, Infof("cache-control", spec+" (example)", "", "the response does not carry Cache-Control: no-store as the RFC's example does"))
	}
	if !response.IsJSON() {
		out.Issues = append(out.Issues, Errorf("content-type", spec, "", "Content-Type is %q, want application/json", response.Header.Get("Content-Type")))
	}
	if out.UserCode != "" && out.VerificationURI != "" && strings.Contains(out.VerificationURI, out.UserCode) {
		out.Issues = append(out.Issues, Warnf("user-code-in-uri", "RFC 8628 §3.3", "verification_uri", "verification_uri embeds the user code, which is NOT RECOMMENDED"))
	}
	if out.VerificationURIComplete == "" {
		out.Issues = append(out.Issues, Infof("verification-uri-complete-absent", spec, "verification_uri_complete", "verification_uri_complete is optional but saves the user typing the code"))
	}
	return out, nil
}

// DevicePollStatus reports one poll to the caller.
type DevicePollStatus struct {
	Attempt int
	Waiting string
	// SlowDown is set when the server asked for a longer interval.
	SlowDown bool
}

// DevicePoll polls the token endpoint until the user decides or the code
// expires. onPoll, when set, is called after every pending answer.
func (c *Client) DevicePoll(ctx context.Context, tokenEndpoint string, auth *DeviceAuthorization, credentials *Credentials, advertised []string, dpop *DPoP, onPoll func(DevicePollStatus)) (*TokenResult, error) {
	interval := time.Duration(auth.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	if auth.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	attempt := 0
	for {
		attempt++
		result, err := c.Token(ctx, TokenRequest{
			Endpoint:    tokenEndpoint,
			Grant:       GrantDeviceCode,
			Credentials: credentials,
			Advertised:  advertised,
			Params:      url.Values{"device_code": {auth.DeviceCode}},
			DPoP:        dpop,
		})
		if err == nil {
			return result, nil
		}
		var oauthErr *Error
		if !errors.As(err, &oauthErr) {
			return nil, err
		}
		status := DevicePollStatus{Attempt: attempt, Waiting: oauthErr.Code}
		switch oauthErr.Code {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
			status.SlowDown = true
		case "access_denied", "expired_token":
			return nil, oauthErr
		default:
			return nil, oauthErr
		}
		if onPoll != nil {
			onPoll(status)
		}
		if time.Now().After(deadline) {
			return nil, &Error{Code: "expired_token", Description: "the device code expired before the user approved it"}
		}
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
