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

// Registration is a client's configuration as the server returns it.
type Registration struct {
	Raw                     map[string]any
	ClientID                string
	ClientSecret            string
	ClientSecretExpiresAt   time.Time
	RegistrationClientURI   string
	RegistrationAccessToken string
	Response                *Response
	Issues                  []cligen.Issue
}

// Register posts a client metadata document to the registration endpoint
// (RFC 7591 §3.1). initialToken, when set, authorizes the request.
func (c *Client) Register(ctx context.Context, endpoint string, metadata map[string]any, initialToken string) (*Registration, error) {
	if endpoint == "" {
		return nil, errors.New("the server advertises no registration_endpoint")
	}
	headers := http.Header{}
	if initialToken != "" {
		headers.Set("Authorization", "Bearer "+initialToken)
	}
	response, err := c.PostJSON(ctx, http.MethodPost, endpoint, metadata, headers)
	if err != nil {
		return nil, err
	}
	if response.Status < 200 || response.Status >= 300 {
		return nil, ParseError(response)
	}
	registration, err := parseRegistration(response)
	if err != nil {
		return nil, err
	}
	if response.Status != 201 {
		registration.Issues = append(registration.Issues, Warnf("registration-status", "RFC 7591 §3.2.1", "", "the response status is %d, want 201 Created", response.Status))
	}
	registration.Issues = append(registration.Issues, compareRegistration(metadata, registration.Raw)...)
	return registration, nil
}

// Read fetches a client's configuration (RFC 7592 §2.1).
func (c *Client) ReadClient(ctx context.Context, registrationURI, registrationToken string) (*Registration, error) {
	return c.manage(ctx, http.MethodGet, registrationURI, registrationToken, nil)
}

// UpdateClient replaces a client's configuration (RFC 7592 §2.2).
func (c *Client) UpdateClient(ctx context.Context, registrationURI, registrationToken string, metadata map[string]any) (*Registration, error) {
	return c.manage(ctx, http.MethodPut, registrationURI, registrationToken, metadata)
}

// DeleteClient deprovisions a client (RFC 7592 §2.3) and reports the status
// the server answered with; §2.3 requires 204, and 200 is accepted as success
// so the caller can grade the difference.
func (c *Client) DeleteClient(ctx context.Context, registrationURI, registrationToken string) (int, error) {
	if registrationURI == "" {
		return 0, errors.New("no registration_client_uri: pass --registration-uri or register a client with --save first")
	}
	req, err := http.NewRequest(http.MethodDelete, registrationURI, nil)
	if err != nil {
		return 0, err
	}
	if registrationToken != "" {
		req.Header.Set("Authorization", "Bearer "+registrationToken)
	}
	response, err := c.Do(ctx, req)
	if err != nil {
		return 0, err
	}
	if response.Status != 204 && response.Status != 200 {
		return response.Status, ParseError(response)
	}
	return response.Status, nil
}

func (c *Client) manage(ctx context.Context, method, registrationURI, registrationToken string, metadata map[string]any) (*Registration, error) {
	if registrationURI == "" {
		return nil, errors.New("no registration_client_uri: pass --registration-uri or register a client with --save first")
	}
	headers := http.Header{}
	if registrationToken != "" {
		headers.Set("Authorization", "Bearer "+registrationToken)
	}
	var response *Response
	var err error
	if metadata != nil {
		response, err = c.PostJSON(ctx, method, registrationURI, metadata, headers)
	} else {
		req, reqErr := http.NewRequest(method, registrationURI, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		for name, values := range headers {
			req.Header[name] = values
		}
		response, err = c.Do(ctx, req)
	}
	if err != nil {
		return nil, err
	}
	if response.Status != 200 {
		return nil, ParseError(response)
	}
	return parseRegistration(response)
}

// ParseTokenlessRegistration reads the identifiers out of a registration
// response so a client created by accident can be deleted again.
func ParseTokenlessRegistration(response *Response) (*Registration, error) {
	return parseRegistration(response)
}

func parseRegistration(response *Response) (*Registration, error) {
	document, err := response.JSON()
	if err != nil {
		return nil, fmt.Errorf("registration response: %w", err)
	}
	out := &Registration{Raw: document, Response: response, Issues: []cligen.Issue{}}
	out.ClientID, _ = document["client_id"].(string)
	out.ClientSecret, _ = document["client_secret"].(string)
	out.RegistrationClientURI, _ = document["registration_client_uri"].(string)
	out.RegistrationAccessToken, _ = document["registration_access_token"].(string)
	if expires := numberField(document, "client_secret_expires_at"); expires > 0 {
		out.ClientSecretExpiresAt = time.Unix(int64(expires), 0)
	}

	const spec = "RFC 7591 §3.2.1"
	if out.ClientID == "" {
		out.Issues = append(out.Issues, Errorf("client-id-missing", spec, "client_id", "client_id is required"))
	}
	if out.ClientSecret != "" {
		if _, ok := document["client_secret_expires_at"]; !ok {
			out.Issues = append(out.Issues, Errorf("secret-expiry-missing", spec, "client_secret_expires_at", "client_secret_expires_at is required when a secret is issued (0 means never)"))
		}
	}
	if (out.RegistrationClientURI == "") != (out.RegistrationAccessToken == "") {
		out.Issues = append(out.Issues, Errorf("management-pair", "RFC 7592 §3", "registration_client_uri", "registration_client_uri and registration_access_token must be returned together"))
	}
	if out.RegistrationClientURI == "" {
		out.Issues = append(out.Issues, Infof("no-management", "RFC 7592", "registration_client_uri", "the server does not support client configuration management"))
	}
	if !response.IsJSON() {
		out.Issues = append(out.Issues, Errorf("content-type", "RFC 7591 §3.2, RFC 7592 §2.1", "", "Content-Type is %q, want application/json", response.Header.Get("Content-Type")))
	}
	if out.RegistrationClientURI != "" {
		if u, err := url.Parse(out.RegistrationClientURI); err != nil || (u.Scheme != "https" && !IsLoopback(u.Hostname())) {
			out.Issues = append(out.Issues, Errorf("management-uri-not-https", "RFC 7592 §2", "registration_client_uri", "registration_client_uri must be protected by TLS"))
		}
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Cache-Control")), "no-store") {
		out.Issues = append(out.Issues, Infof("cache-control", spec+" (example)", "", "the response does not carry Cache-Control: no-store as the RFC's examples do"))
	}
	return out, nil
}

// compareRegistration checks that the server echoed every requested value
// or replaced it; RFC 7591 §3.2.1 lets a server substitute, but it must then
// return the substituted value.
func compareRegistration(requested, returned map[string]any) []cligen.Issue {
	var issues []cligen.Issue
	for name := range requested {
		if _, ok := returned[name]; !ok {
			issues = append(issues, Warnf("metadata-dropped", "RFC 7591 §3.2.1", name, "%s was requested but the response does not include it; the server must return the value it registered", name))
		}
	}
	return issues
}
