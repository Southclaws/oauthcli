// Package oauth implements the client side of OAuth 2.0, OAuth 2.1 and OpenID
// Connect as a testing tool needs it: discovery, token requests with every
// grant and client authentication method, DPoP, PKCE, the authorization code
// and device flows, dynamic registration, and the validation rules the
// specifications define for each response.
package oauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Southclaws/oauthcli/internal/cligen"
)

// Client is the HTTP client every request goes through. It carries the
// transport settings, the extra headers, and the trace hook.
type Client struct {
	HTTP *http.Client
	// Headers are added to every request.
	Headers http.Header
	// AllowHTTP permits plain http beyond loopback addresses.
	AllowHTTP bool
	// Trace, when set, receives one line per request and response.
	Trace func(format string, args ...any)
	// UserAgent identifies the tool to the server.
	UserAgent string
}

// Options configure a Client.
type Options struct {
	Timeout   time.Duration
	Insecure  bool
	AllowHTTP bool
	Headers   []string
	Trace     func(format string, args ...any)
}

// NewClient builds a Client. Redirects are never followed automatically,
// because the authorization endpoint's redirect is the response under test.
func NewClient(opts Options) (*Client, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.Insecure} //nolint:gosec // the user asked for --insecure
	transport.ForceAttemptHTTP2 = true

	headers := http.Header{}
	for _, raw := range opts.Headers {
		name, value, ok := strings.Cut(raw, ":")
		if !ok {
			return nil, fmt.Errorf("header %q must be Name:Value", raw)
		}
		headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}

	return &Client{
		HTTP: &http.Client{
			Timeout:   opts.Timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Headers:   headers,
		AllowHTTP: opts.AllowHTTP,
		Trace:     opts.Trace,
		UserAgent: "oauthcli/" + Version,
	}, nil
}

// Version is stamped by the build and reported in the User-Agent header.
var Version = "dev"

// Response is an HTTP response read in full, with the timing that produced it.
type Response struct {
	Status  int
	Header  http.Header
	Body    []byte
	Elapsed time.Duration
	URL     string
	// TLS is the connection state, when the request used TLS.
	TLS *tls.ConnectionState
}

// ContentType is the media type of the response without parameters.
func (r *Response) ContentType() string {
	mediaType, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	return strings.ToLower(strings.TrimSpace(mediaType))
}

// IsJSON reports whether the body was declared as JSON, including the +json
// structured suffix that RFC 9728 and others use.
func (r *Response) IsJSON() bool {
	ct := r.ContentType()
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}

// JSON decodes the body as a JSON object.
func (r *Response) JSON() (map[string]any, error) {
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(r.Body))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("body is not a JSON object: %w", err)
	}
	return document, nil
}

// ErrUnreachable wraps every transport-level failure so the exit code can
// tell "the server did not answer" from "the server said no".
var ErrUnreachable = errors.New("unreachable")

// Do sends a request and reads the whole response. Transport failures are
// wrapped in ErrUnreachable. An HTTP error status is not an error here; the
// caller decides what a status means for its operation.
func (c *Client) Do(ctx context.Context, req *http.Request) (*Response, error) {
	if err := c.checkScheme(req.URL); err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	for name, values := range c.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}

	c.traceRequest(req)
	started := time.Now()
	response, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s %s: %w", ErrUnreachable, req.Method, req.URL, unwrapURLError(err))
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrUnreachable, req.URL, err)
	}
	out := &Response{
		Status:  response.StatusCode,
		Header:  response.Header,
		Body:    body,
		Elapsed: time.Since(started),
		URL:     req.URL.String(),
		TLS:     response.TLS,
	}
	c.traceResponse(out)
	return out, nil
}

// Get fetches a URL.
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
}

// PostForm posts application/x-www-form-urlencoded parameters.
func (c *Client) PostForm(ctx context.Context, rawURL string, form url.Values, headers http.Header) (*Response, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	return c.Do(ctx, req)
}

// PostJSON posts a JSON document.
func (c *Client) PostJSON(ctx context.Context, method, rawURL string, document any, headers http.Header) (*Response, error) {
	body, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	return c.Do(ctx, req)
}

// checkScheme enforces the https rule. Loopback addresses may use http so a
// local development server can be tested; everything else needs --allow-http.
func (c *Client) checkScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if c.AllowHTTP || IsLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("refusing plain http to %s: OAuth requires TLS (pass --allow-http to override)", u.Host)
	}
	return fmt.Errorf("unsupported URL scheme %q in %s", u.Scheme, u)
}

// IsLoopback reports whether host names the local machine.
func IsLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) traceRequest(req *http.Request) {
	if c.Trace == nil {
		return
	}
	c.Trace("> %s %s", req.Method, req.URL)
	for name, values := range req.Header {
		for _, value := range values {
			c.Trace(">   %s: %s", name, redactHeader(name, value))
		}
	}
	if req.Body != nil && req.GetBody != nil {
		body, err := req.GetBody()
		if err == nil {
			data, _ := io.ReadAll(body)
			if len(data) > 0 {
				c.Trace(">   %s", redactForm(string(data)))
			}
		}
	}
}

func (c *Client) traceResponse(r *Response) {
	if c.Trace == nil {
		return
	}
	c.Trace("< %d (%s)", r.Status, r.Elapsed.Round(time.Millisecond))
	for name, values := range r.Header {
		for _, value := range values {
			c.Trace("<   %s: %s", name, value)
		}
	}
	if len(r.Body) > 0 {
		body := string(r.Body)
		if len(body) > 2000 {
			body = body[:2000] + "…"
		}
		c.Trace("<   %s", redactJSON(body))
	}
}

var secretHeaders = map[string]bool{"authorization": true, "dpop": true}

func redactHeader(name, value string) string {
	if !secretHeaders[strings.ToLower(name)] {
		return value
	}
	scheme, rest, ok := strings.Cut(value, " ")
	if !ok {
		return "[redacted]"
	}
	return scheme + " " + shorten(rest)
}

var secretParams = []string{"client_secret", "code", "code_verifier", "refresh_token", "token", "password", "assertion", "client_assertion", "subject_token", "actor_token", "access_token", "id_token", "registration_access_token", "device_code"}

func redactForm(body string) string {
	values, err := url.ParseQuery(body)
	if err != nil {
		return "[body]"
	}
	for _, name := range secretParams {
		if v := values.Get(name); v != "" {
			values.Set(name, shorten(v))
		}
	}
	decoded, _ := url.QueryUnescape(values.Encode())
	return decoded
}

func redactJSON(body string) string {
	var document map[string]any
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		return body
	}
	for _, name := range secretParams {
		if v, ok := document[name].(string); ok {
			document[name] = shorten(v)
		}
	}
	out, err := json.Marshal(document)
	if err != nil {
		return body
	}
	return string(out)
}

func shorten(secret string) string {
	if len(secret) <= 12 {
		return "[redacted]"
	}
	return secret[:6] + "…" + secret[len(secret)-4:]
}

func unwrapURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// Error is an OAuth error response, as RFC 6749 §5.2 defines it.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	Status      int    `json:"-"`
	// Endpoint is the URL that answered.
	Endpoint string `json:"-"`
	// Header is the response header, kept because RFC 6749 §5.2 requires
	// WWW-Authenticate on an invalid_client answer to a Basic-authenticated
	// request.
	Header http.Header `json:"-"`
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s", e.Code)
	if e.Description != "" {
		fmt.Fprintf(&b, ": %s", e.Description)
	}
	if e.Status != 0 {
		fmt.Fprintf(&b, " (HTTP %d", e.Status)
		if e.Endpoint != "" {
			fmt.Fprintf(&b, " from %s", e.Endpoint)
		}
		b.WriteString(")")
	}
	return b.String()
}

// ParseError turns an error response into an Error. When the body is not an
// OAuth error document a generic Error is built from the status line so the
// caller still gets the endpoint and status.
func ParseError(r *Response) *Error {
	e := &Error{Status: r.Status, Endpoint: r.URL, Header: r.Header}
	if document, err := r.JSON(); err == nil {
		e.Code, _ = document["error"].(string)
		e.Description, _ = document["error_description"].(string)
		e.URI, _ = document["error_uri"].(string)
	}
	if e.Code == "" {
		e.Code = fmt.Sprintf("http_%d", r.Status)
		if e.Description == "" {
			e.Description = strings.TrimSpace(string(truncateBytes(r.Body, 200)))
		}
	}
	return e
}

func truncateBytes(data []byte, n int) []byte {
	if len(data) <= n {
		return data
	}
	return append(data[:n:n], []byte("…")...)
}

// Issue helpers build the finding type the specification declares.

func issue(severity, code, message string) cligen.Issue {
	return cligen.Issue{Severity: severity, Code: code, Message: message}
}

func fieldIssue(severity, code, field, spec, message string) cligen.Issue {
	i := issue(severity, code, message)
	if field != "" {
		i.Field = &field
	}
	if spec != "" {
		i.Spec = &spec
	}
	return i
}

// Errorf, Warnf and Infof build issues of each severity.
func Errorf(code, spec, field, format string, args ...any) cligen.Issue {
	return fieldIssue("error", code, field, spec, fmt.Sprintf(format, args...))
}

func Warnf(code, spec, field, format string, args ...any) cligen.Issue {
	return fieldIssue("warning", code, field, spec, fmt.Sprintf(format, args...))
}

func Infof(code, spec, field, format string, args ...any) cligen.Issue {
	return fieldIssue("info", code, field, spec, fmt.Sprintf(format, args...))
}

// HasErrors reports whether any issue is an error.
func HasErrors(issues []cligen.Issue) bool {
	for _, i := range issues {
		if i.Severity == "error" {
			return true
		}
	}
	return false
}

// Ptr returns a pointer to v, for the optional members of generated types.
func Ptr[T any](v T) *T { return &v }
