package oauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/jose"
)

// AuthorizationRequest is everything that goes into an authorization URL.
type AuthorizationRequest struct {
	Endpoint     string
	ClientID     string
	RedirectURI  string
	Scopes       []string
	State        string
	Nonce        string
	PKCE         *PKCE
	Audience     string
	Resources    []string
	Prompt       string
	LoginHint    string
	MaxAge       time.Duration
	ResponseMode string
	// Extra parameters, added last so they can override anything.
	Extra url.Values
}

// Values returns the request as query parameters.
func (r *AuthorizationRequest) Values() url.Values {
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", r.ClientID)
	if r.RedirectURI != "" {
		values.Set("redirect_uri", r.RedirectURI)
	}
	if len(r.Scopes) > 0 {
		values.Set("scope", strings.Join(r.Scopes, " "))
	}
	if r.State != "" {
		values.Set("state", r.State)
	}
	if r.Nonce != "" {
		values.Set("nonce", r.Nonce)
	}
	if r.PKCE != nil {
		values.Set("code_challenge", r.PKCE.Challenge)
		values.Set("code_challenge_method", r.PKCE.Method)
	}
	if r.Audience != "" {
		values.Set("audience", r.Audience)
	}
	for _, resource := range r.Resources {
		values.Add("resource", resource)
	}
	if r.Prompt != "" {
		values.Set("prompt", r.Prompt)
	}
	if r.LoginHint != "" {
		values.Set("login_hint", r.LoginHint)
	}
	if r.MaxAge > 0 {
		values.Set("max_age", fmt.Sprint(int(r.MaxAge.Seconds())))
	}
	if r.ResponseMode != "" {
		values.Set("response_mode", r.ResponseMode)
	}
	for name, items := range r.Extra {
		values.Del(name)
		for _, item := range items {
			values.Add(name, item)
		}
	}
	return values
}

// URL builds the authorization URL, keeping any query the endpoint already
// carries.
func (r *AuthorizationRequest) URL() (string, error) {
	u, err := url.Parse(r.Endpoint)
	if err != nil {
		return "", err
	}
	query := u.Query()
	for name, items := range r.Values() {
		for _, item := range items {
			query.Add(name, item)
		}
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

// Push sends the request to the pushed authorization request endpoint
// (RFC 9126) and returns the request_uri and its lifetime.
func (c *Client) Push(ctx context.Context, endpoint string, r *AuthorizationRequest, credentials *Credentials, advertised []string, dpop *DPoP) (string, int, []cligen.Issue, error) {
	if endpoint == "" {
		return "", 0, nil, errors.New("the server advertises no pushed_authorization_request_endpoint")
	}
	form := r.Values()
	headers := http.Header{}
	method, err := credentials.Resolve(advertised)
	if err != nil {
		return "", 0, nil, err
	}
	if err := credentials.Apply(method, form, headers, endpoint); err != nil {
		return "", 0, nil, err
	}
	if dpop != nil {
		proof, err := dpop.Proof(http.MethodPost, endpoint, "")
		if err != nil {
			return "", 0, nil, err
		}
		headers.Set("DPoP", proof)
	}
	response, err := c.PostForm(ctx, endpoint, form, headers)
	if err != nil {
		return "", 0, nil, err
	}
	if response.Status < 200 || response.Status >= 300 {
		return "", 0, nil, ParseError(response)
	}
	document, err := response.JSON()
	if err != nil {
		return "", 0, nil, fmt.Errorf("PAR response: %w", err)
	}
	requestURI, _ := document["request_uri"].(string)
	expiresIn := numberField(document, "expires_in")

	var issues []cligen.Issue
	if response.Status != 201 {
		issues = append(issues, Errorf("par-status", "RFC 9126 §2.2", "", "the PAR response status is %d; a successful response MUST use 201", response.Status))
	}
	if !response.IsJSON() {
		issues = append(issues, Errorf("par-content-type", "RFC 9126 §2.2", "", "the PAR response Content-Type is %q, want application/json", response.Header.Get("Content-Type")))
	}
	if requestURI == "" {
		return "", 0, issues, errors.New("the PAR response has no request_uri")
	}
	if !strings.HasPrefix(requestURI, "urn:ietf:params:oauth:request_uri:") {
		issues = append(issues, Infof("par-request-uri-form", "RFC 9126 §2.2", "request_uri", "request_uri %q does not use the urn:ietf:params:oauth:request_uri: form the RFC suggests (MAY)", requestURI))
	}
	if expiresIn <= 0 {
		issues = append(issues, Errorf("par-expires-in", "RFC 9126 §2.2", "expires_in", "the response includes expires_in as a positive number of seconds"))
	}
	return requestURI, expiresIn, issues, nil
}

// Callback is what the authorization server sent back to the redirect URI.
type Callback struct {
	Code             string
	State            string
	Issuer           string
	Error            string
	ErrorDescription string
	// Raw is every parameter received, for the report.
	Raw url.Values
}

// ParseCallback reads a redirect URL, or a bare code, into a Callback. A
// fragment response is accepted as well as a query response, because a
// person pasting the URL back may have either.
func ParseCallback(text string) (*Callback, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("nothing to parse")
	}
	if !strings.Contains(text, "=") && !strings.Contains(text, "://") {
		return &Callback{Code: text, Raw: url.Values{"code": {text}}}, nil
	}
	var values url.Values
	if strings.Contains(text, "://") {
		u, err := url.Parse(text)
		if err != nil {
			return nil, err
		}
		values = u.Query()
		if fragment, err := url.ParseQuery(u.Fragment); err == nil {
			for name, items := range fragment {
				values[name] = items
			}
		}
	} else {
		var err error
		values, err = url.ParseQuery(strings.TrimPrefix(strings.TrimPrefix(text, "?"), "#"))
		if err != nil {
			return nil, err
		}
	}
	return callbackFromValues(values), nil
}

func callbackFromValues(values url.Values) *Callback {
	return &Callback{
		Code:             values.Get("code"),
		State:            values.Get("state"),
		Issuer:           values.Get("iss"),
		Error:            values.Get("error"),
		ErrorDescription: values.Get("error_description"),
		Raw:              values,
	}
}

// Listener waits for the browser to come back to a loopback redirect URI.
type Listener struct {
	server   *http.Server
	listener net.Listener
	path     string
	result   chan *Callback
	// RedirectURI is the URI the listener answers on.
	RedirectURI string
}

// Listen binds a loopback port. redirectURI may name a fixed port and path;
// with an empty host or port 0 a free port is chosen and the URI returned
// reflects it.
func Listen(redirectURI string, port int) (*Listener, error) {
	path := "/callback"
	host := "127.0.0.1"
	if redirectURI != "" {
		u, err := url.Parse(redirectURI)
		if err != nil {
			return nil, fmt.Errorf("redirect URI: %w", err)
		}
		if !IsLoopback(u.Hostname()) {
			return nil, fmt.Errorf("redirect URI %s is not a loopback address; use --manual to paste the result back", redirectURI)
		}
		if u.Path != "" {
			path = u.Path
		}
		host = u.Hostname()
		if p := u.Port(); p != "" && port == 0 {
			fmt.Sscanf(p, "%d", &port)
		}
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, fmt.Errorf("listen on %s:%d: %w", host, port, err)
	}
	actual := listener.Addr().(*net.TCPAddr).Port
	// OAuth 2.1 §8.4.2 and RFC 8252 §7.3: a loopback redirect URI matches
	// exactly except for the port, so the registered host is kept as given
	// and only the port may be substituted.
	l := &Listener{
		listener:    listener,
		path:        path,
		result:      make(chan *Callback, 1),
		RedirectURI: fmt.Sprintf("http://%s:%d%s", host, actual, path),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, l.handle)
	l.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go l.server.Serve(listener) //nolint:errcheck // Serve returns ErrServerClosed on Close
	return l, nil
}

func (l *Listener) handle(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			values = r.PostForm
		}
	}
	callback := callbackFromValues(values)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if callback.Error != "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, callbackPage, "Authorization failed", callback.Error+": "+callback.ErrorDescription)
	} else if callback.Code == "" {
		// A fragment response cannot be seen by the server; a tiny script
		// resubmits it as a query so the flow still completes.
		fmt.Fprint(w, fragmentPage)
		return
	} else {
		fmt.Fprintf(w, callbackPage, "Signed in", "You can close this tab and return to the terminal.")
	}
	select {
	case l.result <- callback:
	default:
	}
}

// Wait blocks until the browser comes back or the context ends.
func (l *Listener) Wait(ctx context.Context) (*Callback, error) {
	select {
	case callback := <-l.result:
		return callback, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("gave up waiting for the browser: %w", ctx.Err())
	}
}

// Close stops listening.
func (l *Listener) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = l.server.Shutdown(ctx)
}

const callbackPage = `<!doctype html><html><head><meta charset="utf-8"><title>oauthcli</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#1a1a2e;color:#eee}
main{text-align:center;padding:2rem 3rem;border:1px solid #6b50ff;border-radius:12px}h1{margin:0 0 .5rem;color:#c4b5fd}p{margin:0;color:#aaa}</style></head>
<body><main><h1>%s</h1><p>%s</p></main></body></html>`

const fragmentPage = `<!doctype html><html><head><meta charset="utf-8"><title>oauthcli</title></head>
<body><script>if(location.hash){location.replace(location.pathname+'?'+location.hash.slice(1))}else{document.body.textContent='No authorization response received.'}</script></body></html>`

// OpenBrowser opens a URL with the platform's default browser.
func OpenBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}

// ValidateCallback applies the checks a client must make on an authorization
// response: state must match, an error is an error, and when the server
// advertises RFC 9207 the iss parameter must be present and correct.
func ValidateCallback(callback *Callback, state, issuer string, issParameterAdvertised bool) ([]cligen.Issue, error) {
	var issues []cligen.Issue
	// RFC 6749 §4.1.2.1 requires state on error responses too, so it is
	// checked before the error is surfaced.
	if state != "" && callback.State != state {
		return issues, fmt.Errorf("state mismatch: sent %q, received %q; the response may not belong to this request", state, callback.State)
	}
	if callback.Error != "" {
		return issues, &Error{Code: callback.Error, Description: callback.ErrorDescription}
	}
	if callback.Code == "" {
		return issues, errors.New("the authorization response has no code")
	}
	switch {
	case callback.Issuer == "" && issParameterAdvertised:
		issues = append(issues, Errorf("iss-missing", "RFC 9207 §2", "iss", "the server advertises authorization_response_iss_parameter_supported but sent no iss"))
	case callback.Issuer == "":
		issues = append(issues, Infof("iss-absent", "RFC 9207", "iss", "the authorization response carries no iss parameter; mix-up attacks are not mitigated"))
	case strings.TrimRight(callback.Issuer, "/") != strings.TrimRight(issuer, "/"):
		return issues, fmt.Errorf("iss mismatch: the response claims issuer %q, want %q", callback.Issuer, issuer)
	}
	return issues, nil
}

// NewState and NewNonce generate unguessable values.
func NewState() string { return jose.RandomString(24) }
func NewNonce() string { return jose.RandomString(24) }
