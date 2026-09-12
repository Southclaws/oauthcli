package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Southclaws/oauthcli/internal/cligen"
)

// ResourceMetadata is an RFC 9728 protected resource metadata document.
type ResourceMetadata struct {
	Raw      map[string]any
	URL      string
	Resource string
	Response *Response
}

// FetchResourceMetadata fetches /.well-known/oauth-protected-resource for a
// resource identifier, trying the inserted and appended spellings.
func (c *Client) FetchResourceMetadata(ctx context.Context, resource string) (*ResourceMetadata, error) {
	var lastErr error
	for _, candidate := range WellKnownURLs(resource, KindResource) {
		response, err := c.Get(ctx, candidate)
		if err != nil {
			lastErr = err
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
		return &ResourceMetadata{Raw: document, URL: candidate, Resource: resource, Response: response}, nil
	}
	return nil, fmt.Errorf("%w for resource %s: %v", ErrNoMetadata, resource, lastErr)
}

// String returns a string member.
func (r *ResourceMetadata) String(name string) string {
	value, _ := r.Raw[name].(string)
	return value
}

// Strings returns an array-of-strings member.
func (r *ResourceMetadata) Strings(name string) []string {
	items, _ := r.Raw[name].([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Validate applies the RFC 9728 rules.
func (r *ResourceMetadata) Validate(allowHTTP bool) []cligen.Issue {
	var issues []cligen.Issue
	const spec = "RFC 9728 §2"

	if r.Response != nil && !r.Response.IsJSON() {
		issues = append(issues, Errorf("content-type", "RFC 9728 §3.2", "", "Content-Type is %q, want application/json", r.Response.Header.Get("Content-Type")))
	}
	if r.URL != "" && len(WellKnownURLs(r.Resource, KindResource)) > 0 && r.URL != WellKnownURLs(r.Resource, KindResource)[0] {
		issues = append(issues, Warnf("location-appended", "RFC 9728 §3, §3.1", "", "the document was found at %s; RFC 9728 inserts the well-known path between the host and the path, at %s", r.URL, WellKnownURLs(r.Resource, KindResource)[0]))
	}
	claimed := r.String("resource")
	switch {
	case claimed == "":
		issues = append(issues, Errorf("resource-missing", spec, "resource", "resource is required"))
	case claimed == r.Resource:
	case strings.TrimRight(claimed, "/") == strings.TrimRight(r.Resource, "/"):
		issues = append(issues, Warnf("resource-trailing-slash", "RFC 9728 §3.3", "resource", "resource is %q but the document was fetched for %q; they differ only by a trailing slash, which a strict client treats as a mismatch", claimed, r.Resource))
	default:
		issues = append(issues, Errorf("resource-mismatch", "RFC 9728 §3.3", "resource", "resource is %q but the document was fetched for %q; a client must reject this", claimed, r.Resource))
	}
	if claimed != "" {
		if u, err := url.Parse(claimed); err == nil {
			if u.Scheme != "https" && !(allowHTTP || IsLoopback(u.Hostname())) {
				issues = append(issues, Errorf("resource-not-https", "RFC 9728 §1.2", "resource", "a resource identifier must use https"))
			}
			if u.Fragment != "" {
				issues = append(issues, Errorf("resource-has-fragment", "RFC 9728 §1.2", "resource", "a resource identifier must not have a fragment component"))
			}
			if u.RawQuery != "" {
				issues = append(issues, Warnf("resource-has-query", "RFC 9728 §1.2, RFC 8707 §2", "resource", "a resource identifier should not include a query component"))
			}
		}
	}
	servers := r.Strings("authorization_servers")
	if !r.hasMember("authorization_servers") {
		issues = append(issues, Infof("authorization-servers-missing", spec, "authorization_servers", "authorization_servers is absent (optional); the set of servers may not be enumerable"))
	}
	for _, server := range servers {
		u, err := url.Parse(server)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(allowHTTP || IsLoopback(u.Hostname()))) || u.RawQuery != "" || u.Fragment != "" {
			issues = append(issues, Errorf("authorization-server-invalid", "RFC 8414 §2", "authorization_servers", "%q is not an https issuer identifier without query or fragment", server))
		}
	}
	for name, value := range r.Raw {
		if items, ok := value.([]any); ok && len(items) == 0 && name != "bearer_methods_supported" {
			issues = append(issues, Errorf("empty-array", "RFC 9728 §3.2", name, "%s is an empty array; parameters with zero values must be omitted", name))
		}
	}
	if jwks := r.String("jwks_uri"); jwks != "" {
		if u, err := url.Parse(jwks); err != nil || (u.Scheme != "https" && !(allowHTTP || IsLoopback(u.Hostname()))) {
			issues = append(issues, Errorf("jwks-not-https", spec, "jwks_uri", "jwks_uri must use https"))
		}
	}
	if contains(r.Strings("resource_signing_alg_values_supported"), "none") {
		issues = append(issues, Errorf("signing-alg-none", spec, "resource_signing_alg_values_supported", "the value none must not be used"))
	}
	if methods := r.Strings("bearer_methods_supported"); len(methods) > 0 {
		for _, method := range methods {
			if method != "header" && method != "body" && method != "query" {
				issues = append(issues, Warnf("bearer-method-unknown", spec, "bearer_methods_supported", "%q is not a method RFC 6750 defines", method))
			}
			if method == "query" {
				issues = append(issues, Warnf("bearer-query", "OAuth 2.1 §5.1", "bearer_methods_supported", "sending tokens in the query string is removed by OAuth 2.1"))
			}
		}
	}
	if !r.hasMember("scopes_supported") {
		issues = append(issues, Warnf("scopes-missing", spec, "scopes_supported", "scopes_supported is recommended"))
	}
	if !r.hasMember("resource_name") {
		issues = append(issues, Warnf("resource-name-missing", spec, "resource_name", "resource_name is recommended"))
	}
	return issues
}

func (r *ResourceMetadata) hasMember(name string) bool {
	_, ok := r.Raw[name]
	return ok
}

// Has reports whether a member is present.
func (r *ResourceMetadata) Has(name string) bool { return r.hasMember(name) }

// Challenge is a parsed WWW-Authenticate challenge.
type Challenge struct {
	Scheme string
	Params map[string]string
}

// ParseChallenges decodes every challenge of a WWW-Authenticate header. A
// resource may offer several schemes in one header (for example DPoP and
// Bearer), separated by commas like the parameters themselves; a new challenge
// starts wherever a token is followed by a space rather than "=".
func ParseChallenges(header string) []*Challenge {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}
	var out []*Challenge
	var current *Challenge
	for _, part := range splitParams(header) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		scheme, rest, hasSpace := strings.Cut(part, " ")
		if !strings.Contains(scheme, "=") && (hasSpace || !strings.Contains(part, "=")) {
			current = &Challenge{Scheme: scheme, Params: map[string]string{}}
			out = append(out, current)
			part = rest
			if part == "" {
				continue
			}
		}
		if current == nil {
			current = &Challenge{Scheme: "", Params: map[string]string{}}
			out = append(out, current)
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		current.Params[strings.ToLower(strings.TrimSpace(name))] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return out
}

// ParseChallenge returns the Bearer challenge of a WWW-Authenticate header
// when there is one, otherwise the first challenge. RFC 6750 §3 puts error,
// scope and realm there; RFC 9728 §5.1 adds resource_metadata.
func ParseChallenge(header string) *Challenge {
	challenges := ParseChallenges(header)
	if len(challenges) == 0 {
		return nil
	}
	for _, challenge := range challenges {
		if strings.EqualFold(challenge.Scheme, "Bearer") {
			return challenge
		}
	}
	return challenges[0]
}

// splitParams splits on commas outside quotes.
func splitParams(text string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	for _, r := range text {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ',' && !inQuotes:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

// ProbeResource sends an unauthenticated request to a resource and returns
// the challenge it answers with.
func (c *Client) ProbeResource(ctx context.Context, resource string) (*Challenge, *Response, error) {
	req, err := http.NewRequest(http.MethodGet, resource, nil)
	if err != nil {
		return nil, nil, err
	}
	response, err := c.Do(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	return ParseChallenge(response.Header.Get("WWW-Authenticate")), response, nil
}
