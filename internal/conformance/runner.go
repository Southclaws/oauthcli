// Package conformance audits an authorization server against the OAuth and
// OpenID specifications and produces a checklist with a verdict per
// specification.
package conformance

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/oauth"
)

// Check statuses.
const (
	Pass     = "pass"
	Fail     = "fail"
	Warn     = "warn"
	Skip     = "skip"
	Untested = "untested"
)

// Spec verdicts.
const (
	Conformant    = "conformant"
	NonConformant = "non-conformant"
	NotSupported  = "not-supported"
	NotTested     = "not-tested"
)

// Options configure an audit.
type Options struct {
	Issuer      string
	Credentials *oauth.Credentials
	Scopes      []string
	Audience    string
	Resources   []string
	// Token is a user-supplied access token to validate. It is never revoked.
	Token string
	// RefreshToken exercises the refresh_token grant when given.
	RefreshToken string
	// ResourceURLs are protected resources to check RFC 9728 metadata for.
	ResourceURLs []string
	// RedirectURI is used for authorization endpoint probes.
	RedirectURI string
	// Offline skips every request that needs credentials.
	Offline bool
	// Register opts in to dynamic client registration checks.
	Register bool
	// Negative opts in to the wrong-secret probe.
	Negative bool
	// InitialToken authorizes dynamic registration when the server requires one.
	InitialToken string
	// DPoPKey, when set, is used for the DPoP check; otherwise a key is
	// generated.
	DPoPKey string
	// Only and Skip filter specifications by id.
	Only []string
	Skip []string
	// AllowHTTP relaxes the https rules.
	AllowHTTP bool
	// Insecure records that TLS verification was disabled, so the
	// certificate check is reported as skipped.
	Insecure bool
	// Progress, when set, receives every check as it completes.
	Progress func(spec *Spec, check cligen.Check)
}

// Spec collects the checks of one specification.
type Spec struct {
	ID     string
	Title  string
	URL    string
	Checks []cligen.Check
	// supported records the presence test; nil means unknown.
	supported *bool
	// unsupportedReason explains a not-supported verdict.
	unsupportedReason string
	runner            *Runner
}

// Runner holds the state an audit accumulates: the metadata, the key set,
// and any token it obtained.
type Runner struct {
	Client   *oauth.Client
	Options  Options
	Metadata *oauth.Metadata
	// OpenID is the openid-configuration document when the primary metadata
	// came from RFC 8414 and the OpenID document also exists.
	OpenID *oauth.Metadata
	Keys   *oauth.KeySet
	// Obtained is the client credentials token the audit got for itself.
	Obtained *oauth.TokenResult
	// refreshed is the result of the refresh_token grant, when it ran.
	refreshed *oauth.TokenResult
	// clientRecognised records that the token endpoint accepted the client's
	// identity (any answer other than invalid_client), so a later
	// invalid_client from another endpoint points at that endpoint.
	clientRecognised bool
	// grantUnavailable explains why the client credentials grant could not
	// be used, so dependent checks read as untested instead of failed.
	grantUnavailable string
	specs            []*Spec
	started          time.Time
}

// New prepares an audit.
func New(client *oauth.Client, opts Options) *Runner {
	return &Runner{Client: client, Options: opts}
}

// hasCredentials reports whether the token endpoint can be exercised.
func (r *Runner) hasCredentials() bool {
	if r.Options.Offline || r.Options.Credentials == nil || r.Options.Credentials.ClientID == "" {
		return false
	}
	return r.Options.Credentials.ClientSecret != "" || r.Options.Credentials.Key != nil
}

// clientID is the client id for anonymous probes that need one.
func (r *Runner) clientID() string {
	if r.Options.Credentials == nil {
		return ""
	}
	return r.Options.Credentials.ClientID
}

func (r *Runner) spec(id, title, url string) *Spec {
	s := &Spec{ID: id, Title: title, URL: url, Checks: []cligen.Check{}, runner: r}
	r.specs = append(r.specs, s)
	return s
}

func (r *Runner) wanted(id string) bool {
	if len(r.Options.Skip) > 0 && containsFold(r.Options.Skip, id) {
		return false
	}
	if len(r.Options.Only) > 0 {
		return containsFold(r.Options.Only, id)
	}
	return true
}

func containsFold(items []string, value string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return true
		}
	}
	return false
}

// add records a check and reports it.
func (s *Spec) add(check cligen.Check) {
	if check.Spec == nil {
		check.Spec = &s.Title
	}
	s.Checks = append(s.Checks, check)
	if s.runner.Options.Progress != nil {
		s.runner.Options.Progress(s, check)
	}
}

func (s *Spec) check(status, id, title, section, detail string) {
	check := cligen.Check{ID: s.ID + "." + id, Title: title, Status: status}
	if section != "" {
		check.Section = &section
	}
	if detail != "" {
		check.Detail = &detail
	}
	s.add(check)
}

func (s *Spec) pass(id, title, section, detail string) { s.check(Pass, id, title, section, detail) }
func (s *Spec) fail(id, title, section, detail string) { s.check(Fail, id, title, section, detail) }
func (s *Spec) warn(id, title, section, detail string) { s.check(Warn, id, title, section, detail) }
func (s *Spec) skip(id, title, section, detail string) { s.check(Skip, id, title, section, detail) }
func (s *Spec) untested(id, title, section, detail string) {
	s.check(Untested, id, title, section, detail)
}

// supportedIf records the presence test of a specification.
func (s *Spec) supportedIf(ok bool, reason string) {
	s.supported = &ok
	if !ok {
		s.unsupportedReason = reason
	}
}

// requirement grades a boolean: pass when ok, otherwise fail or warn.
func (s *Spec) requirement(ok bool, severity, id, title, section, okDetail, badDetail string) {
	if ok {
		s.pass(id, title, section, okDetail)
		return
	}
	s.check(severity, id, title, section, badDetail)
}

// fromIssues grades a check by whether a finding with code exists among
// issues: absent is a pass; an error fails, a warning warns, an info passes
// with the message as detail.
func (s *Spec) fromIssues(issues []cligen.Issue, code, id, title, section, okDetail string) {
	for _, issue := range issues {
		if issue.Code != code {
			continue
		}
		check := cligen.Check{ID: s.ID + "." + id, Title: title, Detail: &issue.Message}
		if issue.Spec != nil {
			check.Section = issue.Spec
		} else if section != "" {
			check.Section = &section
		}
		switch issue.Severity {
		case "error":
			check.Status = Fail
		case "warning":
			check.Status = Warn
		default:
			check.Status = Pass
		}
		s.add(check)
		return
	}
	s.pass(id, title, section, okDetail)
}

// fromIssuesAny grades a check from the first finding whose code is in codes,
// reporting whether one was found so the caller can add the pass otherwise.
func (s *Spec) fromIssuesAny(issues []cligen.Issue, codes []string, id, title, section string) bool {
	for _, code := range codes {
		for _, issue := range issues {
			if issue.Code == code {
				s.add(issueCheck(s, issue, id, title))
				return true
			}
		}
	}
	return false
}

// issueCheck converts a finding into a check, mapping severity to status and
// keeping the finding's own section citation.
func issueCheck(s *Spec, issue cligen.Issue, id, title string) cligen.Check {
	check := cligen.Check{ID: s.ID + "." + id, Title: title, Detail: &issue.Message}
	if issue.Spec != nil {
		check.Section = issue.Spec
	}
	switch issue.Severity {
	case "error":
		check.Status = Fail
	case "warning":
		check.Status = Warn
	default:
		check.Status = Pass
	}
	return check
}

// Verdict decides the specification's overall result.
func (s *Spec) Verdict() string {
	if s.supported != nil && !*s.supported {
		return NotSupported
	}
	tested, failed := false, false
	for _, check := range s.Checks {
		switch check.Status {
		case Fail:
			failed = true
			tested = true
		case Pass, Warn:
			tested = true
		}
	}
	switch {
	case failed:
		return NonConformant
	case !tested:
		return NotTested
	default:
		return Conformant
	}
}

// Run executes every wanted specification and assembles the report.
func (r *Runner) Run(ctx context.Context) (cligen.ConformanceReport, error) {
	r.started = time.Now()

	if err := r.discover(ctx); err != nil {
		return cligen.ConformanceReport{}, err
	}

	for _, step := range []struct {
		id  string
		run func(context.Context)
	}{
		{"rfc8414", r.checkMetadata},
		{"oidc-discovery", r.checkOpenIDDiscovery},
		{"tls", r.checkTransport},
		{"rfc7517", r.checkKeys},
		{"rfc6749", r.checkCore},
		{"rfc7636", r.checkPKCE},
		{"oauth2.1", r.checkOAuth21},
		{"rfc9068", r.checkJWTAccessTokens},
		{"rfc6750", r.checkBearer},
		{"oidc-core", r.checkOpenIDCore},
		{"rfc7662", r.checkIntrospection},
		{"rfc8628", r.checkDevice},
		{"rfc9126", r.checkPAR},
		{"rfc9449", r.checkDPoP},
		{"rfc8707", r.checkResourceIndicators},
		{"rfc7523", r.checkJWTClientAuth},
		{"rfc8693", r.checkTokenExchange},
		{"rfc7009", r.checkRevocation},
		{"rfc7591", r.checkRegistration},
		{"rfc9728", r.checkProtectedResource},
		{"rfc9207", r.checkIssuerParameter},
		{"rfc8705", r.checkMTLS},
		{"rfc9101", r.checkJAR},
		{"rfc9396", r.checkRAR},
		{"cimd", r.checkCIMD},
	} {
		if !r.wanted(step.id) {
			continue
		}
		if ctx.Err() != nil {
			return cligen.ConformanceReport{}, ctx.Err()
		}
		step.run(ctx)
	}

	return r.report(), nil
}

// discover fetches the metadata every check depends on. A missing document
// is not fatal here: the metadata specification reports it and everything
// else is marked untested.
func (r *Runner) discover(ctx context.Context) error {
	metadata, err := r.Client.FetchMetadata(ctx, r.Options.Issuer, "auto")
	if err != nil {
		if strings.Contains(err.Error(), oauth.ErrUnreachable.Error()) {
			return err
		}
		return nil
	}
	r.Metadata = metadata
	if r.Options.Credentials != nil && r.Options.Credentials.AssertionAudience == "" {
		r.Options.Credentials.AssertionAudience = metadata.String("token_endpoint")
	}
	if metadata.Kind == oauth.KindOAuth {
		if openid, err := r.Client.FetchMetadata(ctx, r.Options.Issuer, "openid"); err == nil {
			r.OpenID = openid
		}
	}
	if jwks := metadata.String("jwks_uri"); jwks != "" {
		r.Keys, _ = r.Client.FetchKeys(ctx, jwks)
	}
	return nil
}

func (r *Runner) report() cligen.ConformanceReport {
	report := cligen.ConformanceReport{
		Issuer:    r.Options.Issuer,
		StartedAt: r.started,
		ElapsedMs: int(time.Since(r.started).Milliseconds()),
		Specs:     make([]cligen.SpecResult, 0, len(r.specs)),
		Passed:    true,
	}
	credentials := r.hasCredentials()
	report.Credentials = &credentials

	for _, spec := range r.specs {
		result := cligen.SpecResult{ID: spec.ID, Title: spec.Title, Verdict: spec.Verdict(), Checks: spec.Checks}
		if spec.URL != "" {
			result.URL = &spec.URL
		}
		if result.Verdict == NotSupported && spec.unsupportedReason != "" && len(spec.Checks) == 0 {
			result.Checks = append(result.Checks, cligen.Check{ID: spec.ID + ".advertised", Title: spec.unsupportedReason, Status: Skip})
		}
		switch result.Verdict {
		case Conformant:
			report.Summary.Conformant++
		case NonConformant:
			report.Summary.NonConformant++
			report.Passed = false
		case NotSupported:
			report.Summary.NotSupported++
		case NotTested:
			report.Summary.NotTested++
		}
		for _, check := range result.Checks {
			switch check.Status {
			case Pass:
				report.Summary.Pass++
			case Fail:
				report.Summary.Fail++
			case Warn:
				report.Summary.Warn++
			case Skip:
				report.Summary.Skip++
			case Untested:
				report.Summary.Untested++
			}
		}
		report.Specs = append(report.Specs, result)
	}
	return report
}

// advertisedOnly is the shape of a specification the tool can only observe
// through metadata.
func (r *Runner) advertisedOnly(id, title, url string, supported bool, detail string) {
	s := r.spec(id, title, url)
	if r.Metadata == nil {
		s.untested("advertised", "advertised in metadata", "", "no metadata document")
		return
	}
	s.supportedIf(supported, "not advertised")
	if supported {
		s.pass("advertised", "advertised in metadata", "", detail)
	}
}

// obtainToken gets a client credentials token once and keeps it for every
// check that needs one. It returns nil when there are no credentials or the
// grant is not supported.
func (r *Runner) obtainToken(ctx context.Context, dpop *oauth.DPoP) (*oauth.TokenResult, error) {
	if !r.hasCredentials() || r.Metadata == nil {
		return nil, nil
	}
	if dpop == nil && r.Obtained != nil {
		return r.Obtained, nil
	}
	result, err := r.Client.Token(ctx, oauth.TokenRequest{
		Endpoint:    r.Metadata.String("token_endpoint"),
		Grant:       oauth.GrantClientCredentials,
		Credentials: r.Options.Credentials,
		Advertised:  r.Metadata.TokenAuthMethods(),
		Scopes:      r.Options.Scopes,
		Audience:    r.Options.Audience,
		Resources:   r.Options.Resources,
		DPoP:        dpop,
	})
	if err != nil {
		return nil, err
	}
	if dpop == nil {
		r.Obtained = result
	}
	return result, nil
}

// validationToken is the token to validate: the user's, or the one obtained.
func (r *Runner) validationToken(ctx context.Context) string {
	if r.Options.Token != "" {
		return r.Options.Token
	}
	if result, err := r.obtainToken(ctx, nil); err == nil && result != nil {
		return result.AccessToken
	}
	return ""
}

func describeErr(err error) string {
	return fmt.Sprintf("%v", err)
}
