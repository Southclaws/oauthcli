package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/jose"
)

// InspectOptions tune how a token is described.
type InspectOptions struct {
	// Verifier verifies the signature; nil skips verification.
	Verifier *Verifier
	// ExpectedIssuer, when set, must equal the iss claim.
	ExpectedIssuer string
	// ExpectedAudience, when set, must be in the aud claim (ID tokens).
	ExpectedAudience string
	// Nonce, when set, must equal the nonce claim (ID tokens).
	Nonce string
	// IDToken applies the OpenID Connect Core §3.1.3.7 rules.
	IDToken bool
	// AccessToken applies the RFC 9068 rules where the token claims to be one.
	AccessToken bool
	// Leeway tolerates clock skew on exp and nbf.
	Leeway time.Duration
}

// Inspect decodes a token, checks its timestamps and, with a verifier, its
// signature. An opaque token yields a TokenInfo of kind opaque.
func Inspect(ctx context.Context, token string, opts InspectOptions) (cligen.TokenInfo, *jose.JWS) {
	info := cligen.TokenInfo{Kind: "opaque", Issues: []cligen.Issue{}}
	jws, err := jose.Parse(token)
	if err != nil {
		switch {
		case strings.Count(strings.TrimSpace(token), ".") == 4:
			info.Issues = append(info.Issues, Infof("encrypted-jwt", "RFC 7519 §7.2", "", "the token is an encrypted JWT (JWE), which this tool does not decrypt"))
		case !errors.Is(err, jose.ErrNotJWT):
			info.Issues = append(info.Issues, Warnf("token-undecodable", "", "", "%v", err))
		}
		return info, nil
	}

	info.Kind = "jwt"
	header := cligen.Document(jws.Header)
	claims := cligen.Document(jws.Claims)
	info.Header = &header
	info.Claims = &claims
	info.Timing = timing(jws, opts.Leeway)

	const rfc7519 = "RFC 7519 §4.1"
	typ := jws.Typ()
	// RFC 9068 binds only tokens that declare its media type; a JWT access
	// token without it is a plain JWT and is graded under RFC 7519 alone.
	atJWT := strings.EqualFold(typ, "at+jwt") || strings.EqualFold(typ, "application/at+jwt")
	profile := opts.IDToken || atJWT

	for _, claim := range []string{"exp", "nbf", "iat"} {
		if value, ok := jws.Claims[claim]; ok {
			if _, numeric := numericValue(value); !numeric {
				info.Issues = append(info.Issues, Errorf("claim-not-numeric", numericDateSection(claim), claim, "%s must be a NumericDate (JSON number); got %T", claim, value))
			}
		}
	}
	if value, ok := jws.Claims["aud"]; ok {
		if _, isString := value.(string); !isString {
			if items, isArray := value.([]any); !isArray || len(jws.Strings("aud")) != len(items) {
				info.Issues = append(info.Issues, Errorf("aud-type", "RFC 7519 §4.1.3", "aud", "aud must be a string or an array of strings"))
			}
		}
	}
	if info.Timing.Expired {
		info.Issues = append(info.Issues, Errorf("expired", rfc7519+".4", "exp", "the token expired %s ago", render(-durationUntil(*info.Timing.ExpiresAt))))
	}
	if info.Timing.NotYetValid != nil && *info.Timing.NotYetValid {
		info.Issues = append(info.Issues, Errorf("not-yet-valid", rfc7519+".5", "nbf", "the token is not valid before %s", info.Timing.NotBefore.Format(time.RFC3339)))
	}
	if info.Timing.ExpiresAt == nil && !profile {
		info.Issues = append(info.Issues, Infof("no-exp", rfc7519+".4", "exp", "the token has no expiry (optional in RFC 7519)"))
	}
	switch {
	case jws.Alg() == "":
		info.Issues = append(info.Issues, Errorf("alg-missing", "RFC 7515 §4.1.1", "alg", "the header has no alg; it is required in every JWS"))
	case jws.Alg() == "none":
		spec := "RFC 7518 §3.6, RFC 8725 §3.2"
		switch {
		case atJWT:
			spec = "RFC 9068 §2.1, §4"
		case opts.IDToken:
			spec = "OpenID Connect Core 1.0 §2"
		}
		info.Issues = append(info.Issues, Errorf("alg-none", spec, "alg", "the token is unsigned; implementations must not accept unsecured JWTs by default"))
		if len(jws.Signature) > 0 {
			info.Issues = append(info.Issues, Errorf("none-with-signature", "RFC 7518 §3.6", "alg", "alg is none but the signature segment is not empty"))
		}
	}
	if strings.HasPrefix(jws.Alg(), "HS") {
		if atJWT || opts.AccessToken {
			info.Issues = append(info.Issues, Warnf("symmetric-alg", "RFC 9068 §2.1", "alg", "%s uses a shared secret; asymmetric cryptography is recommended for access tokens", jws.Alg()))
		} else if opts.IDToken {
			info.Issues = append(info.Issues, Infof("symmetric-alg", "OpenID Connect Core 1.0 §10.1", "alg", "%s uses the client secret as the key, which Core permits for confidential clients", jws.Alg()))
		}
	}
	if opts.AccessToken && !atJWT && !opts.IDToken {
		info.Issues = append(info.Issues, Infof("typ-not-at-jwt", "RFC 9068 §2.1", "typ", "typ is %q, so the RFC 9068 access token profile does not apply", typ))
	}
	if atJWT {
		for _, claim := range []string{"iss", "exp", "aud", "sub", "client_id", "iat", "jti"} {
			if _, ok := jws.Claims[claim]; !ok {
				info.Issues = append(info.Issues, Errorf("claim-missing", "RFC 9068 §2.2", claim, "a JWT access token must carry %s", claim))
			}
		}
	}
	if opts.ExpectedIssuer != "" {
		iss := jws.String("iss")
		spec := "RFC 9068 §4"
		if opts.IDToken {
			spec = "OpenID Connect Core 1.0 §3.1.3.7"
		}
		switch {
		case iss == opts.ExpectedIssuer:
		case strings.TrimRight(iss, "/") == strings.TrimRight(opts.ExpectedIssuer, "/"):
			info.Issues = append(info.Issues, Warnf("issuer-trailing-slash", spec, "iss", "iss is %q and the issuer is %q; they differ only by a trailing slash, which a strict client treats as a mismatch", iss, opts.ExpectedIssuer))
		default:
			info.Issues = append(info.Issues, Errorf("issuer-mismatch", spec, "iss", "iss is %q, want exactly %q", iss, opts.ExpectedIssuer))
		}
	}

	if opts.IDToken {
		info.Issues = append(info.Issues, idTokenIssues(jws, opts)...)
	}

	if opts.Verifier != nil {
		signature := opts.Verifier.Verify(ctx, jws)
		info.Signature = &signature
		switch signature.Status {
		case "invalid":
			info.Issues = append(info.Issues, Errorf("signature-invalid", "RFC 7515 §5.2", "", "signature verification failed: %s", deref(signature.Error)))
		case "unverified":
			info.Issues = append(info.Issues, Warnf("signature-unverified", "", "", "signature not verified: %s", deref(signature.Error)))
		}
	} else {
		alg := jws.Alg()
		signature := cligen.Signature{Status: "unverified"}
		if alg != "" {
			signature.Alg = &alg
		}
		if alg == "" || alg == "none" {
			signature.Status = "unsigned"
		}
		if kid := jws.Kid(); kid != "" {
			signature.Kid = &kid
		}
		info.Signature = &signature
	}

	return info, jws
}

func numericDateSection(claim string) string {
	switch claim {
	case "exp":
		return "RFC 7519 §4.1.4"
	case "nbf":
		return "RFC 7519 §4.1.5"
	default:
		return "RFC 7519 §4.1.6"
	}
}

func numericValue(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}

func idTokenIssues(jws *jose.JWS, opts InspectOptions) []cligen.Issue {
	const core = "OpenID Connect Core 1.0 §3.1.3.7"
	var issues []cligen.Issue
	for _, claim := range []string{"iss", "sub", "aud", "exp", "iat"} {
		if _, ok := jws.Claims[claim]; !ok {
			issues = append(issues, Errorf("claim-missing", "OpenID Connect Core 1.0 §2", claim, "an ID token must carry %s", claim))
		}
	}
	if iss := jws.String("iss"); iss != "" {
		if u, err := url.Parse(iss); err != nil || u.Scheme != "https" || u.RawQuery != "" || u.Fragment != "" {
			if !(u != nil && IsLoopback(u.Hostname())) {
				issues = append(issues, Errorf("iss-form", "OpenID Connect Core 1.0 §2", "iss", "iss must be an https URL with no query or fragment; got %q", iss))
			}
		}
	}
	audiences := jws.Strings("aud")
	if opts.ExpectedAudience != "" && !contains(audiences, opts.ExpectedAudience) {
		issues = append(issues, Errorf("audience-mismatch", core, "aud", "aud %v does not include the client %q", audiences, opts.ExpectedAudience))
	}
	if azp := jws.String("azp"); azp != "" && opts.ExpectedAudience != "" && azp != opts.ExpectedAudience {
		issues = append(issues, Errorf("azp-mismatch", "OpenID Connect Core 1.0 §2", "azp", "azp is %q; when present it must be the client id %q", azp, opts.ExpectedAudience))
	}
	if opts.Nonce != "" {
		if nonce := jws.String("nonce"); nonce != opts.Nonce {
			issues = append(issues, Errorf("nonce-mismatch", core, "nonce", "nonce is %q, want the value sent in the request", nonce))
		}
	}
	if sub := jws.String("sub"); len(sub) > 255 {
		issues = append(issues, Errorf("sub-too-long", "OpenID Connect Core 1.0 §2", "sub", "sub is %d characters; the limit is 255", len(sub)))
	}
	return issues
}

func timing(jws *jose.JWS, leeway time.Duration) *cligen.Timing {
	out := &cligen.Timing{}
	now := time.Now()
	if iat, ok := jws.Time("iat"); ok {
		out.IssuedAt = &iat
	}
	if nbf, ok := jws.Time("nbf"); ok {
		out.NotBefore = &nbf
		notYet := now.Add(leeway).Before(nbf)
		out.NotYetValid = &notYet
	}
	if exp, ok := jws.Time("exp"); ok {
		out.ExpiresAt = &exp
		out.Expired = now.Add(-leeway).After(exp)
		remaining := render(exp.Sub(now))
		out.ExpiresIn = &remaining
		if out.IssuedAt != nil {
			lifetime := render(exp.Sub(*out.IssuedAt))
			out.Lifetime = &lifetime
		}
	}
	return out
}

func durationUntil(t time.Time) time.Duration { return time.Until(t) }

// render formats a duration the way the report shows it.
func render(d time.Duration) string {
	negative := d < 0
	if negative {
		d = -d
	}
	d = d.Round(time.Second)
	var text string
	switch {
	case d >= 48*time.Hour:
		text = fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		text = fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		text = fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		text = fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if negative {
		return "-" + text
	}
	return text
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
