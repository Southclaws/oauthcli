// Package rfcs embeds the verbatim text of the specifications the checks
// cite, so a finding can be read next to the sentence that defines it
// without leaving the terminal.
//
// The IETF documents are reproduced in full and without modification under
// the IETF Trust Legal Provisions; the OpenID Foundation documents under the
// licence in their own Notices appendix, for the purpose of implementing the
// specifications. Each text carries its own copyright notice.
package rfcs

import (
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed *.txt
var files embed.FS

// Spec describes one embedded specification.
type Spec struct {
	ID    string
	Title string
	File  string
	URL   string
	// Aliases are other ids that select the same specification.
	Aliases []string
}

// Specs lists every embedded specification in citation order.
var Specs = []Spec{
	{"rfc6749", "The OAuth 2.0 Authorization Framework", "rfc6749-oauth2-authorization-framework.txt", "https://www.rfc-editor.org/rfc/rfc6749", nil},
	{"rfc6750", "Bearer Token Usage", "rfc6750-bearer-token-usage.txt", "https://www.rfc-editor.org/rfc/rfc6750", nil},
	{"oauth2.1", "The OAuth 2.1 Authorization Framework (draft-ietf-oauth-v2-1)", "draft-oauth-v2-1.txt", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1", []string{"oauth21", "2.1", "v2-1"}},
	{"rfc9700", "Best Current Practice for OAuth 2.0 Security", "rfc9700-oauth2-security-best-current-practice.txt", "https://www.rfc-editor.org/rfc/rfc9700", []string{"bcp240", "security-bcp"}},
	{"rfc7636", "Proof Key for Code Exchange (PKCE)", "rfc7636-pkce.txt", "https://www.rfc-editor.org/rfc/rfc7636", []string{"pkce"}},
	{"rfc8252", "OAuth 2.0 for Native Apps", "rfc8252-oauth2-for-native-apps.txt", "https://www.rfc-editor.org/rfc/rfc8252", []string{"native-apps"}},
	{"rfc8414", "Authorization Server Metadata", "rfc8414-authorization-server-metadata.txt", "https://www.rfc-editor.org/rfc/rfc8414", []string{"metadata"}},
	{"rfc7591", "Dynamic Client Registration Protocol", "rfc7591-dynamic-client-registration.txt", "https://www.rfc-editor.org/rfc/rfc7591", []string{"dcr"}},
	{"rfc7592", "Dynamic Client Registration Management Protocol", "rfc7592-dynamic-client-registration-management.txt", "https://www.rfc-editor.org/rfc/rfc7592", nil},
	{"rfc7662", "Token Introspection", "rfc7662-token-introspection.txt", "https://www.rfc-editor.org/rfc/rfc7662", []string{"introspection"}},
	{"rfc7009", "Token Revocation", "rfc7009-token-revocation.txt", "https://www.rfc-editor.org/rfc/rfc7009", []string{"revocation"}},
	{"rfc8628", "Device Authorization Grant", "rfc8628-device-authorization-grant.txt", "https://www.rfc-editor.org/rfc/rfc8628", []string{"device"}},
	{"rfc9126", "Pushed Authorization Requests", "rfc9126-pushed-authorization-requests.txt", "https://www.rfc-editor.org/rfc/rfc9126", []string{"par"}},
	{"rfc9449", "Demonstrating Proof of Possession (DPoP)", "rfc9449-dpop.txt", "https://www.rfc-editor.org/rfc/rfc9449", []string{"dpop"}},
	{"rfc8707", "Resource Indicators", "rfc8707-resource-indicators.txt", "https://www.rfc-editor.org/rfc/rfc8707", []string{"resource-indicators"}},
	{"rfc7523", "JWT Profile for Client Authentication and Authorization Grants", "rfc7523-jwt-bearer-assertion.txt", "https://www.rfc-editor.org/rfc/rfc7523", []string{"jwt-bearer"}},
	{"rfc8693", "Token Exchange", "rfc8693-token-exchange.txt", "https://www.rfc-editor.org/rfc/rfc8693", []string{"token-exchange"}},
	{"rfc9068", "JWT Profile for OAuth 2.0 Access Tokens", "rfc9068-jwt-profile-for-access-tokens.txt", "https://www.rfc-editor.org/rfc/rfc9068", []string{"at-jwt"}},
	{"rfc9207", "Authorization Server Issuer Identification", "rfc9207-authorization-server-issuer-identification.txt", "https://www.rfc-editor.org/rfc/rfc9207", nil},
	{"rfc9728", "Protected Resource Metadata", "rfc9728-protected-resource-metadata.txt", "https://www.rfc-editor.org/rfc/rfc9728", []string{"prm"}},
	{"cimd", "OAuth Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document)", "draft-ietf-oauth-client-id-metadata-document.txt", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document", []string{"client-id-metadata-document"}},
	{"rfc7519", "JSON Web Token (JWT)", "rfc7519-jwt.txt", "https://www.rfc-editor.org/rfc/rfc7519", []string{"jwt"}},
	{"rfc7517", "JSON Web Key (JWK)", "rfc7517-jwk.txt", "https://www.rfc-editor.org/rfc/rfc7517", []string{"jwk"}},
	{"rfc7518", "JSON Web Algorithms (JWA)", "rfc7518-jwa.txt", "https://www.rfc-editor.org/rfc/rfc7518", []string{"jwa"}},
	{"rfc7638", "JSON Web Key (JWK) Thumbprint", "rfc7638-jwk-thumbprint.txt", "https://www.rfc-editor.org/rfc/rfc7638", []string{"thumbprint"}},
	{"rfc8725", "JSON Web Token Best Current Practices", "rfc8725-jwt-best-current-practices.txt", "https://www.rfc-editor.org/rfc/rfc8725", []string{"jwt-bcp"}},
	{"rfc8996", "Deprecating TLS 1.0 and TLS 1.1 (BCP 195)", "rfc8996-deprecating-tls-1.0-1.1.txt", "https://www.rfc-editor.org/rfc/rfc8996", nil},
	{"rfc9325", "Recommendations for Secure Use of TLS and DTLS (BCP 195)", "rfc9325-tls-recommendations.txt", "https://www.rfc-editor.org/rfc/rfc9325", []string{"bcp195"}},
	{"oidc-core", "OpenID Connect Core 1.0", "openid-connect-core-1_0.txt", "https://openid.net/specs/openid-connect-core-1_0.html", []string{"oidc", "openid-connect-core", "core"}},
	{"oidc-discovery", "OpenID Connect Discovery 1.0", "openid-connect-discovery-1_0.txt", "https://openid.net/specs/openid-connect-discovery-1_0.html", []string{"discovery", "openid-configuration", "openid-connect-discovery"}},
}

// Find resolves an id, alias, bare RFC number or file name.
func Find(query string) (*Spec, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	q = strings.TrimPrefix(q, "§")
	if _, err := fmt.Sscanf(q, "%d", new(int)); err == nil && !strings.HasPrefix(q, "rfc") && !strings.Contains(q, ".") {
		q = "rfc" + q
	}
	q = strings.ReplaceAll(q, "rfc ", "rfc")
	for i := range Specs {
		spec := &Specs[i]
		if q == spec.ID || q == strings.TrimSuffix(spec.File, ".txt") || q == spec.File {
			return spec, nil
		}
		for _, alias := range spec.Aliases {
			if q == alias {
				return spec, nil
			}
		}
	}
	ids := make([]string, 0, len(Specs))
	for _, spec := range Specs {
		ids = append(ids, spec.ID)
	}
	sort.Strings(ids)
	return nil, fmt.Errorf("no specification %q; available: %s", query, strings.Join(ids, ", "))
}

// Text returns the full text of a specification.
func Text(spec *Spec) (string, error) {
	data, err := files.ReadFile(spec.File)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Size returns the size of a specification's text in bytes.
func Size(spec *Spec) int {
	data, err := files.ReadFile(spec.File)
	if err != nil {
		return 0
	}
	return len(data)
}

var (
	// headingPattern matches "5.2.  Error Response" and "4.1.2.1.  Title".
	headingPattern = regexp.MustCompile(`^(\d+(?:\.\d+)*)\.?\s{1,3}\S`)
	// appendixPattern matches "Appendix B.  Notices".
	appendixPattern = regexp.MustCompile(`^Appendix ([A-Z])(?:\.\d+)*\.?\s`)
	// pageFooter and pageHeader are the RFC page furniture.
	pageFooter = regexp.MustCompile(`\[Page \d+\]\s*$`)
	pageHeader = regexp.MustCompile(`^(RFC \d+|Internet-Draft)\s.*\s(January|February|March|April|May|June|July|August|September|October|November|December) \d{4}\s*$`)
)

// Section extracts one numbered section and its subsections from a text.
// Page headers and footers are removed so the section reads continuously.
func Section(text, number string) (string, error) {
	number = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(number), "§"), ".")
	if number == "" {
		return "", fmt.Errorf("no section given")
	}
	appendix := ""
	if strings.HasPrefix(strings.ToLower(number), "appendix ") {
		appendix = strings.ToUpper(strings.TrimSpace(number[len("appendix "):]))
	} else if len(number) == 1 && number[0] >= 'A' && number[0] <= 'Z' {
		appendix = number
	}

	var out []string
	capturing := false
	// The OpenID texts separate a heading number from its title with a
	// non-breaking space, which Go's \s does not match.
	text = strings.ReplaceAll(text, "\u00a0", " ")
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		clean := strings.TrimRight(strings.ReplaceAll(line, "\f", ""), " \r")
		if pageFooter.MatchString(clean) || pageHeader.MatchString(clean) || isNavigation(clean) {
			continue
		}
		// A heading stands alone before a blank line; a numbered list item
		// is followed by an indented continuation or the next item.
		heading := i+1 >= len(lines) || strings.TrimSpace(lines[i+1]) == ""
		if match := headingPattern.FindStringSubmatch(clean); match != nil && appendix == "" && heading {
			found := match[1]
			if found == number {
				capturing = true
			} else if capturing && isSuccessor(found, number) {
				break
			}
		} else if match := appendixPattern.FindStringSubmatch(clean); match != nil {
			if appendix != "" && match[1] == appendix {
				capturing = true
			} else if capturing {
				break
			}
		}
		if capturing {
			out = append(out, clean)
		}
	}
	if !capturing {
		return "", fmt.Errorf("section %s not found", number)
	}
	return strings.TrimSpace(collapseBlankLines(strings.Join(out, "\n"))) + "\n", nil
}

// isNavigation matches the "TOC" back-links the OpenID texts print between
// sections.
func isNavigation(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "TOC" || (trimmed != "" && strings.Trim(trimmed, "-") == "")
}

// isSuccessor reports whether heading number found comes after want in
// document order without being one of its subsections: a sibling such as
// 5.3 after 5.2, or an ancestor's sibling such as 6 after 5.2. Numbered list
// items inside a section ("1.", "2.") sort before the section and so do not
// end it.
func isSuccessor(found, want string) bool {
	a := strings.Split(found, ".")
	b := strings.Split(want, ".")
	for i := 0; i < len(a) && i < len(b); i++ {
		var x, y int
		fmt.Sscanf(a[i], "%d", &x)
		fmt.Sscanf(b[i], "%d", &y)
		if x != y {
			return x > y
		}
	}
	return false
}

// collapseBlankLines reduces runs of blank lines left by removed page breaks.
func collapseBlankLines(text string) string {
	for strings.Contains(text, "\n\n\n") {
		text = strings.ReplaceAll(text, "\n\n\n", "\n\n")
	}
	return text
}
