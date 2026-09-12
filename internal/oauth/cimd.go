package oauth

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Southclaws/oauthcli/internal/cligen"
)

// CIMDSpec names the client ID metadata document draft.
const CIMDSpec = "draft-ietf-oauth-client-id-metadata-document"

// FetchCIMD fetches and validates a client ID metadata document.
func (c *Client) FetchCIMD(ctx context.Context, clientID string) (map[string]any, []cligen.Issue, error) {
	issues := ValidateCIMDURL(clientID)
	if HasErrors(issues) {
		return nil, issues, fmt.Errorf("%s is not a valid client ID URL", clientID)
	}
	response, err := c.Get(ctx, clientID)
	if err != nil {
		return nil, issues, err
	}
	if response.Status != 200 {
		return nil, issues, fmt.Errorf("%w: %s: HTTP %d (the document must be served with 200 and redirects are not followed, %s §5)", ErrUnreachable, clientID, response.Status, CIMDSpec)
	}
	if !response.IsJSON() {
		issues = append(issues, Warnf("content-type", CIMDSpec+" §4", "", "Content-Type is %q; the document must be JSON, served as application/json or a more specific +json type", response.Header.Get("Content-Type")))
	}
	document, err := response.JSON()
	if err != nil {
		return nil, issues, err
	}
	issues = append(issues, ValidateCIMD(clientID, document)...)
	return document, issues, nil
}

// ValidateCIMDURL applies the URL rules of the draft: https, a host, a path
// component, no fragment, no credentials, no dot segments.
func ValidateCIMDURL(clientID string) []cligen.Issue {
	var issues []cligen.Issue
	const spec = CIMDSpec + " §3"
	u, err := url.Parse(clientID)
	if err != nil || u.Host == "" {
		return append(issues, Errorf("client-id-not-url", spec, "client_id", "%q is not an absolute URL", clientID))
	}
	if u.Scheme != "https" {
		issues = append(issues, Errorf("client-id-not-https", spec, "client_id", "the client ID URL must use https"))
	}
	switch u.Path {
	case "":
		issues = append(issues, Errorf("client-id-no-path", spec, "client_id", "the client ID URL must have a path component"))
	case "/":
		issues = append(issues, Warnf("client-id-root-path", spec, "client_id", "a path of / is not recommended"))
	}
	if u.Fragment != "" {
		issues = append(issues, Errorf("client-id-fragment", spec, "client_id", "the client ID URL must not have a fragment"))
	}
	if u.RawQuery != "" {
		issues = append(issues, Warnf("client-id-query", spec, "client_id", "the client ID URL should not have a query component"))
	}
	if u.User != nil {
		issues = append(issues, Errorf("client-id-userinfo", spec, "client_id", "the client ID URL must not carry credentials"))
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			issues = append(issues, Errorf("client-id-dot-segments", spec, "client_id", "the client ID URL must not contain single-dot or double-dot path segments"))
			break
		}
	}
	return issues
}

// ValidateCIMD applies the document rules of the draft.
func ValidateCIMD(clientID string, document map[string]any) []cligen.Issue {
	var issues []cligen.Issue
	const spec = CIMDSpec + " §4"

	claimed, _ := document["client_id"].(string)
	switch {
	case claimed == "":
		issues = append(issues, Errorf("client-id-missing", spec, "client_id", "client_id is required and must equal the document URL"))
	case claimed != clientID:
		issues = append(issues, Errorf("client-id-mismatch", spec, "client_id", "client_id is %q but the document was fetched from %q", claimed, clientID))
	}

	grants := stringList(document["grant_types"])
	redirectBased := len(grants) == 0 || contains(grants, "authorization_code") || contains(grants, "implicit")
	redirects, _ := document["redirect_uris"].([]any)
	if len(redirects) == 0 && redirectBased {
		issues = append(issues, Warnf("redirect-uris-missing", CIMDSpec+" §4.2", "redirect_uris", "redirect_uris is absent; a client using the authorization code grant needs it"))
	}
	for _, item := range redirects {
		text, ok := item.(string)
		if !ok {
			issues = append(issues, Errorf("redirect-uri-type", "RFC 7591 §2", "redirect_uris", "redirect_uris must be an array of strings"))
			continue
		}
		u, err := url.Parse(text)
		if err != nil || u.Host == "" && !strings.HasPrefix(text, "http://127.0.0.1") {
			issues = append(issues, Errorf("redirect-uri-invalid", CIMDSpec+" §4.2", "redirect_uris", "%q is not an absolute URL", text))
			continue
		}
		if u.Scheme == "http" && !IsLoopback(u.Hostname()) {
			issues = append(issues, Warnf("redirect-uri-http", "OAuth 2.1 §2.3.1", "redirect_uris", "%q uses http beyond loopback", text))
		}
	}

	if method, ok := document["token_endpoint_auth_method"].(string); ok {
		switch method {
		case "none", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth":
		case "client_secret_basic", "client_secret_post", "client_secret_jwt":
			issues = append(issues, Errorf("shared-secret-auth", CIMDSpec+" §4.1", "token_endpoint_auth_method", "a URL-identified client has no shared secret with the server; %s must not be used", method))
		default:
			issues = append(issues, Warnf("auth-method-unknown", CIMDSpec+" §4.1", "token_endpoint_auth_method", "%q is not a registered method", method))
		}
		if method == "private_key_jwt" {
			_, hasJWKS := document["jwks"]
			jwksURI, _ := document["jwks_uri"].(string)
			if !hasJWKS && jwksURI == "" {
				issues = append(issues, Errorf("jwks-missing", CIMDSpec+" §4.1, §8.2", "jwks_uri", "private_key_jwt needs jwks or jwks_uri so the server can find the client's key"))
			}
		}
	} else {
		issues = append(issues, Warnf("auth-method-default", CIMDSpec+" §4.1, RFC 7591 §2", "token_endpoint_auth_method", "token_endpoint_auth_method is absent; RFC 7591 defaults it to client_secret_basic, which a URL-identified client cannot use, so it should be set explicitly"))
	}

	if _, ok := document["client_secret"]; ok {
		issues = append(issues, Errorf("client-secret-published", CIMDSpec+" §4.1", "client_secret", "a public document must not contain a client_secret"))
	}
	if _, ok := document["client_secret_expires_at"]; ok {
		issues = append(issues, Errorf("client-secret-expiry-published", CIMDSpec+" §4.1", "client_secret_expires_at", "client_secret_expires_at must not be used"))
	}
	if jwks, ok := document["jwks"].(map[string]any); ok {
		if keys, ok := jwks["keys"].([]any); ok {
			for _, item := range keys {
				key, _ := item.(map[string]any)
				for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
					if _, private := key[member]; private {
						issues = append(issues, Errorf("jwks-private-key", CIMDSpec+" §4.1", "jwks", "the embedded key set contains private key material (%s)", member))
						break
					}
				}
			}
		}
	}
	if name, _ := document["client_name"].(string); name == "" {
		issues = append(issues, Infof("client-name-missing", "RFC 7591 §2", "client_name", "client_name is recommended so consent screens can show who is asking"))
	}
	return issues
}

func stringList(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// CIMDTemplate builds a document to host at clientID.
func CIMDTemplate(clientID, name string, redirectURIs, grantTypes []string, authMethod, jwksURI string) map[string]any {
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	document := map[string]any{
		"client_id":                  clientID,
		"client_name":                name,
		"redirect_uris":              redirectURIs,
		"grant_types":                grantTypes,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethod,
	}
	if jwksURI != "" {
		document["jwks_uri"] = jwksURI
	}
	if u, err := url.Parse(clientID); err == nil {
		document["client_uri"] = u.Scheme + "://" + u.Host
	}
	return document
}
