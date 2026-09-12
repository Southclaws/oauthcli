package oauth

import (
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Southclaws/oauthcli/internal/jose"
)

// Client authentication methods, named as token_endpoint_auth_methods_supported
// names them.
const (
	AuthAuto            = "auto"
	AuthBasic           = "client_secret_basic"
	AuthPost            = "client_secret_post"
	AuthSecretJWT       = "client_secret_jwt"
	AuthPrivateKeyJWT   = "private_key_jwt"
	AuthNone            = "none"
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// AuthMethods lists every method the tool can perform.
var AuthMethods = []string{AuthAuto, AuthBasic, AuthPost, AuthSecretJWT, AuthPrivateKeyJWT, AuthNone}

// Credentials identify the client at the token endpoint.
type Credentials struct {
	ClientID     string
	ClientSecret string
	// Key signs client assertions for private_key_jwt.
	Key crypto.Signer
	// KeyID is placed in the assertion header when set.
	KeyID  string
	Method string
	// AssertionAudience is the aud of client assertions. RFC 7523 §3 lets a
	// server accept only its issuer or token endpoint URL, so the token
	// endpoint is used for every endpoint once it is known; without it the
	// endpoint being called is used.
	AssertionAudience string
	// AssertionLifetime is how long a client assertion stays valid; zero
	// means AssertionDefaultLifetime, negative produces an expired assertion
	// for negative tests.
	AssertionLifetime time.Duration
}

// AssertionDefaultLifetime is the exp of a client assertion measured from
// issuance; RFC 7523 §3 asks for a short lifetime.
const AssertionDefaultLifetime = 2 * time.Minute

// LoadKey reads a PEM private key for private_key_jwt.
func LoadKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}
	return jose.ParsePrivateKeyPEM(data)
}

// Resolve picks the method to use. auto prefers what the server advertises
// and the credentials allow: private_key_jwt with a key, client_secret_basic
// with a secret, or none for a public client.
func (c *Credentials) Resolve(advertised []string) (string, error) {
	if c.Method != "" && c.Method != AuthAuto {
		switch c.Method {
		case AuthBasic, AuthPost, AuthSecretJWT:
			if c.ClientSecret == "" {
				return "", fmt.Errorf("%s needs a client secret", c.Method)
			}
		case AuthPrivateKeyJWT:
			if c.Key == nil {
				return "", errors.New("private_key_jwt needs --client-key")
			}
		case AuthNone:
		default:
			return "", fmt.Errorf("unknown auth method %q (known: %s)", c.Method, strings.Join(AuthMethods, ", "))
		}
		return c.Method, nil
	}

	supports := func(method string) bool { return len(advertised) == 0 || contains(advertised, method) }
	switch {
	case c.Key != nil && supports(AuthPrivateKeyJWT):
		return AuthPrivateKeyJWT, nil
	case c.ClientSecret != "" && supports(AuthBasic):
		return AuthBasic, nil
	case c.ClientSecret != "" && supports(AuthPost):
		return AuthPost, nil
	case c.ClientSecret != "" && supports(AuthSecretJWT):
		return AuthSecretJWT, nil
	case c.ClientSecret != "":
		return AuthBasic, nil
	case c.Key != nil:
		return AuthPrivateKeyJWT, nil
	}
	return AuthNone, nil
}

// Apply adds the client authentication to a token endpoint request. audience
// is the token endpoint URL, which RFC 7523 §3 uses as the assertion audience.
func (c *Credentials) Apply(method string, form url.Values, headers http.Header, audience string) error {
	if c.ClientID == "" {
		return errors.New("no client id: pass --client-id, OAUTH_CLIENT_ID or a profile")
	}
	if c.AssertionAudience != "" {
		audience = c.AssertionAudience
	}
	switch method {
	case AuthBasic:
		// RFC 6749 §2.3.1 form-encodes both values before base64 encoding.
		headers.Set("Authorization", "Basic "+basicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret)))
	case AuthPost:
		form.Set("client_id", c.ClientID)
		form.Set("client_secret", c.ClientSecret)
	case AuthSecretJWT:
		assertion, err := c.assertion(jose.HMACSigner([]byte(c.ClientSecret)), "HS256", audience)
		if err != nil {
			return err
		}
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	case AuthPrivateKeyJWT:
		alg, err := jose.DefaultAlg(c.Key)
		if err != nil {
			return err
		}
		assertion, err := c.assertion(c.Key, alg, audience)
		if err != nil {
			return err
		}
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	case AuthNone:
		form.Set("client_id", c.ClientID)
	default:
		return fmt.Errorf("unknown auth method %q", method)
	}
	return nil
}

// assertion builds the RFC 7523 §3 client authentication JWT.
func (c *Credentials) assertion(signer crypto.Signer, alg, audience string) (string, error) {
	now := time.Now()
	header := map[string]any{"typ": "JWT"}
	if c.KeyID != "" {
		header["kid"] = c.KeyID
	}
	lifetime := c.AssertionLifetime
	if lifetime == 0 {
		lifetime = AssertionDefaultLifetime
	}
	claims := map[string]any{
		"iss": c.ClientID,
		"sub": c.ClientID,
		"aud": audience,
		"iat": now.Add(min(lifetime, 0)).Unix(),
		"exp": now.Add(lifetime).Unix(),
		"jti": jose.RandomString(16),
	}
	return jose.Sign(header, claims, signer, alg)
}

func basicAuth(user, password string) string {
	return jose.EncodeStd([]byte(user + ":" + password))
}
