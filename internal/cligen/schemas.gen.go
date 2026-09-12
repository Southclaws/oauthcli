package cligen

import (
	"time"
)

// One feature an authorization server can advertise.
type Capability struct {
	// The advertised value that decided support.
	Detail    *string `json:"detail,omitempty"`
	ID        string  `json:"id"`
	Spec      string  `json:"spec"`
	Supported bool    `json:"supported"`
	Title     string  `json:"title"`
}

type CertificateInfo struct {
	Expired      bool      `json:"expired"`
	Issuer       string    `json:"issuer"`
	NotAfter     time.Time `json:"notAfter"`
	NotBefore    time.Time `json:"notBefore"`
	SerialNumber *string   `json:"serialNumber,omitempty"`
	Subject      string    `json:"subject"`
}

// A decoded WWW-Authenticate challenge.
type Challenge struct {
	HTTPStatus *int              `json:"httpStatus,omitempty"`
	Params     map[string]string `json:"params"`
	Scheme     string            `json:"scheme"`
}

// A JSON document exactly as the server sent it.
type Document = interface{}

// One conformance check.
type Check struct {
	Detail   *string   `json:"detail,omitempty"`
	Evidence *Document `json:"evidence,omitempty"`
	ID       string    `json:"id"`
	Section  *string   `json:"section,omitempty"`
	Spec     *string   `json:"spec,omitempty"`
	Status   string    `json:"status"`
	Title    string    `json:"title"`
}

// One validation finding.
type Issue struct {
	// Stable identifier of the rule, e.g. issuer-mismatch.
	Code string `json:"code"`
	// The metadata member or claim the finding is about.
	Field    *string `json:"field,omitempty"`
	Message  string  `json:"message"`
	Severity string  `json:"severity"`
	// The specification and section that defines the rule.
	Spec *string `json:"spec,omitempty"`
}

type CimdReport struct {
	Document Document `json:"document"`
	Issues   []Issue  `json:"issues"`
	// Whether the configured issuer advertises support, when one is configured.
	ServerSupport *bool  `json:"serverSupport,omitempty"`
	URL           string `json:"url"`
}

// Every check for one specification and its overall verdict.
type SpecResult struct {
	Checks  []Check `json:"checks"`
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	URL     *string `json:"url,omitempty"`
	Verdict string  `json:"verdict"`
}

type Summary struct {
	Conformant    int `json:"conformant"`
	Fail          int `json:"fail"`
	NonConformant int `json:"nonConformant"`
	NotSupported  int `json:"notSupported"`
	NotTested     int `json:"notTested"`
	Pass          int `json:"pass"`
	Skip          int `json:"skip"`
	Untested      int `json:"untested"`
	Warn          int `json:"warn"`
}

type ConformanceReport struct {
	// Whether the audit had client credentials to use.
	Credentials *bool        `json:"credentials,omitempty"`
	ElapsedMs   int          `json:"elapsedMs"`
	Issuer      string       `json:"issuer"`
	Label       *string      `json:"label,omitempty"`
	Passed      bool         `json:"passed"`
	Specs       []SpecResult `json:"specs"`
	StartedAt   time.Time    `json:"startedAt"`
	Summary     Summary      `json:"summary"`
}

// One key of a JSON Web Key Set.
type Jwk struct {
	Alg *string `json:"alg,omitempty"`
	// Key size in bits.
	Bits        *int             `json:"bits,omitempty"`
	Certificate *CertificateInfo `json:"certificate,omitempty"`
	Crv         *string          `json:"crv,omitempty"`
	Issues      []Issue          `json:"issues"`
	Kid         *string          `json:"kid,omitempty"`
	Kty         string           `json:"kty"`
	// The public key in PEM form, when requested.
	Pem *string `json:"pem,omitempty"`
	// RFC 7638 SHA-256 thumbprint.
	Thumbprint string  `json:"thumbprint"`
	Use        *string `json:"use,omitempty"`
}

// The outcome of fetching one well-known location.
type WellKnownProbe struct {
	ContentType *string `json:"contentType,omitempty"`
	ElapsedMs   int     `json:"elapsedMs"`
	Error       *string `json:"error,omitempty"`
	HTTPStatus  *int    `json:"httpStatus,omitempty"`
	// Which document the location serves.
	Kind   string  `json:"kind"`
	Spec   *string `json:"spec,omitempty"`
	Status string  `json:"status"`
	// A one-line description of what was found.
	Summary *string `json:"summary,omitempty"`
	URL     string  `json:"url"`
}

type DiscoveryReport struct {
	Capabilities []Capability     `json:"capabilities"`
	Issuer       string           `json:"issuer"`
	Issues       []Issue          `json:"issues"`
	Keys         []Jwk            `json:"keys,omitempty"`
	Metadata     *Document        `json:"metadata,omitempty"`
	Probes       []WellKnownProbe `json:"probes"`
	Resource     *Document        `json:"resource,omitempty"`
}

type Endpoint struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Expectation struct {
	Actual   *string `json:"actual,omitempty"`
	Expected *string `json:"expected,omitempty"`
	Ok       bool    `json:"ok"`
	Rule     string  `json:"rule"`
}

type Signature struct {
	Alg   *string `json:"alg,omitempty"`
	Error *string `json:"error,omitempty"`
	// Where the verification key came from.
	KeySource *string `json:"keySource,omitempty"`
	Kid       *string `json:"kid,omitempty"`
	Status    string  `json:"status"`
}

type Timing struct {
	Expired   bool       `json:"expired"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// Remaining lifetime, negative when expired.
	ExpiresIn *string    `json:"expiresIn,omitempty"`
	IssuedAt  *time.Time `json:"issuedAt,omitempty"`
	// Total lifetime from iat to exp.
	Lifetime    *string    `json:"lifetime,omitempty"`
	NotBefore   *time.Time `json:"notBefore,omitempty"`
	NotYetValid *bool      `json:"notYetValid,omitempty"`
}

type TokenInfo struct {
	Claims    *Document  `json:"claims,omitempty"`
	Header    *Document  `json:"header,omitempty"`
	Issues    []Issue    `json:"issues"`
	Kind      string     `json:"kind"`
	Signature *Signature `json:"signature,omitempty"`
	Timing    *Timing    `json:"timing,omitempty"`
}

type ExpectationReport struct {
	Checks []Expectation `json:"checks"`
	Passed bool          `json:"passed"`
	Token  TokenInfo     `json:"token"`
}

type IntrospectionReport struct {
	Active   bool     `json:"active"`
	Endpoint string   `json:"endpoint"`
	Issues   []Issue  `json:"issues"`
	Response Document `json:"response"`
}

type KeySet struct {
	Issues []Issue `json:"issues"`
	Keys   []Jwk   `json:"keys"`
	URL    string  `json:"url"`
}

type MetadataReport struct {
	Capabilities []Capability `json:"capabilities"`
	ElapsedMs    *int         `json:"elapsedMs,omitempty"`
	Endpoints    []Endpoint   `json:"endpoints"`
	HTTPStatus   *int         `json:"httpStatus,omitempty"`
	Issuer       string       `json:"issuer"`
	Issues       []Issue      `json:"issues"`
	Kind         string       `json:"kind"`
	Metadata     Document     `json:"metadata"`
	// The well-known URL the document was fetched from.
	URL string `json:"url"`
}

type PkceResult struct {
	Challenge string `json:"challenge"`
	Method    string `json:"method"`
	Verifier  string `json:"verifier"`
}

type Profile struct {
	Audience    *string  `json:"audience,omitempty"`
	AuthMethod  *string  `json:"authMethod,omitempty"`
	ClientID    *string  `json:"clientId,omitempty"`
	Description *string  `json:"description,omitempty"`
	HasSecret   bool     `json:"hasSecret"`
	HasToken    *bool    `json:"hasToken,omitempty"`
	IsDefault   bool     `json:"isDefault"`
	Issuer      string   `json:"issuer"`
	Name        string   `json:"name"`
	RedirectURI *string  `json:"redirectUri,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

type ProfileList = []Profile

// One embedded specification, with its text when one was requested.
type Reference struct {
	Bytes   int     `json:"bytes"`
	File    string  `json:"file"`
	ID      string  `json:"id"`
	Section *string `json:"section,omitempty"`
	Text    *string `json:"text,omitempty"`
	Title   string  `json:"title"`
	URL     string  `json:"url"`
}

type ReferenceList = []Reference

type RegistrationReport struct {
	ClientID                string     `json:"clientId"`
	ClientSecret            *string    `json:"clientSecret,omitempty"`
	ClientSecretExpiresAt   *time.Time `json:"clientSecretExpiresAt,omitempty"`
	Endpoint                string     `json:"endpoint"`
	Issues                  []Issue    `json:"issues"`
	RegistrationAccessToken *string    `json:"registrationAccessToken,omitempty"`
	RegistrationClientURI   *string    `json:"registrationClientUri,omitempty"`
	Response                Document   `json:"response"`
	Saved                   *bool      `json:"saved,omitempty"`
}

type ResourceReport struct {
	AuthorizationServers []string   `json:"authorizationServers"`
	Challenge            *Challenge `json:"challenge,omitempty"`
	Issues               []Issue    `json:"issues"`
	Metadata             Document   `json:"metadata"`
	MetadataURL          string     `json:"metadataUrl"`
	Resource             *string    `json:"resource,omitempty"`
	URL                  string     `json:"url"`
}

type RevocationReport struct {
	Endpoint         string  `json:"endpoint"`
	HTTPStatus       int     `json:"httpStatus"`
	Issues           []Issue `json:"issues"`
	Ok               bool    `json:"ok"`
	VerifiedInactive *bool   `json:"verifiedInactive,omitempty"`
}

type TokenResponse struct {
	AccessToken     string     `json:"accessToken"`
	AccessTokenInfo *TokenInfo `json:"accessTokenInfo,omitempty"`
	// Thumbprint of the DPoP key the token is bound to.
	DpopThumbprint *string    `json:"dpopThumbprint,omitempty"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	ExpiresIn      *int       `json:"expiresIn,omitempty"`
	IDToken        *string    `json:"idToken,omitempty"`
	IDTokenInfo    *TokenInfo `json:"idTokenInfo,omitempty"`
	Issues         []Issue    `json:"issues"`
	Raw            Document   `json:"raw"`
	RefreshToken   *string    `json:"refreshToken,omitempty"`
	Saved          *bool      `json:"saved,omitempty"`
	Scope          *string    `json:"scope,omitempty"`
	TokenType      string     `json:"tokenType"`
}

type TokenStatus struct {
	ClientID        *string    `json:"clientId,omitempty"`
	Dpop            bool       `json:"dpop"`
	Expired         bool       `json:"expired"`
	ExpiresAt       *time.Time `json:"expiresAt,omitempty"`
	ExpiresIn       *string    `json:"expiresIn,omitempty"`
	HasIDToken      bool       `json:"hasIdToken"`
	HasRefreshToken bool       `json:"hasRefreshToken"`
	Issuer          *string    `json:"issuer,omitempty"`
	ObtainedAt      *time.Time `json:"obtainedAt,omitempty"`
	Profile         string     `json:"profile"`
	Scope           *string    `json:"scope,omitempty"`
	Subject         *string    `json:"subject,omitempty"`
	TokenType       *string    `json:"tokenType,omitempty"`
}

type TokenStatusList = []TokenStatus

type UserInfoReport struct {
	Claims   Document `json:"claims"`
	Endpoint string   `json:"endpoint"`
	Issues   []Issue  `json:"issues"`
	Sub      *string  `json:"sub,omitempty"`
}
