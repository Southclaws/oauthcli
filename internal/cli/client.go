package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/oauth"
	"github.com/Southclaws/oauthcli/internal/render"
)

// clientRegister registers a client dynamically.
func clientRegister(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ClientRegisterParams) (cligen.RegistrationReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.RegistrationReport{}, err
	}
	issuer, err := s.issuer("")
	if err != nil {
		return cligen.RegistrationReport{}, err
	}
	metadata, err := s.metadataFor(ctx, issuer)
	if err != nil {
		return cligen.RegistrationReport{}, err
	}
	endpoint := metadata.String("registration_endpoint")
	if endpoint == "" {
		return cligen.RegistrationReport{}, fmt.Errorf("%w: %s advertises no registration_endpoint", ErrNotFound, issuer)
	}

	document := map[string]any{}
	if p.From != "" {
		document, err = readJSONDocument(p.From, s.in)
		if err != nil {
			return cligen.RegistrationReport{}, err
		}
	}
	if p.ClientName != "" {
		document["client_name"] = p.ClientName
	} else if _, ok := document["client_name"]; !ok {
		document["client_name"] = "oauthcli"
	}
	if s.Settings.RedirectURI != "" {
		document["redirect_uris"] = []string{s.Settings.RedirectURI}
	}
	if len(p.GrantType) > 0 {
		document["grant_types"] = p.GrantType
	}
	if len(p.ResponseType) > 0 {
		document["response_types"] = p.ResponseType
	}
	if p.TokenAuth != "" {
		document["token_endpoint_auth_method"] = string(p.TokenAuth)
	}
	if len(s.Settings.Scopes) > 0 {
		document["scope"] = strings.Join(s.Settings.Scopes, " ")
	}
	for name, value := range map[string]string{
		"client_uri": p.ClientUri, "logo_uri": p.LogoUri, "software_id": p.SoftwareId,
		"software_version": p.SoftwareVersion, "jwks_uri": p.JwksUri,
	} {
		if value != "" {
			document[name] = value
		}
	}
	if len(p.Contact) > 0 {
		document["contacts"] = p.Contact
	}
	if err := applyJSONParams(document, p.Param); err != nil {
		return cligen.RegistrationReport{}, err
	}
	if _, ok := document["redirect_uris"]; !ok {
		grants, _ := document["grant_types"].([]string)
		if len(grants) == 0 || containsString(grants, "authorization_code") {
			s.Err.Warnf("no redirect_uris: pass --redirect-uri unless the client only uses grants without a redirect")
		}
	}

	registration, err := s.Client.Register(ctx, endpoint, document, p.InitialToken)
	if err != nil {
		return cligen.RegistrationReport{Endpoint: endpoint}, oauthError(err)
	}
	report := registrationReport(endpoint, registration)

	if p.Save {
		profile := s.File.Upsert(profileNameOrDefault(s.Profile))
		profile.Issuer = issuer
		profile.Client.ID = registration.ClientID
		profile.Client.Secret = registration.ClientSecret
		if method, _ := registration.Raw["token_endpoint_auth_method"].(string); method != "" {
			profile.Client.AuthMethod = method
		}
		if s.Settings.RedirectURI != "" {
			profile.RedirectURI = s.Settings.RedirectURI
		}
		if len(s.Settings.Scopes) > 0 {
			profile.Scopes = s.Settings.Scopes
		}
		profile.Registration.ClientURI = registration.RegistrationClientURI
		profile.Registration.AccessToken = registration.RegistrationAccessToken
		if err := s.File.Save(); err != nil {
			return report, err
		}
		report.Saved = oauth.Ptr(true)
	}

	if machineReadable(string(p.Format)) {
		return report, nil
	}
	s.renderRegistration(report, p.Reveal, "Registered client")
	if report.Saved != nil {
		s.Out.Notef("saved as profile %q in %s", profileNameOrDefault(s.Profile), s.File.SourcePath())
	}
	return report, nil
}

func profileNameOrDefault(name string) string {
	if name == "" {
		return "default"
	}
	return name
}

func registrationReport(endpoint string, registration *oauth.Registration) cligen.RegistrationReport {
	report := cligen.RegistrationReport{
		Endpoint: endpoint,
		ClientID: registration.ClientID,
		Response: cligen.Document(registration.Raw),
		Issues:   registration.Issues,
	}
	if registration.ClientSecret != "" {
		report.ClientSecret = &registration.ClientSecret
	}
	if !registration.ClientSecretExpiresAt.IsZero() {
		report.ClientSecretExpiresAt = &registration.ClientSecretExpiresAt
	}
	if registration.RegistrationClientURI != "" {
		report.RegistrationClientURI = &registration.RegistrationClientURI
	}
	if registration.RegistrationAccessToken != "" {
		report.RegistrationAccessToken = &registration.RegistrationAccessToken
	}
	return report
}

func (s *session) renderRegistration(report cligen.RegistrationReport, reveal bool, title string) {
	out := s.Out
	out.Title(title, report.Endpoint)
	fields := []render.Field{render.FS("client_id", report.ClientID, out.T.Styles.Code)}
	if report.ClientSecret != nil {
		secret := *report.ClientSecret
		if !reveal {
			secret = render.Mask(secret) + out.T.Styles.Faint.Render("  (--reveal to show)")
		}
		fields = append(fields, render.F("client_secret", secret))
	}
	if report.ClientSecretExpiresAt != nil {
		fields = append(fields, render.F("secret expires", report.ClientSecretExpiresAt.Local().Format(time.RFC3339)))
	}
	if report.RegistrationClientURI != nil {
		fields = append(fields, render.F("registration_client_uri", *report.RegistrationClientURI))
	}
	if report.RegistrationAccessToken != nil {
		token := *report.RegistrationAccessToken
		if !reveal {
			token = render.Mask(token)
		}
		fields = append(fields, render.F("registration_access_token", token))
	}
	out.KV(fields)
	if document, ok := report.Response.(map[string]any); ok {
		out.Section("Metadata")
		filtered := map[string]any{}
		for name, value := range document {
			switch name {
			case "client_id", "client_secret", "client_secret_expires_at", "registration_client_uri", "registration_access_token":
				continue
			}
			filtered[name] = value
		}
		renderClaims(out, filtered)
	}
	if len(report.Issues) > 0 {
		out.Section("Findings  " + out.T.Styles.Faint.Render(issueSummary(report.Issues)))
		s.printIssues(out, report.Issues)
	}
}

// registrationHandle resolves the RFC 7592 URI and token from flags or the
// profile.
func (s *session) registrationHandle(uri, token string) (string, string, error) {
	if uri == "" {
		uri = s.Settings.Registration.ClientURI
	}
	if token == "" {
		token = s.Settings.Registration.AccessToken
	}
	if uri == "" {
		return "", "", fmt.Errorf("%w: no registration_client_uri; pass --registration-uri or register with --save", ErrNotFound)
	}
	return uri, token, nil
}

// clientGet reads a registered client.
func clientGet(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ClientGetParams) (cligen.RegistrationReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.RegistrationReport{}, err
	}
	uri, token, err := s.registrationHandle(p.RegistrationUri, p.RegistrationToken)
	if err != nil {
		return cligen.RegistrationReport{}, err
	}
	registration, err := s.Client.ReadClient(ctx, uri, token)
	if err != nil {
		return cligen.RegistrationReport{Endpoint: uri}, oauthError(err)
	}
	s.rememberRotation(uri, registration)
	report := registrationReport(uri, registration)
	if machineReadable(string(p.Format)) {
		return report, nil
	}
	s.renderRegistration(report, p.Reveal, "Client configuration")
	return report, nil
}

// clientUpdate replaces a registered client's configuration.
func clientUpdate(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ClientUpdateParams) (cligen.RegistrationReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.RegistrationReport{}, err
	}
	uri, token, err := s.registrationHandle(p.RegistrationUri, p.RegistrationToken)
	if err != nil {
		return cligen.RegistrationReport{}, err
	}
	var document map[string]any
	if p.From != "" {
		document, err = readJSONDocument(p.From, s.in)
		if err != nil {
			return cligen.RegistrationReport{}, err
		}
		if _, ok := document["client_id"]; !ok && s.Settings.Client.ID != "" {
			document["client_id"] = s.Settings.Client.ID
		}
	} else {
		current, err := s.Client.ReadClient(ctx, uri, token)
		if err != nil {
			return cligen.RegistrationReport{Endpoint: uri}, oauthError(err)
		}
		document = current.Raw
		s.rememberRotation(uri, current)
	}
	// RFC 7592 §2.2: the update must not carry the server-assigned
	// management members, and must echo client_id.
	for _, name := range []string{"registration_access_token", "registration_client_uri", "client_secret_expires_at", "client_id_issued_at"} {
		delete(document, name)
	}
	if _, ok := document["client_id"]; !ok {
		return cligen.RegistrationReport{}, fmt.Errorf("the update document must include client_id (RFC 7592 §2.2)")
	}
	if p.ClientName != "" {
		document["client_name"] = p.ClientName
	}
	if len(p.GrantType) > 0 {
		document["grant_types"] = p.GrantType
	}
	if s.Settings.RedirectURI != "" && cmd.Flags().Changed("redirect-uri") {
		document["redirect_uris"] = []string{s.Settings.RedirectURI}
	}
	if err := applyJSONParams(document, p.Param); err != nil {
		return cligen.RegistrationReport{}, err
	}
	registration, err := s.Client.UpdateClient(ctx, uri, token, document)
	if err != nil {
		return cligen.RegistrationReport{Endpoint: uri}, oauthError(err)
	}
	report := registrationReport(uri, registration)
	s.rememberRotation(uri, registration)
	if machineReadable(string(p.Format)) {
		return report, nil
	}
	s.renderRegistration(report, p.Reveal, "Updated client")
	return report, nil
}

// rememberRotation stores a client secret or registration access token the
// server rotated. RFC 7592 §2.1 and §2.2 require the client to discard the
// previous values immediately.
func (s *session) rememberRotation(uri string, registration *oauth.Registration) {
	profile, ok := s.File.Profiles[s.Profile]
	if !ok || profile.Registration.ClientURI != uri {
		return
	}
	changed := false
	if registration.ClientSecret != "" && registration.ClientSecret != profile.Client.Secret {
		profile.Client.Secret = registration.ClientSecret
		changed = true
	}
	if registration.RegistrationAccessToken != "" && registration.RegistrationAccessToken != profile.Registration.AccessToken {
		profile.Registration.AccessToken = registration.RegistrationAccessToken
		changed = true
	}
	if changed {
		if err := s.File.Save(); err == nil {
			s.Err.Notef("the server rotated the client's credentials; the profile was updated")
		}
	}
}

// clientDelete deprovisions a registered client.
func clientDelete(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ClientDeleteParams) error {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return err
	}
	uri, token, err := s.registrationHandle(p.RegistrationUri, p.RegistrationToken)
	if err != nil {
		return err
	}
	if !p.Yes {
		confirmed, err := promptConfirm(fmt.Sprintf("Delete the client at %s?", uri))
		if err != nil {
			return fmt.Errorf("%w (pass --yes to skip the prompt)", err)
		}
		if !confirmed {
			return fmt.Errorf("cancelled")
		}
	}
	if _, err := s.Client.DeleteClient(ctx, uri, token); err != nil {
		return oauthError(err)
	}
	if s.Profile != "" {
		if profile, ok := s.File.Profiles[s.Profile]; ok && profile.Registration.ClientURI == uri {
			profile.Registration = struct {
				ClientURI   string `yaml:"clientUri,omitempty"`
				AccessToken string `yaml:"accessToken,omitempty"`
			}{}
			profile.Client.ID = ""
			profile.Client.Secret = ""
			_ = s.File.Save()
		}
	}
	s.Out.Okf("deleted the client at %s", uri)
	return nil
}

// cimdCheck fetches and validates a client ID metadata document.
func cimdCheck(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.CimdCheckParams) (cligen.CimdReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.CimdReport{}, err
	}
	report := cligen.CimdReport{URL: p.Url, Document: map[string]any{}, Issues: []cligen.Issue{}}
	document, issues, err := s.Client.FetchCIMD(ctx, p.Url)
	report.Issues = issues
	if document != nil {
		report.Document = cligen.Document(document)
	}
	if err != nil && document == nil {
		if machineReadable(string(p.Format)) {
			return report, err
		}
		s.Out.Title("Client ID metadata document", p.Url)
		s.printIssues(s.Out, report.Issues)
		return report, err
	}
	if s.Settings.Issuer != "" {
		if issuer, err := s.issuer(""); err == nil {
			if metadata, err := s.metadataFor(ctx, issuer); err == nil {
				supported, _ := metadata.Bool("client_id_metadata_document_supported")
				report.ServerSupport = &supported
				if !supported {
					report.Issues = append(report.Issues, oauth.Warnf("server-unsupported", oauth.CIMDSpec+" §5", "client_id_metadata_document_supported", "%s does not advertise client_id_metadata_document_supported", issuer))
				}
			}
		}
	}
	if machineReadable(string(p.Format)) {
		if oauth.HasErrors(report.Issues) {
			return report, s.fail(string(p.Format), report, fmt.Errorf("%w: the document has errors", ErrFailed))
		}
		return report, nil
	}
	out := s.Out
	out.Title("Client ID metadata document", p.Url)
	renderClaims(out, document)
	if report.ServerSupport != nil {
		out.Println()
		if *report.ServerSupport {
			out.Okf("%s advertises support for client ID metadata documents", s.Settings.Issuer)
		} else {
			out.Warnf("%s does not advertise support for client ID metadata documents", s.Settings.Issuer)
		}
	}
	out.Section("Findings  " + out.T.Styles.Faint.Render(issueSummary(report.Issues)))
	if len(report.Issues) == 0 {
		out.Okf("the document is valid")
	}
	s.printIssues(out, report.Issues)
	if oauth.HasErrors(report.Issues) {
		return report, fmt.Errorf("%w: the document has errors", ErrFailed)
	}
	return report, nil
}

// cimdNew writes a client ID metadata document template.
func cimdNew(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.CimdNewParams) error {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return err
	}
	if issues := oauth.ValidateCIMDURL(p.Url); oauth.HasErrors(issues) {
		s.printIssues(s.Err, issues)
		return fmt.Errorf("%s is not a valid client ID URL", p.Url)
	}
	var redirects []string
	if s.Settings.RedirectURI != "" {
		redirects = []string{s.Settings.RedirectURI}
	}
	if string(p.TokenAuth) == "private_key_jwt" && p.JwksUri == "" {
		return fmt.Errorf("private_key_jwt needs --jwks-uri")
	}
	document := oauth.CIMDTemplate(p.Url, p.ClientName, redirects, p.GrantType, string(p.TokenAuth), p.JwksUri)
	if len(s.Settings.Scopes) > 0 {
		document["scope"] = strings.Join(s.Settings.Scopes, " ")
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	if p.Out == "-" || p.Out == "" {
		fmt.Fprintln(s.Out.Raw(), string(encoded))
		return nil
	}
	if err := os.WriteFile(p.Out, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	s.Out.Okf("wrote %s; serve it at %s with Content-Type application/json", p.Out, p.Url)
	return nil
}

// readJSONDocument reads a JSON object from a file or stdin.
func readJSONDocument(path string, in io.Reader) (map[string]any, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(in)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("%s is not a JSON object: %w", path, err)
	}
	return document, nil
}

// applyJSONParams sets name=value pairs on a document, parsing a value as
// JSON when it is one so lists and booleans can be given.
func applyJSONParams(document map[string]any, pairs []string) error {
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || name == "" {
			return fmt.Errorf("parameter %q must be name=value", pair)
		}
		var parsed any
		if err := json.Unmarshal([]byte(value), &parsed); err == nil {
			document[name] = parsed
		} else {
			document[name] = value
		}
	}
	return nil
}
