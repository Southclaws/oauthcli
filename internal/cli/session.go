// Package cli implements the handlers behind the generated command tree. Each
// handler parses nothing and validates nothing - the generated constructors have
// already done both - so it is only concerned with talking to a server and
// rendering the result.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/config"
	"github.com/Southclaws/oauthcli/internal/oauth"
	"github.com/Southclaws/oauthcli/internal/render"
)

// Sentinel errors let the root command map a failure to the exit code the
// specification documents, without every handler knowing the numbers.
var (
	ErrUnreachable  = oauth.ErrUnreachable
	ErrOAuth        = errors.New("oauth error")
	ErrNotFound     = errors.New("not found")
	ErrFailed       = errors.New("failed")
	ErrInvalidToken = errors.New("invalid token")
)

// output holds the two streams a command writes to: results on stdout,
// progress and warnings on stderr.
type output struct {
	Out *render.Printer
	Err *render.Printer
}

func newOutput(cmd *cobra.Command, commandIO cligen.IO) *output {
	noColor, _ := cmd.Flags().GetBool("no-color")
	theme, _ := cmd.Flags().GetString("theme")
	options := render.Options{NoColor: noColor, Theme: theme}
	return &output{
		Out: render.NewPrinter(commandIO.Out, options),
		Err: render.NewPrinter(commandIO.Err, options),
	}
}

// session is everything a handler needs: the resolved settings, the HTTP
// client, the streams, and lazily fetched metadata.
type session struct {
	*output
	cmd      *cobra.Command
	in       io.Reader
	File     *config.File
	Profile  string
	Settings *config.Profile
	Client   *oauth.Client
	Verbose  int

	metadata *oauth.Metadata
}

// newSession resolves the settings from flags, environment and profile, and
// builds the HTTP client. Flags win over the profile.
func newSession(cmd *cobra.Command, commandIO cligen.IO) (*session, error) {
	streams := newOutput(cmd, commandIO)
	flags := cmd.Flags()

	configPath, _ := flags.GetString("config")
	file, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	profileName, _ := flags.GetString("profile")
	name, profile, err := file.Resolve(profileName)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	settings := *profile

	if v, _ := flags.GetString("issuer"); v != "" {
		settings.Issuer = v
	}
	if v, _ := flags.GetString("client-id"); v != "" {
		settings.Client.ID = v
	}
	if v, _ := flags.GetString("client-secret"); v != "" {
		settings.Client.Secret = v
	}
	if v, _ := flags.GetString("client-secret-file"); v != "" {
		settings.Client.SecretFile = v
	}
	if v, _ := flags.GetString("client-key"); v != "" {
		settings.Client.Key = v
	}
	if v, _ := flags.GetString("auth-method"); v != "" && v != "auto" {
		settings.Client.AuthMethod = v
	}
	if v, _ := flags.GetStringSlice("scope"); len(v) > 0 {
		settings.Scopes = splitScopes(v)
	}
	if v, _ := flags.GetString("redirect-uri"); v != "" {
		settings.RedirectURI = v
	}
	if v, _ := flags.GetString("audience"); v != "" {
		settings.Audience = v
	}
	if v, _ := flags.GetStringArray("resource"); len(v) > 0 {
		settings.Resources = v
	}
	if v, _ := flags.GetBool("insecure"); v {
		settings.Insecure = true
	}
	if v, _ := flags.GetBool("allow-http"); v {
		settings.AllowHTTP = true
	}
	if settings.Client.Secret == "" && settings.Client.SecretFile != "" {
		secret, err := readSecretFile(settings.Client.SecretFile, commandIO.In)
		if err != nil {
			return nil, err
		}
		settings.Client.Secret = secret
	}
	if settings.Client.AuthMethod != "" && !containsString(oauth.AuthMethods, settings.Client.AuthMethod) {
		return nil, fmt.Errorf("unknown --auth-method %q (known: %s)", settings.Client.AuthMethod, strings.Join(oauth.AuthMethods, ", "))
	}

	timeout, _ := flags.GetDuration("timeout")
	headers, _ := flags.GetStringArray("header")
	trace, _ := flags.GetBool("trace")
	verbose, _ := flags.GetCount("verbose")

	var tracer func(string, ...any)
	if trace || verbose > 1 {
		tracer = func(format string, args ...any) {
			streams.Err.Println(streams.Err.T.Styles.Faint.Render(fmt.Sprintf(format, args...)))
		}
	}
	client, err := oauth.NewClient(oauth.Options{
		Timeout:   timeout,
		Insecure:  settings.Insecure,
		AllowHTTP: settings.AllowHTTP,
		Headers:   headers,
		Trace:     tracer,
	})
	if err != nil {
		return nil, err
	}
	if settings.Insecure && verbose > 0 {
		streams.Err.Warnf("TLS certificate verification is disabled")
	}

	return &session{
		output:   streams,
		cmd:      cmd,
		in:       commandIO.In,
		File:     file,
		Profile:  name,
		Settings: &settings,
		Client:   client,
		Verbose:  verbose,
	}, nil
}

// splitScopes accepts scopes given as separate flags, comma lists, or one
// space-separated string, since all three are common.
func splitScopes(values []string) []string {
	var out []string
	for _, value := range values {
		for _, scope := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' }) {
			if scope != "" && !containsString(out, scope) {
				out = append(out, scope)
			}
		}
	}
	return out
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func readSecretFile(path string, in io.Reader) (string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(in)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// issuer resolves the issuer from an argument, the flags or the profile.
func (s *session) issuer(argument string) (string, error) {
	raw := argument
	if raw == "" {
		raw = s.Settings.Issuer
	}
	issuer, err := oauth.NormalizeIssuer(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return issuer, nil
}

// metadataFor fetches the issuer's metadata once per session.
func (s *session) metadataFor(ctx context.Context, issuer string) (*oauth.Metadata, error) {
	if s.metadata != nil && s.metadata.Issuer == issuer {
		return s.metadata, nil
	}
	if s.Verbose > 0 {
		s.Err.Notef("discovering %s", issuer)
	}
	metadata, err := s.Client.FetchMetadata(ctx, issuer, "auto")
	if err != nil {
		return nil, wrapFetch(err)
	}
	if s.Verbose > 0 {
		s.Err.Notef("metadata from %s", metadata.URL)
	}
	s.metadata = metadata
	return metadata, nil
}

// wrapFetch maps a discovery failure to the exit code family it belongs to.
func wrapFetch(err error) error {
	if errors.Is(err, oauth.ErrNoMetadata) {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return err
}

// credentials builds the client credentials from the settings.
func (s *session) credentials() (*oauth.Credentials, error) {
	credentials := &oauth.Credentials{
		ClientID:     s.Settings.Client.ID,
		ClientSecret: s.Settings.Client.Secret,
		Method:       s.Settings.Client.AuthMethod,
	}
	if s.Settings.Client.Key != "" {
		key, err := oauth.LoadKey(s.Settings.Client.Key)
		if err != nil {
			return nil, err
		}
		credentials.Key = key
	}
	return credentials, nil
}

// dpop returns the DPoP key when --dpop is set: the saved one for the profile
// when a saved token is bound, otherwise a fresh or loaded key.
func (s *session) dpop() (*oauth.DPoP, error) {
	enabled, _ := s.cmd.Flags().GetBool("dpop")
	keyPath, _ := s.cmd.Flags().GetString("dpop-key")
	if !enabled && keyPath == "" {
		return nil, nil
	}
	if keyPath == "" {
		if saved, err := s.savedToken(); err == nil && len(saved.DPoPKey) > 0 {
			return oauth.DPoPFromJWK(saved.DPoPKey)
		}
	}
	return oauth.NewDPoP(keyPath)
}

// store opens the token store next to the configuration file.
func (s *session) store() (*config.Store, error) {
	path, _ := s.cmd.Flags().GetString("config")
	return config.LoadStore(path)
}

// savedToken returns the token saved for the active profile.
func (s *session) savedToken() (*config.Token, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	return store.Get(s.Profile)
}

// token resolves the token a command acts on: the argument, stdin for "-",
// OAUTH_TOKEN, --token-file, then the saved token of the profile.
func (s *session) token(argument string) (string, *config.Token, error) {
	switch {
	case argument == "-":
		text, err := readAllTrim(s.in)
		return text, nil, err
	case argument != "":
		return argument, nil, nil
	}
	if fromEnv := os.Getenv("OAUTH_TOKEN"); fromEnv != "" {
		return fromEnv, nil, nil
	}
	if file, _ := s.cmd.Flags().GetString("token-file"); file != "" {
		text, err := readSecretFile(file, s.in)
		return text, nil, err
	}
	saved, err := s.savedToken()
	if err != nil {
		return "", nil, fmt.Errorf("%w: no token given and %w; pass TOKEN, set OAUTH_TOKEN, or run `oauthcli token get --save`", ErrNotFound, err)
	}
	if saved.Expired() && s.Verbose >= 0 {
		s.Err.Warnf("the saved token expired %s ago", render.Duration(time.Since(saved.ExpiresAt)))
	}
	return saved.AccessToken, saved, nil
}

func readAllTrim(in io.Reader) (string, error) {
	if in == nil {
		return "", errors.New("no stdin")
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "", errors.New("stdin was empty")
	}
	// A pasted token may arrive with a trailing newline and nothing else, or
	// as the first field of a plain-format row.
	if scanner := bufio.NewScanner(strings.NewReader(text)); scanner.Scan() {
		return strings.Fields(scanner.Text())[0], nil
	}
	return text, nil
}

// saveToken stores a token response for the active profile.
func (s *session) saveToken(result *oauth.TokenResult, issuer string, dpop *oauth.DPoP) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	token := &config.Token{
		Issuer:       issuer,
		ClientID:     s.Settings.Client.ID,
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		RefreshToken: result.RefreshToken,
		IDToken:      result.IDToken,
		Scope:        result.Scope,
		ObtainedAt:   time.Now(),
		ExpiresAt:    result.ExpiresAt,
	}
	if existing, err := store.Get(s.Profile); err == nil && token.RefreshToken == "" && existing.RefreshToken != "" && existing.Issuer == issuer {
		// A refresh response without a new refresh token keeps the old one.
		token.RefreshToken = existing.RefreshToken
	}
	if dpop != nil {
		key, err := dpop.JWK()
		if err != nil {
			return err
		}
		token.DPoPKey = key
	}
	store.Put(s.Profile, token)
	if err := store.Save(); err != nil {
		return err
	}
	if s.Verbose > 0 {
		s.Err.Notef("saved the token for profile %q in %s", config.Key(s.Profile), store.SourcePath())
	}
	return nil
}

// machineReadable reports whether a format is one the generated command
// encodes itself, in which case a handler must print nothing.
func machineReadable(format string) bool {
	return format == "json" || format == "yaml"
}

// fail returns err after writing value in a machine-readable format. The
// generated command encodes a result only on success, but a failed
// expectation or audit must still deliver its document to the caller along
// with the exit code.
func (s *session) fail(format string, value any, err error) error {
	if err == nil || !machineReadable(format) {
		return err
	}
	if encodeErr := encodeDocument(s, format, value); encodeErr != nil {
		return encodeErr
	}
	return err
}

// oauthError wraps an *oauth.Error so the exit code is 3.
func oauthError(err error) error {
	var oauthErr *oauth.Error
	if errors.As(err, &oauthErr) {
		return fmt.Errorf("%w: %w", ErrOAuth, err)
	}
	return err
}

// printIssues writes findings as status lines.
func (o *output) printIssues(p *render.Printer, issues []cligen.Issue) {
	for _, issue := range issues {
		status := "warn"
		switch issue.Severity {
		case "error":
			status = "fail"
		case "info":
			status = "skip"
		}
		suffix := ""
		if issue.Spec != nil {
			suffix = "  " + p.T.Styles.Faint.Render(*issue.Spec)
		}
		glyph, style := p.Status(status)
		p.Printf("%s %s%s\n", style.Render(glyph), issue.Message, suffix)
	}
}

// issueSummary counts findings by severity for a one-line summary.
func issueSummary(issues []cligen.Issue) string {
	errors, warnings := 0, 0
	for _, issue := range issues {
		switch issue.Severity {
		case "error":
			errors++
		case "warning":
			warnings++
		}
	}
	switch {
	case errors == 0 && warnings == 0:
		return "no problems found"
	case errors == 0:
		return fmt.Sprintf("%d warning(s)", warnings)
	default:
		return fmt.Sprintf("%d error(s), %d warning(s)", errors, warnings)
	}
}

// parseParams turns name=value pairs into form values.
func parseParams(pairs []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("parameter %q must be name=value", pair)
		}
		out[name] = append(out[name], value)
	}
	return out, nil
}
