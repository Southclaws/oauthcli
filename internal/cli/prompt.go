package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"charm.land/huh/v2"
	"github.com/charmbracelet/x/term"

	"github.com/Southclaws/oauthcli/internal/oauth"
)

// ErrNotInteractive reports that a prompt was needed but there is no terminal
// to show it on. The remedy is a flag, not a retry.
var ErrNotInteractive = errors.New("no terminal to prompt on")

// interactive reports whether prompts can be shown.
func interactive() bool {
	return term.IsTerminal(os.Stdin.Fd()) && term.IsTerminal(os.Stdout.Fd())
}

// promptConfirm asks a yes/no question.
func promptConfirm(question string) (bool, error) {
	if !interactive() {
		return false, ErrNotInteractive
	}
	answer := false
	field := huh.NewConfirm().Title(question).Affirmative("Yes").Negative("No").Value(&answer)
	if err := huh.Run(field); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return false, nil
		}
		return false, err
	}
	return answer, nil
}

// promptLine asks for one line of text. Without a terminal the line is read
// from stdin, so a script can pipe the answer in.
func promptLine(title string, in io.Reader) (string, error) {
	if !interactive() {
		reader := bufio.NewReader(in)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read %s from stdin: %w", strings.ToLower(title), err)
		}
		return strings.TrimSpace(line), nil
	}
	var answer string
	field := huh.NewInput().Title(title).Value(&answer)
	if err := huh.Run(field); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return "", fmt.Errorf("cancelled")
		}
		return "", err
	}
	return strings.TrimSpace(answer), nil
}

// profileForm is the answers collected by the interactive profile wizard.
type profileForm struct {
	Name        string
	Issuer      string
	ClientID    string
	Secret      string
	AuthMethod  string
	Scopes      string
	RedirectURI string
	MakeDefault bool
}

// runProfileForm asks for the settings of a new profile. Once the issuer is
// known its metadata is fetched so the scopes and authentication methods
// offered are the ones that will work.
func runProfileForm(ctx context.Context, s *session, form *profileForm) error {
	if !interactive() {
		return ErrNotInteractive
	}

	first := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Profile name").Description("The name you will pass to --profile.").Value(&form.Name).Validate(huh.ValidateNotEmpty()),
		huh.NewInput().Title("Issuer URL").Description("For example https://auth.example.com.").Value(&form.Issuer).Validate(func(value string) error {
			_, err := oauth.NormalizeIssuer(value)
			return err
		}),
	))
	if err := first.Run(); err != nil {
		return formError(err)
	}

	methods := []string{"auto", "client_secret_basic", "client_secret_post", "private_key_jwt", "none"}
	scopeOptions := []string{"openid", "profile", "email", "offline_access"}
	issuer, err := oauth.NormalizeIssuer(form.Issuer)
	if err == nil {
		if metadata, err := s.Client.FetchMetadata(ctx, issuer, "auto"); err == nil {
			if advertised := metadata.TokenAuthMethods(); len(advertised) > 0 {
				methods = append([]string{"auto"}, advertised...)
			}
			if scopes := metadata.Strings("scopes_supported"); len(scopes) > 0 {
				scopeOptions = scopes
			}
			s.Err.Okf("found metadata at %s", metadata.URL)
		} else {
			s.Err.Warnf("cannot reach %s yet (%v); offering the standard choices", issuer, err)
		}
	}

	selected := splitScopes([]string{form.Scopes})
	second := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Client id").Description("Leave empty for anonymous discovery and audits only.").Value(&form.ClientID),
			huh.NewInput().Title("Client secret").Description("Stored in plain text; leave empty to use OAUTH_CLIENT_SECRET or a public client.").EchoMode(huh.EchoModePassword).Value(&form.Secret),
			huh.NewSelect[string]().Title("Client authentication").Description("auto picks from what the server advertises.").Options(huh.NewOptions(methods...)...).Value(&form.AuthMethod),
		),
		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("Scopes").Description("Space to toggle, enter to accept.").Options(huh.NewOptions(scopeOptions...)...).Value(&selected).Filterable(true),
			huh.NewInput().Title("Redirect URI").Description("Loopback URI for the authorization code flow.").Value(&form.RedirectURI),
			huh.NewConfirm().Title("Make this the default profile?").Value(&form.MakeDefault),
		),
	)
	if err := second.Run(); err != nil {
		return formError(err)
	}
	form.Scopes = strings.Join(selected, " ")
	return nil
}

func formError(err error) error {
	if errors.Is(err, huh.ErrUserAborted) {
		return fmt.Errorf("cancelled")
	}
	return err
}
