package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/spf13/cobra"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/config"
	"github.com/Southclaws/oauthcli/internal/oauth"
	"github.com/Southclaws/oauthcli/internal/render"
)

// configInit creates a profile, asking for each setting unless told not to.
//
// The form offers the scopes and client authentication methods the issuer
// actually advertises, because those are the only answers that will work.
func configInit(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ConfigInitParams) error {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return err
	}
	file := s.File
	if _, exists := file.Profiles[p.Name]; exists && !p.Force {
		if p.NonInteractive {
			return fmt.Errorf("profile %q already exists; pass --force to replace it", p.Name)
		}
		replace, err := promptConfirm(fmt.Sprintf("Profile %q already exists. Replace it?", p.Name))
		if err != nil || !replace {
			return fmt.Errorf("profile %q already exists; pass --force to replace it", p.Name)
		}
	}

	form := profileForm{
		Name:        p.Name,
		Issuer:      s.Settings.Issuer,
		ClientID:    s.Settings.Client.ID,
		Secret:      s.Settings.Client.Secret,
		AuthMethod:  s.Settings.Client.AuthMethod,
		Scopes:      strings.Join(s.Settings.Scopes, " "),
		RedirectURI: s.Settings.RedirectURI,
		MakeDefault: p.Default,
	}
	if form.AuthMethod == "" {
		form.AuthMethod = "auto"
	}
	if form.RedirectURI == "" {
		form.RedirectURI = "http://127.0.0.1:8085/callback"
	}

	if !p.NonInteractive {
		if err := runProfileForm(ctx, s, &form); err != nil {
			return err
		}
	} else if form.Issuer == "" {
		return fmt.Errorf("--non-interactive needs --issuer")
	}

	issuer, err := oauth.NormalizeIssuer(form.Issuer)
	if err != nil {
		return err
	}
	profile := file.Upsert(form.Name)
	profile.Issuer = issuer
	profile.Client.ID = form.ClientID
	profile.Client.Secret = form.Secret
	if form.AuthMethod != "auto" {
		profile.Client.AuthMethod = form.AuthMethod
	} else {
		profile.Client.AuthMethod = ""
	}
	profile.Scopes = splitScopes([]string{form.Scopes})
	profile.RedirectURI = form.RedirectURI
	profile.Audience = s.Settings.Audience
	profile.Resources = s.Settings.Resources
	if s.Settings.Client.Key != "" {
		profile.Client.Key = s.Settings.Client.Key
	}
	if s.Settings.Client.SecretFile != "" {
		profile.Client.SecretFile = s.Settings.Client.SecretFile
		profile.Client.Secret = ""
	}
	profile.Insecure = s.Settings.Insecure
	profile.AllowHTTP = s.Settings.AllowHTTP
	if form.MakeDefault {
		file.Default = form.Name
	}
	if err := file.Save(); err != nil {
		return err
	}

	s.Out.Okf("wrote profile %q to %s", form.Name, file.SourcePath())
	if profile.Client.Secret != "" {
		s.Err.Warnf("the client secret is stored in plain text; consider client.secretFile or OAUTH_CLIENT_SECRET instead")
	}
	s.Out.Notef("try it with: oauthcli discover -p %s", form.Name)
	return nil
}

// configShow prints the settings a command would use.
func configShow(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ConfigShowParams) error {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return err
	}
	format := string(p.Format)

	if p.All {
		document := *s.File
		if !p.Reveal {
			document.Profiles = map[string]*config.Profile{}
			for name, profile := range s.File.Profiles {
				document.Profiles[name] = profile.Redacted()
			}
		}
		return encodeDocument(s, format, document)
	}

	settings := *s.Settings
	if !p.Reveal {
		settings = *settings.Redacted()
	}
	if format != "text" {
		return encodeDocument(s, format, map[string]any{
			"profile":    s.Profile,
			"configFile": s.File.SourcePath(),
			"settings":   settings,
		})
	}

	out := s.Out
	out.Title("Resolved settings", s.File.SourcePath())
	fields := []render.Field{
		render.F("Profile", orNone(s.Profile)),
		render.F("Issuer", orNone(settings.Issuer)),
		render.F("Client id", orNone(settings.Client.ID)),
		render.F("Client secret", orNone(settings.Client.Secret)),
		render.F("Auth method", orAuto(settings.Client.AuthMethod)),
		render.F("Scopes", orNone(strings.Join(settings.Scopes, " "))),
		render.F("Redirect URI", orNone(settings.RedirectURI)),
	}
	if settings.Client.Key != "" {
		fields = append(fields, render.F("Client key", settings.Client.Key))
	}
	if settings.Audience != "" {
		fields = append(fields, render.F("Audience", settings.Audience))
	}
	if len(settings.Resources) > 0 {
		fields = append(fields, render.F("Resources", strings.Join(settings.Resources, "\n")))
	}
	if settings.Registration.ClientURI != "" {
		fields = append(fields, render.F("Registration URI", settings.Registration.ClientURI))
	}
	if settings.Insecure {
		fields = append(fields, render.FS("Insecure", "TLS verification disabled", out.T.Styles.Warn))
	}
	if settings.AllowHTTP {
		fields = append(fields, render.FS("Allow http", "yes", out.T.Styles.Warn))
	}
	out.KV(fields)
	if saved, err := s.savedToken(); err == nil {
		out.Println()
		state := "valid"
		if saved.Expired() {
			state = "expired"
		}
		out.Notef("a saved token exists for this profile (%s); see `oauthcli token status`", state)
	}
	return nil
}

func encodeDocument(s *session, format string, document any) error {
	if format == "json" {
		encoder := json.NewEncoder(s.Out.Raw())
		encoder.SetIndent("", "  ")
		return encoder.Encode(document)
	}
	encoded, err := yaml.MarshalWithOptions(document, yaml.Indent(2), yaml.IndentSequence(true))
	if err != nil {
		return err
	}
	_, err = s.Out.Raw().Write(encoded)
	return err
}

func orNone(value string) string {
	if value == "" {
		return "(not set)"
	}
	return value
}

func orAuto(value string) string {
	if value == "" {
		return "auto"
	}
	return value
}

// configList lists the configured profiles.
func configList(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ConfigListParams) (cligen.ProfileList, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return nil, err
	}
	store, _ := s.store()
	defaultName := s.File.DefaultName()
	profiles := cligen.ProfileList{}
	for _, name := range s.File.Names() {
		profile := s.File.Profiles[name]
		entry := cligen.Profile{
			Name:      name,
			IsDefault: name == defaultName,
			Issuer:    profile.Issuer,
			HasSecret: profile.Client.Secret != "" || profile.Client.SecretFile != "",
			Scopes:    profile.Scopes,
		}
		if profile.Description != "" {
			entry.Description = &profile.Description
		}
		if profile.Client.ID != "" {
			entry.ClientID = &profile.Client.ID
		}
		if profile.Client.AuthMethod != "" {
			entry.AuthMethod = &profile.Client.AuthMethod
		}
		if profile.RedirectURI != "" {
			entry.RedirectURI = &profile.RedirectURI
		}
		if profile.Audience != "" {
			entry.Audience = &profile.Audience
		}
		if store != nil {
			_, err := store.Get(name)
			entry.HasToken = oauth.Ptr(err == nil)
		}
		profiles = append(profiles, entry)
	}

	format := string(p.Format)
	if machineReadable(format) {
		return profiles, nil
	}
	if len(profiles) == 0 && format != "plain" {
		s.Out.Notef("no profiles in %s; create one with: oauthcli config init", s.File.SourcePath())
		return profiles, nil
	}
	rows := make([][]string, 0, len(profiles))
	for _, profile := range profiles {
		marker := ""
		if profile.IsDefault {
			marker = s.Out.T.Symbols.Good
		}
		token := "-"
		if profile.HasToken != nil && *profile.HasToken {
			token = "yes"
		}
		rows = append(rows, []string{marker, profile.Name, profile.Issuer, deref(profile.ClientID, "-"), deref(profile.AuthMethod, "auto"), strings.Join(profile.Scopes, " "), token})
	}
	if format == "plain" {
		s.Out.Plain(rows)
		return profiles, nil
	}
	s.Out.Title("Profiles", s.File.SourcePath())
	s.Out.Table([]string{"", "NAME", "ISSUER", "CLIENT", "AUTH", "SCOPES", "TOKEN"}, rows)
	return profiles, nil
}

// configUse makes a profile the default.
func configUse(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ConfigUseParams) error {
	streams := newOutput(cmd, commandIO)
	path, _ := cmd.Flags().GetString("config")
	file, err := config.Load(path)
	if err != nil {
		return err
	}
	if _, _, err := file.Resolve(p.Name); err != nil {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	file.Default = p.Name
	if err := file.Save(); err != nil {
		return err
	}
	streams.Out.Okf("default profile is now %q", p.Name)
	return nil
}

// configSet changes one setting of a profile.
func configSet(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ConfigSetParams) error {
	streams := newOutput(cmd, commandIO)
	path, _ := cmd.Flags().GetString("config")
	file, err := config.Load(path)
	if err != nil {
		return err
	}
	name := p.Name
	if name == "" {
		if fromFlag, _ := cmd.Flags().GetString("profile"); fromFlag != "" {
			name = fromFlag
		} else {
			name = file.DefaultName()
		}
	}
	if name == "" {
		name = "default"
	}
	profile := file.Upsert(name)
	if err := profile.Set(p.Setting, p.Value); err != nil {
		return err
	}
	if err := file.Save(); err != nil {
		return err
	}
	shown := p.Value
	if strings.Contains(p.Setting, "secret") || strings.Contains(p.Setting, "accessToken") {
		shown = render.Mask(p.Value)
	}
	streams.Out.Okf("%s.%s = %s", name, p.Setting, shown)
	return nil
}

// configRemove deletes a profile and its saved token.
func configRemove(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ConfigRemoveParams) error {
	streams := newOutput(cmd, commandIO)
	path, _ := cmd.Flags().GetString("config")
	file, err := config.Load(path)
	if err != nil {
		return err
	}
	if !p.Yes {
		confirmed, err := promptConfirm(fmt.Sprintf("Delete profile %q and its saved token?", p.Name))
		if err != nil {
			return fmt.Errorf("%w (pass --yes to skip the prompt)", err)
		}
		if !confirmed {
			return fmt.Errorf("cancelled")
		}
	}
	if err := file.Remove(p.Name); err != nil {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	if err := file.Save(); err != nil {
		return err
	}
	if store, err := config.LoadStore(path); err == nil && store.Delete(p.Name) {
		_ = store.Save()
	}
	streams.Out.Okf("deleted profile %q", p.Name)
	return nil
}

// configPath prints where the configuration file lives.
func configPath(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ConfigPathParams) error {
	path, _ := cmd.Flags().GetString("config")
	fmt.Fprintln(commandIO.Out, config.Path(path))
	return nil
}
