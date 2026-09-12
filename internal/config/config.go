// Package config reads and writes the profiles that let a command name an
// authorization server and a client instead of describing them, and the tokens
// those profiles have obtained.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

// File is the whole configuration document.
type File struct {
	// Default names the profile used when no --profile is given.
	Default  string              `yaml:"default,omitempty"`
	Profiles map[string]*Profile `yaml:"profiles"`

	path string
}

// Profile is one issuer and one client a command can be pointed at.
type Profile struct {
	Description string   `yaml:"description,omitempty"`
	Issuer      string   `yaml:"issuer"`
	Client      Client   `yaml:"client,omitempty"`
	Scopes      []string `yaml:"scopes,omitempty"`
	RedirectURI string   `yaml:"redirectUri,omitempty"`
	Audience    string   `yaml:"audience,omitempty"`
	Resources   []string `yaml:"resources,omitempty"`
	// Insecure accepts a TLS certificate that fails verification.
	Insecure bool `yaml:"insecure,omitempty"`
	// AllowHTTP permits plain http URLs beyond the loopback interface.
	AllowHTTP bool `yaml:"allowHttp,omitempty"`
	// Registration holds what RFC 7592 needs to manage a dynamically
	// registered client.
	Registration Registration `yaml:"registration,omitempty"`
}

// Client identifies the OAuth client and how it authenticates.
type Client struct {
	ID string `yaml:"id,omitempty"`
	// Secret is stored in plain text, so SecretFile or OAUTH_CLIENT_SECRET is
	// preferable on a shared machine.
	Secret     string `yaml:"secret,omitempty"`
	SecretFile string `yaml:"secretFile,omitempty"`
	// Key is a PEM private key for private_key_jwt.
	Key string `yaml:"key,omitempty"`
	// AuthMethod is a token_endpoint_auth_method value, or auto.
	AuthMethod string `yaml:"authMethod,omitempty"`
}

// Registration is the management handle RFC 7592 returns on registration.
type Registration struct {
	ClientURI   string `yaml:"clientUri,omitempty"`
	AccessToken string `yaml:"accessToken,omitempty"`
}

// ErrNoProfile reports that a named profile is not in the file.
var ErrNoProfile = errors.New("no such profile")

// Dir is the directory holding the configuration file and the token store:
// the per-user configuration directory the platform defines.
func Dir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "oauth"
	}
	return filepath.Join(dir, "oauth")
}

// Path is the configuration file's location. An explicit override wins, then
// OAUTH_CONFIG, then the default location.
func Path(override string) string {
	if override != "" {
		return override
	}
	if fromEnv := os.Getenv("OAUTH_CONFIG"); fromEnv != "" {
		return fromEnv
	}
	return filepath.Join(Dir(), "config.yaml")
}

// Load reads the configuration file. A missing file yields an empty document,
// so every command works before anything is configured.
func Load(override string) (*File, error) {
	path := Path(override)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &File{Profiles: map[string]*Profile{}, path: path}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var file File
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if file.Profiles == nil {
		file.Profiles = map[string]*Profile{}
	}
	file.path = path

	return &file, nil
}

// SourcePath is the file this document was read from.
func (f *File) SourcePath() string { return f.path }

// Save writes the document back. The file is written 0600 because it can hold
// a client secret.
func (f *File) Save() error {
	if f.path == "" {
		f.path = Path("")
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(f.path), err)
	}

	data, err := yaml.MarshalWithOptions(f, yaml.Indent(2), yaml.IndentSequence(true))
	if err != nil {
		return err
	}

	header := "# oauthcli profiles. Edit by hand or with `oauthcli config set`.\n"
	if err := os.WriteFile(f.path, append([]byte(header), data...), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", f.path, err)
	}
	return nil
}

// Names lists the profile names in alphabetical order.
func (f *File) Names() []string {
	names := make([]string, 0, len(f.Profiles))
	for name := range f.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// DefaultName is the profile a command uses when none is named: the declared
// default, or the only profile when there is exactly one.
func (f *File) DefaultName() string {
	if f.Default != "" {
		return f.Default
	}
	if len(f.Profiles) == 1 {
		return f.Names()[0]
	}
	return ""
}

// Resolve returns the named profile, or the default one when name is empty. A
// name that is not present is an error, but an empty file is not: it resolves
// to an unnamed, empty profile that flags can fill in.
func (f *File) Resolve(name string) (string, *Profile, error) {
	if name == "" {
		name = f.DefaultName()
	}
	if name == "" {
		return "", &Profile{}, nil
	}

	profile, ok := f.Profiles[name]
	if !ok {
		return "", nil, fmt.Errorf("%w: %q (configured: %s)", ErrNoProfile, name, strings.Join(f.Names(), ", "))
	}
	if profile == nil {
		profile = &Profile{}
	}
	return name, profile, nil
}

// Upsert returns the named profile, creating it when absent.
func (f *File) Upsert(name string) *Profile {
	if f.Profiles == nil {
		f.Profiles = map[string]*Profile{}
	}
	if profile, ok := f.Profiles[name]; ok && profile != nil {
		return profile
	}
	profile := &Profile{}
	f.Profiles[name] = profile
	if f.Default == "" {
		f.Default = name
	}
	return profile
}

// Remove deletes a profile, clearing the default when it pointed at it.
func (f *File) Remove(name string) error {
	if _, ok := f.Profiles[name]; !ok {
		return fmt.Errorf("%w: %q", ErrNoProfile, name)
	}
	delete(f.Profiles, name)
	if f.Default == name {
		f.Default = ""
	}
	return nil
}

// Redacted returns a copy with secrets replaced, for printing.
func (p *Profile) Redacted() *Profile {
	clone := *p
	if clone.Client.Secret != "" {
		clone.Client.Secret = "••••••••"
	}
	if clone.Registration.AccessToken != "" {
		clone.Registration.AccessToken = "••••••••"
	}
	return &clone
}

// SettableKeys are the dotted keys `config set` understands.
var SettableKeys = []string{
	"description",
	"issuer",
	"client.id",
	"client.secret",
	"client.secretFile",
	"client.key",
	"client.authMethod",
	"scopes",
	"redirectUri",
	"audience",
	"resources",
	"insecure",
	"allowHttp",
	"registration.clientUri",
	"registration.accessToken",
}

// Set assigns one dotted key on a profile. List-valued keys take a
// comma-separated value; boolean keys take anything strconv.ParseBool accepts.
func (p *Profile) Set(key, value string) error {
	list := func() []string {
		if strings.TrimSpace(value) == "" {
			return nil
		}
		parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' })
		return parts
	}

	boolean := func() (bool, error) {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return false, fmt.Errorf("%s must be true or false, got %q", key, value)
		}
		return parsed, nil
	}

	var err error
	switch key {
	case "description":
		p.Description = value
	case "issuer":
		p.Issuer = value
	case "client.id":
		p.Client.ID = value
	case "client.secret":
		p.Client.Secret = value
	case "client.secretFile":
		p.Client.SecretFile = value
	case "client.key":
		p.Client.Key = value
	case "client.authMethod":
		p.Client.AuthMethod = value
	case "scopes", "scope":
		p.Scopes = list()
	case "redirectUri":
		p.RedirectURI = value
	case "audience":
		p.Audience = value
	case "resources", "resource":
		p.Resources = list()
	case "insecure":
		p.Insecure, err = boolean()
	case "allowHttp":
		p.AllowHTTP, err = boolean()
	case "registration.clientUri":
		p.Registration.ClientURI = value
	case "registration.accessToken":
		p.Registration.AccessToken = value
	default:
		return fmt.Errorf("unknown setting %q (known: %s)", key, strings.Join(SettableKeys, ", "))
	}

	return err
}
