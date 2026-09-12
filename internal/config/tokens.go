package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Token is a token response kept for a profile so later commands can present
// it without asking the server again.
type Token struct {
	Issuer       string    `json:"issuer,omitempty"`
	ClientID     string    `json:"clientId,omitempty"`
	AccessToken  string    `json:"accessToken"`
	TokenType    string    `json:"tokenType,omitempty"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	IDToken      string    `json:"idToken,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	ObtainedAt   time.Time `json:"obtainedAt"`
	ExpiresAt    time.Time `json:"expiresAt,omitzero"`
	// DPoPKey is the private JWK the token is bound to, when it is.
	DPoPKey json.RawMessage `json:"dpopKey,omitempty"`
}

// Expired reports whether the token's lifetime has passed. A token without an
// expiry is treated as live.
func (t *Token) Expired() bool {
	return !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)
}

// Store is the set of saved tokens, keyed by profile name.
type Store struct {
	Tokens map[string]*Token `json:"tokens"`

	path string
}

// ErrNoToken reports that a profile has no saved token.
var ErrNoToken = errors.New("no saved token")

// StorePath is the token store's location, next to the configuration file.
func StorePath(configOverride string) string {
	return filepath.Join(filepath.Dir(Path(configOverride)), "tokens.json")
}

// LoadStore reads the token store. A missing file yields an empty store.
func LoadStore(configOverride string) (*Store, error) {
	path := StorePath(configOverride)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Store{Tokens: map[string]*Token{}, path: path}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var store Store
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if store.Tokens == nil {
		store.Tokens = map[string]*Token{}
	}
	store.path = path
	return &store, nil
}

// SourcePath is the file this store was read from.
func (s *Store) SourcePath() string { return s.path }

// Save writes the store back with mode 0600, because it holds bearer tokens.
func (s *Store) Save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(s.path), err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", s.path, err)
	}
	return nil
}

// Key is the store key for a profile. A command run without a profile still
// gets a slot, so `token get --save` followed by `token inspect` works with
// nothing configured.
func Key(profile string) string {
	if profile == "" {
		return "_default"
	}
	return profile
}

// Get returns the saved token of a profile.
func (s *Store) Get(profile string) (*Token, error) {
	token, ok := s.Tokens[Key(profile)]
	if !ok || token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("%w for profile %q", ErrNoToken, Key(profile))
	}
	return token, nil
}

// Put saves a token for a profile.
func (s *Store) Put(profile string, token *Token) {
	if s.Tokens == nil {
		s.Tokens = map[string]*Token{}
	}
	s.Tokens[Key(profile)] = token
}

// Delete forgets the token of a profile.
func (s *Store) Delete(profile string) bool {
	key := Key(profile)
	_, ok := s.Tokens[key]
	delete(s.Tokens, key)
	return ok
}

// Names lists the profiles that have a saved token, in alphabetical order.
func (s *Store) Names() []string {
	names := make([]string, 0, len(s.Tokens))
	for name := range s.Tokens {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
