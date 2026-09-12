package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileRoundTripsThroughSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	file, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	profile := file.Upsert("dev")
	if err := profile.Set("issuer", "https://auth.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := profile.Set("client.id", "app"); err != nil {
		t.Fatal(err)
	}
	if err := profile.Set("scopes", "openid, email profile"); err != nil {
		t.Fatal(err)
	}
	if err := profile.Set("insecure", "true"); err != nil {
		t.Fatal(err)
	}
	if err := profile.Set("nonsense", "x"); err == nil {
		t.Fatal("unknown key must be rejected")
	}
	if err := file.Save(); err != nil {
		t.Fatal(err)
	}

	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	name, resolved, err := again.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if name != "dev" {
		t.Fatalf("the only profile should be the default, got %q", name)
	}
	if resolved.Issuer != "https://auth.example.com" || resolved.Client.ID != "app" || !resolved.Insecure {
		t.Fatalf("profile did not round trip: %+v", resolved)
	}
	if len(resolved.Scopes) != 3 {
		t.Fatalf("scopes: %v", resolved.Scopes)
	}
	if _, _, err := again.Resolve("missing"); err == nil {
		t.Fatal("unknown profile must fail")
	}
	if redacted := resolved.Redacted(); redacted.Client.Secret != "" {
		t.Fatal("redacted secret should be empty when none is set")
	}
}

func TestTokenStore(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	store, err := LoadStore(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("dev"); err == nil {
		t.Fatal("empty store must report no token")
	}
	store.Put("dev", &Token{AccessToken: "abc", ExpiresAt: time.Now().Add(time.Hour), ObtainedAt: time.Now()})
	store.Put("", &Token{AccessToken: "def", ExpiresAt: time.Now().Add(-time.Hour), ObtainedAt: time.Now()})
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := LoadStore(configPath)
	if err != nil {
		t.Fatal(err)
	}
	token, err := again.Get("dev")
	if err != nil || token.AccessToken != "abc" || token.Expired() {
		t.Fatalf("saved token: %+v %v", token, err)
	}
	unnamed, err := again.Get("")
	if err != nil || !unnamed.Expired() {
		t.Fatalf("default slot: %+v %v", unnamed, err)
	}
	if names := again.Names(); len(names) != 2 || names[0] != "_default" {
		t.Fatalf("names: %v", names)
	}
	if !again.Delete("dev") || again.Delete("dev") {
		t.Fatal("delete should succeed once")
	}
}
