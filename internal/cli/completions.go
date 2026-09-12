package cli

import (
	"context"
	"os"
	"time"

	"github.com/carapace-sh/carapace"

	"github.com/Southclaws/oauthcli/internal/config"
	"github.com/Southclaws/oauthcli/internal/oauth"
	"github.com/Southclaws/oauthcli/rfcs"
)

// actionReferences offers the embedded specifications by id, described by
// their titles.
func actionReferences() carapace.Action {
	values := make([]string, 0, len(rfcs.Specs)*2)
	for _, spec := range rfcs.Specs {
		values = append(values, spec.ID, spec.Title)
	}
	return carapace.ActionValuesDescribed(values...)
}

// specIDs are the specification identifiers `check --only` accepts.
var specIDs = [][2]string{
	{"rfc8414", "Authorization Server Metadata"},
	{"oidc-discovery", "OpenID Connect Discovery"},
	{"tls", "Transport security"},
	{"rfc7517", "JSON Web Key Set"},
	{"rfc6749", "OAuth 2.0 core endpoints"},
	{"rfc7636", "PKCE"},
	{"oauth2.1", "OAuth 2.1"},
	{"rfc9068", "JWT access tokens"},
	{"rfc6750", "Bearer token usage"},
	{"oidc-core", "OpenID Connect Core"},
	{"rfc7662", "Token introspection"},
	{"rfc7009", "Token revocation"},
	{"rfc8628", "Device authorization grant"},
	{"rfc9126", "Pushed authorization requests"},
	{"rfc9449", "DPoP"},
	{"rfc8707", "Resource indicators"},
	{"rfc7523", "JWT client authentication"},
	{"rfc8693", "Token exchange"},
	{"rfc7591", "Dynamic client registration"},
	{"rfc9728", "Protected resource metadata"},
	{"rfc9207", "Issuer identification"},
	{"rfc8705", "Mutual TLS"},
	{"rfc9101", "JWT-secured authorization requests"},
	{"rfc9396", "Rich authorization requests"},
	{"cimd", "Client ID metadata documents"},
}

func actionSpecs() carapace.Action {
	values := make([]string, 0, len(specIDs)*2)
	for _, spec := range specIDs {
		values = append(values, spec[0], spec[1])
	}
	return carapace.ActionValuesDescribed(values...).UniqueList(",")
}

// actionProfiles offers the profiles in the configuration file, described by
// their issuer.
func actionProfiles() carapace.Action {
	return carapace.ActionCallback(func(carapace.Context) carapace.Action {
		file, err := config.Load("")
		if err != nil {
			return carapace.ActionMessage("cannot read the configuration: %v", err)
		}
		values := make([]string, 0, len(file.Profiles)*2)
		for _, name := range file.Names() {
			values = append(values, name, file.Profiles[name].Issuer)
		}
		if len(values) == 0 {
			return carapace.ActionMessage("no profiles configured; run oauthcli config init")
		}
		return carapace.ActionValuesDescribed(values...)
	})
}

// actionIssuers offers every issuer already configured.
func actionIssuers() carapace.Action {
	return carapace.ActionCallback(func(carapace.Context) carapace.Action {
		file, err := config.Load("")
		if err != nil {
			return carapace.ActionValues()
		}
		seen := map[string]bool{}
		values := []string{}
		for _, name := range file.Names() {
			issuer := file.Profiles[name].Issuer
			if issuer == "" || seen[issuer] {
				continue
			}
			seen[issuer] = true
			values = append(values, issuer, name)
		}
		return carapace.ActionValuesDescribed(values...)
	})
}

// actionClientIDs offers the client ids of configured profiles.
func actionClientIDs() carapace.Action {
	return carapace.ActionCallback(func(carapace.Context) carapace.Action {
		file, err := config.Load("")
		if err != nil {
			return carapace.ActionValues()
		}
		values := []string{}
		for _, name := range file.Names() {
			if id := file.Profiles[name].Client.ID; id != "" {
				values = append(values, id, name)
			}
		}
		return carapace.ActionValuesDescribed(values...)
	})
}

// actionSettings offers the dotted keys `config set` understands.
func actionSettings() carapace.Action {
	return carapace.ActionValues(config.SettableKeys...)
}

// actionScopes completes scopes from the issuer's scopes_supported, bounded
// hard in time so that pressing tab never leaves a shell waiting.
func actionScopes() carapace.Action {
	return carapace.ActionCallback(func(c carapace.Context) carapace.Action {
		standard := []string{"openid", "profile", "email", "address", "phone", "offline_access"}
		issuer := c.Getenv("OAUTH_ISSUER")
		if issuer == "" {
			file, err := config.Load(os.Getenv("OAUTH_CONFIG"))
			if err == nil {
				if _, profile, err := file.Resolve(c.Getenv("OAUTH_PROFILE")); err == nil {
					issuer = profile.Issuer
				}
			}
		}
		if issuer == "" {
			return carapace.ActionValues(standard...).UniqueList(",")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		client, err := oauth.NewClient(oauth.Options{Timeout: 2 * time.Second})
		if err != nil {
			return carapace.ActionValues(standard...).UniqueList(",")
		}
		normalized, err := oauth.NormalizeIssuer(issuer)
		if err != nil {
			return carapace.ActionValues(standard...).UniqueList(",")
		}
		metadata, err := client.FetchMetadata(ctx, normalized, "auto")
		if err != nil {
			return carapace.ActionValues(standard...).UniqueList(",")
		}
		scopes := metadata.Strings("scopes_supported")
		if len(scopes) == 0 {
			scopes = standard
		}
		return carapace.ActionValues(scopes...).UniqueList(",")
	})
}
