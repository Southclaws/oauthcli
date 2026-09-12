package cli

import (
	"context"
	"errors"
	"image/color"
	"os"
	"os/signal"
	"syscall"

	"charm.land/lipgloss/v2"
	"github.com/carapace-sh/carapace"
	"github.com/charmbracelet/fang"
	"github.com/charmbracelet/x/exp/charmtone"
	"github.com/spf13/cobra"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/oauth"
)

// Version is the version reported by --version. It is overridden at build time
// with -ldflags "-X github.com/Southclaws/oauthcli/internal/cli.Version=…".
var Version = "0.1.0"

//go:generate opencli generate go-cobra ../../opencli.yaml --output ../cligen --package cligen

// exitCodes maps the sentinel errors to the exit codes the specification
// documents, so a script can tell an unreachable server from a failed
// expectation.
var exitCodes = []struct {
	err  error
	code int
}{
	{ErrUnreachable, 2},
	{ErrOAuth, 3},
	{ErrNotFound, 4},
	{ErrFailed, 5},
	{ErrInvalidToken, 6},
}

// NewRootCommand assembles the command tree from the generated constructors.
//
// Every command's flags, arguments, help text and output contract come from
// opencli.yaml; the handlers only implement behaviour. Adding a command
// therefore starts in the specification, not here.
func NewRootCommand() *cobra.Command {
	root := cligen.NewRootCommand(
		cligen.NewDiscoverCommand(discover),
		cligen.NewMetadataCommand(metadata),
		cligen.NewJwksCommand(jwks),
		cligen.NewResourceCommand(resource),
		cligen.NewTokenCommand(tokenGet, tokenRefresh, tokenInspect, tokenIntrospect, tokenRevoke, tokenExpect, tokenStatus, tokenClear),
		cligen.NewUserinfoCommand(userinfo),
		cligen.NewFlowCommand(flowCode, flowDevice),
		cligen.NewClientCommand(clientRegister, clientGet, clientUpdate, clientDelete),
		cligen.NewCimdCommand(cimdCheck, cimdNew),
		cligen.NewCheckCommand(check),
		cligen.NewSkillCommand(skill),
		cligen.NewReferenceCommand(reference),
		cligen.NewPkceCommand(pkce),
		cligen.NewConfigCommand(configInit, configShow, configList, configUse, configSet, configRemove, configPath),
	)

	// Handlers report their own errors through fang's error handler, so cobra
	// must not also print usage for a runtime failure.
	root.SilenceUsage = true
	root.SilenceErrors = true

	registerCompletions(root)
	return root
}

// Execute runs the command line.
//
// fang provides the styled help, error and version output, and the manpage and
// completion subcommands; carapace provides the completion values themselves.
func Execute(ctx context.Context) int {
	// An interactive flow must unwind on ctrl-c: close the listener, stop
	// polling, and report cancellation rather than die mid-request.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	oauth.Version = Version
	root := NewRootCommand()

	err := fang.Execute(ctx, root,
		fang.WithVersion(Version),
		fang.WithColorSchemeFunc(colorScheme),
	)
	if err == nil {
		return 0
	}
	for _, mapping := range exitCodes {
		if errors.Is(err, mapping.err) {
			return mapping.code
		}
	}
	return 1
}

// registerCompletions teaches the shell what each flag and argument accepts.
func registerCompletions(root *cobra.Command) {
	carapace.Gen(root).FlagCompletion(carapace.ActionMap{
		"profile":            actionProfiles(),
		"config":             carapace.ActionFiles(".yaml", ".yml"),
		"issuer":             actionIssuers(),
		"client-id":          actionClientIDs(),
		"client-secret-file": carapace.ActionFiles(),
		"client-key":         carapace.ActionFiles(".pem", ".key"),
		"dpop-key":           carapace.ActionFiles(".pem", ".key"),
		"token-file":         carapace.ActionFiles(),
		"auth-method":        carapace.ActionValues(oauth.AuthMethods...),
		"scope":              actionScopes(),
		"theme":              carapace.ActionValues("charm", "nord", "dracula", "mono"),
	})

	for _, command := range allCommands(root) {
		registerCommandCompletions(command)
	}
}

func allCommands(root *cobra.Command) []*cobra.Command {
	commands := []*cobra.Command{root}
	for _, child := range root.Commands() {
		commands = append(commands, allCommands(child)...)
	}
	return commands
}

func registerCommandCompletions(command *cobra.Command) {
	flags := carapace.ActionMap{}
	if command.Flags().Lookup("from") != nil {
		flags["from"] = carapace.ActionFiles(".json")
	}
	if command.Flags().Lookup("keys") != nil && command.Flags().Lookup("keys").Value.Type() == "string" {
		flags["keys"] = carapace.ActionFiles(".json")
	}
	if command.Flags().Lookup("only") != nil {
		flags["only"] = actionSpecs()
		flags["skip"] = actionSpecs()
	}
	if command.Flags().Lookup("out") != nil {
		flags["out"] = carapace.ActionDirectories()
	}
	if command.Flags().Lookup("grant-type") != nil {
		flags["grant-type"] = carapace.ActionValues(
			"authorization_code", "client_credentials", "refresh_token",
			oauth.GrantDeviceCode, oauth.GrantJWTBearer, oauth.GrantTokenExchange,
		)
	}
	if len(flags) > 0 {
		carapace.Gen(command).FlagCompletion(flags)
	}

	switch command.CommandPath() {
	case "oauthcli discover", "oauthcli metadata", "oauthcli check", "oauthcli jwks":
		carapace.Gen(command).PositionalCompletion(actionIssuers())
	case "oauthcli config use", "oauthcli config remove":
		carapace.Gen(command).PositionalCompletion(actionProfiles())
	case "oauthcli config set":
		carapace.Gen(command).PositionalCompletion(actionSettings())
	case "oauthcli reference", "oauthcli rfc", "oauthcli spec", "oauthcli docs":
		carapace.Gen(command).PositionalCompletion(actionReferences())
	}
}

// colorScheme themes fang's help, error and version output with the same
// CharmTone palette the rest of the output uses.
func colorScheme(light lipgloss.LightDarkFunc) fang.ColorScheme {
	hex := func(key charmtone.Key) color.Color { return lipgloss.Color(key.Hex()) }

	base := fang.DefaultColorScheme(light)
	base.Title = hex(charmtone.Charple)
	base.Command = hex(charmtone.Malibu)
	base.Flag = hex(charmtone.Guac)
	base.Argument = light(hex(charmtone.Pepper), hex(charmtone.Salt))
	base.Program = hex(charmtone.Charple)
	base.DimmedArgument = hex(charmtone.Squid)
	base.Description = light(hex(charmtone.Charcoal), hex(charmtone.Smoke))
	base.ErrorHeader = [2]color.Color{hex(charmtone.Salt), hex(charmtone.Sriracha)}
	return base
}
