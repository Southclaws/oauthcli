package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/Southclaws/oauthcli/internal/cligen"
)

// The specification is the behavioural contract; these tests check that the
// generated tree and the agent guide agree with it.

// visible filters out cobra's help and completion commands and carapace's
// hidden completion tree.
func visible(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, command := range allCommands(root) {
		path := command.CommandPath()
		if command.Name() == "help" || strings.Contains(path, " completion") || strings.Contains(path, "_carapace") {
			continue
		}
		out = append(out, command)
	}
	return out
}

func leafCommands(root *cobra.Command) []*cobra.Command {
	var leaves []*cobra.Command
	for _, command := range visible(root)[1:] {
		if !command.HasSubCommands() {
			leaves = append(leaves, command)
		}
	}
	return leaves
}

func TestEveryLeafCommandIsCoveredByTheSkillGuide(t *testing.T) {
	root := NewRootCommand()
	for _, command := range leafCommands(root) {
		path := command.CommandPath()
		if !strings.Contains(skillGuide, path) {
			t.Errorf("SKILL.md does not mention %q", path)
		}
	}
}

func TestEveryCommandDescribesItself(t *testing.T) {
	root := NewRootCommand()
	for _, command := range visible(root) {
		if command.Short == "" {
			t.Errorf("%s has no short description", command.CommandPath())
		}
		if !command.HasSubCommands() && command.Long == "" && command.Example == "" && len(command.Aliases) == 0 {
			// A leaf with no explanation and no example is a leaf an agent
			// has to guess at.
			t.Logf("note: %s has neither a long description nor an example", command.CommandPath())
		}
	}
}

// fang sentence-cases the first word of every description, so a description
// that starts with an acronym renders wrongly ("Oauth"). Descriptions must
// therefore start with an ordinary word.
func TestFlagDescriptionsDoNotStartWithAnAcronym(t *testing.T) {
	root := NewRootCommand()
	for _, command := range visible(root) {
		command.Flags().VisitAll(func(flag *pflag.Flag) {
			first := strings.Fields(flag.Usage)
			if len(first) == 0 {
				t.Errorf("%s --%s has no description", command.CommandPath(), flag.Name)
				return
			}
			word := strings.Trim(first[0], ",.:;")
			upper := 0
			for _, r := range word {
				if unicode.IsUpper(r) {
					upper++
				}
			}
			if upper > 1 {
				t.Errorf("%s --%s description starts with %q, which fang will sentence-case", command.CommandPath(), flag.Name, word)
			}
		})
	}
}

func TestRootHelpPointsAgentsAtTheSkill(t *testing.T) {
	root := NewRootCommand()
	for _, want := range []string{"oauthcli skill", "oauthcli discover", "oauthcli check", "--format json", "exit codes"} {
		if !strings.Contains(root.Long, want) {
			t.Errorf("root description does not mention %q", want)
		}
	}
}

func TestReferenceCoversEveryCommand(t *testing.T) {
	root := NewRootCommand()
	reference := Reference(root)
	for _, command := range leafCommands(root) {
		if !strings.Contains(reference, "## "+command.CommandPath()+"\n") {
			t.Errorf("reference lacks a section for %s", command.CommandPath())
		}
	}
	if !strings.Contains(reference, "--format") {
		t.Error("reference does not list flags")
	}
}

// pkce has no network dependency, so it exercises the whole generated path:
// flag parsing, handler, JSON encoding.
func TestPkceCommandProducesJSON(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"pkce", "--format", "json", "--length", "50"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var result cligen.PkceResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("output is not the declared schema: %v\n%s", err, out.String())
	}
	if len(result.Verifier) != 50 || result.Method != "S256" || result.Challenge == "" {
		t.Fatalf("unexpected result %+v", result)
	}
}

func TestInvalidFormatIsRejectedBeforeTheHandlerRuns(t *testing.T) {
	root := NewRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"pkce", "--format", "xml"})
	if err := root.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid --format") {
		t.Fatalf("expected an invalid format error, got %v", err)
	}
}

func TestSplitScopesAcceptsEveryCommonSpelling(t *testing.T) {
	got := splitScopes([]string{"openid,email", "profile read", "openid"})
	if len(got) != 4 || got[0] != "openid" || got[3] != "read" {
		t.Fatalf("splitScopes = %v", got)
	}
}
