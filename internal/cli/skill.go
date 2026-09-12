package cli

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/Southclaws/oauthcli/internal/cligen"
)

//go:embed skill/SKILL.md
var skillGuide string

// skill prints the agent usage guide, with the generated reference on request.
func skill(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.SkillParams) error {
	streams := newOutput(cmd, commandIO)
	text := skillGuide
	if p.Full {
		text += "\n" + Reference(cmd.Root())
	}
	if p.Out != "" {
		if err := os.MkdirAll(p.Out, 0o755); err != nil {
			return err
		}
		path := filepath.Join(p.Out, "SKILL.md")
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			return err
		}
		streams.Out.Okf("wrote %s", path)
		return nil
	}
	return streams.Out.Markdown(text)
}

// Reference renders every command of the tree as Markdown: usage, description,
// arguments, flags and examples. It reads the cobra tree the specification
// generated, so it cannot drift from what the commands accept.
func Reference(root *cobra.Command) string {
	var b strings.Builder
	b.WriteString("# Command reference\n\n")
	b.WriteString("Generated from the OpenCLI specification. Global flags apply to every command.\n\n")
	b.WriteString("## Global flags\n\n")
	writeFlags(&b, root.PersistentFlags())

	for _, command := range allCommands(root)[1:] {
		if command.Hidden || command.Name() == "help" || command.Name() == "completion" || strings.HasPrefix(command.Name(), "_") {
			continue
		}
		fmt.Fprintf(&b, "## %s\n\n", command.CommandPath())
		if command.Long != "" {
			b.WriteString(strings.TrimSpace(command.Long) + "\n\n")
		} else if command.Short != "" {
			b.WriteString(command.Short + "\n\n")
		}
		fmt.Fprintf(&b, "```\n%s\n```\n\n", command.UseLine())
		if len(command.Aliases) > 0 {
			fmt.Fprintf(&b, "Aliases: %s\n\n", strings.Join(command.Aliases, ", "))
		}
		if command.HasAvailableLocalFlags() {
			writeFlags(&b, command.LocalNonPersistentFlags())
		}
		if command.Example != "" {
			b.WriteString("Examples:\n\n```bash\n" + strings.TrimSpace(unindent(command.Example)) + "\n```\n\n")
		}
	}
	return b.String()
}

func writeFlags(b *strings.Builder, flags *pflag.FlagSet) {
	var rows []string
	flags.VisitAll(func(flag *pflag.Flag) {
		if flag.Hidden || flag.Name == "help" {
			return
		}
		name := "--" + flag.Name
		if flag.Shorthand != "" {
			name = "-" + flag.Shorthand + ", " + name
		}
		usage := flag.Usage
		if flag.DefValue != "" && flag.DefValue != "false" && flag.DefValue != "0" && flag.DefValue != "[]" {
			usage += fmt.Sprintf(" (default %s)", flag.DefValue)
		}
		rows = append(rows, fmt.Sprintf("| `%s` | %s |", name, strings.ReplaceAll(usage, "|", "\\|")))
	})
	if len(rows) == 0 {
		return
	}
	sort.Strings(rows)
	b.WriteString("| Flag | Description |\n|---|---|\n")
	b.WriteString(strings.Join(rows, "\n"))
	b.WriteString("\n\n")
}

func unindent(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimPrefix(line, "  ")
	}
	return strings.Join(lines, "\n")
}
