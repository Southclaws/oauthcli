package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/internal/conformance"
	"github.com/Southclaws/oauthcli/internal/oauth"
	"github.com/Southclaws/oauthcli/internal/render"
)

// check audits an issuer against the specifications.
func check(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.CheckParams) (cligen.ConformanceReport, error) {
	s, err := newSession(cmd, commandIO)
	if err != nil {
		return cligen.ConformanceReport{}, err
	}
	issuer, err := s.issuer(p.IssuerUrl)
	if err != nil {
		return cligen.ConformanceReport{}, err
	}
	credentials, err := s.credentials()
	if err != nil {
		return cligen.ConformanceReport{}, err
	}
	dpopKey, _ := cmd.Flags().GetString("dpop-key")

	format := string(p.Format)
	live := !machineReadable(format) && format == "checklist" && s.Err.TTY
	var progress func(spec *conformance.Spec, check cligen.Check)
	if live {
		progress = func(spec *conformance.Spec, check cligen.Check) {
			glyph, style := s.Err.Status(check.Status)
			s.Err.Printf("\r\x1b[2K%s %s %s", style.Render(glyph), s.Err.T.Styles.Faint.Render(spec.ID), render.Truncate(check.Title, max(20, s.Err.Width-20)))
		}
	}

	runner := conformance.New(s.Client, conformance.Options{
		Issuer:       issuer,
		Credentials:  credentials,
		Scopes:       s.Settings.Scopes,
		Audience:     s.Settings.Audience,
		Resources:    s.Settings.Resources,
		Token:        p.Token,
		RefreshToken: p.RefreshToken,
		ResourceURLs: p.ResourceUrl,
		RedirectURI:  s.Settings.RedirectURI,
		Offline:      p.Offline,
		Register:     p.Register,
		Negative:     p.Negative,
		DPoPKey:      dpopKey,
		Only:         p.Only,
		Skip:         p.Skip,
		AllowHTTP:    s.Settings.AllowHTTP,
		Insecure:     s.Settings.Insecure,
		Progress:     progress,
	})
	if s.Verbose > 0 || live {
		mode := "anonymous"
		if credentials.ClientID != "" && (credentials.ClientSecret != "" || credentials.Key != nil) && !p.Offline {
			mode = "with client " + credentials.ClientID
		}
		s.Err.Notef("auditing %s (%s)", issuer, mode)
	}

	report, err := runner.Run(ctx)
	if live {
		s.Err.Print("\r\x1b[2K")
	}
	if err != nil {
		return cligen.ConformanceReport{}, err
	}
	if p.Label != "" {
		report.Label = &p.Label
	}

	warnings := report.Summary.Warn > 0
	failed := !report.Passed || (string(p.FailOn) == "warn" && warnings)

	if machineReadable(format) {
		if failed {
			return report, s.fail(format, report, fmt.Errorf("%w: the audit found non-conformances", ErrFailed))
		}
		return report, nil
	}

	switch format {
	case "table":
		renderCheckTable(s.Out, report)
	case "plain":
		renderCheckPlain(s.Out, report)
	case "markdown":
		if err := s.Out.Markdown(checkMarkdown(report)); err != nil {
			return report, err
		}
	default:
		renderChecklist(s.Out, report, string(p.Show) == "problems")
	}
	if failed {
		return report, fmt.Errorf("%w: the audit found non-conformances", ErrFailed)
	}
	return report, nil
}

func verdictBadge(out *render.Printer, verdict string) string {
	switch verdict {
	case conformance.Conformant:
		return out.Badge("good", "SUPPORTED · CONFORMANT")
	case conformance.NonConformant:
		return out.Badge("bad", "SUPPORTED · NON-CONFORMANT")
	case conformance.NotSupported:
		return out.Badge("skip", "NOT SUPPORTED")
	default:
		return out.Badge("info", "NOT TESTED")
	}
}

func verdictText(verdict string) string {
	switch verdict {
	case conformance.Conformant:
		return "supported, conformant"
	case conformance.NonConformant:
		return "supported, non-conformant"
	case conformance.NotSupported:
		return "not supported"
	default:
		return "not tested"
	}
}

// renderChecklist prints the grouped checklist.
func renderChecklist(out *render.Printer, report cligen.ConformanceReport, problemsOnly bool) {
	title := report.Issuer
	if report.Label != nil {
		title = *report.Label
	}
	mode := "anonymous"
	if report.Credentials != nil && *report.Credentials {
		mode = "with credentials"
	}
	out.Title(title, fmt.Sprintf("%s · %s · %s", mode, render.Duration(time.Duration(report.ElapsedMs)*time.Millisecond), report.StartedAt.Local().Format(time.RFC3339)))
	out.Println()

	for _, spec := range report.Specs {
		problems := 0
		for _, check := range spec.Checks {
			if check.Status == conformance.Fail || check.Status == conformance.Warn {
				problems++
			}
		}
		out.Printf("%s %s  %s\n", out.T.Styles.Accent.Render(out.T.Symbols.Spec), out.T.Styles.Title.Render(spec.Title), verdictBadge(out, spec.Verdict))
		for _, check := range spec.Checks {
			if problemsOnly && check.Status != conformance.Fail && check.Status != conformance.Warn {
				continue
			}
			if spec.Verdict == conformance.NotSupported && check.Status == conformance.Skip && len(spec.Checks) == 1 {
				out.Printf("    %s\n", out.T.Styles.Faint.Render(check.Title))
				continue
			}
			glyph, style := out.Status(check.Status)
			line := fmt.Sprintf("    %s %s", style.Render(glyph), check.Title)
			if check.Section != nil && *check.Section != "" {
				line += "  " + out.T.Styles.Faint.Render(*check.Section)
			}
			out.Println(line)
			if check.Detail != nil && *check.Detail != "" && (check.Status != conformance.Pass || verboseDetail(check)) {
				detailStyle := out.T.Styles.Dim
				if check.Status == conformance.Fail {
					detailStyle = out.T.Styles.Bad
				}
				for _, part := range wrapText(*check.Detail, max(40, out.Width-8)) {
					out.Printf("        %s\n", detailStyle.Render(part))
				}
			}
		}
		if problemsOnly && problems == 0 && spec.Verdict != conformance.NotSupported {
			out.Printf("    %s\n", out.T.Styles.Faint.Render(fmt.Sprintf("%d check(s), no problems", len(spec.Checks))))
		}
		out.Println()
	}

	summary := report.Summary
	out.Printf("%s  %s  %s  %s\n",
		out.Badge("good", fmt.Sprintf("%d CONFORMANT", summary.Conformant)),
		out.Badge("bad", fmt.Sprintf("%d NON-CONFORMANT", summary.NonConformant)),
		out.Badge("skip", fmt.Sprintf("%d NOT SUPPORTED", summary.NotSupported)),
		out.Badge("info", fmt.Sprintf("%d NOT TESTED", summary.NotTested)),
	)
	out.Println(out.T.Styles.Dim.Render(fmt.Sprintf("%d checks: %d passed, %d failed, %d warnings, %d skipped, %d untested",
		summary.Pass+summary.Fail+summary.Warn+summary.Skip+summary.Untested, summary.Pass, summary.Fail, summary.Warn, summary.Skip, summary.Untested)))
	if report.Credentials != nil && !*report.Credentials && summary.Untested > 0 {
		out.Notef("%d checks need credentials: add --client-id and --client-secret (or a profile) to run them", summary.Untested)
	}
}

// verboseDetail reports whether a passing check's detail is worth a line: the
// ones that carry a value a reader wants to see, such as a URL or a timing.
func verboseDetail(check cligen.Check) bool {
	return strings.HasSuffix(check.ID, ".found") || strings.HasSuffix(check.ID, ".advertised") || strings.HasSuffix(check.ID, ".version") || strings.HasSuffix(check.ID, ".client-credentials") || strings.HasSuffix(check.ID, ".jwt") || strings.HasSuffix(check.ID, ".lifetime") || strings.HasSuffix(check.ID, ".certificate")
}

func wrapText(text string, width int) []string {
	words := strings.Fields(text)
	var lines []string
	var current string
	for _, word := range words {
		if current != "" && len(current)+len(word)+1 > width {
			lines = append(lines, current)
			current = ""
		}
		if current != "" {
			current += " "
		}
		current += word
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func checkRows(report cligen.ConformanceReport) [][]string {
	var rows [][]string
	for _, spec := range report.Specs {
		for _, check := range spec.Checks {
			rows = append(rows, []string{spec.ID, check.Status, check.Title, deref(check.Section, ""), deref(check.Detail, "")})
		}
	}
	return rows
}

func renderCheckTable(out *render.Printer, report cligen.ConformanceReport) {
	rows := make([][]string, 0, len(report.Specs))
	for _, spec := range report.Specs {
		rows = append(rows, []string{spec.ID, spec.Title, verdictText(spec.Verdict), fmt.Sprint(len(spec.Checks))})
	}
	out.Title(report.Issuer, "verdict per specification")
	out.Table([]string{"ID", "SPECIFICATION", "VERDICT", "CHECKS"}, rows)
	out.Println()
	out.Table([]string{"SPEC", "STATUS", "CHECK", "SECTION", "DETAIL"}, checkRows(report))
}

func renderCheckPlain(out *render.Printer, report cligen.ConformanceReport) {
	out.Plain(checkRows(report))
}

// checkMarkdown renders the report as a document for a pull request.
func checkMarkdown(report cligen.ConformanceReport) string {
	var b strings.Builder
	title := report.Issuer
	if report.Label != nil {
		title = *report.Label
	}
	fmt.Fprintf(&b, "# OAuth conformance: %s\n\n", title)
	mode := "anonymous"
	if report.Credentials != nil && *report.Credentials {
		mode = "with client credentials"
	}
	fmt.Fprintf(&b, "Issuer `%s`, audited %s (%s) in %s by oauthcli.\n\n", report.Issuer, report.StartedAt.Format(time.RFC3339), mode, render.Duration(time.Duration(report.ElapsedMs)*time.Millisecond))
	fmt.Fprintf(&b, "| Verdict | Count |\n|---|---|\n| Supported, conformant | %d |\n| Supported, non-conformant | %d |\n| Not supported | %d |\n| Not tested | %d |\n\n",
		report.Summary.Conformant, report.Summary.NonConformant, report.Summary.NotSupported, report.Summary.NotTested)

	b.WriteString("## Specifications\n\n| Specification | Verdict |\n|---|---|\n")
	for _, spec := range report.Specs {
		name := spec.Title
		if spec.URL != nil {
			name = fmt.Sprintf("[%s](%s)", spec.Title, *spec.URL)
		}
		fmt.Fprintf(&b, "| %s | %s |\n", name, verdictText(spec.Verdict))
	}

	marks := map[string]string{
		conformance.Pass:     ":white_check_mark:",
		conformance.Fail:     ":x:",
		conformance.Warn:     ":warning:",
		conformance.Skip:     ":heavy_minus_sign:",
		conformance.Untested: ":grey_question:",
	}
	for _, spec := range report.Specs {
		fmt.Fprintf(&b, "\n## %s\n\n**%s**\n\n", spec.Title, verdictText(spec.Verdict))
		for _, check := range spec.Checks {
			fmt.Fprintf(&b, "- %s %s", marks[check.Status], check.Title)
			if check.Section != nil && *check.Section != "" {
				fmt.Fprintf(&b, " _(%s)_", *check.Section)
			}
			if check.Detail != nil && *check.Detail != "" && check.Status != conformance.Pass {
				fmt.Fprintf(&b, "  \n  %s", *check.Detail)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

var _ = oauth.Ptr[string]
