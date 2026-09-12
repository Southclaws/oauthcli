package render

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"charm.land/glamour/v2"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/term"
)

// Printer writes themed output to one stream. Styling is always applied and the
// colour profile of the underlying writer decides what survives, so a piped or
// redirected stream degrades to plain text without the callers knowing.
type Printer struct {
	w     *colorprofile.Writer
	raw   io.Writer
	T     Theme
	Width int
	TTY   bool
}

// Options configure a Printer.
type Options struct {
	NoColor bool
	Theme   string
	Width   int
}

// NewPrinter builds a Printer for out. When out is a terminal its capabilities
// and width are detected; otherwise a 100-column plain-text profile is used.
func NewPrinter(out io.Writer, opts Options) *Printer {
	writer := colorprofile.NewWriter(out, os.Environ())
	if opts.NoColor {
		writer.Profile = colorprofile.NoTTY
	}

	width := opts.Width
	dark, tty := true, false
	if file, ok := out.(*os.File); ok && term.IsTerminal(file.Fd()) {
		tty = true
		if w, _, err := term.GetSize(file.Fd()); err == nil && w > 0 && width == 0 {
			width = w
		}
		// Querying the terminal for its background colour costs a round trip
		// and only pays off when styling is actually going to be emitted.
		if writer.Profile != colorprofile.NoTTY {
			dark = lipgloss.HasDarkBackground(os.Stdin, file)
		}
	}
	if width <= 0 {
		width = 100
	}

	return &Printer{
		w:     writer,
		raw:   out,
		T:     ThemeByName(opts.Theme, dark),
		Width: width,
		TTY:   tty,
	}
}

// Writer returns the styled writer, for callers that render their own output.
func (p *Printer) Writer() io.Writer { return p.w }

// Raw returns the unwrapped writer, for machine-readable output that must not
// be touched by the colour profile.
func (p *Printer) Raw() io.Writer { return p.raw }

func (p *Printer) Print(s string)                              { fmt.Fprint(p.w, s) }
func (p *Printer) Printf(format string, args ...any)           { fmt.Fprintf(p.w, format, args...) }
func (p *Printer) Println(args ...any)                         { fmt.Fprintln(p.w, args...) }
func (p *Printer) Styled(s lipgloss.Style, text string) string { return s.Render(text) }

// Title writes a heading with an optional subtitle to its right.
func (p *Printer) Title(title, subtitle string) {
	line := p.T.Styles.Title.Render(title)
	if subtitle != "" {
		line += "  " + p.T.Styles.Faint.Render(subtitle)
	}
	fmt.Fprintln(p.w, line)
}

// Section writes a secondary heading preceded by a blank line.
func (p *Printer) Section(title string) {
	fmt.Fprintln(p.w)
	fmt.Fprintln(p.w, p.T.Styles.Subtitle.Render(title))
}

// Notef writes an informational line prefixed with a bullet.
func (p *Printer) Notef(format string, args ...any) {
	fmt.Fprintf(p.w, "%s %s\n",
		p.T.Styles.Accent.Render(p.T.Symbols.Bullet),
		p.T.Styles.Dim.Render(fmt.Sprintf(format, args...)))
}

// Warnf writes a warning line.
func (p *Printer) Warnf(format string, args ...any) {
	fmt.Fprintf(p.w, "%s %s\n",
		p.T.Styles.Warn.Render(p.T.Symbols.Warn),
		p.T.Styles.Value.Render(fmt.Sprintf(format, args...)))
}

// Errorf writes a failure line.
func (p *Printer) Errorf(format string, args ...any) {
	fmt.Fprintf(p.w, "%s %s\n",
		p.T.Styles.Bad.Render(p.T.Symbols.Bad),
		p.T.Styles.Value.Render(fmt.Sprintf(format, args...)))
}

// Okf writes a success line.
func (p *Printer) Okf(format string, args ...any) {
	fmt.Fprintf(p.w, "%s %s\n",
		p.T.Styles.Good.Render(p.T.Symbols.Good),
		p.T.Styles.Value.Render(fmt.Sprintf(format, args...)))
}

// Status returns the glyph and style for a pass/warn/fail/skip/untested state.
func (p *Printer) Status(status string) (string, lipgloss.Style) {
	s := p.T.Symbols
	switch status {
	case "pass", "found", "verified", "ok", "active", "true":
		return s.Good, p.T.Styles.Good
	case "warn", "warning", "unverified", "unsigned":
		return s.Warn, p.T.Styles.Warn
	case "fail", "error", "invalid", "missing":
		return s.Bad, p.T.Styles.Bad
	case "untested":
		return s.Untested, p.T.Styles.Skip
	default:
		return s.Skip, p.T.Styles.Skip
	}
}

// Statusf writes a line led by the glyph for status.
func (p *Printer) Statusf(status, format string, args ...any) {
	glyph, style := p.Status(status)
	fmt.Fprintf(p.w, "%s %s\n", style.Render(glyph), p.T.Styles.Value.Render(fmt.Sprintf(format, args...)))
}

// Badge renders a short upper-case label on a coloured background.
func (p *Printer) Badge(kind, text string) string {
	switch kind {
	case "good":
		return p.T.Styles.BadgeGood.Render(text)
	case "warn":
		return p.T.Styles.BadgeWarn.Render(text)
	case "bad":
		return p.T.Styles.BadgeBad.Render(text)
	case "info":
		return p.T.Styles.BadgeInfo.Render(text)
	default:
		return p.T.Styles.BadgeSkip.Render(text)
	}
}

// Field is one row of a key/value block.
type Field struct {
	Key   string
	Value string
	Style *lipgloss.Style
}

// F builds a plain field.
func F(key, value string) Field { return Field{Key: key, Value: value} }

// FS builds a field whose value carries its own style.
func FS(key, value string, style lipgloss.Style) Field {
	return Field{Key: key, Value: value, Style: &style}
}

// KV writes a key/value block with the keys right-aligned into one column.
func (p *Printer) KV(fields []Field) {
	width := 0
	for _, f := range fields {
		if f.Key != "" && lipgloss.Width(f.Key) > width {
			width = lipgloss.Width(f.Key)
		}
	}

	key := p.T.Styles.Key.Width(width + 1).AlignHorizontal(lipgloss.Right)
	for _, f := range fields {
		if f.Key == "" && f.Value == "" {
			fmt.Fprintln(p.w)
			continue
		}
		value := p.T.Styles.Value
		if f.Style != nil {
			value = *f.Style
		}
		lines := strings.Split(f.Value, "\n")
		fmt.Fprintf(p.w, "%s  %s\n", key.Render(f.Key), value.Render(lines[0]))
		for _, line := range lines[1:] {
			fmt.Fprintf(p.w, "%s  %s\n", key.Render(""), value.Render(line))
		}
	}
}

// Table writes a table with a styled header and rows. The table is capped to
// the printer's width so a long value wraps inside its cell.
func (p *Printer) Table(headers []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Fprintln(p.w, p.T.Styles.Faint.Render("no results"))
		return
	}

	t := table.New().
		Headers(headers...).
		Rows(rows...).
		Border(lipgloss.NormalBorder()).
		BorderStyle(p.T.Styles.Border).
		BorderTop(false).
		BorderBottom(false).
		BorderLeft(false).
		BorderRight(false).
		BorderColumn(false).
		BorderRow(false).
		Wrap(true).
		StyleFunc(func(row, _ int) lipgloss.Style {
			if row == table.HeaderRow {
				return p.T.Styles.Header
			}
			return p.T.Styles.Cell
		})

	if naturalWidth(headers, rows) > p.Width {
		t = t.Width(p.Width)
	}

	fmt.Fprintln(p.w, t.Render())
}

// naturalWidth is the width a table needs to show every cell in full.
func naturalWidth(headers []string, rows [][]string) int {
	columns := make([]int, len(headers))
	for index, header := range headers {
		columns[index] = lipgloss.Width(header)
	}
	for _, row := range rows {
		for index, cell := range row {
			if index < len(columns) {
				columns[index] = max(columns[index], lipgloss.Width(cell))
			}
		}
	}

	total := 0
	for _, width := range columns {
		total += width + 2
	}
	return total
}

// Plain writes tab-separated rows with no styling and no header.
func (p *Printer) Plain(rows [][]string) {
	for _, row := range rows {
		fmt.Fprintln(p.raw, strings.Join(row, "\t"))
	}
}

// Box draws content inside a rounded border, for the one value a person must
// read, such as a device code.
func (p *Printer) Box(content string) {
	fmt.Fprintln(p.w, p.T.Styles.Box.Render(content))
}

// Markdown renders source as styled Markdown at the printer's width. On a
// stream without colour the Markdown is printed as written, which is what a
// file or a pull request wants.
func (p *Printer) Markdown(source string) error {
	if p.w.Profile == colorprofile.NoTTY || p.w.Profile == colorprofile.Ascii {
		_, err := io.WriteString(p.raw, source)
		return err
	}

	style := glamour.WithStandardStyle("dark")
	if !p.T.Dark {
		style = glamour.WithStandardStyle("light")
	}
	renderer, err := glamour.NewTermRenderer(style, glamour.WithWordWrap(min(p.Width, 100)))
	if err != nil {
		return err
	}
	out, err := renderer.Render(source)
	if err != nil {
		return err
	}
	_, err = io.WriteString(p.w, out)
	return err
}

// Truncate shortens s to width, marking the cut with an ellipsis.
func Truncate(s string, width int) string {
	if width <= 0 || lipgloss.Width(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}

	runes := []rune(s)
	for len(runes) > 0 {
		candidate := string(runes) + "…"
		if lipgloss.Width(candidate) <= width {
			return candidate
		}
		runes = runes[:len(runes)-1]
	}
	return "…"
}

// Duration formats d in the coarsest unit that keeps it readable: "2h 05m",
// "45s", "3d 4h". Negative durations are prefixed with a minus sign.
func Duration(d time.Duration) string {
	sign := ""
	if d < 0 {
		sign = "-"
		d = -d
	}
	switch {
	case d >= 48*time.Hour:
		days := int(d.Hours()) / 24
		hours := int(d.Hours()) % 24
		return fmt.Sprintf("%s%dd %dh", sign, days, hours)
	case d >= time.Hour:
		return fmt.Sprintf("%s%dh %02dm", sign, int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%s%dm %02ds", sign, int(d.Minutes()), int(d.Seconds())%60)
	case d >= time.Second:
		return fmt.Sprintf("%s%ds", sign, int(d.Seconds()))
	default:
		return fmt.Sprintf("%s%dms", sign, d.Milliseconds())
	}
}

// Mask hides all but the first and last few characters of a secret.
func Mask(secret string) string {
	if secret == "" {
		return ""
	}
	if len(secret) <= 12 {
		return strings.Repeat("•", len(secret))
	}
	return secret[:4] + strings.Repeat("•", 8) + secret[len(secret)-4:]
}
