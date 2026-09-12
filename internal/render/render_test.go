package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"
)

func newTestPrinter(width int) (*Printer, *bytes.Buffer) {
	buffer := &bytes.Buffer{}
	return NewPrinter(buffer, Options{NoColor: true, Width: width}), buffer
}

func TestTableIsCappedAtTheTerminalWidth(t *testing.T) {
	printer, buffer := newTestPrinter(40)
	printer.Table([]string{"A", "B"}, [][]string{{strings.Repeat("x", 60), strings.Repeat("y", 60)}})
	for line := range strings.SplitSeq(strings.TrimSpace(buffer.String()), "\n") {
		if width := lipgloss.Width(line); width > 40 {
			t.Errorf("line is %d cells wide, want at most 40", width)
		}
	}
}

func TestPlainIsTabSeparatedWithoutStyling(t *testing.T) {
	printer, buffer := newTestPrinter(80)
	printer.Plain([][]string{{"a", "b"}, {"c", "d"}})
	if buffer.String() != "a\tb\nc\td\n" {
		t.Fatalf("plain output %q", buffer.String())
	}
}

func TestKVAlignsKeysAndHandlesMultilineValues(t *testing.T) {
	printer, buffer := newTestPrinter(80)
	printer.KV([]Field{F("Issuer", "https://a"), F("Scopes", "openid\nemail")})
	lines := strings.Split(strings.TrimRight(buffer.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %q", buffer.String())
	}
	if !strings.HasSuffix(lines[2], "email") {
		t.Fatalf("continuation line %q", lines[2])
	}
}

func TestDuration(t *testing.T) {
	cases := map[time.Duration]string{
		90 * time.Second:            "1m 30s",
		3*time.Hour + 5*time.Minute: "3h 05m",
		49 * time.Hour:              "2d 1h",
		-30 * time.Second:           "-30s",
		250 * time.Millisecond:      "250ms",
	}
	for d, want := range cases {
		if got := Duration(d); got != want {
			t.Errorf("Duration(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestMaskKeepsOnlyTheEnds(t *testing.T) {
	if Mask("short") != "•••••" {
		t.Fatalf("short secret: %q", Mask("short"))
	}
	masked := Mask("abcdefghijklmnopqrstuvwxyz")
	if !strings.HasPrefix(masked, "abcd") || !strings.HasSuffix(masked, "wxyz") || strings.Contains(masked, "mnop") {
		t.Fatalf("masked: %q", masked)
	}
}

func TestTruncate(t *testing.T) {
	if Truncate("hello world", 5) != "hell…" {
		t.Fatalf("got %q", Truncate("hello world", 5))
	}
	if Truncate("hi", 5) != "hi" {
		t.Fatal("short strings must pass through")
	}
}

func TestMarkdownWithoutColourIsVerbatim(t *testing.T) {
	printer, buffer := newTestPrinter(80)
	if err := printer.Markdown("# Title\n\n- item\n"); err != nil {
		t.Fatal(err)
	}
	if buffer.String() != "# Title\n\n- item\n" {
		t.Fatalf("markdown was altered: %q", buffer.String())
	}
}
