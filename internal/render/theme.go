// Package render turns results into terminal output: themed styles, tables,
// key/value blocks, checklists and Markdown, with one colour vocabulary for
// pass, warn and fail that runs through all of them.
package render

import (
	"image/color"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/exp/charmtone"
)

// Palette is the full set of colours a theme provides. Every style in the tool
// is built from these, so a new theme only has to supply colours.
type Palette struct {
	Text    color.Color
	Dim     color.Color
	Faint   color.Color
	Accent  color.Color
	Accent2 color.Color
	Accent3 color.Color

	Good color.Color
	Warn color.Color
	Bad  color.Color

	SelBg color.Color
	SelFg color.Color
}

// Styles are the styles every renderer draws with, derived from a Palette.
type Styles struct {
	Title    lipgloss.Style
	Subtitle lipgloss.Style
	Key      lipgloss.Style
	Value    lipgloss.Style
	Dim      lipgloss.Style
	Faint    lipgloss.Style
	Accent   lipgloss.Style
	URL      lipgloss.Style
	Code     lipgloss.Style

	Good lipgloss.Style
	Warn lipgloss.Style
	Bad  lipgloss.Style
	Skip lipgloss.Style

	Header lipgloss.Style
	Cell   lipgloss.Style
	Border lipgloss.Style

	BadgeGood lipgloss.Style
	BadgeWarn lipgloss.Style
	BadgeBad  lipgloss.Style
	BadgeSkip lipgloss.Style
	BadgeInfo lipgloss.Style

	Box lipgloss.Style
}

// Theme is a named palette together with the styles derived from it.
type Theme struct {
	Name    string
	Dark    bool
	Colors  Palette
	Styles  Styles
	Symbols Symbols
}

// Symbols are the glyphs used to draw structure and state.
type Symbols struct {
	Good     string
	Warn     string
	Bad      string
	Skip     string
	Untested string
	Arrow    string
	Bullet   string
	Ellipsis string
	Spec     string
	Lock     string
	Unlock   string
}

func unicodeSymbols() Symbols {
	return Symbols{
		Good:     "●",
		Warn:     "◐",
		Bad:      "✗",
		Skip:     "○",
		Untested: "◌",
		Arrow:    "→",
		Bullet:   "•",
		Ellipsis: "…",
		Spec:     "◆",
		Lock:     "🔒",
		Unlock:   "🔓",
	}
}

// ThemeNames are the themes a user may select, in the order they are offered.
var ThemeNames = []string{"charm", "nord", "dracula", "mono"}

// ThemeByName returns the named theme, or the charm theme when the name is not
// recognised. dark selects the variant tuned for a dark background.
func ThemeByName(name string, dark bool) Theme {
	var p Palette
	switch name {
	case "nord":
		p = nordPalette(dark)
	case "dracula":
		p = draculaPalette()
	case "mono":
		p = monoPalette(dark)
	default:
		name = "charm"
		p = charmPalette(dark)
	}

	return Theme{Name: name, Dark: dark, Colors: p, Styles: newStyles(p), Symbols: unicodeSymbols()}
}

// charmPalette draws from CharmTone, the palette the charm libraries ship, so
// the tool looks like the toolkit it is built with.
func charmPalette(dark bool) Palette {
	pick := lipgloss.LightDark(dark)
	hex := func(k charmtone.Key) color.Color { return lipgloss.Color(k.Hex()) }

	return Palette{
		Text:    pick(hex(charmtone.Pepper), hex(charmtone.Salt)),
		Dim:     pick(hex(charmtone.Charcoal), hex(charmtone.Smoke)),
		Faint:   pick(hex(charmtone.Squid), hex(charmtone.Iron)),
		Accent:  hex(charmtone.Charple),
		Accent2: hex(charmtone.Malibu),
		Accent3: hex(charmtone.Cheeky),
		Good:    hex(charmtone.Guac),
		Warn:    hex(charmtone.Zest),
		Bad:     hex(charmtone.Sriracha),
		SelBg:   hex(charmtone.Charple),
		SelFg:   hex(charmtone.Salt),
	}
}

func nordPalette(dark bool) Palette {
	pick := lipgloss.LightDark(dark)
	return Palette{
		Text:    pick(lipgloss.Color("#2E3440"), lipgloss.Color("#ECEFF4")),
		Dim:     pick(lipgloss.Color("#4C566A"), lipgloss.Color("#D8DEE9")),
		Faint:   lipgloss.Color("#616E88"),
		Accent:  lipgloss.Color("#88C0D0"),
		Accent2: lipgloss.Color("#81A1C1"),
		Accent3: lipgloss.Color("#B48EAD"),
		Good:    lipgloss.Color("#A3BE8C"),
		Warn:    lipgloss.Color("#EBCB8B"),
		Bad:     lipgloss.Color("#BF616A"),
		SelBg:   lipgloss.Color("#434C5E"),
		SelFg:   lipgloss.Color("#ECEFF4"),
	}
}

func draculaPalette() Palette {
	return Palette{
		Text:    lipgloss.Color("#F8F8F2"),
		Dim:     lipgloss.Color("#BFBFD0"),
		Faint:   lipgloss.Color("#6272A4"),
		Accent:  lipgloss.Color("#BD93F9"),
		Accent2: lipgloss.Color("#8BE9FD"),
		Accent3: lipgloss.Color("#FF79C6"),
		Good:    lipgloss.Color("#50FA7B"),
		Warn:    lipgloss.Color("#F1FA8C"),
		Bad:     lipgloss.Color("#FF5555"),
		SelBg:   lipgloss.Color("#44475A"),
		SelFg:   lipgloss.Color("#F8F8F2"),
	}
}

// monoPalette keeps the shape of the output without using hue to carry meaning.
func monoPalette(dark bool) Palette {
	pick := lipgloss.LightDark(dark)
	text := pick(lipgloss.Color("#000000"), lipgloss.Color("#FFFFFF"))
	return Palette{
		Text:    text,
		Dim:     pick(lipgloss.Color("#4A4A4A"), lipgloss.Color("#BBBBBB")),
		Faint:   lipgloss.Color("#777777"),
		Accent:  text,
		Accent2: pick(lipgloss.Color("#333333"), lipgloss.Color("#DDDDDD")),
		Accent3: pick(lipgloss.Color("#555555"), lipgloss.Color("#AAAAAA")),
		Good:    text,
		Warn:    pick(lipgloss.Color("#555555"), lipgloss.Color("#AAAAAA")),
		Bad:     text,
		SelBg:   pick(lipgloss.Color("#DDDDDD"), lipgloss.Color("#444444")),
		SelFg:   text,
	}
}

func newStyles(p Palette) Styles {
	base := lipgloss.NewStyle()
	badge := base.Bold(true).Padding(0, 1)
	return Styles{
		Title:    base.Bold(true).Foreground(p.Accent),
		Subtitle: base.Foreground(p.Accent2),
		Key:      base.Foreground(p.Dim),
		Value:    base.Foreground(p.Text),
		Dim:      base.Foreground(p.Dim),
		Faint:    base.Foreground(p.Faint),
		Accent:   base.Foreground(p.Accent),
		URL:      base.Foreground(p.Accent2).Underline(true),
		Code:     base.Foreground(p.Accent3),

		Good: base.Foreground(p.Good),
		Warn: base.Foreground(p.Warn),
		Bad:  base.Foreground(p.Bad),
		Skip: base.Foreground(p.Faint),

		Header: base.Bold(true).Foreground(p.Accent).Padding(0, 1),
		Cell:   base.Foreground(p.Text).Padding(0, 1),
		Border: base.Foreground(p.Faint),

		BadgeGood: badge.Foreground(p.SelFg).Background(p.Good),
		BadgeWarn: badge.Foreground(lipgloss.Color("#000000")).Background(p.Warn),
		BadgeBad:  badge.Foreground(p.SelFg).Background(p.Bad),
		BadgeSkip: badge.Foreground(p.SelFg).Background(p.Faint),
		BadgeInfo: badge.Foreground(p.SelFg).Background(p.Accent),

		Box: base.Border(lipgloss.RoundedBorder()).BorderForeground(p.Accent).Padding(0, 2),
	}
}
