package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Theme is the only source of terminal color and style policy. Components
// consume semantic tokens instead of choosing presentation values themselves.
type Theme struct {
	Primary            lipgloss.Style
	Secondary          lipgloss.Style
	Normal             lipgloss.Style
	Muted              lipgloss.Style
	Success            lipgloss.Style
	Warning            lipgloss.Style
	Danger             lipgloss.Style
	Border             lipgloss.Style
	SelectedForeground lipgloss.Style
	SelectedBackground lipgloss.Style
	plain              bool
}

func DefaultTheme() Theme {
	return Theme{
		Primary:            lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("69")),
		Secondary:          lipgloss.NewStyle().Foreground(lipgloss.Color("75")),
		Normal:             lipgloss.NewStyle().Foreground(lipgloss.Color("252")),
		Muted:              lipgloss.NewStyle().Foreground(lipgloss.Color("243")),
		Success:            lipgloss.NewStyle().Foreground(lipgloss.Color("42")),
		Warning:            lipgloss.NewStyle().Foreground(lipgloss.Color("214")),
		Danger:             lipgloss.NewStyle().Foreground(lipgloss.Color("196")),
		Border:             lipgloss.NewStyle().Foreground(lipgloss.Color("240")),
		SelectedForeground: lipgloss.NewStyle().Foreground(lipgloss.Color("0")),
		SelectedBackground: lipgloss.NewStyle().Background(lipgloss.Color("214")),
	}
}

// PlainTheme makes component snapshots independent of the host color profile.
func PlainTheme() Theme { return Theme{plain: true} }

func (theme Theme) render(style lipgloss.Style, value string) string {
	if theme.plain {
		return value
	}
	return style.Render(value)
}

func (theme Theme) Header(value string) string   { return theme.render(theme.Primary, value) }
func (theme Theme) Subtle(value string) string   { return theme.render(theme.Muted, value) }
func (theme Theme) Emphasis(value string) string { return theme.render(theme.Secondary, value) }
func (theme Theme) Positive(value string) string { return theme.render(theme.Success, value) }
func (theme Theme) Caution(value string) string  { return theme.render(theme.Warning, value) }
func (theme Theme) Negative(value string) string { return theme.render(theme.Danger, value) }
func (theme Theme) Standard(value string) string { return theme.render(theme.Normal, value) }

func (theme Theme) CommandBar(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if width == 1 {
		return "│"
	}
	return "│" + theme.ClampLine(value, max(0, width-2)) + "│"
}

func (theme Theme) TableStyles() table.Styles {
	styles := table.DefaultStyles()
	if theme.plain {
		return styles
	}
	styles.Header = styles.Header.Inherit(theme.Primary)
	styles.Selected = styles.Selected.Inherit(theme.SelectedForeground).Inherit(theme.SelectedBackground)
	return styles
}

func (theme Theme) Alert(severity AlertSeverity, value string) string {
	switch severity {
	case AlertSuccess:
		return theme.Positive(value)
	case AlertWarning:
		return theme.Caution(value)
	case AlertError:
		return theme.Negative(value)
	default:
		return theme.Emphasis(value)
	}
}

func (theme Theme) ClampLine(value string, width int) string {
	if width <= 0 {
		return ""
	}
	value = strings.ReplaceAll(value, "\n", " ")
	if ansi.StringWidth(value) > width {
		value = ansi.Truncate(value, width, "…")
	}
	return value + strings.Repeat(" ", max(0, width-ansi.StringWidth(value)))
}

func (theme Theme) Frame(title string, state PageState, body string, width, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	title = SanitizeCell(title)
	if state != PageReady {
		title += " · " + string(state)
	}
	if width < 2 || height < 2 {
		return fitBlock(theme.Header(title), width, height, theme)
	}
	contentWidth, contentHeight := width-2, height-2
	content := fitBlock(body, contentWidth, contentHeight, theme)
	style := lipgloss.NewStyle().Width(contentWidth).Height(contentHeight).Border(lipgloss.RoundedBorder())
	if !theme.plain {
		style = style.Inherit(theme.Border)
	}
	framed := style.Render(content)
	if title != "" && contentWidth > 0 {
		label := ansi.Truncate(theme.Header(" "+title+" "), max(0, width-2), "…")
		lines := strings.Split(framed, "\n")
		if len(lines) > 0 {
			end := min(width-1, 1+ansi.StringWidth(label))
			lines[0] = ansi.Cut(lines[0], 0, 1) + label + ansi.Cut(lines[0], end, width)
			framed = strings.Join(lines, "\n")
		}
	}
	return fitBlock(framed, width, height, theme)
}

func fitBlock(value string, width, height int, theme Theme) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimSuffix(value, "\n"), "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	for index := range lines {
		lines[index] = theme.ClampLine(lines[index], width)
	}
	return strings.Join(lines, "\n")
}
