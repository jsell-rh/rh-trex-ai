package tui

import (
	"fmt"
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
	FieldTitleStyle    lipgloss.Style
	BreadcrumbAncestor lipgloss.Style
	BreadcrumbActive   lipgloss.Style
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
		FieldTitleStyle:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255")),
		BreadcrumbAncestor: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("214")),
		BreadcrumbActive:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("69")),
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

func (theme Theme) Header(value string) string    { return theme.render(theme.Primary, value) }
func (theme Theme) Subtle(value string) string    { return theme.render(theme.Muted, value) }
func (theme Theme) Emphasis(value string) string  { return theme.render(theme.Secondary, value) }
func (theme Theme) Positive(value string) string  { return theme.render(theme.Success, value) }
func (theme Theme) Caution(value string) string   { return theme.render(theme.Warning, value) }
func (theme Theme) Negative(value string) string  { return theme.render(theme.Danger, value) }
func (theme Theme) Standard(value string) string  { return theme.render(theme.Normal, value) }
func (theme Theme) HeaderKey(value string) string { return theme.Caution(value) }
func (theme Theme) FieldTitle(value string) string {
	return theme.render(theme.FieldTitleStyle, value)
}
func (theme Theme) FieldMetadata(value string) string { return theme.Subtle(value) }

func (theme Theme) Shortcut(shortcut ShortcutHint, keyWidth int) string {
	tokenWidth := ansi.StringWidth("<" + shortcut.Key + ">")
	padding := strings.Repeat(" ", max(1, keyWidth-tokenWidth+1))
	return theme.Subtle("<") + theme.Emphasis(shortcut.Key) + theme.Subtle(">") + padding + theme.Standard(shortcut.Description)
}

func (theme Theme) BreadcrumbBadge(label string, active bool) string {
	value := " <" + SanitizeCell(label) + "> "
	if active {
		return theme.render(theme.BreadcrumbActive, value)
	}
	return theme.render(theme.BreadcrumbAncestor, value)
}

func (theme Theme) FrameLabel(title PageFrameTitle, state PageState) string {
	kind := SanitizeCell(title.Kind)
	context := SanitizeCell(title.Context)
	if context == "" {
		context = "all"
	}
	label := theme.Header(kind) + theme.Standard("(") + theme.Emphasis(context) + theme.Standard(")")
	if title.Count != nil {
		label += theme.Standard("[") + theme.Caution(fmt.Sprintf("%d", *title.Count)) + theme.Standard("]")
	}
	if state != PageReady {
		label += theme.Standard(" · ") + theme.PageState(state, string(state))
	}
	return label
}

func (theme Theme) PageState(state PageState, value string) string {
	switch state {
	case PageForbidden, PageFatal:
		return theme.Negative(value)
	case PageStale:
		return theme.Caution(value)
	case PageLoading:
		return theme.Emphasis(value)
	default:
		return theme.Subtle(value)
	}
}

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
	title = SanitizeCell(title)
	label := theme.Header(title)
	if state != PageReady {
		label += theme.Standard(" · ") + theme.PageState(state, string(state))
	}
	return theme.frame(label, title != "", body, width, height)
}

func (theme Theme) ResourceFrame(title PageFrameTitle, state PageState, body string, width, height int) string {
	return theme.frame(theme.FrameLabel(title, state), title.Kind != "", body, width, height)
}

func (theme Theme) frame(label string, hasTitle bool, body string, width, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	if width < 2 || height < 2 {
		return fitBlock(label, width, height, theme)
	}
	contentWidth, contentHeight := width-2, height-2
	content := fitBlock(body, contentWidth, contentHeight, theme)
	style := lipgloss.NewStyle().Width(contentWidth).Height(contentHeight).Border(lipgloss.RoundedBorder())
	if !theme.plain {
		style = style.Inherit(theme.Border)
	}
	framed := style.Render(content)
	if hasTitle && contentWidth > 0 {
		label = ansi.Truncate(" "+label+" ", contentWidth, "…")
		lines := strings.Split(framed, "\n")
		if len(lines) > 0 {
			labelWidth := ansi.StringWidth(label)
			start := 1 + max(0, (contentWidth-labelWidth)/2)
			end := min(width-1, start+labelWidth)
			lines[0] = ansi.Cut(lines[0], 0, start) + label + ansi.Cut(lines[0], end, width)
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
