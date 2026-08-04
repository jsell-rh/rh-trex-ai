package tui

import (
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"
)

type HeaderModel struct {
	Service       string
	Page          string
	Origin        string
	Authenticated bool
	Scope         string
	Refreshing    bool
	LastSuccess   time.Time
	Now           time.Time
	Actions       []LocalAction
}

type ShellView struct {
	Header     HeaderModel
	Page       Page
	Command    string
	Breadcrumb string
	HintIDs    []BindingID
}

type Shell struct {
	Theme  Theme
	Keys   KeyRegistry
	Alerts AlertManager
	Modal  ModalHost
}

func NewShell(token string) Shell {
	return Shell{Theme: DefaultTheme(), Keys: DefaultKeyRegistry(), Alerts: NewAlertManager(token)}
}

func (shell *Shell) hintText(view ShellView) string {
	hints := shell.Keys.Hints(view.HintIDs...)
	var actions []LocalAction
	if view.Page != nil {
		actions = view.Page.Actions()
	}
	if actionHints := shell.Keys.ActionHints(actions); actionHints != "" && view.Command == "" && !shell.Modal.Active() {
		if hints != "" {
			hints += "  "
		}
		hints += actionHints
	}
	return hints
}

func (shell *Shell) Layout(view ShellView, width, height int) ShellLayout {
	return CalculateShellLayout(width, height, view.Command != "", headerMetadata(view.Header), shell.hintText(view))
}

func (shell *Shell) Render(view ShellView, width, height int) string {
	if view.Page == nil {
		view.Page = SemanticPage{PageTitle: "Unavailable", PageState: PageFatal, PageContent: "No page is available"}
	}
	hints := shell.hintText(view)
	layout := shell.Layout(view, width, height)
	rows := make([]string, 0, layout.Height)
	if layout.HeaderRows > 0 {
		rows = append(rows, shell.Theme.ClampLine(renderHeader(view.Header, layout, shell.Theme), layout.Width))
	}
	if layout.CommandRows > 0 {
		rows = append(rows, shell.Theme.CommandBar(view.Command, layout.Width))
	}
	if layout.PageRows > 0 {
		pageBody := shell.Modal.Render(view.Page.Content(), layout.ContentWidth, layout.ContentHeight, shell.Theme)
		framed := shell.Theme.Frame(pageFrameTitle(view.Page), view.Page.State(), pageBody, layout.Width, layout.PageRows)
		rows = append(rows, strings.Split(framed, "\n")...)
	}
	if layout.BreadcrumbRows > 0 {
		rows = append(rows, shell.Theme.ClampLine("› "+SanitizeCell(view.Breadcrumb), layout.Width))
	}
	if layout.HintRows > 0 {
		rows = append(rows, shell.Theme.ClampLine(shell.Theme.Subtle(hints), layout.Width))
	}
	for len(rows) < layout.Height-layout.AlertRows {
		rows = append(rows, shell.Theme.ClampLine("", layout.Width))
	}
	if layout.AlertRows > 0 {
		alertLine := ""
		if alert, present := shell.Alerts.Active(); present {
			alertLine = shell.Theme.Alert(alert.Severity, alertPrefix(alert.Severity)+": "+alert.Summary)
		}
		rows = append(rows, shell.Theme.ClampLine(alertLine, layout.Width))
	}
	if len(rows) > layout.Height {
		rows = rows[:layout.Height]
	}
	return strings.Join(rows, "\n")
}

func renderHeader(header HeaderModel, layout ShellLayout, theme Theme) string {
	primary := SanitizeCell(header.Service)
	if header.Page != "" {
		if primary != "" {
			primary += " — "
		}
		primary += SanitizeCell(header.Page)
	}
	result := theme.Header(primary)
	if layout.ShowMetadata {
		if metadata := headerMetadata(header); metadata != "" {
			gap := max(1, layout.Width-ansi.StringWidth(result)-ansi.StringWidth(metadata))
			if ansi.StringWidth(result)+gap+ansi.StringWidth(metadata) <= layout.Width {
				result += strings.Repeat(" ", gap) + theme.Subtle(metadata)
			}
		}
	}
	return result
}

func headerMetadata(header HeaderModel) string {
	var parts []string
	if raw := strings.TrimSpace(header.Origin); raw != "" {
		if parsed, err := url.Parse(raw); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			parts = append(parts, parsed.Scheme+"://"+parsed.Host)
		}
	}
	if header.Authenticated {
		parts = append(parts, "authenticated")
	} else {
		parts = append(parts, "anonymous")
	}
	if header.Scope != "" {
		parts = append(parts, SanitizeCell(header.Scope))
	}
	if header.Refreshing {
		parts = append(parts, "refreshing…")
	} else if !header.LastSuccess.IsZero() {
		now := header.Now
		if now.IsZero() {
			now = time.Now()
		}
		age := max(time.Duration(0), now.Sub(header.LastSuccess)).Round(time.Second)
		parts = append(parts, "refreshed "+age.String()+" ago")
	}
	for _, action := range header.Actions {
		if action.Hotkey != "" {
			parts = append(parts, "["+SanitizeCell(action.Hotkey)+"] "+SanitizeCell(action.Label))
		}
	}
	return strings.Join(parts, " · ")
}
