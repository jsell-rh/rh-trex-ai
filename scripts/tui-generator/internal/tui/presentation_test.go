package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestContinuousLayoutNeverProducesNegativeDimensions(t *testing.T) {
	for _, size := range [][2]int{{120, 40}, {48, 12}, {8, 4}, {1, 1}, {0, 0}, {-5, -2}} {
		layout := CalculateShellLayout(size[0], size[1], true, "metadata", "hints")
		values := []int{layout.Width, layout.Height, layout.HeaderRows, layout.CommandRows, layout.PageRows, layout.BreadcrumbRows, layout.HintRows, layout.AlertRows, layout.ContentWidth, layout.ContentHeight}
		for _, value := range values {
			if value < 0 {
				t.Fatalf("layout for %v contains negative value: %#v", size, layout)
			}
		}
		if layout.HeaderRows+layout.CommandRows+layout.PageRows+layout.BreadcrumbRows+layout.HintRows+layout.AlertRows != layout.Height {
			t.Fatalf("layout for %v does not consume terminal height: %#v", size, layout)
		}
	}
}

func TestShellSnapshotKeepsAlertOnFinalRowAcrossTransitions(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	shell := NewShell("")
	shell.Theme = PlainTheme()
	shell.Alerts.now = func() time.Time { return now }
	shell.Alerts.Push("request", AlertError, "network unavailable")
	count := 2
	page := ResourceTablePage{SemanticPage{PageTitle: "Items", PageCount: &count, PageState: PageStale, PageContent: "NAME  STATE\none   ready\ntwo   waiting"}}
	view := ShellView{Header: HeaderModel{Service: "Inventory API", Page: "Items", Origin: "https://api.example.test", Authenticated: true}, Page: page, Breadcrumb: "Items", HintIDs: []BindingID{KeyHelp, KeyQuit}}

	assertRail := func(label string, output string, height int) {
		t.Helper()
		lines := strings.Split(output, "\n")
		if len(lines) != height {
			t.Fatalf("%s height = %d, want %d\n%s", label, len(lines), height, output)
		}
		if got := strings.TrimSpace(lines[len(lines)-1]); !strings.HasPrefix(got, "ERROR:") {
			t.Fatalf("%s final row = %q\n%s", label, got, output)
		}
	}

	spacious := shell.Render(view, 64, 12)
	assertRail("spacious", spacious, 12)
	if !strings.Contains(spacious, "Inventory API — Items") || !strings.Contains(spacious, "Items[2] · stale") {
		t.Fatalf("spacious snapshot lost semantic chrome:\n%s", spacious)
	}

	view.Command = "/ waiting"
	command := shell.Render(view, 64, 12)
	assertRail("command", command, 12)
	if !strings.Contains(command, "/ waiting") {
		t.Fatalf("command snapshot omitted command bar:\n%s", command)
	}

	shell.Modal.Open(StaticDialog{DialogKind: DialogHelp, DialogTitle: "Help", DialogContent: "? help", DialogFooter: "esc close"})
	dialog := shell.Render(view, 64, 12)
	assertRail("dialog", dialog, 12)
	if !strings.Contains(dialog, "Help") || !strings.Contains(dialog, "? help") {
		t.Fatalf("dialog snapshot omitted overlay:\n%s", dialog)
	}

	narrow := shell.Render(view, 9, 5)
	assertRail("narrow", narrow, 5)
	if !strings.Contains(narrow, "Items") {
		t.Fatalf("narrow snapshot lost page identity:\n%s", narrow)
	}
}

func TestPageFrameRendersEverySemanticState(t *testing.T) {
	theme := PlainTheme()
	for _, state := range []PageState{PageReady, PageLoading, PageEmpty, PageForbidden, PageStale, PageFatal} {
		output := theme.Frame("Records", state, "content", 32, 5)
		if len(strings.Split(output, "\n")) != 5 || !strings.Contains(output, "Records") {
			t.Fatalf("state %s frame = %q", state, output)
		}
		if state != PageReady && !strings.Contains(output, string(state)) {
			t.Fatalf("state %s absent from frame: %q", state, output)
		}
	}
}

func TestPlainPageFrameSnapshot(t *testing.T) {
	const expected = "╭ Items ───────╮\n│one           │\n│              │\n╰──────────────╯"
	if actual := PlainTheme().Frame("Items", PageReady, "one", 16, 4); actual != expected {
		t.Fatalf("page-frame snapshot changed\nexpected:\n%s\nactual:\n%s", expected, actual)
	}
}

func TestAlertSeverityLifetimePriorityAndRedaction(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	manager := NewAlertManager("top-secret")
	manager.now = func() time.Time { return now }
	manager.Push("info", AlertInfo, "connected")
	manager.Push("warning", AlertWarning, "slow response")
	manager.Push("error", AlertError, "Bearer abc.def and top-secret failed")
	manager.Push("success", AlertSuccess, "recovered")
	active, present := manager.Active()
	if !present || active.Severity != AlertError || strings.Contains(active.Summary, "abc.def") || strings.Contains(active.Summary, "top-secret") {
		t.Fatalf("active alert = %#v, present %v", active, present)
	}
	manager.Clear("error")
	active, _ = manager.Active()
	if active.Severity != AlertWarning {
		t.Fatalf("warning did not outrank transient alerts: %#v", active)
	}
	manager.Clear("warning")
	now = now.Add(alertLifetime + time.Second)
	if _, present := manager.Active(); present {
		t.Fatalf("transient alerts did not expire: %#v", manager.alerts)
	}
}

func TestFormDialogFocusEnumValidationZeroAndDuplicateSubmit(t *testing.T) {
	operation := Operation{
		ID: "createItem", Method: "POST",
		Parameters: []Parameter{{Name: "dry_run", In: "query", Type: "boolean", Default: false}},
		RequestBody: &RequestBody{Required: true, ContentType: "application/json", Fields: []InputField{
			{Name: "count", Type: "integer", Required: true, Default: 0},
			{Name: "state", Type: "string", Required: true, Enum: []any{"new", "ready"}, Default: "new"},
		}},
	}
	keys := DefaultKeyRegistry()
	form := NewFormDialog(operation, map[string]any{}, keys)
	if len(form.fields) != 3 || form.fields[0].descriptor.Name != "dry_run" || form.fields[1].descriptor.Name != "count" || form.fields[2].descriptor.Name != "state" {
		t.Fatalf("deterministic fields = %#v", form.fields)
	}
	if !strings.Contains(form.Content(), "count") || !strings.Contains(form.Content(), "‹ new ›") {
		t.Fatalf("form content = %q", form.Content())
	}
	_, _ = form.Update(tea.KeyMsg{Type: tea.KeyEnter})
	_, _ = form.Update(tea.KeyMsg{Type: tea.KeyEnter})
	event, _ := form.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !event.Submitted || string(event.Request.Body) != `{"count":0,"state":"new"}` {
		t.Fatalf("zero/default submission = event %#v, body %s", event, event.Request.Body)
	}
	duplicate, _ := form.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if duplicate.Submitted {
		t.Fatal("in-flight form accepted duplicate submission")
	}
}

func TestRequiredStructuredBodySubmitsEmptyObject(t *testing.T) {
	form := NewFormDialog(Operation{
		ID: "createItem",
		RequestBody: &RequestBody{Required: true, ContentType: "application/json", Fields: []InputField{
			{Name: "state", Type: "string", Enum: []any{"new", "ready"}},
		}},
	}, nil, DefaultKeyRegistry())
	if !strings.Contains(form.Content(), "‹ unset ›") {
		t.Fatalf("optional enum was not initially unset: %q", form.Content())
	}
	event, _ := form.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !event.Submitted || string(event.Request.Body) != `{}` {
		t.Fatalf("required empty body = event %#v, body %q", event, event.Request.Body)
	}
}

func TestDestructiveConfirmationStartsOnCancelAndSubmitsOnce(t *testing.T) {
	keys := DefaultKeyRegistry()
	dialog := NewConfirmationDialog("Delete", Confirmation{Title: "Confirm delete", Message: "Delete it?", Destructive: true}, keys)
	if !strings.Contains(dialog.Content(), "[ Cancel ]") {
		t.Fatalf("safe focus absent: %q", dialog.Content())
	}
	confirmed, canceled := dialog.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if confirmed || !canceled {
		t.Fatalf("enter on safe focus = confirmed %v, canceled %v", confirmed, canceled)
	}
	dialog = NewConfirmationDialog("Delete", Confirmation{Title: "Confirm delete", Message: "Delete it?", Destructive: true}, keys)
	_, _ = dialog.Update(tea.KeyMsg{Type: tea.KeyTab})
	confirmed, canceled = dialog.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !confirmed || canceled {
		t.Fatalf("explicit confirmation = confirmed %v, canceled %v", confirmed, canceled)
	}
	confirmed, _ = dialog.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if confirmed {
		t.Fatal("in-flight confirmation accepted duplicate submit")
	}
}

func TestResourceTableSortAndCommandHistoryAreShared(t *testing.T) {
	view := View{ID: "records", Kind: "collection", IdentityProperty: "id", DefaultSort: "name", Columns: []Column{{Property: "name", Label: "NAME"}, {Property: "id", Label: "ID"}}}
	component := ResourceTableComponent{}
	component.Reset(view, PlainTheme(), 50, 8, 0)
	component.SetRows(view, []map[string]any{{"id": "2", "name": "Beta"}, {"id": "1", "name": "Alpha"}}, "", "", 50, 8, 0)
	component.table.SetCursor(1)
	component.CycleSort(view)
	selected := component.Selected()
	if component.sortProperty != "id" || selected == nil || selected.Identity != "2" {
		t.Fatalf("sort cycle lost state: property %q, selected %#v", component.sortProperty, component.Selected())
	}
	component.ReverseSort()
	if component.rows[0].Identity != "2" || component.Selected() == nil || component.Selected().Identity != "2" {
		t.Fatalf("reverse sort lost order or selection: rows %#v, selected %#v", component.rows, component.Selected())
	}

	bar := NewCommandBar()
	bar.Remember("records")
	bar.Remember("accounts")
	bar.MoveHistory(-1)
	if bar.Value() != "accounts" {
		t.Fatalf("latest command history = %q", bar.Value())
	}
	bar.MoveHistory(-1)
	if bar.Value() != "records" {
		t.Fatalf("previous command history = %q", bar.Value())
	}
}

func TestControlActionHotkeysUseMetadataGrammarAndBubbleTeaDispatch(t *testing.T) {
	registry := DefaultKeyRegistry()
	if !registry.Reserved("ctrl-c") {
		t.Fatal("metadata-form global control key was not reserved")
	}
	operation := Operation{Presentation: ActionPresentation{Hotkey: "ctrl-z"}}
	if !registry.ActionMatches(tea.KeyMsg{Type: tea.KeyCtrlZ}, operation) {
		t.Fatal("metadata-form control key did not match Bubble Tea key event")
	}
}
