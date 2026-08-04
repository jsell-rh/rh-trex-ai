package tui

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

func TestGeneratedRuntimeNavigationWithTeatest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.EscapedPath() {
		case "/parents":
			_, _ = io.WriteString(writer, `{"items":[{"id":"parent/7","name":"Alpha\u001b]52;c;b3duZWQ=\u0007"},{"id":"parent-8","name":"Other"}]}`)
		case "/parents/parent%2F7":
			assertBearer(t, request)
			_, _ = io.WriteString(writer, `{"id":"parent/7","name":"Alpha","description":"Parent restored \u001b[31mred\u001b[0m"}`)
		case "/parents/parent%2F7/children":
			assertBearer(t, request)
			_, _ = io.WriteString(writer, `{"items":[{"id":"child/1","name":"Scoped Kid"}]}`)
		case "/parents/parent%2F7/children/child%2F1":
			assertBearer(t, request)
			_, _ = io.WriteString(writer, `{"id":"child/1","name":"Scoped Kid","description":"Child detail"}`)
		case "/accounts":
			_, _ = io.WriteString(writer, `{"items":[{"id":"account-9","name":"Account Nine"}]}`)
		case "/accounts/account-9":
			assertBearer(t, request)
			_, _ = io.WriteString(writer, `{"id":"account-9","name":"Account Nine","description":"Account restored"}`)
		case "/parents/account-9/children":
			assertBearer(t, request)
			_, _ = io.WriteString(writer, `{"items":[{"id":"account-child","name":"Account Kid"}]}`)
		case "/children":
			if request.Header.Get("Authorization") != "" {
				t.Errorf("public operation received authorization")
			}
			_, _ = io.WriteString(writer, `{"items":[{"id":"public-child","name":"Public Kid"}]}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	model, err := NewModel(runtimeTestDescriptor(server.URL), ClientConfig{BaseURL: server.URL, Token: "token"})
	if err != nil {
		t.Fatal(err)
	}
	testModel := teatest.NewTestModel(t, model, teatest.WithInitialTermSize(110, 32))
	t.Cleanup(func() { _ = testModel.Quit() })

	waitForText(t, testModel, "Alpha")
	output := readOutput(t, testModel.Output())
	if bytes.Contains(output, []byte("b3duZWQ=")) || bytes.Contains(output, []byte("\x1b]52")) {
		t.Fatalf("terminal injection reached output: %q", output)
	}
	testModel.Type("/other")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForText(t, testModel, "Other")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitForText(t, testModel, "Alpha")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForTexts(t, testModel, "description: Parent restored red", "Parents > Parent[parent/7]")

	// The item has two outgoing relationships, so Enter must open a stable chooser.
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForTexts(t, testModel, "RELATIONSHIP", "Children", "Public Children")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForTexts(t, testModel, "Scoped Kid", "Parents > Parent[parent/7] > Children[parent/7]")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForTexts(t, testModel, "description: Child detail", "Child[child/1]")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitForText(t, testModel, "Scoped Kid")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitForTexts(t, testModel, "description: Parent restored red", "Parents > Parent[parent/7]")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitForText(t, testModel, "Other")

	// Reach the same scoped child view through a different parent and prove Esc
	// restores that distinct history rather than a canonical parent.
	testModel.Type(":ac")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForText(t, testModel, "Account Nine")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForTexts(t, testModel, "description: Account restored", "Accounts > Account[account-9]")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForTexts(t, testModel, "Account Kid", "Accounts > Account[account-9] > Children[account-9]")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitForTexts(t, testModel, "description: Account restored", "Accounts > Account[account-9]")

	if err := testModel.Quit(); err != nil {
		t.Fatal(err)
	}
	final, ok := testModel.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(*Model)
	if !ok || len(final.frames) != 2 || final.frames[0].TargetViewID != "accounts" || final.frames[1].TargetViewID != "account" {
		t.Fatalf("multi-parent history = %#v", final)
	}
}

func TestStreamingIsIncrementalBoundedSanitizedAndCancelable(t *testing.T) {
	canceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/resources":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"items":[{"id":"one","name":"One"}]}`)
		case "/events":
			writer.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := writer.(http.Flusher)
			if !ok {
				t.Error("test writer cannot flush")
				return
			}
			_, _ = io.WriteString(writer, "data: safe\x1b]52;c;bad\x07 event\n\n")
			flusher.Flush()
			<-request.Context().Done()
			close(canceled)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	descriptor := Descriptor{
		Title: "Stream test", Servers: []Server{{URL: server.URL}},
		Views: []View{{ID: "resources", Kind: "collection", Label: "Resources", IdentityProperty: "id", Columns: []Column{{Property: "name", Label: "NAME"}}, OperationIDs: []string{"listResources", "streamEvents"}, ListOperationID: "listResources"}},
		Operations: []Operation{
			{ID: "listResources", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/resources"}}, Response: ResponseShape{ItemsPointer: "/items"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: EffectiveSecurity{None: true}},
			{ID: "streamEvents", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/events"}}, Response: ResponseShape{ContentType: "text/event-stream", Stream: true}, SuccessStatuses: []string{"200"}, Capabilities: []string{"stream"}, Security: EffectiveSecurity{None: true}},
		},
	}
	model, err := NewModel(descriptor, ClientConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	testModel := teatest.NewTestModel(t, model, teatest.WithInitialTermSize(100, 30))
	t.Cleanup(func() { _ = testModel.Quit() })
	waitForText(t, testModel, "One")
	testModel.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	waitForText(t, testModel, "streamEvents")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForText(t, testModel, "safe event")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEsc})
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("Esc did not cancel the stream request")
	}
	if err := testModel.Quit(); err != nil {
		t.Fatal(err)
	}
	final := testModel.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(*Model)
	if final.mode != modeBrowse || final.streamCancel != nil || final.streamEvents != nil {
		t.Fatalf("stream state was not cleared: %#v", final)
	}

	bounded := &Model{detail: viewport.New(80, 20)}
	for index := 0; index < maxVisibleStreamEvents+25; index++ {
		bounded.appendStreamEvent(fmt.Sprintf("event-%03d", index))
	}
	if len(bounded.streamLines) != maxVisibleStreamEvents || bounded.streamLines[0] != "event-025" {
		t.Fatalf("bounded stream window = %d, first %q", len(bounded.streamLines), bounded.streamLines[0])
	}
}

func TestActionWithMissingInputsIsVisibleButMakesNoRequest(t *testing.T) {
	var actionRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			actionRequests.Add(1)
		}
		_, _ = io.WriteString(writer, `{"items":[]}`)
	}))
	defer server.Close()
	descriptor := Descriptor{
		Title: "Action test", Servers: []Server{{URL: server.URL}},
		Views: []View{{ID: "things", Kind: "collection", Label: "Things", OperationIDs: []string{"listThings", "archiveThings"}, ListOperationID: "listThings"}},
		Operations: []Operation{
			{ID: "listThings", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/things"}}, Response: ResponseShape{ItemsPointer: "/items"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: EffectiveSecurity{None: true}},
			{ID: "archiveThings", Method: http.MethodPost, PathParts: []PathPart{{Literal: "/things:archive"}}, Parameters: []Parameter{{Name: "confirm", In: "query", Required: true}}, RequestBody: &RequestBody{Required: true, ContentType: "application/json"}, SuccessStatuses: []string{"202"}, Capabilities: []string{"action"}, Security: EffectiveSecurity{None: true}},
		},
	}
	model, err := NewModel(descriptor, ClientConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	testModel := teatest.NewTestModel(t, model, teatest.WithInitialTermSize(110, 30))
	t.Cleanup(func() { _ = testModel.Quit() })
	waitForText(t, testModel, "Loaded 0 items")
	testModel.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	waitForTexts(t, testModel, "archiveThings", "disabled: requires query confirm, request body")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForText(t, testModel, "Action unavailable: requires query confirm, request body")
	if actionRequests.Load() != 0 {
		t.Fatalf("disabled action made %d requests", actionRequests.Load())
	}
}

func TestAPIErrorIsInlineAndTerminalSafe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(writer, "safe\x1b]52;c;clipboard\x07 error")
	}))
	defer server.Close()
	descriptor := Descriptor{
		Title: "Error test", Servers: []Server{{URL: server.URL}},
		Views:      []View{{ID: "things", Kind: "collection", Label: "Things", OperationIDs: []string{"listThings"}, ListOperationID: "listThings"}},
		Operations: []Operation{{ID: "listThings", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/things"}}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: EffectiveSecurity{None: true}}},
	}
	model, err := NewModel(descriptor, ClientConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	testModel := teatest.NewTestModel(t, model, teatest.WithInitialTermSize(90, 25))
	t.Cleanup(func() { _ = testModel.Quit() })
	waitForText(t, testModel, "safe error")
	output := readOutput(t, testModel.Output())
	if bytes.Contains(output, []byte("clipboard")) || bytes.Contains(output, []byte("\x1b]52")) {
		t.Fatalf("unsafe error reached output: %q", output)
	}
}

func TestEvaluateExplicitRuntimeBindingsAndMissingValue(t *testing.T) {
	frame := Frame{Bindings: map[string]any{"project_id": "project/1"}}
	row := Row{Raw: map[string]any{"id": "agent/7"}}
	edge := Edge{Name: "children", Bindings: []Binding{
		{Target: "project_id", SourceKind: "runtime-expression", Source: "$request.path.project_id"},
		{Target: "agent_id", SourceKind: "runtime-expression", Source: "$response.body#/id"},
		{Target: "mode", SourceKind: "literal", Source: "active"},
	}}
	bindings, err := evaluateBindings(edge, frame, row)
	if err != nil {
		t.Fatal(err)
	}
	if bindings["project_id"] != "project/1" || bindings["agent_id"] != "agent/7" || bindings["mode"] != "active" {
		t.Fatalf("bindings = %#v", bindings)
	}
	edge.Bindings[1].Source = "$response.body#/missing"
	if _, err := evaluateBindings(edge, frame, row); err == nil || !strings.Contains(err.Error(), "cannot bind agent_id") {
		t.Fatalf("missing binding error = %v", err)
	}
}

func TestColumnPriorityControlsNarrowTerminalRetention(t *testing.T) {
	model := &Model{width: 25, height: 20}
	view := View{Columns: []Column{
		{Property: "low", Label: "LOW", Priority: 1},
		{Property: "high", Label: "HIGH", Priority: 100},
		{Property: "medium", Label: "MEDIUM", Priority: 50},
	}}
	model.rebuildTable(view)
	if !reflect.DeepEqual(model.displayColumns, []int{1}) {
		t.Fatalf("narrow retained columns = %#v, want highest-priority index", model.displayColumns)
	}
	model.width = 46
	model.configureTableColumns(view)
	if !reflect.DeepEqual(model.displayColumns, []int{1, 2}) {
		t.Fatalf("wider retained columns = %#v, want priority order retained in declaration order", model.displayColumns)
	}
}

func TestPopRestoresCollectionSelectionByIdentity(t *testing.T) {
	descriptor := Descriptor{
		Views: []View{
			{ID: "parents", Kind: "collection", Label: "Parents", IdentityProperty: "id", DefaultSort: "id", Columns: []Column{{Property: "id", Label: "ID"}}, ListOperationID: "listParents"},
			{ID: "children", Kind: "collection", Label: "Children", IdentityProperty: "id", Columns: []Column{{Property: "id", Label: "ID"}}},
		},
		Operations: []Operation{{ID: "listParents", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/parents"}}, Capabilities: []string{"list"}}},
	}
	model := &Model{
		descriptor: descriptor, width: 80, height: 25,
		frames: []Frame{
			{TargetViewID: "parents", Label: "Parents", Bindings: map[string]any{}},
			{TargetViewID: "children", Label: "Children", SelectedIdentity: "parent-2", Bindings: map[string]any{}},
		},
	}
	model.rebuildTable(*descriptor.View("children"))
	_, _ = model.popFrame()
	model.setRows(*descriptor.View("parents"), []map[string]any{{"id": "parent-1"}, {"id": "parent-2"}})
	selected := model.selectedRow()
	if selected == nil || selected.Identity != "parent-2" {
		t.Fatalf("restored selection = %#v", selected)
	}
}

func runtimeTestDescriptor(server string) Descriptor {
	return Descriptor{
		Title: "Runtime test", Servers: []Server{{URL: server}},
		Views: []View{
			{ID: "parents", Kind: "collection", Label: "Parents", IdentityProperty: "id", DefaultSort: "name", Columns: []Column{{Property: "name", Label: "NAME"}, {Property: "id", Label: "ID"}}, OperationIDs: []string{"listParents"}, Capabilities: []string{"list"}, ListOperationID: "listParents"},
			{ID: "parent", Kind: "item", Label: "Parent", IdentityProperty: "id", Columns: []Column{{Property: "id", Label: "ID"}}, OperationIDs: []string{"getParent"}, Capabilities: []string{"get"}, GetOperationID: "getParent"},
			{ID: "accounts", Kind: "collection", Label: "Accounts", Aliases: []string{"ac"}, IdentityProperty: "id", DefaultSort: "name", Columns: []Column{{Property: "name", Label: "NAME"}}, OperationIDs: []string{"listAccounts"}, Capabilities: []string{"list"}, ListOperationID: "listAccounts"},
			{ID: "account", Kind: "item", Label: "Account", IdentityProperty: "id", Columns: []Column{{Property: "id", Label: "ID"}}, OperationIDs: []string{"getAccount"}, Capabilities: []string{"get"}, GetOperationID: "getAccount"},
			{ID: "children", Kind: "collection", Label: "Children", Aliases: []string{"ch"}, IdentityProperty: "id", DefaultSort: "name", Columns: []Column{{Property: "name", Label: "NAME"}}, ScopeParameters: []string{"parent_id"}, OperationIDs: []string{"listChildren"}, Capabilities: []string{"list"}, ListOperationID: "listChildren"},
			{ID: "child", Kind: "item", Label: "Child", IdentityProperty: "id", Columns: []Column{{Property: "id", Label: "ID"}}, ScopeParameters: []string{"parent_id"}, OperationIDs: []string{"getChild"}, Capabilities: []string{"get"}, GetOperationID: "getChild"},
			{ID: "public-children", Kind: "collection", Label: "Public Children", IdentityProperty: "id", Columns: []Column{{Property: "name", Label: "NAME"}}, OperationIDs: []string{"listPublicChildren"}, Capabilities: []string{"list"}, ListOperationID: "listPublicChildren"},
		},
		Operations: []Operation{
			{ID: "listParents", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/parents"}}, Response: ResponseShape{ItemsPointer: "/items"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: EffectiveSecurity{None: true}},
			{ID: "getParent", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/parents/"}, {Parameter: "parent_id"}}, Parameters: []Parameter{{Name: "parent_id", In: "path", Required: true, Type: "string"}}, Response: ResponseShape{ContentType: "application/json"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"get"}, Security: bearerSecurity()},
			{ID: "listAccounts", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/accounts"}}, Response: ResponseShape{ItemsPointer: "/items"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: EffectiveSecurity{None: true}},
			{ID: "getAccount", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/accounts/"}, {Parameter: "account_id"}}, Parameters: []Parameter{{Name: "account_id", In: "path", Required: true, Type: "string"}}, Response: ResponseShape{ContentType: "application/json"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"get"}, Security: bearerSecurity()},
			{ID: "listChildren", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/parents/"}, {Parameter: "parent_id"}, {Literal: "/children"}}, Parameters: []Parameter{{Name: "parent_id", In: "path", Required: true, Type: "string"}}, Response: ResponseShape{ItemsPointer: "/items"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: bearerSecurity()},
			{ID: "getChild", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/parents/"}, {Parameter: "parent_id"}, {Literal: "/children/"}, {Parameter: "child_id"}}, Parameters: []Parameter{{Name: "parent_id", In: "path", Required: true, Type: "string"}, {Name: "child_id", In: "path", Required: true, Type: "string"}}, Response: ResponseShape{ContentType: "application/json"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"get"}, Security: bearerSecurity()},
			{ID: "listPublicChildren", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/children"}}, Response: ResponseShape{ItemsPointer: "/items"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: EffectiveSecurity{None: true}},
		},
		Edges: []Edge{
			{ID: "parents-item", Name: "details", SourceViewID: "parents", TargetViewID: "parent", TargetOperationID: "getParent", Provenance: "collection-item", Bindings: []Binding{{Target: "parent_id", SourceKind: "row-property", Source: "id"}}, Navigable: true},
			{ID: "parent-children", Name: "children", SourceViewID: "parent", TargetViewID: "children", TargetOperationID: "listChildren", Provenance: "explicit-link", Bindings: []Binding{{Target: "parent_id", SourceKind: "runtime-expression", Source: "$response.body#/id"}}, Navigable: true},
			{ID: "parent-public", Name: "publicChildren", SourceViewID: "parent", TargetViewID: "public-children", TargetOperationID: "listPublicChildren", Provenance: "explicit-link", Navigable: true},
			{ID: "children-item", Name: "details", SourceViewID: "children", TargetViewID: "child", TargetOperationID: "getChild", Provenance: "collection-item", Bindings: []Binding{{Target: "parent_id", SourceKind: "frame-path", Source: "parent_id"}, {Target: "child_id", SourceKind: "row-property", Source: "id"}}, Navigable: true},
			{ID: "accounts-item", Name: "details", SourceViewID: "accounts", TargetViewID: "account", TargetOperationID: "getAccount", Provenance: "collection-item", Bindings: []Binding{{Target: "account_id", SourceKind: "row-property", Source: "id"}}, Navigable: true},
			{ID: "account-children", Name: "children", SourceViewID: "account", TargetViewID: "children", TargetOperationID: "listChildren", Provenance: "explicit-link", Bindings: []Binding{{Target: "parent_id", SourceKind: "runtime-expression", Source: "$response.body#/id"}}, Navigable: true},
		},
	}
}

func bearerSecurity() EffectiveSecurity {
	return EffectiveSecurity{Requirements: []SecurityAlternative{{Schemes: []string{"Bearer"}}}}
}

func assertBearer(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Header.Get("Authorization") != "Bearer token" {
		t.Errorf("missing authorization: %#v", request.Header)
	}
}

func waitForText(t *testing.T, model *teatest.TestModel, text string) {
	t.Helper()
	teatest.WaitFor(t, model.Output(), func(output []byte) bool { return bytes.Contains(output, []byte(text)) }, teatest.WithDuration(5*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
}

func waitForTexts(t *testing.T, model *teatest.TestModel, texts ...string) {
	t.Helper()
	teatest.WaitFor(t, model.Output(), func(output []byte) bool {
		for _, text := range texts {
			if !bytes.Contains(output, []byte(text)) {
				return false
			}
		}
		return true
	}, teatest.WithDuration(5*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
}

func readOutput(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
