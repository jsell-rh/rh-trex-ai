package tui

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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

	bounded := &Model{DetailStreamComponent: DetailStreamComponent{detail: viewport.New(80, 20), autoscroll: true}}
	for index := 0; index < maxVisibleStreamEvents+25; index++ {
		bounded.appendStreamEvent(fmt.Sprintf("event-%03d", index))
	}
	if len(bounded.streamLines) != maxVisibleStreamEvents || bounded.streamLines[0] != "event-025" {
		t.Fatalf("bounded stream window = %d, first %q", len(bounded.streamLines), bounded.streamLines[0])
	}
}

func TestGenericActionInputsExecuteDocumentedRequest(t *testing.T) {
	actionRequests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			actionRequests <- request.URL.EscapedPath() + "?" + request.URL.RawQuery + "|" + request.Header.Get("X-Reason") + "|" + string(body)
			writer.WriteHeader(http.StatusAccepted)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"items":[]}`)
	}))
	defer server.Close()
	descriptor := Descriptor{
		Title: "Action test", Servers: []Server{{URL: server.URL}},
		Views: []View{{ID: "things", Kind: "collection", Label: "Things", OperationIDs: []string{"listThings", "archiveThing"}, ListOperationID: "listThings"}},
		Operations: []Operation{
			{ID: "listThings", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/things"}}, Response: ResponseShape{ItemsPointer: "/items"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: EffectiveSecurity{None: true}},
			{
				ID: "archiveThing", Method: http.MethodPost,
				PathParts: []PathPart{{Literal: "/things/"}, {Parameter: "thing_id"}, {Literal: ":archive"}},
				Parameters: []Parameter{
					{Name: "thing_id", In: "path", Required: true, Style: "simple", Type: "string"},
					{Name: "thing_id", In: "query", Style: "form", Type: "string"},
					{Name: "X-Reason", In: "header", Required: true, Style: "simple", Type: "string"},
				},
				RequestBody:     &RequestBody{Required: true, ContentType: "application/json", Fields: []InputField{{Name: "name", Type: "string", Required: true}}},
				SuccessStatuses: []string{"202"}, Capabilities: []string{"action"}, Security: EffectiveSecurity{None: true},
			},
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
	waitForTexts(t, testModel, "archiveThing", "POST · 4 input(s)")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForText(t, testModel, "path parameter thing_id (string) — required")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForText(t, testModel, "path parameter thing_id is required")
	select {
	case request := <-actionRequests:
		t.Fatalf("empty required input made request %q", request)
	default:
	}
	testModel.Type("thing/7")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForText(t, testModel, "query parameter thing_id (string) — optional")
	testModel.Type("notify")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForText(t, testModel, "header parameter X-Reason (string) — required")
	testModel.Type("operator requested")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForText(t, testModel, "body field name (string) — required")
	testModel.Type("updated")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForText(t, testModel, "Operation completed")
	select {
	case request := <-actionRequests:
		if request != `/things/thing%2F7:archive?thing_id=notify|operator requested|{"name":"updated"}` {
			t.Fatalf("action request = %q", request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("action request was not received")
	}
}

func TestActionChooserUsesOnlyDocumentedCapabilities(t *testing.T) {
	descriptor := Descriptor{
		Views: []View{{
			ID: "record", Kind: "item", Label: "Record",
			OperationIDs: []string{"patchRecord", "streamRecordEvents"},
			Capabilities: []string{"stream", "update"},
		}},
		Operations: []Operation{
			{ID: "patchRecord", Method: http.MethodPatch, Capabilities: []string{"update"}},
			{ID: "streamRecordEvents", Method: http.MethodGet, Capabilities: []string{"stream"}},
		},
	}
	model := &Model{
		descriptor: descriptor,
		frames:     []Frame{{TargetViewID: "record", Bindings: map[string]any{}}},
	}
	_, _ = model.openActions()
	if model.mode != modeActions || len(model.chosenOperations) != 2 {
		t.Fatalf("action chooser state = mode %v, operations %#v", model.mode, model.chosenOperations)
	}
	if got := []string{model.chosenOperations[0].ID, model.chosenOperations[1].ID}; !reflect.DeepEqual(got, []string{"patchRecord", "streamRecordEvents"}) {
		t.Fatalf("action chooser controls = %v, want documented patch and stream only", got)
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

func TestBreadcrumbSanitizesAPIDerivedIdentityWithTeatest(t *testing.T) {
	const injectedID = "one\x1b]52;c;breadcrumb-owned\x07"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/items" {
			_, _ = io.WriteString(writer, `{"items":[{"id":"one\u001b]52;c;breadcrumb-owned\u0007","name":"Safe"}]}`)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/items/"+injectedID) {
			_, _ = io.WriteString(writer, `{"id":"one\u001b]52;c;breadcrumb-owned\u0007","name":"Safe detail"}`)
			return
		}
		http.NotFound(writer, request)
	}))
	defer server.Close()
	descriptor := Descriptor{
		Title: "Breadcrumb test", Servers: []Server{{URL: server.URL}},
		Views: []View{
			{ID: "items", Kind: "collection", Label: "Items", IdentityProperty: "id", Columns: []Column{{Property: "name", Label: "NAME"}}, OperationIDs: []string{"listItems"}, ListOperationID: "listItems"},
			{ID: "item", Kind: "item", Label: "Item", IdentityProperty: "id", Columns: []Column{{Property: "name", Label: "NAME"}}, OperationIDs: []string{"getItem"}, GetOperationID: "getItem"},
		},
		Operations: []Operation{
			{ID: "listItems", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/items"}}, Response: ResponseShape{ItemsPointer: "/items"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: EffectiveSecurity{None: true}},
			{ID: "getItem", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/items/"}, {Parameter: "item_id"}}, Parameters: []Parameter{{Name: "item_id", In: "path", Required: true, Type: "string"}}, SuccessStatuses: []string{"200"}, Capabilities: []string{"get"}, Security: EffectiveSecurity{None: true}},
		},
		Edges: []Edge{{ID: "items-item", Name: "details", SourceViewID: "items", TargetViewID: "item", TargetOperationID: "getItem", Provenance: "collection-item", Bindings: []Binding{{Target: "item_id", SourceKind: "row-property", Source: "id"}}, Navigable: true}},
	}
	model, err := NewModel(descriptor, ClientConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	testModel := teatest.NewTestModel(t, model, teatest.WithInitialTermSize(90, 25))
	t.Cleanup(func() { _ = testModel.Quit() })
	waitForText(t, testModel, "Safe")
	testModel.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForTexts(t, testModel, "Safe detail", "Items > Item[one]")
	output := readOutput(t, testModel.Output())
	if bytes.Contains(output, []byte("breadcrumb-owned")) || bytes.Contains(output, []byte("\x1b]52")) {
		t.Fatalf("unsafe breadcrumb identity reached output: %q", output)
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

func TestEvaluateStandardLinkRuntimeExpressions(t *testing.T) {
	operation := Operation{Parameters: []Parameter{
		{Name: "id", In: "path"},
		{Name: "id", In: "query"},
		{Name: "id", In: "header"},
	}}
	frame := Frame{
		Bindings: map[string]any{"project_id": "project/1"},
		RequestValues: captureRequestValues(operation, map[string]any{
			ParameterValueKey("path", "id"):   "path-id",
			ParameterValueKey("query", "id"):  "query-id",
			ParameterValueKey("header", "id"): "header-id",
		}),
		RequestBody:   decodeRuntimeBody([]byte(`{"parent":{"id":"parent/9"}}`)),
		RequestURL:    "https://api.example.test/parents/path-id?id=query-id",
		RequestMethod: http.MethodPost,
		ResponseHeaders: http.Header{
			"Location": []string{"/children/child-3"},
		},
		ResponseBody:   map[string]any{"id": "child-3"},
		ResponseStatus: http.StatusCreated,
	}
	row := Row{Raw: map[string]any{"id": "fallback-row"}}
	edge := Edge{Name: "standard expressions", Bindings: []Binding{
		{Target: "url", SourceKind: "runtime-expression", Source: "$url"},
		{Target: "method", SourceKind: "runtime-expression", Source: "$method"},
		{Target: "status", SourceKind: "runtime-expression", Source: "$statusCode"},
		{Target: "path", SourceKind: "runtime-expression", Source: "$request.path.id"},
		{Target: "query", SourceKind: "runtime-expression", Source: "$request.query.id"},
		{Target: "request_header", SourceKind: "runtime-expression", Source: "$request.header.ID"},
		{Target: "request_body_full", SourceKind: "runtime-expression", Source: "$request.body"},
		{Target: "request_body", SourceKind: "runtime-expression", Source: "$request.body#/parent/id"},
		{Target: "response_header", SourceKind: "runtime-expression", Source: "$response.header.location"},
		{Target: "response_body_full", SourceKind: "runtime-expression", Source: "$response.body"},
		{Target: "response_body", SourceKind: "runtime-expression", Source: "$response.body#/id"},
	}}
	bindings, err := evaluateBindings(edge, frame, row)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"project_id": "project/1", "url": frame.RequestURL, "method": http.MethodPost, "status": http.StatusCreated,
		"path": "path-id", "query": "query-id", "request_header": "header-id", "request_body": "parent/9",
		"response_header": "/children/child-3", "response_body": "child-3",
		"request_body_full": frame.RequestBody, "response_body_full": frame.ResponseBody,
	}
	if !reflect.DeepEqual(bindings, want) {
		t.Fatalf("standard runtime bindings = %#v, want %#v", bindings, want)
	}
}

func TestModelScrollsColumnsWithoutChangingRowsOrFilterWidths(t *testing.T) {
	view := View{
		ID: "records", Kind: "collection", Label: "Records", IdentityProperty: "id", DefaultSort: "a",
		Columns: []Column{
			{Property: "a", Label: "A", Priority: 100, Type: "integer"},
			{Property: "b", Label: "B", Priority: 90, Type: "integer"},
			{Property: "c", Label: "C", Priority: 80, Type: "integer"},
			{Property: "d", Label: "D", Priority: 70, Type: "integer"},
			{Property: "e", Label: "E", Priority: 60, Type: "integer"},
			{Property: "f", Label: "F", Priority: 50, Type: "integer"},
		},
	}
	model := &Model{
		descriptor: Descriptor{Views: []View{view}}, width: 24, height: 20,
		frames: []Frame{{TargetViewID: view.ID, Label: view.Label, Bindings: map[string]any{}}},
	}
	model.rebuildTable(view)
	items := []map[string]any{
		{"id": "record-1", "a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": "needle-one"},
		{"id": "record-2", "a": 2, "b": 3, "c": 4, "d": 5, "e": 6, "f": "needle-two"},
	}
	model.setRows(view, items)
	if !reflect.DeepEqual(model.displayColumns, []int{0, 1, 2}) || model.leftOverflow != 0 || model.rightOverflow != 3 {
		t.Fatalf("initial horizontal state = columns %v, left %d, right %d", model.displayColumns, model.leftOverflow, model.rightOverflow)
	}
	if output := model.tableView(); strings.Contains(output, "◀") || !strings.Contains(output, "3 ▶") {
		t.Fatalf("left-edge affordance = %q", output)
	}
	model.table.SetCursor(1)
	selected := model.selectedRow()
	_, _ = model.handleKey(tea.KeyMsg{Type: tea.KeyRight})
	if model.frames[0].ColumnOffset != 1 || !reflect.DeepEqual(model.displayColumns, []int{1, 2, 3}) {
		t.Fatalf("scrolled state = frame %#v, columns %v", model.frames[0], model.displayColumns)
	}
	_, _ = model.handleKey(tea.KeyMsg{Type: tea.KeyRight})
	if model.frames[0].ColumnOffset != 2 || !reflect.DeepEqual(model.displayColumns, []int{2, 3, 4}) {
		t.Fatalf("second scrolled state = frame %#v, columns %v", model.frames[0], model.displayColumns)
	}
	_, _ = model.handleKey(tea.KeyMsg{Type: tea.KeyRight})
	if model.frames[0].ColumnOffset != 3 || !reflect.DeepEqual(model.displayColumns, []int{3, 4, 5}) {
		t.Fatalf("right-edge state = frame %#v, columns %v", model.frames[0], model.displayColumns)
	}
	if output := model.tableView(); !strings.Contains(output, "◀ 3") || strings.Contains(output, "▶") {
		t.Fatalf("right-edge affordance = %q", output)
	}
	_, _ = model.handleKey(tea.KeyMsg{Type: tea.KeyLeft})
	if model.frames[0].ColumnOffset != 2 || !reflect.DeepEqual(model.displayColumns, []int{2, 3, 4}) {
		t.Fatalf("left-scrolled state = frame %#v, columns %v", model.frames[0], model.displayColumns)
	}
	if after := model.selectedRow(); selected == nil || after == nil || after.Identity != selected.Identity {
		t.Fatalf("row selection changed during horizontal scroll: before %#v, after %#v", selected, after)
	}

	widths := append([]int(nil), model.columnWidths...)
	model.filter = "needle"
	model.applyFilter()
	if len(model.visible) != 2 || !reflect.DeepEqual(widths, model.columnWidths) {
		t.Fatalf("off-screen filter changed rows or widths: rows %d, widths %v -> %v", len(model.visible), widths, model.columnWidths)
	}
	if output := model.View(); !strings.Contains(output, "◀ 2") || !strings.Contains(output, "1 ▶") || !strings.Contains(output, columnScrollHint()) {
		t.Fatalf("overflow affordance absent from view: %q", output)
	}
	model.setRows(view, items)
	if model.frames[0].ColumnOffset != 2 || model.leftOverflow != 2 {
		t.Fatalf("refresh lost horizontal offset: frame %#v, left %d", model.frames[0], model.leftOverflow)
	}

	model.width = 50
	model.resize()
	if model.frames[0].ColumnOffset != 0 || model.leftOverflow != 0 || model.rightOverflow != 0 || len(model.displayColumns) != len(view.Columns) {
		t.Fatalf("wide resize did not clamp offset and reveal all columns: frame %#v, columns %v, left %d, right %d", model.frames[0], model.displayColumns, model.leftOverflow, model.rightOverflow)
	}
	model.table.SetCursor(1)
	selected = model.selectedRow()
	model.width = 24
	model.resize()
	if !reflect.DeepEqual(model.displayColumns, []int{0, 1, 2}) || model.rightOverflow != 3 {
		t.Fatalf("narrow resize did not restore overflow: columns %v, right %d", model.displayColumns, model.rightOverflow)
	}
	if after := model.selectedRow(); selected == nil || after == nil || after.Identity != selected.Identity {
		t.Fatalf("row selection changed during narrow resize: before %#v, after %#v", selected, after)
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

func TestRefreshFailurePreservesContentAndLaterSuccessRestoresSelection(t *testing.T) {
	fail := false
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		if fail {
			http.Error(writer, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"items":[{"id":"one","name":"One"},{"id":"two","name":"Two"}]}`)
	}))
	defer server.Close()
	descriptor := Descriptor{
		Title: "Refresh test", Servers: []Server{{URL: server.URL}},
		Views:      []View{{ID: "things", Kind: "collection", Label: "Things", IdentityProperty: "id", DefaultSort: "name", Columns: []Column{{Property: "name", Label: "NAME"}}, OperationIDs: []string{"listThings"}, ListOperationID: "listThings"}},
		Operations: []Operation{{ID: "listThings", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/things"}}, Response: ResponseShape{ItemsPointer: "/items"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: EffectiveSecurity{None: true}}},
	}
	model, err := NewModel(descriptor, ClientConfig{BaseURL: server.URL, RefreshInterval: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	initial := model.loadCurrent()
	if initial == nil {
		t.Fatal("initial load command is nil")
	}
	_, _ = model.handleResult(initial().(operationResultMsg))
	model.table.SetCursor(1)
	selected := model.selectedRow()
	if selected == nil || selected.Identity != "two" {
		t.Fatalf("initial selection = %#v", selected)
	}

	fail = true
	refresh := model.refreshCurrent()
	if refresh == nil || !model.frames[0].InFlight || !model.frames[0].Refreshing {
		t.Fatalf("refresh did not enter in-flight state: %#v", model.frames[0])
	}
	if duplicate := model.refreshCurrent(); duplicate != nil {
		t.Fatal("overlapping refresh command was created")
	}
	_, _ = model.handleResult(refresh().(operationResultMsg))
	if len(model.rows) != 2 || !model.frames[0].Stale || model.frames[0].InFlight || model.frames[0].Refreshing {
		t.Fatalf("failed refresh state = frame %#v, rows %d", model.frames[0], len(model.rows))
	}
	alert, present := model.shell.Alerts.Active()
	if !present || alert.Severity != AlertError || !strings.Contains(alert.Summary, "HTTP 503") {
		t.Fatalf("refresh alert = %#v, present %v", alert, present)
	}

	fail = false
	refresh = model.refreshCurrent()
	_, _ = model.handleResult(refresh().(operationResultMsg))
	selected = model.selectedRow()
	if selected == nil || selected.Identity != "two" || model.frames[0].Stale || model.frames[0].LastSuccess.IsZero() {
		t.Fatalf("successful refresh state = frame %#v, selection %#v", model.frames[0], selected)
	}
	for _, candidate := range model.shell.Alerts.alerts {
		if candidate.Key == model.refreshAlertKey(model.frames[0].ID) {
			t.Fatalf("successful retry retained refresh error %#v", candidate)
		}
	}
	if requests != 3 {
		t.Fatalf("requests = %d, want initial plus two refreshes", requests)
	}
}

func TestInvalidSuccessfulReadShapeDoesNotRecordRefreshSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"unexpected":[]}`)
	}))
	defer server.Close()
	model, err := NewModel(runtimeTestDescriptor(server.URL), ClientConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	request := model.loadCurrent()
	_, _ = model.handleResult(request().(operationResultMsg))
	if !model.frames[0].LoadFailed || !model.frames[0].LastSuccess.IsZero() {
		t.Fatalf("invalid response shape recorded success: %#v", model.frames[0])
	}
	alert, present := model.shell.Alerts.Active()
	if !present || alert.Severity != AlertError || !strings.Contains(alert.Summary, "items") {
		t.Fatalf("invalid response alert = %#v, present %v", alert, present)
	}
}

func TestPollingCanBeDisabledAndStalenessUsesConfiguredThreshold(t *testing.T) {
	descriptor := runtimeTestDescriptor("http://localhost:8000")
	model, err := NewModel(descriptor, ClientConfig{BaseURL: "http://localhost:8000", RefreshInterval: 0})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	model.frames[0].LastSuccess = now
	model.nextRefresh = now
	_, _ = model.Update(presentationPulseMsg{now: now.Add(20 * time.Second)})
	if model.frames[0].InFlight {
		t.Fatal("disabled polling started a request")
	}
	if !model.frames[0].Stale {
		t.Fatal("page did not become stale after the fifteen-second floor")
	}

	model.refreshInterval = 10 * time.Second
	model.frames[0].Stale = false
	model.updateStaleness(now.Add(29 * time.Second))
	if model.frames[0].Stale {
		t.Fatal("page became stale before three configured intervals")
	}
	model.updateStaleness(now.Add(31 * time.Second))
	if !model.frames[0].Stale {
		t.Fatal("page did not become stale after three configured intervals")
	}
}

func TestHiddenFrameResultIsIgnoredWithoutLeavingRequestStuck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"items":[{"id":"one","name":"One"}]}`)
	}))
	defer server.Close()
	descriptor := runtimeTestDescriptor(server.URL)
	model, err := NewModel(descriptor, ClientConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	initial := model.loadCurrent()
	_, _ = model.handleResult(initial().(operationResultMsg))
	refresh := model.refreshCurrent()
	parentID := model.frames[0].ID
	model.frames = append(model.frames, Frame{ID: model.newFrameID(), TargetViewID: "accounts", Label: "Accounts", Bindings: map[string]any{}})
	before := len(model.rows)
	_, _ = model.handleResult(refresh().(operationResultMsg))
	if model.frames[0].InFlight || model.frames[0].Refreshing {
		t.Fatalf("hidden frame %d remained in flight: %#v", parentID, model.frames[0])
	}
	if len(model.rows) != before {
		t.Fatalf("hidden result changed active content: %d -> %d", before, len(model.rows))
	}
}

func TestModelRejectsNegativeRefreshInterval(t *testing.T) {
	_, err := NewModel(runtimeTestDescriptor("http://localhost:8000"), ClientConfig{BaseURL: "http://localhost:8000", RefreshInterval: -time.Second})
	if err == nil || !strings.Contains(err.Error(), "non-negative") {
		t.Fatalf("negative refresh interval error = %v", err)
	}
}

func TestOperationHotkeyUsesSafeConfirmationAndSubmitsOnce(t *testing.T) {
	actionRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodDelete {
			actionRequests++
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"items":[]}`)
	}))
	defer server.Close()
	descriptor := Descriptor{
		Title: "Action confirmation", Servers: []Server{{URL: server.URL}},
		Views: []View{{ID: "things", Kind: "collection", Label: "Things", OperationIDs: []string{"listThings", "deleteThings"}, ListOperationID: "listThings"}},
		Operations: []Operation{
			{ID: "listThings", Method: http.MethodGet, PathParts: []PathPart{{Literal: "/things"}}, Response: ResponseShape{ItemsPointer: "/items"}, SuccessStatuses: []string{"200"}, Capabilities: []string{"list"}, Security: EffectiveSecurity{None: true}},
			{ID: "deleteThings", Method: http.MethodDelete, PathParts: []PathPart{{Literal: "/things"}}, SuccessStatuses: []string{"204"}, Capabilities: []string{"delete"}, Security: EffectiveSecurity{None: true}, Presentation: ActionPresentation{Label: "Delete all", Hotkey: "x", Confirmation: &Confirmation{Title: "Confirm delete", Message: "Delete all things?", Destructive: true}}},
		},
	}
	model, err := NewModel(descriptor, ClientConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, command := model.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if command != nil || model.mode != modeConfirmation || model.confirmation == nil || model.confirmation.confirmFocus {
		t.Fatalf("hotkey confirmation state = mode %v, dialog %#v, command %v", model.mode, model.confirmation, command)
	}
	_, command = model.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if command != nil || model.mode != modeBrowse || actionRequests != 0 {
		t.Fatalf("safe cancel issued request: mode %v, command %v, requests %d", model.mode, command, actionRequests)
	}

	_, _ = model.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	_, _ = model.handleKey(tea.KeyMsg{Type: tea.KeyTab})
	_, command = model.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if command == nil {
		t.Fatal("explicit confirmation did not create request")
	}
	_, duplicate := model.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if duplicate != nil {
		t.Fatal("repeated confirmation created a second request")
	}
	_, refresh := model.handleResult(command().(operationResultMsg))
	if refresh == nil || actionRequests != 1 {
		t.Fatalf("confirmed action = requests %d, refresh %v", actionRequests, refresh)
	}
	_, _ = model.handleResult(refresh().(operationResultMsg))
	if actionRequests != 1 || model.mode != modeBrowse {
		t.Fatalf("post-action state = requests %d, mode %v", actionRequests, model.mode)
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
