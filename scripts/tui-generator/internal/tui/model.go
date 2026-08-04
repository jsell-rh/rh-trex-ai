package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Row struct {
	Raw      map[string]any
	Identity string
	Cells    []string
}

type Frame struct {
	EdgeID           string
	SourceViewID     string
	SelectedIdentity string
	Bindings         map[string]any
	TargetViewID     string
	Label            string
	Selected         *Row
	RequestValues    map[string]any
	RequestBody      any
	ResponseHeaders  http.Header
	ResponseBody     any
}

type mode int

const (
	modeBrowse mode = iota
	modeFilter
	modeSwitch
	modeRelationships
	modeActions
	modeActionInput
	modeDetail
)

const (
	maxVisibleStreamEvents = 500
	maxVisibleStreamBytes  = 1 << 20
	maxActionInputBytes    = 64 << 10
)

type actionPrompt struct {
	Parameter *Parameter
	Body      bool
}

type Model struct {
	descriptor       Descriptor
	client           *Client
	frames           []Frame
	rows             []Row
	visible          []Row
	displayColumns   []int
	table            table.Model
	chooser          table.Model
	input            textinput.Model
	detail           viewport.Model
	mode             mode
	filter           string
	restoreIdentity  string
	status           string
	width            int
	height           int
	loading          bool
	chosenEdges      []Edge
	chosenOperations []Operation
	actionOperation  Operation
	actionPrompts    []actionPrompt
	actionPrompt     int
	actionRequest    RequestInput
	streamCancel     context.CancelFunc
	streamEvents     <-chan streamEvent
	streamLines      []string
	streamBytes      int
}

type operationResultMsg struct {
	viewID      string
	operationID string
	input       RequestInput
	result      Result
	err         error
}

type streamOpenedMsg struct {
	viewID string
	events <-chan streamEvent
	err    error
}

type streamEventMsg struct {
	viewID string
	events <-chan streamEvent
	event  streamEvent
}

type streamEvent struct {
	text string
	err  error
	done bool
}

func NewModel(descriptor Descriptor, config ClientConfig) (*Model, error) {
	client, err := NewClient(descriptor, config)
	if err != nil {
		return nil, err
	}
	root := firstRootView(descriptor)
	if root == nil {
		return nil, fmt.Errorf("descriptor has no globally addressable list view")
	}
	input := textinput.New()
	input.CharLimit = 256
	detail := viewport.New(80, 20)
	model := &Model{
		descriptor: descriptor, client: client, input: input, detail: detail,
		width: 100, height: 30,
		frames: []Frame{{TargetViewID: root.ID, Label: root.Label, Bindings: map[string]any{}}},
	}
	model.rebuildTable(*root)
	return model, nil
}

func (model *Model) Init() tea.Cmd {
	return model.loadCurrent()
}

func (model *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := message.(type) {
	case tea.WindowSizeMsg:
		model.width, model.height = typed.Width, typed.Height
		model.resize()
		return model, nil
	case operationResultMsg:
		return model.handleResult(typed)
	case streamOpenedMsg:
		if model.currentView() == nil || typed.viewID != model.currentView().ID {
			return model, nil
		}
		model.loading = false
		if typed.err != nil {
			model.status = SanitizeCell(typed.err.Error())
			return model, nil
		}
		model.streamEvents = typed.events
		model.streamLines = nil
		model.streamBytes = 0
		model.detail.SetContent("")
		model.mode = modeDetail
		model.status = "Stream connected"
		return model, waitStreamEvent(typed.viewID, typed.events)
	case streamEventMsg:
		if typed.events != model.streamEvents || model.currentView() == nil || typed.viewID != model.currentView().ID {
			return model, nil
		}
		if typed.event.err != nil {
			model.status = SanitizeCell(typed.event.err.Error())
			model.streamEvents = nil
			model.streamCancel = nil
			return model, nil
		}
		if typed.event.done {
			model.status = "Stream closed"
			model.streamEvents = nil
			model.streamCancel = nil
			return model, nil
		}
		model.appendStreamEvent(typed.event.text)
		return model, waitStreamEvent(typed.viewID, typed.events)
	case tea.KeyMsg:
		return model.handleKey(typed)
	}
	if model.mode == modeBrowse {
		var command tea.Cmd
		model.table, command = model.table.Update(message)
		return model, command
	}
	if model.mode == modeDetail {
		var command tea.Cmd
		model.detail, command = model.detail.Update(message)
		return model, command
	}
	return model, nil
}

func (model *Model) View() string {
	view := model.currentView()
	if view == nil {
		return "No view\n"
	}
	var body string
	switch model.mode {
	case modeFilter:
		body = model.table.View() + "\n/" + model.input.View()
	case modeSwitch:
		body = model.table.View() + "\n:" + model.input.View()
	case modeRelationships, modeActions:
		body = model.chooser.View()
	case modeActionInput:
		body = model.actionInputView()
	case modeDetail:
		body = model.detail.View()
	default:
		body = model.table.View()
	}
	header := lipgloss.NewStyle().Bold(true).Render(SanitizeCell(model.descriptor.Title) + " — " + SanitizeCell(view.Label))
	status := SanitizeCell(model.status)
	if model.loading {
		status = "Loading…"
	}
	hints := "[:] resources  [/] filter  [Enter] navigate  [d] detail  [a] actions  [Esc] back  [q] quit"
	return header + "\n" + SanitizeCell(model.breadcrumb()) + "\n" + body + "\n" + hints + "\n" + status + "\n"
}

func (model *Model) handleKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.String() == "ctrl+c" || (key.String() == "q" && model.mode == modeBrowse) {
		model.cancelStream()
		return model, tea.Quit
	}
	if model.mode == modeFilter || model.mode == modeSwitch {
		return model.handleInputKey(key)
	}
	if model.mode == modeActionInput {
		return model.handleActionInputKey(key)
	}
	if model.mode == modeRelationships || model.mode == modeActions {
		return model.handleChooserKey(key)
	}
	if model.mode == modeDetail {
		if key.String() == "esc" {
			view := model.currentView()
			wasStreaming := model.streamEvents != nil || model.streamCancel != nil
			model.cancelStream()
			if len(model.frames) > 1 && view != nil && (view.Kind == "stream" || (!wasStreaming && view.Kind == "item")) {
				return model.popFrame()
			}
			model.mode = modeBrowse
			return model, nil
		}
		if key.String() == "enter" {
			return model.followRelationships()
		}
		var command tea.Cmd
		model.detail, command = model.detail.Update(key)
		return model, command
	}
	switch key.String() {
	case "/":
		model.mode = modeFilter
		model.input.CharLimit = 256
		model.input.SetValue(model.filter)
		model.input.Focus()
		return model, textinput.Blink
	case ":":
		model.mode = modeSwitch
		model.input.CharLimit = 256
		model.input.SetValue("")
		model.input.Focus()
		return model, textinput.Blink
	case "esc":
		if model.filter != "" {
			model.filter = ""
			model.applyFilter()
			return model, nil
		}
		return model.popFrame()
	case "enter":
		return model.followRelationships()
	case "d":
		row := model.selectedRow()
		if row == nil {
			model.status = "No selected item"
			return model, nil
		}
		model.detail.SetContent(renderDetail(row.Raw))
		model.mode = modeDetail
		return model, nil
	case "a":
		return model.openActions()
	}
	var command tea.Cmd
	model.table, command = model.table.Update(key)
	return model, command
}

func (model *Model) handleInputKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.String() == "esc" {
		model.mode = modeBrowse
		model.input.Blur()
		return model, nil
	}
	if key.String() == "enter" {
		value := strings.TrimSpace(model.input.Value())
		model.input.Blur()
		if model.mode == modeFilter {
			model.filter = value
			model.applyFilter()
			model.mode = modeBrowse
			return model, nil
		}
		view := model.addressableView(value)
		if view == nil {
			model.status = "Unknown or unavailable resource: " + SanitizeCell(value)
			model.mode = modeBrowse
			return model, nil
		}
		bindings := availableBindings(model.frames)
		model.frames = []Frame{{TargetViewID: view.ID, Label: view.Label, Bindings: bindings}}
		model.mode = modeBrowse
		model.rebuildTable(*view)
		return model, model.loadCurrent()
	}
	var command tea.Cmd
	model.input, command = model.input.Update(key)
	if model.mode == modeFilter {
		model.filter = model.input.Value()
		model.applyFilter()
	}
	return model, command
}

func (model *Model) handleChooserKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.String() == "esc" {
		model.mode = modeBrowse
		return model, nil
	}
	if key.String() == "enter" {
		index := model.chooser.Cursor()
		if model.mode == modeRelationships && index < len(model.chosenEdges) {
			edge := model.chosenEdges[index]
			model.mode = modeBrowse
			return model.pushEdge(edge)
		}
		if model.mode == modeActions && index < len(model.chosenOperations) {
			operation := model.chosenOperations[index]
			return model.beginAction(operation)
		}
	}
	var command tea.Cmd
	model.chooser, command = model.chooser.Update(key)
	return model, command
}

func (model *Model) followRelationships() (tea.Model, tea.Cmd) {
	view := model.currentView()
	if view == nil {
		return model, nil
	}
	edges := model.descriptor.Outgoing(view.ID)
	if len(edges) == 0 {
		row := model.selectedRow()
		if row != nil {
			model.detail.SetContent(renderDetail(row.Raw))
			model.mode = modeDetail
		}
		return model, nil
	}
	if len(edges) == 1 {
		return model.pushEdge(edges[0])
	}
	model.chosenEdges = edges
	rows := make([]table.Row, 0, len(edges))
	for _, edge := range edges {
		target := model.descriptor.View(edge.TargetViewID)
		label := edge.Name
		if target != nil {
			label = target.Label
		}
		rows = append(rows, table.Row{SanitizeCell(label), SanitizeCell(edge.Provenance)})
	}
	model.chooser = newChooser([]table.Column{{Title: "RELATIONSHIP", Width: 40}, {Title: "SOURCE", Width: 20}}, rows)
	model.mode = modeRelationships
	return model, nil
}

func (model *Model) pushEdge(edge Edge) (tea.Model, tea.Cmd) {
	row := model.selectedRow()
	if row == nil {
		model.status = "Relationship requires a selected item"
		return model, nil
	}
	bindings, err := evaluateBindings(edge, model.frames[len(model.frames)-1], *row)
	if err != nil {
		model.status = err.Error()
		return model, nil
	}
	target := model.descriptor.View(edge.TargetViewID)
	if target == nil {
		model.status = "Relationship target is unavailable"
		return model, nil
	}
	frame := Frame{
		EdgeID: edge.ID, SourceViewID: edge.SourceViewID, SelectedIdentity: row.Identity,
		Bindings: bindings, TargetViewID: target.ID, Label: target.Label, Selected: row,
	}
	model.frames = append(model.frames, frame)
	model.filter = ""
	model.mode = modeBrowse
	model.rebuildTable(*target)
	return model, model.loadCurrent()
}

func (model *Model) popFrame() (tea.Model, tea.Cmd) {
	if len(model.frames) <= 1 {
		return model, nil
	}
	model.cancelStream()
	model.restoreIdentity = model.frames[len(model.frames)-1].SelectedIdentity
	model.frames = model.frames[:len(model.frames)-1]
	view := model.currentView()
	model.mode = modeBrowse
	if view != nil {
		model.rebuildTable(*view)
	}
	return model, model.loadCurrent()
}

func (model *Model) openActions() (tea.Model, tea.Cmd) {
	view := model.currentView()
	if view == nil {
		return model, nil
	}
	var operations []Operation
	for _, id := range view.OperationIDs {
		operation := model.descriptor.Operation(id)
		if operation == nil || containsString(operation.Capabilities, "list") || containsString(operation.Capabilities, "get") {
			continue
		}
		operations = append(operations, *operation)
	}
	if len(operations) == 0 {
		model.status = "No documented actions for this view"
		return model, nil
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].ID < operations[j].ID })
	model.chosenOperations = operations
	rows := make([]table.Row, 0, len(operations))
	values := cloneBindings(model.frames[len(model.frames)-1].Bindings)
	for _, operation := range operations {
		label := operation.Summary
		if label == "" {
			label = operation.ID
		}
		state := operation.Method
		if count := actionInputCount(operation, values); count > 0 {
			state += fmt.Sprintf(" · %d input(s)", count)
		}
		rows = append(rows, table.Row{SanitizeCell(label), SanitizeCell(state)})
	}
	model.chooser = newChooser([]table.Column{{Title: "ACTION", Width: 38}, {Title: "METHOD / INPUTS", Width: 46}}, rows)
	model.mode = modeActions
	return model, nil
}

func (model *Model) beginAction(operation Operation) (tea.Model, tea.Cmd) {
	values := cloneBindings(model.frames[len(model.frames)-1].Bindings)
	for _, parameter := range operation.Parameters {
		if parameter.In != "path" {
			continue
		}
		if value, present := values[parameter.Name]; present {
			values[ParameterValueKey(parameter.In, parameter.Name)] = value
		}
	}
	model.actionOperation = operation
	model.actionRequest = RequestInput{Values: values}
	model.actionPrompts = nil
	model.actionPrompt = 0
	for index := range operation.Parameters {
		parameter := &operation.Parameters[index]
		if value, present := operationParameterValue(operation, *parameter, values); present && strings.TrimSpace(scalarString(value)) != "" {
			continue
		}
		model.actionPrompts = append(model.actionPrompts, actionPrompt{Parameter: parameter})
	}
	if operation.RequestBody != nil {
		model.actionPrompts = append(model.actionPrompts, actionPrompt{Body: true})
	}
	if len(model.actionPrompts) == 0 {
		model.mode = modeBrowse
		return model, model.executeAction(operation, model.actionRequest)
	}
	model.mode = modeActionInput
	model.status = ""
	model.input.CharLimit = maxActionInputBytes
	model.input.SetValue("")
	model.input.Focus()
	return model, textinput.Blink
}

func (model *Model) actionInputView() string {
	if model.actionPrompt >= len(model.actionPrompts) {
		return "Preparing request…"
	}
	prompt := model.actionPrompts[model.actionPrompt]
	required := false
	description := ""
	if prompt.Body {
		required = model.actionOperation.RequestBody != nil && model.actionOperation.RequestBody.Required
		description = "JSON request body"
		if model.actionOperation.RequestBody != nil && model.actionOperation.RequestBody.ContentType != "" {
			description += " (" + model.actionOperation.RequestBody.ContentType + ")"
		}
	} else if prompt.Parameter != nil {
		required = prompt.Parameter.Required
		description = prompt.Parameter.In + " parameter " + prompt.Parameter.Name
		if prompt.Parameter.Type != "" {
			description += " (" + prompt.Parameter.Type + ")"
		}
	}
	necessity := "optional; Enter skips"
	if required {
		necessity = "required"
	}
	return fmt.Sprintf("%s\nInput %d/%d — %s — %s\n> %s", SanitizeCell(actionLabel(model.actionOperation)), model.actionPrompt+1, len(model.actionPrompts), SanitizeCell(description), necessity, model.input.View())
}

func (model *Model) handleActionInputKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.String() == "esc" {
		model.input.Blur()
		model.mode = modeBrowse
		model.status = "Action canceled"
		return model, nil
	}
	if key.String() != "enter" {
		var command tea.Cmd
		model.input, command = model.input.Update(key)
		return model, command
	}
	prompt := model.actionPrompts[model.actionPrompt]
	value := strings.TrimSpace(model.input.Value())
	if prompt.Body {
		if value == "" && model.actionOperation.RequestBody != nil && model.actionOperation.RequestBody.Required {
			model.status = "A JSON request body is required"
			return model, nil
		}
		body := []byte(value)
		if err := validateRequestBody(model.actionOperation, body); err != nil {
			model.status = SanitizeCell(err.Error())
			return model, nil
		}
		model.actionRequest.Body = body
	} else if prompt.Parameter != nil {
		if value == "" {
			if prompt.Parameter.Required {
				model.status = fmt.Sprintf("%s parameter %s is required", prompt.Parameter.In, prompt.Parameter.Name)
				return model, nil
			}
		} else {
			parsed, err := parseParameterInput(*prompt.Parameter, value)
			if err != nil {
				model.status = SanitizeCell(err.Error())
				return model, nil
			}
			model.actionRequest.Values[ParameterValueKey(prompt.Parameter.In, prompt.Parameter.Name)] = parsed
		}
	}
	model.actionPrompt++
	model.status = ""
	model.input.SetValue("")
	if model.actionPrompt < len(model.actionPrompts) {
		return model, nil
	}
	model.input.Blur()
	model.mode = modeBrowse
	return model, model.executeAction(model.actionOperation, model.actionRequest)
}

func parseParameterInput(parameter Parameter, value string) (any, error) {
	if parameter.Type != "array" && parameter.Type != "object" {
		if err := validateParameter(parameter, value); err != nil {
			return nil, fmt.Errorf("%s parameter %s: %w", parameter.In, parameter.Name, err)
		}
		return value, nil
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var parsed any
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("%s parameter %s must be valid JSON: %w", parameter.In, parameter.Name, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("%s parameter %s must contain one JSON value: %w", parameter.In, parameter.Name, err)
	}
	if err := validateParameter(parameter, parsed); err != nil {
		return nil, fmt.Errorf("%s parameter %s: %w", parameter.In, parameter.Name, err)
	}
	return parsed, nil
}

func (model *Model) executeAction(operation Operation, input RequestInput) tea.Cmd {
	if containsString(operation.Capabilities, "stream") {
		return model.openStream(operation, input)
	}
	return model.execute(operation, input)
}

func (model *Model) loadCurrent() tea.Cmd {
	view := model.currentView()
	if view == nil {
		return nil
	}
	if view.ListOperationID != "" {
		operation := model.descriptor.Operation(view.ListOperationID)
		if operation != nil {
			return model.execute(*operation, RequestInput{Values: cloneBindings(model.frames[len(model.frames)-1].Bindings)})
		}
	}
	if view.GetOperationID != "" {
		operation := model.descriptor.Operation(view.GetOperationID)
		if operation != nil {
			return model.execute(*operation, RequestInput{Values: cloneBindings(model.frames[len(model.frames)-1].Bindings)})
		}
	}
	if len(view.StreamOperationIDs) > 0 {
		operation := model.descriptor.Operation(view.StreamOperationIDs[0])
		if operation != nil {
			return model.openStream(*operation, RequestInput{Values: cloneBindings(model.frames[len(model.frames)-1].Bindings)})
		}
	}
	model.status = "View has no executable read operation"
	return nil
}

func (model *Model) execute(operation Operation, input RequestInput) tea.Cmd {
	model.loading = true
	viewID := model.frames[len(model.frames)-1].TargetViewID
	return func() tea.Msg {
		result, err := model.client.Execute(context.Background(), operation, input)
		return operationResultMsg{viewID: viewID, operationID: operation.ID, input: input, result: result, err: err}
	}
}

func (model *Model) openStream(operation Operation, input RequestInput) tea.Cmd {
	model.cancelStream()
	ctx, cancel := context.WithCancel(context.Background())
	model.streamCancel = cancel
	model.loading = true
	viewID := model.frames[len(model.frames)-1].TargetViewID
	return func() tea.Msg {
		response, err := model.client.OpenStream(ctx, operation, input)
		if err != nil {
			return streamOpenedMsg{viewID: viewID, err: err}
		}
		events := make(chan streamEvent, 1)
		go pumpStream(ctx, response.Body, operation.Response.ContentType, events)
		return streamOpenedMsg{viewID: viewID, events: events}
	}
}

func waitStreamEvent(viewID string, events <-chan streamEvent) tea.Cmd {
	return func() tea.Msg {
		event, open := <-events
		if !open {
			event.done = true
		}
		return streamEventMsg{viewID: viewID, events: events, event: event}
	}
}

func (model *Model) appendStreamEvent(value string) {
	line := Sanitize(value)
	if len(line) > maxVisibleStreamBytes {
		start := len(line) - maxVisibleStreamBytes
		for start < len(line) && !utf8.RuneStart(line[start]) {
			start++
		}
		line = line[start:]
	}
	model.streamLines = append(model.streamLines, line)
	model.streamBytes += len(line)
	for len(model.streamLines) > maxVisibleStreamEvents || model.streamBytes > maxVisibleStreamBytes {
		model.streamBytes -= len(model.streamLines[0])
		model.streamLines = model.streamLines[1:]
	}
	model.detail.SetContent(strings.Join(model.streamLines, "\n"))
	model.detail.GotoBottom()
}

func (model *Model) handleResult(message operationResultMsg) (tea.Model, tea.Cmd) {
	if model.currentView() == nil || message.viewID != model.currentView().ID {
		return model, nil
	}
	model.loading = false
	if message.err != nil {
		model.status = SanitizeCell(message.err.Error())
		return model, nil
	}
	operation := model.descriptor.Operation(message.operationID)
	if operation == nil {
		return model, nil
	}
	view := model.currentView()
	frame := &model.frames[len(model.frames)-1]
	frame.RequestValues = cloneBindings(message.input.Values)
	frame.RequestBody = decodeRuntimeBody(message.input.Body)
	frame.ResponseHeaders = message.result.Headers.Clone()
	frame.ResponseBody = message.result.Body
	if containsString(operation.Capabilities, "list") && !operation.Response.Stream {
		items, err := responseItems(message.result.Body, operation.Response.ItemsPointer)
		if err != nil {
			model.status = err.Error()
			return model, nil
		}
		model.setRows(*view, items)
		model.status = fmt.Sprintf("Loaded %d items", len(items))
		return model, nil
	}
	if object, ok := message.result.Body.(map[string]any); ok {
		row := rowFor(*view, object)
		frame.Selected = &row
		model.detail.SetContent(renderDetail(object))
		model.mode = modeDetail
		model.status = "Loaded " + view.Label
		return model, nil
	}
	model.status = "Operation completed"
	return model, nil
}

func (model *Model) rebuildTable(view View) {
	styles := table.DefaultStyles()
	styles.Header = styles.Header.Bold(true).Foreground(lipgloss.Color("69"))
	styles.Selected = styles.Selected.Foreground(lipgloss.Color("0")).Background(lipgloss.Color("214"))
	model.table = table.New(table.WithFocused(true), table.WithHeight(max(3, model.height-8)))
	model.table.SetStyles(styles)
	model.configureTableColumns(view)
	model.rows = nil
	model.visible = nil
}

func (model *Model) configureTableColumns(view View) {
	if len(view.Columns) == 0 {
		model.displayColumns = nil
		model.table.SetColumns([]table.Column{{Title: "VALUE", Width: max(8, model.width-4)}})
		return
	}
	available := max(10, model.width-4)
	retained := max(1, available/21)
	if retained > len(view.Columns) {
		retained = len(view.Columns)
	}
	indexes := make([]int, len(view.Columns))
	for index := range indexes {
		indexes[index] = index
	}
	sort.SliceStable(indexes, func(i, j int) bool {
		left, right := view.Columns[indexes[i]], view.Columns[indexes[j]]
		if left.Priority != right.Priority {
			return left.Priority > right.Priority
		}
		return indexes[i] < indexes[j]
	})
	indexes = indexes[:retained]
	sort.Ints(indexes)
	model.displayColumns = indexes
	width := max(8, available/len(indexes)-1)
	columns := make([]table.Column, 0, len(indexes))
	for _, index := range indexes {
		columns = append(columns, table.Column{Title: SanitizeCell(view.Columns[index].Label), Width: width})
	}
	model.table.SetColumns(columns)
}

func (model *Model) setRows(view View, items []map[string]any) {
	rows := make([]Row, 0, len(items))
	for _, item := range items {
		rows = append(rows, rowFor(view, item))
	}
	sort.SliceStable(rows, func(i, j int) bool {
		left, _ := ResolveJSONPointer(rows[i].Raw, "/"+escapePointer(view.DefaultSort))
		right, _ := ResolveJSONPointer(rows[j].Raw, "/"+escapePointer(view.DefaultSort))
		return scalarString(left) < scalarString(right)
	})
	model.rows = rows
	model.applyFilter()
	if model.restoreIdentity != "" {
		for index := range model.visible {
			if model.visible[index].Identity == model.restoreIdentity {
				model.table.SetCursor(index)
				break
			}
		}
		model.restoreIdentity = ""
	}
}

func rowFor(view View, item map[string]any) Row {
	row := Row{Raw: item}
	if view.IdentityProperty != "" {
		if value, err := ResolveJSONPointer(item, "/"+escapePointer(view.IdentityProperty)); err == nil {
			row.Identity = scalarString(value)
		}
	}
	for _, column := range view.Columns {
		value, _ := ResolveJSONPointer(item, "/"+escapePointer(column.Property))
		row.Cells = append(row.Cells, SanitizeCell(scalarString(value)))
	}
	return row
}

func (model *Model) applyFilter() {
	needle := strings.ToLower(SanitizeCell(model.filter))
	model.visible = nil
	var tableRows []table.Row
	for _, row := range model.rows {
		cells := model.visibleCells(row)
		if needle != "" && !strings.Contains(strings.ToLower(strings.Join(cells, "\x00")), needle) {
			continue
		}
		model.visible = append(model.visible, row)
		tableRows = append(tableRows, table.Row(cells))
	}
	model.table.SetRows(tableRows)
	if len(tableRows) > 0 && model.table.Cursor() < 0 {
		model.table.SetCursor(0)
	}
}

func (model *Model) visibleCells(row Row) []string {
	if len(model.displayColumns) == 0 {
		return []string{SanitizeCell(renderDetail(row.Raw))}
	}
	result := make([]string, 0, len(model.displayColumns))
	for _, index := range model.displayColumns {
		if index < len(row.Cells) {
			result = append(result, row.Cells[index])
		}
	}
	return result
}

func (model *Model) selectedRow() *Row {
	if model.currentView() != nil && model.currentView().Kind == "item" {
		return model.frames[len(model.frames)-1].Selected
	}
	index := model.table.Cursor()
	if index < 0 || index >= len(model.visible) {
		return nil
	}
	return &model.visible[index]
}

func (model *Model) currentView() *View {
	if len(model.frames) == 0 {
		return nil
	}
	return model.descriptor.View(model.frames[len(model.frames)-1].TargetViewID)
}

func (model *Model) addressableView(command string) *View {
	command = strings.ToLower(command)
	bindings := availableBindings(model.frames)
	for index := range model.descriptor.Views {
		view := &model.descriptor.Views[index]
		if view.ListOperationID == "" || !bindingsCover(view.ScopeParameters, bindings) {
			continue
		}
		if strings.EqualFold(view.Label, command) || strings.EqualFold(view.ID, command) {
			return view
		}
		for _, alias := range view.Aliases {
			if alias == command {
				return view
			}
		}
	}
	return nil
}

func (model *Model) breadcrumb() string {
	parts := make([]string, 0, len(model.frames))
	for _, frame := range model.frames {
		part := SanitizeCell(frame.Label)
		if frame.SelectedIdentity != "" {
			part += "[" + SanitizeCell(frame.SelectedIdentity) + "]"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " > ")
}

func (model *Model) resize() {
	model.table.SetHeight(max(3, model.height-8))
	model.table.SetWidth(max(20, model.width-2))
	if view := model.currentView(); view != nil {
		model.configureTableColumns(*view)
		model.applyFilter()
	}
	model.detail.Width = max(20, model.width-2)
	model.detail.Height = max(3, model.height-8)
}

func (model *Model) cancelStream() {
	if model.streamCancel != nil {
		model.streamCancel()
		model.streamCancel = nil
	}
	model.streamEvents = nil
}

func firstRootView(descriptor Descriptor) *View {
	for index := range descriptor.Views {
		view := &descriptor.Views[index]
		if view.ListOperationID != "" && len(view.ScopeParameters) == 0 {
			return view
		}
	}
	return nil
}

func newChooser(columns []table.Column, rows []table.Row) table.Model {
	return table.New(table.WithColumns(columns), table.WithRows(rows), table.WithFocused(true), table.WithHeight(max(3, len(rows))))
}

func evaluateBindings(edge Edge, frame Frame, row Row) (map[string]any, error) {
	result := cloneBindings(frame.Bindings)
	for _, binding := range edge.Bindings {
		var value any
		var err error
		switch binding.SourceKind {
		case "frame-path":
			value, _ = frame.Bindings[binding.Source]
		case "row-property":
			value, err = ResolveJSONPointer(row.Raw, "/"+escapePointer(binding.Source))
		case "runtime-expression":
			value, err = evaluateExpression(binding.Source, frame, row)
		case "literal":
			value = binding.Source
		default:
			err = fmt.Errorf("unsupported binding source %s", binding.SourceKind)
		}
		if err != nil || value == nil || scalarString(value) == "" {
			if err == nil {
				err = fmt.Errorf("value is absent")
			}
			return nil, fmt.Errorf("relationship %s cannot bind %s: %w", edge.Name, binding.Target, err)
		}
		result[binding.Target] = value
	}
	return result, nil
}

func evaluateExpression(expression string, frame Frame, row Row) (any, error) {
	for _, prefix := range []string{"$request.path.", "$request.query."} {
		if !strings.HasPrefix(expression, prefix) {
			continue
		}
		name := strings.TrimPrefix(expression, prefix)
		value, ok := frame.RequestValues[name]
		if !ok {
			value, ok = frame.Bindings[name]
		}
		if !ok {
			return nil, fmt.Errorf("request parameter %s is absent", name)
		}
		return value, nil
	}
	if strings.HasPrefix(expression, "$request.header.") {
		name := strings.TrimPrefix(expression, "$request.header.")
		for candidate, value := range frame.RequestValues {
			if strings.EqualFold(candidate, name) {
				return value, nil
			}
		}
		return nil, fmt.Errorf("request header %s is absent", name)
	}
	if expression == "$request.body#" || strings.HasPrefix(expression, "$request.body#/") {
		return resolveRuntimeBody(frame.RequestBody, strings.TrimPrefix(expression, "$request.body#"), "request")
	}
	if strings.HasPrefix(expression, "$response.header.") {
		name := strings.TrimPrefix(expression, "$response.header.")
		if value := frame.ResponseHeaders.Get(name); value != "" {
			return value, nil
		}
		return nil, fmt.Errorf("response header %s is absent", name)
	}
	if strings.HasPrefix(expression, "$response.body#") {
		body := frame.ResponseBody
		if body == nil {
			body = row.Raw
		}
		return resolveRuntimeBody(body, strings.TrimPrefix(expression, "$response.body#"), "response")
	}
	return nil, fmt.Errorf("unsupported runtime expression %q", expression)
}

func decodeRuntimeBody(body []byte) any {
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return string(body)
	}
	return value
}

func resolveRuntimeBody(body any, pointer, label string) (any, error) {
	if body == nil {
		return nil, fmt.Errorf("%s body is absent", label)
	}
	return ResolveJSONPointer(body, pointer)
}

func responseItems(body any, pointer string) ([]map[string]any, error) {
	value := body
	var err error
	if pointer != "" {
		value, err = ResolveJSONPointer(body, pointer)
		if err != nil {
			return nil, err
		}
	}
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("list response at %q is not an array", pointer)
	}
	items := make([]map[string]any, 0, len(array))
	for index, item := range array {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("list item %d is not an object", index)
		}
		items = append(items, object)
	}
	return items, nil
}

func renderDetail(value any) string {
	var lines []string
	flattenDetail("", value, 0, &lines)
	return strings.Join(lines, "\n")
}

func flattenDetail(prefix string, value any, depth int, lines *[]string) {
	if depth > 8 {
		*lines = append(*lines, SanitizeCell(prefix)+": …")
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := sortedAnyKeys(typed)
		for _, key := range keys {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			flattenDetail(name, typed[key], depth+1, lines)
		}
	case []any:
		for index, item := range typed {
			flattenDetail(fmt.Sprintf("%s[%d]", prefix, index), item, depth+1, lines)
		}
	default:
		*lines = append(*lines, SanitizeCell(prefix)+": "+Sanitize(scalarString(typed)))
	}
}

func pumpStream(ctx context.Context, reader io.ReadCloser, contentType string, events chan<- streamEvent) {
	defer close(events)
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var data []string
	send := func(value string) bool {
		select {
		case events <- streamEvent{text: value}:
			return true
		case <-ctx.Done():
			return false
		}
	}
	flush := func() bool {
		if len(data) > 0 {
			if !send(strings.Join(data, "\n")) {
				return false
			}
			data = nil
		}
		return true
	}
	for scanner.Scan() {
		line := scanner.Text()
		if contentType == "text/event-stream" {
			if line == "" {
				if !flush() {
					return
				}
				continue
			}
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
			continue
		}
		if !send(line) {
			return
		}
	}
	if !flush() {
		return
	}
	if err := scanner.Err(); err != nil {
		select {
		case events <- streamEvent{err: fmt.Errorf("read stream: %w", err)}:
		case <-ctx.Done():
		}
		return
	}
	select {
	case events <- streamEvent{done: true}:
	case <-ctx.Done():
	}
}

func actionInputCount(operation Operation, values map[string]any) int {
	count := 0
	for _, parameter := range operation.Parameters {
		value, ok := operationParameterValue(operation, parameter, values)
		if !ok || strings.TrimSpace(scalarString(value)) == "" {
			count++
		}
	}
	if operation.RequestBody != nil {
		count++
	}
	return count
}

func actionLabel(operation Operation) string {
	if strings.TrimSpace(operation.Summary) != "" {
		return operation.Summary
	}
	return operation.ID
}

func availableBindings(frames []Frame) map[string]any {
	result := make(map[string]any)
	for _, frame := range frames {
		for name, value := range frame.Bindings {
			result[name] = value
		}
	}
	return result
}

func bindingsCover(names []string, values map[string]any) bool {
	for _, name := range names {
		if _, ok := values[name]; !ok {
			return false
		}
	}
	return true
}

func cloneBindings(values map[string]any) map[string]any {
	result := make(map[string]any, len(values))
	for name, value := range values {
		result[name] = value
	}
	return result
}

func escapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}
