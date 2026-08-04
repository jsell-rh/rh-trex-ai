package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

type BindingID string

const (
	KeyQuit             BindingID = "quit"
	KeyForceQuit        BindingID = "force-quit"
	KeyHelp             BindingID = "help"
	KeyCommand          BindingID = "command"
	KeyFilter           BindingID = "filter"
	KeyCancel           BindingID = "cancel"
	KeySubmit           BindingID = "submit"
	KeyNextFocus        BindingID = "next-focus"
	KeyPreviousFocus    BindingID = "previous-focus"
	KeyNavigate         BindingID = "navigate"
	KeyDetail           BindingID = "detail"
	KeyActions          BindingID = "actions"
	KeyColumnsLeft      BindingID = "columns-left"
	KeyColumnsRight     BindingID = "columns-right"
	KeyChoicePrevious   BindingID = "choice-previous"
	KeyChoiceNext       BindingID = "choice-next"
	KeyDismissAlert     BindingID = "dismiss-alert"
	KeyHistoryPrevious  BindingID = "history-previous"
	KeyHistoryNext      BindingID = "history-next"
	KeyToggleAutoscroll BindingID = "toggle-autoscroll"
	KeyAlertDetails     BindingID = "alert-details"
	KeySortNext         BindingID = "sort-next"
	KeySortDirection    BindingID = "sort-direction"
)

type BindingSpec struct {
	ID      BindingID
	Binding key.Binding
	Global  bool
	Order   int
}

type KeyRegistry struct{ bindings map[BindingID]BindingSpec }

func DefaultKeyRegistry() KeyRegistry {
	specs := []BindingSpec{
		{KeyQuit, key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit")), true, 10},
		{KeyForceQuit, key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "quit")), true, 11},
		{KeyHelp, key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")), true, 20},
		{KeyCommand, key.NewBinding(key.WithKeys(":"), key.WithHelp(":", "resources")), true, 30},
		{KeyFilter, key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")), true, 40},
		{KeyCancel, key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back/cancel")), true, 50},
		{KeySubmit, key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select/submit")), true, 60},
		{KeyNextFocus, key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next field")), true, 70},
		{KeyPreviousFocus, key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "previous field")), true, 80},
		{KeyNavigate, key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "navigate")), false, 90},
		{KeyDetail, key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "detail")), false, 100},
		{KeyActions, key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "actions")), false, 110},
		{KeyColumnsLeft, key.NewBinding(key.WithKeys("left"), key.WithHelp("←", "columns left")), false, 120},
		{KeyColumnsRight, key.NewBinding(key.WithKeys("right"), key.WithHelp("→", "columns right")), false, 130},
		{KeyChoicePrevious, key.NewBinding(key.WithKeys("left"), key.WithHelp("←", "previous choice")), false, 131},
		{KeyChoiceNext, key.NewBinding(key.WithKeys("right"), key.WithHelp("→", "next choice")), false, 132},
		{KeyDismissAlert, key.NewBinding(key.WithKeys("ctrl+x"), key.WithHelp("ctrl+x", "dismiss alert")), true, 140},
		{KeyHistoryPrevious, key.NewBinding(key.WithKeys("up"), key.WithHelp("↑", "previous history")), false, 150},
		{KeyHistoryNext, key.NewBinding(key.WithKeys("down"), key.WithHelp("↓", "next history")), false, 160},
		{KeyToggleAutoscroll, key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "toggle autoscroll")), false, 170},
		{KeyAlertDetails, key.NewBinding(key.WithKeys("!"), key.WithHelp("!", "alert details")), true, 180},
		{KeySortNext, key.NewBinding(key.WithKeys("o"), key.WithHelp("o", "next sort")), false, 190},
		{KeySortDirection, key.NewBinding(key.WithKeys("O"), key.WithHelp("O", "reverse sort")), false, 200},
	}
	registry := KeyRegistry{bindings: make(map[BindingID]BindingSpec, len(specs))}
	for _, spec := range specs {
		registry.bindings[spec.ID] = spec
	}
	return registry
}

func (registry KeyRegistry) Matches(message tea.KeyMsg, id BindingID) bool {
	spec, present := registry.bindings[id]
	return present && key.Matches(message, spec.Binding)
}

func (registry KeyRegistry) Hints(ids ...BindingID) string {
	parts := make([]string, 0, len(ids))
	seen := make(map[BindingID]bool)
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if spec, present := registry.bindings[id]; present {
			help := spec.Binding.Help()
			if help.Key != "" && help.Desc != "" {
				parts = append(parts, fmt.Sprintf("[%s] %s", help.Key, help.Desc))
			}
		}
	}
	return strings.Join(parts, "  ")
}

func (registry KeyRegistry) Help(ids ...BindingID) string {
	if len(ids) == 0 {
		for id := range registry.bindings {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return registry.bindings[ids[i]].Order < registry.bindings[ids[j]].Order })
	}
	return registry.Hints(ids...)
}

func (registry KeyRegistry) ColumnHint() string {
	left := registry.bindings[KeyColumnsLeft].Binding.Help().Key
	right := registry.bindings[KeyColumnsRight].Binding.Help().Key
	return fmt.Sprintf("[%s/%s] columns", left, right)
}

func (registry KeyRegistry) Reserved(keyName string) bool {
	keyName = bubbleKeyName(keyName)
	for _, spec := range registry.bindings {
		for _, candidate := range spec.Binding.Keys() {
			if bubbleKeyName(candidate) == keyName {
				return true
			}
		}
	}
	return false
}

func (registry KeyRegistry) ActionMatches(message tea.KeyMsg, operation Operation) bool {
	return operation.Presentation.Hotkey != "" && message.String() == bubbleKeyName(operation.Presentation.Hotkey)
}

func bubbleKeyName(keyName string) string {
	if strings.HasPrefix(keyName, "ctrl-") {
		return "ctrl+" + strings.TrimPrefix(keyName, "ctrl-")
	}
	return keyName
}

func (registry KeyRegistry) ActionHints(actions []LocalAction) string {
	parts := make([]string, 0, len(actions))
	for _, action := range actions {
		if action.Hotkey != "" {
			parts = append(parts, fmt.Sprintf("[%s] %s", SanitizeCell(action.Hotkey), SanitizeCell(action.Label)))
		}
	}
	return strings.Join(parts, "  ")
}
