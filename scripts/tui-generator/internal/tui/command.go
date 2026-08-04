package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type CommandKind string

const (
	CommandResource CommandKind = "resource"
	CommandFilter   CommandKind = "filter"
)

// CommandBar owns the shared input, history, and completion surface.
type CommandBar struct {
	input        textinput.Model
	kind         CommandKind
	history      []string
	historyIndex int
}

func NewCommandBar() CommandBar {
	input := textinput.New()
	input.CharLimit = 256
	return CommandBar{input: input, historyIndex: -1}
}

func (bar *CommandBar) Begin(kind CommandKind, value string) tea.Cmd {
	bar.kind = kind
	bar.historyIndex = -1
	bar.input.CharLimit = 256
	bar.input.SetValue(value)
	bar.input.Focus()
	return textinput.Blink
}

func (bar *CommandBar) Close()                    { bar.input.Blur() }
func (bar *CommandBar) Value() string             { return bar.input.Value() }
func (bar *CommandBar) SetValue(value string)     { bar.input.SetValue(value) }
func (bar *CommandBar) View(prefix string) string { return prefix + " " + bar.input.View() }

func (bar *CommandBar) Remember(value string) {
	value = strings.TrimSpace(value)
	if value == "" || len(bar.history) > 0 && bar.history[len(bar.history)-1] == value {
		return
	}
	bar.history = append(bar.history, value)
	if len(bar.history) > 100 {
		bar.history = append([]string(nil), bar.history[len(bar.history)-100:]...)
	}
}

func (bar *CommandBar) MoveHistory(direction int) {
	if len(bar.history) == 0 {
		return
	}
	if bar.historyIndex < 0 {
		bar.historyIndex = len(bar.history)
	}
	bar.historyIndex = max(0, min(len(bar.history)-1, bar.historyIndex+direction))
	bar.input.SetValue(bar.history[bar.historyIndex])
	bar.input.CursorEnd()
}

func (bar *CommandBar) Update(message tea.Msg) tea.Cmd {
	var command tea.Cmd
	bar.input, command = bar.input.Update(message)
	return command
}
