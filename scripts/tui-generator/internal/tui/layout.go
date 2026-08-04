package tui

import "github.com/charmbracelet/x/ansi"

// ShellLayout is the sole authority for terminal-space allocation. It is
// continuous: no width is treated as a different application mode.
type ShellLayout struct {
	Width, Height  int
	HeaderRows     int
	CommandRows    int
	PageRows       int
	BreadcrumbRows int
	HintRows       int
	AlertRows      int
	ContentWidth   int
	ContentHeight  int
	ShowMetadata   bool
	ShowHints      bool
}

func CalculateShellLayout(width, height int, commandActive bool, metadata, hints string) ShellLayout {
	result := ShellLayout{Width: max(0, width), Height: max(0, height)}
	remaining := result.Height
	reserve := func(target *int) {
		if remaining > 0 {
			*target = 1
			remaining--
		}
	}
	reserve(&result.AlertRows)
	reserve(&result.HeaderRows)
	reserve(&result.BreadcrumbRows)
	if commandActive {
		reserve(&result.CommandRows)
	}
	result.ShowHints = hints != "" && result.Width > 0 && ansi.StringWidth(hints) <= result.Width && remaining > 1
	if result.ShowHints {
		reserve(&result.HintRows)
	}
	result.PageRows = max(0, remaining)
	result.ContentWidth = max(0, result.Width-2)
	result.ContentHeight = max(0, result.PageRows-2)
	result.ShowMetadata = metadata != "" && result.Width > 0 && ansi.StringWidth(metadata) < result.Width
	return result
}
