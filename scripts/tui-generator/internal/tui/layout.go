package tui

import "github.com/charmbracelet/x/ansi"

// ShellLayout is the sole authority for terminal-space allocation. It is
// continuous: no width is treated as a different application mode.
type ShellLayout struct {
	Width, Height   int
	HeaderRows      int
	CommandRows     int
	PageRows        int
	BreadcrumbRows  int
	AlertRows       int
	ContentWidth    int
	ContentHeight   int
	ShowMetadata    bool
	ShortcutPalette ShortcutPalette
}

func CalculateShellLayout(width, height int, commandActive bool, metadata string, shortcuts []ShortcutHint) ShellLayout {
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
	shortcutRows := min(maxShortcutRows, max(0, remaining-1))
	result.ShortcutPalette = LayoutShortcutPalette(shortcuts, result.Width, shortcutRows)
	if result.HeaderRows > 0 {
		result.HeaderRows += result.ShortcutPalette.Rows()
		remaining -= result.ShortcutPalette.Rows()
	}
	result.PageRows = max(0, remaining)
	result.ContentWidth = max(0, result.Width-2)
	result.ContentHeight = max(0, result.PageRows-2)
	result.ShowMetadata = metadata != "" && result.Width > 0 && ansi.StringWidth(metadata) < result.Width
	return result
}
