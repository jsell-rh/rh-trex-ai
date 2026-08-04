package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPresentationPolicyHasOneOwner(t *testing.T) {
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string]string)
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		sources[filepath.Base(path)] = string(data)
	}
	if failures := presentationPolicyViolations(sources); len(failures) > 0 {
		t.Fatalf("presentation policy duplication:\n%s", strings.Join(failures, "\n"))
	}
}

func TestArchitectureGateRejectsSyntheticPageOwnedStyle(t *testing.T) {
	failures := presentationPolicyViolations(map[string]string{"bad_page.go": `package tui
import "github.com/charmbracelet/lipgloss"
func badPage() string { return lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render("bad") }
`})
	if len(failures) == 0 {
		t.Fatal("architecture gate accepted page-owned presentation policy")
	}
}

func presentationPolicyViolations(sources map[string]string) []string {
	var failures []string
	for name, source := range sources {
		if name != "theme.go" && (strings.Contains(source, "lipgloss.Color(") || strings.Contains(source, "lipgloss.NewStyle(")) {
			failures = append(failures, name+": raw style outside theme.go")
		}
		if name != "keys.go" && (strings.Contains(source, "key.NewBinding(") || strings.Contains(source, "key.WithKeys(")) {
			failures = append(failures, name+": key binding outside keys.go")
		}
		if name != "modal.go" && strings.Contains(source, "overlayBlock(") {
			failures = append(failures, name+": dialog positioning outside modal.go")
		}
		if name != "column_layout.go" && strings.Contains(source, "tableColumnMinimumWidth") {
			failures = append(failures, name+": column sizing policy outside column_layout.go")
		}
		if name != "alert.go" && (strings.Contains(source, "alertLifetime") || strings.Contains(source, "alertPriority(")) {
			failures = append(failures, name+": alert lifetime/priority outside alert.go")
		}
		if strings.HasSuffix(name, "page.go") && strings.Contains(source, "RoundedBorder") {
			failures = append(failures, name+": page owns outer chrome")
		}
	}
	return failures
}
