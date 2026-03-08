package compiler_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openshift-online/rh-trex-ai/tsc/compiler"
)

// TestE2E_DinosaurRegistry is the end-to-end integration test for the TSC compiler.
// It compiles the canonical dinosaur-registry example spec and verifies that:
//  1. Compilation succeeds without errors
//  2. The output directory contains main.go, go.mod, and migrations/
//  3. The generated main.go imports spec.NewApplication and all component packages
//  4. The generated SQL migration has the correct table structure
//  5. gofmt reports no formatting issues in generated main.go
func TestE2E_DinosaurRegistry(t *testing.T) {
	specPath := filepath.Join("..", "examples", "dinosaur-registry", "app.tsc.yaml")
	if _, err := os.Stat(specPath); os.IsNotExist(err) {
		t.Skipf("example spec not found at %s — run from tsc-compiler worktree", specPath)
	}

	outDir := t.TempDir()

	c := compiler.New(compiler.NewStubRegistry(), "")
	if err := c.Compile(specPath, outDir); err != nil {
		t.Fatalf("Compile() failed: %v", err)
	}

	// Assert: main.go exists and contains expected structure
	mainGoPath := filepath.Join(outDir, "main.go")
	mainGo, err := os.ReadFile(mainGoPath)
	if err != nil {
		t.Fatalf("main.go not generated: %v", err)
	}
	mainGoStr := string(mainGo)

	for _, want := range []string{
		"spec.NewApplication(",
		"app.AddComponent(",
		"app.Configure(",
		"app.Register(",
		"app.Run(",
		"tsc/spec",
		"DO NOT EDIT",
		"dinosaur-registry",
	} {
		if !strings.Contains(mainGoStr, want) {
			t.Errorf("main.go missing expected content: %q", want)
		}
	}

	// Assert: tsc-postgres AddComponent call appears before tsc-http (dependency order).
	// Search only in the AddComponent block, not the import block.
	addComponentSection := mainGoStr[strings.Index(mainGoStr, "app.AddComponent("):]
	postgresAddIdx := strings.Index(addComponentSection, "tscpostgres")
	httpAddIdx := strings.Index(addComponentSection, "tschttp")
	if postgresAddIdx < 0 {
		t.Error("main.go missing tsc-postgres AddComponent call")
	}
	if httpAddIdx < 0 {
		t.Error("main.go missing tsc-http AddComponent call")
	}
	if postgresAddIdx > 0 && httpAddIdx > 0 && postgresAddIdx > httpAddIdx {
		t.Error("tsc-postgres must be added before tsc-http (dependency order: postgres sets DB, others need DB)")
	}

	// Assert: go.mod exists
	goModPath := filepath.Join(outDir, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		t.Fatalf("go.mod not generated: %v", err)
	}

	// Assert: migrations/ directory with at least one .sql file
	migrDir := filepath.Join(outDir, "migrations")
	entries, err := os.ReadDir(migrDir)
	if err != nil {
		t.Fatalf("migrations/ not generated: %v", err)
	}
	var sqlFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			sqlFiles = append(sqlFiles, e.Name())
		}
	}
	if len(sqlFiles) == 0 {
		t.Fatal("migrations/ contains no .sql files")
	}

	// Assert: migration SQL has correct structure
	sqlPath := filepath.Join(migrDir, sqlFiles[0])
	sqlBytes, err := os.ReadFile(sqlPath)
	if err != nil {
		t.Fatalf("reading migration %s: %v", sqlFiles[0], err)
	}
	sqlStr := string(sqlBytes)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS",
		"dinosaurs",
		"VARCHAR(255)",  // species field with max_length: 255
		"PRIMARY KEY",
		"deleted_at",
	} {
		if !strings.Contains(sqlStr, want) {
			t.Errorf("migration SQL missing expected content: %q\nSQL:\n%s", want, sqlStr)
		}
	}

	// Assert: generated main.go is gofmt-clean
	if gofmt, err := exec.LookPath("gofmt"); err == nil {
		cmd := exec.Command(gofmt, "-l", mainGoPath)
		out, _ := cmd.Output()
		if len(strings.TrimSpace(string(out))) > 0 {
			t.Errorf("generated main.go is not gofmt-clean: %s", out)
		}
	}
}
