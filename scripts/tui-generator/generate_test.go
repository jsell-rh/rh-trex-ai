package main

import (
	"bytes"
	"crypto/sha256"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type treeEntry struct {
	Path   string
	Mode   fs.FileMode
	Digest [sha256.Size]byte
}

func TestDeterministicGeneratedTreeBuildsAndTests(t *testing.T) {
	first := filepath.Join(t.TempDir(), "generated")
	second := filepath.Join(t.TempDir(), "generated")
	options := generateOptions{SpecPath: "testdata/navigation.yaml", Module: "example.com/navigation-tui", Binary: "navigation-tui"}
	options.OutDir = first
	if err := generate(options); err != nil {
		t.Fatal(err)
	}
	options.OutDir = second
	if err := generate(options); err != nil {
		t.Fatal(err)
	}
	firstTree := snapshotTree(t, first)
	secondTree := snapshotTree(t, second)
	if !reflect.DeepEqual(firstTree, secondTree) {
		t.Fatalf("generated trees differ:\nfirst:  %#v\nsecond: %#v", firstTree, secondTree)
	}

	worktree, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range firstTree {
		data, err := os.ReadFile(filepath.Join(first, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(worktree)) {
			t.Fatalf("generated %s contains host path %s", entry.Path, worktree)
		}
		if strings.HasSuffix(entry.Path, ".go") && !bytes.HasPrefix(data, []byte("// Code generated")) {
			t.Fatalf("generated Go file %s lacks a stable notice", entry.Path)
		}
	}
	generatedMain, err := os.ReadFile(filepath.Join(first, "cmd", "navigation-tui", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(generatedMain, []byte(`flag.String("token"`)) || !bytes.Contains(generatedMain, []byte(`flag.String("token-file"`)) {
		t.Fatalf("generated credential flags are unsafe:\n%s", generatedMain)
	}
	if !bytes.Contains(generatedMain, []byte(`flag.Duration("refresh-interval", 5*time.Second`)) {
		t.Fatalf("generated runtime lacks the pinned refresh interval default:\n%s", generatedMain)
	}
	runGeneratedCommand(t, first, "go", "mod", "tidy", "-diff")
	runGeneratedCommand(t, first, "go", "mod", "verify")
	runGeneratedCommand(t, first, "go", "test", "./...")
	runGeneratedCommand(t, first, "go", "build", "./cmd/...")
}

func TestRepositoryOpenAPIGeneratesBuildableRuntime(t *testing.T) {
	output := filepath.Join(t.TempDir(), "repository-tui")
	if err := generate(generateOptions{
		SpecPath: filepath.Join("..", "..", "openapi", "openapi.yaml"),
		OutDir:   output, Module: "example.com/repository-tui", Binary: "trex-tui",
	}); err != nil {
		t.Fatal(err)
	}
	descriptor, err := os.ReadFile(filepath.Join(output, "internal", "tui", "descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, operationID := range []string{
		"listDinosaurs", "createDinosaur", "getDinosaur", "updateDinosaur", "deleteDinosaur",
		"listFossils", "createFossil", "getFossil", "updateFossil", "deleteFossil",
		"listScientists", "createScientist", "getScientist", "updateScientist", "deleteScientist",
	} {
		if !bytes.Contains(descriptor, []byte(`"`+operationID+`"`)) {
			t.Fatalf("repository descriptor omitted operation %s", operationID)
		}
	}
	runGeneratedCommand(t, output, "go", "mod", "tidy", "-diff")
	runGeneratedCommand(t, output, "go", "test", "./...")
	runGeneratedCommand(t, output, "go", "build", "./cmd/...")
}

func TestGenerationReplacesOutputWithoutTouchingSibling(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "generated")
	sibling := output + ".previous"
	if err := os.MkdirAll(output, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "stale"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, outputMarker), []byte(outputMarkerContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sibling, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := generate(generateOptions{
		SpecPath: "testdata/navigation.yaml", OutDir: output,
		Module: "example.com/navigation-tui", Binary: "navigation-tui",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(output, "stale")); !os.IsNotExist(err) {
		t.Fatalf("stale output remains after replacement: %v", err)
	}
	content, err := os.ReadFile(sibling)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "unrelated" {
		t.Fatalf("sibling changed during output replacement: %q", content)
	}
	matches, err := filepath.Glob(filepath.Join(parent, ".tui-backup-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary backups remain after generation: %v", matches)
	}
}

func TestGenerationRefusesToReplaceUnownedOutput(t *testing.T) {
	output := filepath.Join(t.TempDir(), "source-repository")
	if err := os.MkdirAll(output, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(output, "keep-me")
	if err := os.WriteFile(sentinel, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := generate(generateOptions{
		SpecPath: "testdata/navigation.yaml", OutDir: output,
		Module: "example.com/navigation-tui", Binary: "navigation-tui",
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to replace unowned output") {
		t.Fatalf("generation error = %v, want unowned-output refusal", err)
	}
	content, readErr := os.ReadFile(sentinel)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != "unrelated" {
		t.Fatalf("unowned output changed: %q", content)
	}
}

func TestGenerationRefusesSymbolicLinkOutput(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "owned-target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "keep-me")
	if err := os.WriteFile(sentinel, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parent, "generated")
	if err := os.Symlink(target, output); err != nil {
		t.Fatal(err)
	}
	err := generate(generateOptions{
		SpecPath: "testdata/navigation.yaml", OutDir: output,
		Module: "example.com/navigation-tui", Binary: "navigation-tui",
	})
	if err == nil || !strings.Contains(err.Error(), "symbolic-link output") {
		t.Fatalf("generation error = %v, want symbolic-link refusal", err)
	}
	if content, readErr := os.ReadFile(sentinel); readErr != nil || string(content) != "unrelated" {
		t.Fatalf("symbolic-link target changed: content=%q err=%v", content, readErr)
	}
	if info, statErr := os.Lstat(output); statErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("output symlink changed: info=%v err=%v", info, statErr)
	}
}

func snapshotTree(t *testing.T, root string) []treeEntry {
	t.Helper()
	var entries []treeEntry
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, treeEntry{Path: filepath.ToSlash(relative), Mode: info.Mode(), Digest: sha256.Sum256(data)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries
}

func runGeneratedCommand(t *testing.T, directory, name string, arguments ...string) string {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v in %s: %v\n%s", name, arguments, directory, err, output)
	}
	return string(output)
}
