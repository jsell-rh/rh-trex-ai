package components_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/openshift-online/rh-trex-ai/tsc/components"
	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

// fakeComponent is a minimal spec.Component for testing.
type fakeComponent struct {
	name      string
	version   string
	auditHash string
}

func (f *fakeComponent) Name() string                               { return f.name }
func (f *fakeComponent) Version() string                           { return f.version }
func (f *fakeComponent) AuditHash() string                         { return f.auditHash }
func (f *fakeComponent) Configure(_ spec.ComponentConfig) error    { return nil }
func (f *fakeComponent) Register(_ *spec.Application) error        { return nil }
func (f *fakeComponent) Start(_ context.Context) error             { return nil }
func (f *fakeComponent) Stop(_ context.Context) error              { return nil }

func newFake(name, version, hash string) *fakeComponent {
	return &fakeComponent{name: name, version: version, auditHash: hash}
}

const (
	httpName    = "tsc-http"
	httpVersion = "v1.0.0"
	httpHash    = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"

	pgName    = "tsc-postgres"
	pgVersion = "v1.0.0"
	pgHash    = "def456abc123def456abc123def456abc123def456abc123def456abc123deff"
)

func testCatalog() []components.AuditRecord {
	return []components.AuditRecord{
		{Name: httpName, Version: httpVersion, Hash: httpHash},
		{Name: pgName, Version: pgVersion, Hash: pgHash},
	}
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := components.New(testCatalog()...)

	http := newFake(httpName, httpVersion, httpHash)
	if err := reg.Register(http); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := reg.Get(httpName)
	if !ok {
		t.Fatal("Get: component not found after registration")
	}
	if got.Name() != httpName {
		t.Errorf("Get: got name %q, want %q", got.Name(), httpName)
	}
}

func TestRegistry_AuditHashMismatch(t *testing.T) {
	reg := components.New(testCatalog()...)

	bad := newFake(httpName, httpVersion, "wronghashwronghashwronghashwronghashwronghashwronghashwronghashww")
	err := reg.Register(bad)
	if err == nil {
		t.Fatal("Register: expected error for audit hash mismatch, got nil")
	}
}

func TestRegistry_UnknownComponent(t *testing.T) {
	reg := components.New(testCatalog()...)

	unknown := newFake("tsc-unknown", "v1.0.0", "somehash")
	err := reg.Register(unknown)
	if err == nil {
		t.Fatal("Register: expected error for unknown component, got nil")
	}
}

func TestRegistry_DuplicateRegistration(t *testing.T) {
	reg := components.New(testCatalog()...)

	http := newFake(httpName, httpVersion, httpHash)
	if err := reg.Register(http); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := reg.Register(http); err == nil {
		t.Fatal("second Register: expected error for duplicate, got nil")
	}
}

func TestRegistry_All_DeterministicOrder(t *testing.T) {
	reg := components.New(testCatalog()...)

	// Register in reverse alphabetical order.
	pg := newFake(pgName, pgVersion, pgHash)
	http := newFake(httpName, httpVersion, httpHash)
	if err := reg.Register(pg); err != nil {
		t.Fatalf("Register postgres: %v", err)
	}
	if err := reg.Register(http); err != nil {
		t.Fatalf("Register http: %v", err)
	}

	all := reg.All()
	if len(all) != 2 {
		t.Fatalf("All: got %d components, want 2", len(all))
	}
	// Should be alphabetical: tsc-http before tsc-postgres.
	if all[0].Name() != httpName {
		t.Errorf("All[0]: got %q, want %q", all[0].Name(), httpName)
	}
	if all[1].Name() != pgName {
		t.Errorf("All[1]: got %q, want %q", all[1].Name(), pgName)
	}
}

func TestRegistry_Len(t *testing.T) {
	reg := components.New(testCatalog()...)
	if reg.Len() != 0 {
		t.Errorf("Len: got %d, want 0", reg.Len())
	}
	if err := reg.Register(newFake(httpName, httpVersion, httpHash)); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Errorf("Len: got %d, want 1", reg.Len())
	}
}

func TestRegistry_GetMissing(t *testing.T) {
	reg := components.New(testCatalog()...)
	_, ok := reg.Get("tsc-missing")
	if ok {
		t.Error("Get: expected false for missing component, got true")
	}
}

func TestRegistry_MustRegister_Panics(t *testing.T) {
	reg := components.New(testCatalog()...)
	bad := newFake(httpName, httpVersion, "badhashbadhashbadhashbadhashbadhashbadhashbadhashbadhashbadhashb")
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustRegister: expected panic, got nil")
		}
	}()
	reg.MustRegister(bad)
}

func TestHashSourceDir(t *testing.T) {
	dir := t.TempDir()

	// Write two files.
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package b\n"), 0600); err != nil {
		t.Fatal(err)
	}

	h1, err := components.HashSourceDir(dir)
	if err != nil {
		t.Fatalf("HashSourceDir: %v", err)
	}
	if len(h1) != 64 {
		t.Errorf("HashSourceDir: got hash length %d, want 64", len(h1))
	}

	// Same dir hashes identically (deterministic).
	h2, err := components.HashSourceDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("HashSourceDir: not deterministic: %q != %q", h1, h2)
	}

	// Changing a file changes the hash.
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n// changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h3, err := components.HashSourceDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Error("HashSourceDir: hash did not change after file modification")
	}
}
