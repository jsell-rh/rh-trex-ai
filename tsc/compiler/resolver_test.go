package compiler

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var allComponents = []struct {
	name    string
	version string
	module  string
}{
	{"tsc-http", "v1.0.0", "github.com/openshift-online/rh-trex-ai/tsc/components/http"},
	{"tsc-postgres", "v1.0.0", "github.com/openshift-online/rh-trex-ai/tsc/components/postgres"},
	{"tsc-auth-jwt", "v1.0.0", "github.com/openshift-online/rh-trex-ai/tsc/components/auth/jwt"},
	{"tsc-grpc", "v1.0.0", "github.com/openshift-online/rh-trex-ai/tsc/components/grpc"},
	{"tsc-health", "v1.0.0", "github.com/openshift-online/rh-trex-ai/tsc/components/health"},
	{"tsc-metrics", "v1.0.0", "github.com/openshift-online/rh-trex-ai/tsc/components/metrics"},
	{"tsc-events", "v1.0.0", "github.com/openshift-online/rh-trex-ai/tsc/components/events"},
}

func testdataRegistryDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(file), "testdata", "registry")
}

// --- StubRegistry tests ---

func TestStubRegistry_KnownComponents(t *testing.T) {
	reg := NewStubRegistry()
	for _, tc := range allComponents {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := reg.Lookup(tc.name, tc.version)
			if err != nil {
				t.Fatalf("Lookup(%q, %q) unexpected error: %v", tc.name, tc.version, err)
			}
			if entry.Name != tc.name {
				t.Errorf("entry.Name = %q, want %q", entry.Name, tc.name)
			}
			if entry.Version != tc.version {
				t.Errorf("entry.Version = %q, want %q", entry.Version, tc.version)
			}
			if entry.Module != tc.module {
				t.Errorf("entry.Module = %q, want %q", entry.Module, tc.module)
			}
		})
	}
}

func TestStubRegistry_UnknownComponent(t *testing.T) {
	reg := NewStubRegistry()
	_, err := reg.Lookup("tsc-unknown", "v1.0.0")
	if err == nil {
		t.Fatal("expected error for unknown component, got nil")
	}
	if !strings.Contains(err.Error(), "unknown component") {
		t.Errorf("error %q should mention 'unknown component'", err.Error())
	}
}

func TestStubRegistry_WrongVersion(t *testing.T) {
	reg := NewStubRegistry()
	_, err := reg.Lookup("tsc-http", "v9.9.9")
	if err == nil {
		t.Fatal("expected error for wrong version, got nil")
	}
	if !strings.Contains(err.Error(), "v9.9.9") {
		t.Errorf("error %q should mention the requested version", err.Error())
	}
}

// --- FileRegistry tests ---

func TestFileRegistry_KnownComponents(t *testing.T) {
	dir := testdataRegistryDir(t)
	reg := NewFileRegistry(dir)
	for _, tc := range allComponents {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := reg.Lookup(tc.name, tc.version)
			if err != nil {
				t.Fatalf("Lookup(%q, %q) unexpected error: %v", tc.name, tc.version, err)
			}
			if entry.Name != tc.name {
				t.Errorf("entry.Name = %q, want %q", entry.Name, tc.name)
			}
			if entry.Version != tc.version {
				t.Errorf("entry.Version = %q, want %q", entry.Version, tc.version)
			}
			if entry.Module != tc.module {
				t.Errorf("entry.Module = %q, want %q", entry.Module, tc.module)
			}
			if entry.AuditHash == "" {
				t.Error("entry.AuditHash should not be empty")
			}
		})
	}
}

func TestFileRegistry_UnknownComponent(t *testing.T) {
	dir := testdataRegistryDir(t)
	reg := NewFileRegistry(dir)
	_, err := reg.Lookup("tsc-unknown", "v1.0.0")
	if err == nil {
		t.Fatal("expected error for unknown component, got nil")
	}
	if !strings.Contains(err.Error(), "not found in registry") {
		t.Errorf("error %q should mention 'not found in registry'", err.Error())
	}
}

func TestFileRegistry_WrongVersion(t *testing.T) {
	dir := testdataRegistryDir(t)
	reg := NewFileRegistry(dir)
	_, err := reg.Lookup("tsc-http", "v9.9.9")
	if err == nil {
		t.Fatal("expected error for wrong version, got nil")
	}
	if !strings.Contains(err.Error(), "not found in registry") {
		t.Errorf("error %q should mention 'not found in registry'", err.Error())
	}
}

// --- parseRegistryEntry unit tests ---

func TestParseRegistryEntry_Valid(t *testing.T) {
	data := []byte(`
name: tsc-http
version: v1.0.0
module: github.com/openshift-online/tsc-components/http
audit_hash: abc123
`)
	entry, err := parseRegistryEntry(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.Name != "tsc-http" {
		t.Errorf("Name = %q, want %q", entry.Name, "tsc-http")
	}
	if entry.Module != "github.com/openshift-online/tsc-components/http" {
		t.Errorf("Module = %q, want %q", entry.Module, "github.com/openshift-online/tsc-components/http")
	}
	if entry.AuditHash != "abc123" {
		t.Errorf("AuditHash = %q, want %q", entry.AuditHash, "abc123")
	}
}

func TestParseRegistryEntry_MissingName(t *testing.T) {
	data := []byte(`
version: v1.0.0
module: github.com/openshift-online/tsc-components/http
audit_hash: abc123
`)
	_, err := parseRegistryEntry(data)
	if err == nil {
		t.Fatal("expected error for missing name field")
	}
}

func TestParseRegistryEntry_MissingVersion(t *testing.T) {
	data := []byte(`
name: tsc-http
module: github.com/openshift-online/tsc-components/http
audit_hash: abc123
`)
	_, err := parseRegistryEntry(data)
	if err == nil {
		t.Fatal("expected error for missing version field")
	}
}

func TestParseRegistryEntry_MissingModule(t *testing.T) {
	data := []byte(`
name: tsc-http
version: v1.0.0
audit_hash: abc123
`)
	_, err := parseRegistryEntry(data)
	if err == nil {
		t.Fatal("expected error for missing module field")
	}
}

func TestParseRegistryEntry_InvalidYAML(t *testing.T) {
	data := []byte(`{invalid yaml: [`)
	_, err := parseRegistryEntry(data)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}
