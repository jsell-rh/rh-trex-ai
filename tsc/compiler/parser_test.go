package compiler

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testDataDir returns the absolute path to the tsc module root so tests can
// locate spec files and examples regardless of how "go test" is invoked.
func testDataDir() string {
	_, file, _, _ := runtime.Caller(0)
	// file is .../tsc/compiler/parser_test.go
	// module root is three levels up: tsc/compiler → tsc → module root
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func schemaPathForTest() string {
	return filepath.Join(testDataDir(), "tsc", "spec", "schema.json")
}

func goldenSpecPath() string {
	return filepath.Join(testDataDir(), "tsc", "examples", "dinosaur-registry", "app.tsc.yaml")
}

// writeTempSpec writes YAML content to a temp file and returns the path.
// The file is removed when the test finishes.
func writeTempSpec(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "spec-*.yaml")
	if err != nil {
		t.Fatalf("creating temp spec: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp spec: %v", err)
	}
	f.Close()
	return f.Name()
}

// --- Golden-path test ---

func TestParse_ValidSpec(t *testing.T) {
	ir, err := ParseWithSchema(goldenSpecPath(), schemaPathForTest())
	if err != nil {
		t.Fatalf("expected valid spec to parse without error, got: %v", err)
	}

	if ir.Metadata.Name != "dinosaur-registry" {
		t.Errorf("metadata.name: want %q, got %q", "dinosaur-registry", ir.Metadata.Name)
	}
	if ir.Metadata.Version != "1.0.0" {
		t.Errorf("metadata.version: want %q, got %q", "1.0.0", ir.Metadata.Version)
	}
	if _, ok := ir.Components["tsc-http"]; !ok {
		t.Error("expected tsc-http in components")
	}
	if len(ir.Resources) == 0 {
		t.Error("expected at least one resource")
	}
}

// --- Missing required fields ---

func TestParse_MissingAPIVersion(t *testing.T) {
	spec := writeTempSpec(t, `
kind: Application
metadata:
  name: test-app
  version: 1.0.0
components:
  tsc-http: v1.0.0
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for missing apiVersion, got nil")
	}
	if !strings.Contains(err.Error(), "apiVersion") {
		t.Errorf("expected error to mention 'apiVersion', got: %v", err)
	}
}

func TestParse_MissingKind(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
metadata:
  name: test-app
  version: 1.0.0
components:
  tsc-http: v1.0.0
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for missing kind, got nil")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Errorf("expected error to mention 'kind', got: %v", err)
	}
}

func TestParse_MissingMetadata(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Application
components:
  tsc-http: v1.0.0
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for missing metadata, got nil")
	}
	if !strings.Contains(err.Error(), "metadata") {
		t.Errorf("expected error to mention 'metadata', got: %v", err)
	}
}

func TestParse_MissingMetadataName(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Application
metadata:
  version: 1.0.0
components:
  tsc-http: v1.0.0
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for missing metadata.name, got nil")
	}
}

func TestParse_MissingComponents(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Application
metadata:
  name: test-app
  version: 1.0.0
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for missing components, got nil")
	}
	if !strings.Contains(err.Error(), "components") {
		t.Errorf("expected error to mention 'components', got: %v", err)
	}
}

// --- Unknown component names ---

func TestParse_UnknownComponent(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Application
metadata:
  name: test-app
  version: 1.0.0
components:
  tsc-http: v1.0.0
  tsc-unknown-gadget: v1.0.0
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for unknown component name, got nil")
	}
	if !strings.Contains(err.Error(), "tsc-unknown-gadget") {
		t.Errorf("expected error to mention the unknown component name, got: %v", err)
	}
}

func TestParse_AllKnownComponents(t *testing.T) {
	// All seven known components should be accepted.
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Application
metadata:
  name: full-stack
  version: 1.0.0
components:
  tsc-http:     v1.0.0
  tsc-postgres: v1.0.0
  tsc-auth-jwt: v1.0.0
  tsc-grpc:     v1.0.0
  tsc-health:   v1.0.0
  tsc-metrics:  v1.0.0
  tsc-events:   v1.0.0
database:
  type: postgres
  migrations: auto
resources:
  - name: Widget
    plural: widgets
    fields:
      - name: id
        type: uuid
    operations: [create, read]
    events: true
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err != nil {
		t.Fatalf("expected all known components to be accepted, got: %v", err)
	}
}

// --- Invalid field types ---

func TestParse_InvalidFieldType(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Application
metadata:
  name: test-app
  version: 1.0.0
components:
  tsc-http:     v1.0.0
  tsc-postgres: v1.0.0
database:
  type: postgres
  migrations: auto
resources:
  - name: Widget
    plural: widgets
    fields:
      - name: price
        type: decimal
    operations: [create]
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for invalid field type 'decimal', got nil")
	}
	if !strings.Contains(err.Error(), "decimal") {
		t.Errorf("expected error to mention the invalid type, got: %v", err)
	}
}

func TestParse_ValidFieldTypes(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Application
metadata:
  name: type-test
  version: 1.0.0
components:
  tsc-http:     v1.0.0
  tsc-postgres: v1.0.0
database:
  type: postgres
  migrations: auto
resources:
  - name: Record
    plural: records
    fields:
      - name: label
        type: string
      - name: count
        type: int
      - name: ratio
        type: float
      - name: active
        type: bool
      - name: created_at
        type: timestamp
      - name: ref_id
        type: uuid
    operations: [create, read]
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err != nil {
		t.Fatalf("expected all valid field types to be accepted, got: %v", err)
	}
}

// --- Wrong const values ---

func TestParse_WrongAPIVersion(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v2
kind: Application
metadata:
  name: test-app
  version: 1.0.0
components:
  tsc-http: v1.0.0
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for wrong apiVersion, got nil")
	}
}

func TestParse_WrongKind(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Service
metadata:
  name: test-app
  version: 1.0.0
components:
  tsc-http: v1.0.0
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for wrong kind, got nil")
	}
}

// --- Invalid name patterns ---

func TestParse_InvalidMetadataName(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Application
metadata:
  name: MyApp
  version: 1.0.0
components:
  tsc-http: v1.0.0
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for PascalCase metadata.name (must be kebab-case), got nil")
	}
}

func TestParse_InvalidComponentVersion(t *testing.T) {
	spec := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Application
metadata:
  name: test-app
  version: 1.0.0
components:
  tsc-http: 1.0.0
`)
	_, err := ParseWithSchema(spec, schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for component version without 'v' prefix, got nil")
	}
}

// --- Schema path skip ---

func TestParseWithSchema_EmptySchemaPath_SkipsSchemaValidation(t *testing.T) {
	// Without schema validation, a spec that would fail schema checks
	// but passes semantic validate (or fails only on semantics) should
	// only produce semantic errors — not schema errors.
	// Use a completely minimal valid spec to confirm skip works.
	specPath := writeTempSpec(t, `
apiVersion: tsc/v1
kind: Application
metadata:
  name: minimal-app
  version: 1.0.0
components:
  tsc-http: v1.0.0
`)
	// Empty schemaPath skips schema validation.
	_, err := ParseWithSchema(specPath, "")
	// This spec is semantically valid too (no resources, no DB required).
	if err != nil {
		t.Fatalf("expected no error with schema validation skipped, got: %v", err)
	}
}

// --- File not found ---

func TestParse_FileNotFound(t *testing.T) {
	_, err := ParseWithSchema("/nonexistent/path/app.tsc.yaml", schemaPathForTest())
	if err == nil {
		t.Fatal("expected error for missing spec file, got nil")
	}
}
