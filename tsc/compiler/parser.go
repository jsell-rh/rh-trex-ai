package compiler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ghodss/yaml"
	goyaml "gopkg.in/yaml.v3"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

// defaultSchemaPath returns the path to tsc/spec/schema.json resolved relative
// to this source file so it works regardless of working directory.
func defaultSchemaPath() string {
	_, file, _, _ := runtime.Caller(0)
	// file is .../tsc/compiler/parser.go; schema is .../tsc/spec/schema.json
	return filepath.Join(filepath.Dir(file), "..", "spec", "schema.json")
}

// Parse reads, parses, and validates an IR spec file (app.tsc.yaml).
// Validation runs in two passes:
//  1. JSON Schema structural validation against tsc/spec/schema.json
//  2. Semantic validation via spec.Validate (cross-field rules, registry checks)
func Parse(path string) (*spec.IRSpec, error) {
	return ParseWithSchema(path, defaultSchemaPath())
}

// ParseWithSchema is like Parse but lets the caller specify the schema.json path.
// Pass an empty schemaPath to skip JSON Schema validation.
func ParseWithSchema(path, schemaPath string) (*spec.IRSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading spec file: %w", err)
	}

	// Pass 1: JSON Schema structural validation.
	if schemaPath != "" {
		if errs := validateAgainstSchema(data, schemaPath); len(errs) > 0 {
			msgs := make([]string, len(errs))
			for i, e := range errs {
				msgs[i] = e.Error()
			}
			return nil, fmt.Errorf("JSON schema validation failed:\n  - %s", strings.Join(msgs, "\n  - "))
		}
	}

	// Pass 2: Unmarshal YAML into typed struct.
	var ir spec.IRSpec
	if err := goyaml.Unmarshal(data, &ir); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Pass 3: Semantic validation (cross-field rules).
	if errs := spec.Validate(&ir); len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		return nil, fmt.Errorf("spec validation failed:\n  - %s", strings.Join(msgs, "\n  - "))
	}

	return &ir, nil
}

// validateAgainstSchema converts yamlData to JSON and validates it against the
// JSON Schema at schemaPath. Returns all validation errors.
func validateAgainstSchema(yamlData []byte, schemaPath string) []error {
	// Convert YAML → JSON (ghodss/yaml preserves field names correctly).
	jsonBytes, err := yaml.YAMLToJSON(yamlData)
	if err != nil {
		return []error{fmt.Errorf("converting YAML to JSON: %w", err)}
	}

	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		return []error{fmt.Errorf("reading schema file %q: %w", schemaPath, err)}
	}

	sv, err := newSchemaValidator(schemaBytes)
	if err != nil {
		return []error{fmt.Errorf("loading schema: %w", err)}
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return []error{fmt.Errorf("parsing JSON document: %w", err)}
	}

	return sv.Validate(doc)
}
