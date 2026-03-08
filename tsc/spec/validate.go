package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// IRSpec is the top-level parsed representation of an app.tsc.yaml file.
// All fields map 1:1 to the JSON Schema.
type IRSpec struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind"       json:"kind"`
	Metadata   IRMetadata        `yaml:"metadata"   json:"metadata"`
	Components map[string]string `yaml:"components" json:"components"`
	Resources  []IRResource      `yaml:"resources"  json:"resources"`
	API        *IRAPI            `yaml:"api"        json:"api,omitempty"`
	Auth       *IRAuth           `yaml:"auth"       json:"auth,omitempty"`
	Database   *IRDatabase       `yaml:"database"   json:"database,omitempty"`
	Observ     *IRObservability  `yaml:"observability" json:"observability,omitempty"`
}

// IRMetadata holds application identity fields.
type IRMetadata struct {
	Name        string `yaml:"name"        json:"name"`
	Version     string `yaml:"version"     json:"version"`
	Description string `yaml:"description" json:"description,omitempty"`
}

// IRResource describes a data resource in the spec.
type IRResource struct {
	Name       string      `yaml:"name"       json:"name"`
	Plural     string      `yaml:"plural"     json:"plural"`
	Fields     []IRField   `yaml:"fields"     json:"fields"`
	Operations []string    `yaml:"operations" json:"operations"`
	Events     bool        `yaml:"events"     json:"events"`
}

// IRField is a single field within a resource.
type IRField struct {
	Name       string `yaml:"name"        json:"name"`
	Type       string `yaml:"type"        json:"type"`
	Required   bool   `yaml:"required"    json:"required"`
	MaxLength  int    `yaml:"max_length"  json:"max_length,omitempty"`
	Auto       string `yaml:"auto"        json:"auto,omitempty"`
	SoftDelete bool   `yaml:"soft_delete" json:"soft_delete,omitempty"`
}

// IRAPI holds REST and gRPC API configuration.
type IRAPI struct {
	REST *IRRESTConfig `yaml:"rest" json:"rest,omitempty"`
	GRPC *IRGRPCConfig `yaml:"grpc" json:"grpc,omitempty"`
}

// IRRESTConfig holds REST-specific options.
type IRRESTConfig struct {
	BasePath      string `yaml:"base_path"      json:"base_path"`
	VersionHeader bool   `yaml:"version_header" json:"version_header"`
}

// IRGRPCConfig holds gRPC-specific options.
type IRGRPCConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	Port    int  `yaml:"port"    json:"port"`
}

// IRAuth holds authentication configuration.
type IRAuth struct {
	Type      string `yaml:"type"       json:"type"`
	JWKURL    string `yaml:"jwk_url"    json:"jwk_url,omitempty"`
	Required  bool   `yaml:"required"   json:"required"`
	AllowMock string `yaml:"allow_mock" json:"allow_mock,omitempty"`
}

// IRDatabase holds database configuration.
type IRDatabase struct {
	Type       string `yaml:"type"       json:"type"`
	Migrations string `yaml:"migrations" json:"migrations"`
}

// IRObservability holds health check and metrics config.
type IRObservability struct {
	HealthCheck *IRHealthCheck `yaml:"health_check" json:"health_check,omitempty"`
	Metrics     *IRMetrics     `yaml:"metrics"      json:"metrics,omitempty"`
}

// IRHealthCheck holds health check endpoint configuration.
type IRHealthCheck struct {
	Port int    `yaml:"port" json:"port"`
	Path string `yaml:"path" json:"path"`
}

// IRMetrics holds Prometheus metrics endpoint configuration.
type IRMetrics struct {
	Port int    `yaml:"port" json:"port"`
	Path string `yaml:"path" json:"path"`
}

var (
	validComponents = map[string]bool{
		"tsc-http":     true,
		"tsc-postgres": true,
		"tsc-auth-jwt": true,
		"tsc-grpc":     true,
		"tsc-health":   true,
		"tsc-metrics":  true,
		"tsc-events":   true,
	}
	validFieldTypes = map[string]bool{
		"string": true, "int": true, "float": true,
		"bool": true, "timestamp": true, "uuid": true,
	}
	validOperations = map[string]bool{
		"create": true, "read": true, "update": true, "delete": true, "list": true,
	}
	reKebab   = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	rePascal  = regexp.MustCompile(`^[A-Z][a-zA-Z0-9]*$`)
	reSnake   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	reSemver  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	reAppVer  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

// Validate performs semantic validation of a parsed IRSpec.
// It is called by the compiler after YAML/JSON parsing.
// Returns a list of all validation errors (never nil on success).
func Validate(spec *IRSpec) []error {
	var errs []error

	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if spec.APIVersion != "tsc/v1" {
		add("apiVersion must be 'tsc/v1', got %q", spec.APIVersion)
	}
	if spec.Kind != "Application" {
		add("kind must be 'Application', got %q", spec.Kind)
	}

	// Metadata
	if !reKebab.MatchString(spec.Metadata.Name) {
		add("metadata.name must be kebab-case, got %q", spec.Metadata.Name)
	}
	if !reAppVer.MatchString(spec.Metadata.Version) {
		add("metadata.version must be semver (e.g. 1.0.0), got %q", spec.Metadata.Version)
	}

	// Components (SBOM)
	if len(spec.Components) == 0 {
		add("components block must list at least one component")
	}
	for name, ver := range spec.Components {
		if !validComponents[name] {
			add("unknown component %q — not in registry", name)
		}
		if !reSemver.MatchString(ver) {
			add("component %q version must be semver (e.g. v1.0.0), got %q", name, ver)
		}
	}

	// Resources
	resourceNames := map[string]bool{}
	for i, r := range spec.Resources {
		prefix := fmt.Sprintf("resources[%d](%s)", i, r.Name)
		if !rePascal.MatchString(r.Name) {
			add("%s: name must be PascalCase", prefix)
		}
		if !reKebab.MatchString(r.Plural) {
			add("%s: plural must be lowercase-kebab", prefix)
		}
		if resourceNames[r.Name] {
			add("%s: duplicate resource name", prefix)
		}
		resourceNames[r.Name] = true

		if len(r.Fields) == 0 {
			add("%s: must have at least one field", prefix)
		}
		fieldNames := map[string]bool{}
		softDeleteCount := 0
		for j, f := range r.Fields {
			fp := fmt.Sprintf("%s.fields[%d](%s)", prefix, j, f.Name)
			if !reSnake.MatchString(f.Name) {
				add("%s: name must be snake_case", fp)
			}
			if fieldNames[f.Name] {
				add("%s: duplicate field name", fp)
			}
			fieldNames[f.Name] = true
			if !validFieldTypes[f.Type] {
				add("%s: unknown type %q", fp, f.Type)
			}
			if f.MaxLength != 0 && f.Type != "string" {
				add("%s: max_length only applies to string fields", fp)
			}
			if f.Auto != "" && f.Auto != "created" && f.Auto != "updated" {
				add("%s: auto must be 'created' or 'updated'", fp)
			}
			if f.SoftDelete {
				softDeleteCount++
				if f.Type != "timestamp" {
					add("%s: soft_delete field must have type 'timestamp'", fp)
				}
			}
		}
		if softDeleteCount > 1 {
			add("%s: at most one soft_delete field is allowed", prefix)
		}

		if len(r.Operations) == 0 {
			add("%s: must list at least one operation", prefix)
		}
		seen := map[string]bool{}
		for _, op := range r.Operations {
			if !validOperations[op] {
				add("%s: unknown operation %q", prefix, op)
			}
			if seen[op] {
				add("%s: duplicate operation %q", prefix, op)
			}
			seen[op] = true
		}

		// events requires tsc-events component
		if r.Events && spec.Components["tsc-events"] == "" {
			add("%s: events:true requires tsc-events in components", prefix)
		}
	}

	// Auth cross-checks
	if spec.Auth != nil && spec.Auth.Type == "jwt" {
		if spec.Auth.JWKURL == "" {
			add("auth.jwk_url is required when auth.type is 'jwt'")
		}
		if spec.Components["tsc-auth-jwt"] == "" {
			add("auth.type=jwt requires tsc-auth-jwt in components")
		}
	}

	// gRPC cross-checks
	if spec.API != nil && spec.API.GRPC != nil && spec.API.GRPC.Enabled {
		if spec.Components["tsc-grpc"] == "" {
			add("api.grpc.enabled=true requires tsc-grpc in components")
		}
	}

	// Database cross-checks
	if spec.Database != nil {
		if spec.Components["tsc-postgres"] == "" {
			add("database block requires tsc-postgres in components")
		}
	}
	if len(spec.Resources) > 0 && spec.Database == nil {
		add("resources declared but no database block — add a database block")
	}

	return errs
}

// ToResourceDefinitions converts IRResource slice into spec.ResourceDefinition
// slice for use by the Application runtime.
func ToResourceDefinitions(resources []IRResource) []ResourceDefinition {
	out := make([]ResourceDefinition, len(resources))
	for i, r := range resources {
		fields := make([]FieldDefinition, len(r.Fields))
		for j, f := range r.Fields {
			fields[j] = FieldDefinition{
				Name:       f.Name,
				Type:       f.Type,
				Required:   f.Required,
				MaxLength:  f.MaxLength,
				Auto:       f.Auto,
				SoftDelete: f.SoftDelete,
			}
		}
		out[i] = ResourceDefinition{
			Name:       r.Name,
			Plural:     r.Plural,
			Fields:     fields,
			Operations: r.Operations,
			Events:     r.Events,
		}
	}
	return out
}

// LoadSchemaJSON reads and returns the embedded schema.json bytes.
// path is normally the path to this package's schema.json.
func LoadSchemaJSON(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	// Sanity-check: must be valid JSON.
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("schema.json is not valid JSON: %w", err)
	}
	return data, nil
}
