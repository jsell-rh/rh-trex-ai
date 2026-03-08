package postgres

import (
	"testing"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

func TestComponentMetadata(t *testing.T) {
	c := New()
	if c.Name() != componentName {
		t.Errorf("Name() = %q, want %q", c.Name(), componentName)
	}
	if c.Version() != componentVersion {
		t.Errorf("Version() = %q, want %q", c.Version(), componentVersion)
	}
	if c.AuditHash() == "" {
		t.Error("AuditHash() must not be empty")
	}
}

func TestConfigure(t *testing.T) {
	c := New()
	cfg := spec.ComponentConfig{
		"dsn":            "host=localhost dbname=test",
		"max_open_conns": 10,
	}
	if err := c.Configure(cfg); err != nil {
		t.Fatalf("Configure() error: %v", err)
	}
	if c.cfg.DSN != "host=localhost dbname=test" {
		t.Errorf("DSN = %q, want %q", c.cfg.DSN, "host=localhost dbname=test")
	}
	if c.cfg.MaxOpenConns != 10 {
		t.Errorf("MaxOpenConns = %d, want 10", c.cfg.MaxOpenConns)
	}
}

func TestConfigureDefaults(t *testing.T) {
	c := New()
	if err := c.Configure(spec.ComponentConfig{}); err != nil {
		t.Fatalf("Configure() error: %v", err)
	}
	if c.cfg.MaxOpenConns != 25 {
		t.Errorf("default MaxOpenConns = %d, want 25", c.cfg.MaxOpenConns)
	}
	if c.cfg.MaxIdleConns != 5 {
		t.Errorf("default MaxIdleConns = %d, want 5", c.cfg.MaxIdleConns)
	}
}

func TestGenerateMigrationSQL(t *testing.T) {
	resources := []spec.ResourceDefinition{
		{
			Name:   "Dinosaur",
			Plural: "dinosaurs",
			Fields: []spec.FieldDefinition{
				{Name: "species", Type: "string", Required: true, MaxLength: 255},
				{Name: "description", Type: "string"},
				{Name: "created_at", Type: "timestamp", Auto: "created"},
				{Name: "deleted_at", Type: "timestamp", SoftDelete: true},
			},
			Operations: []string{"create", "read", "update", "delete", "list"},
			Events:     true,
		},
	}

	sql := GenerateMigrationSQL(resources)
	if sql == "" {
		t.Fatal("GenerateMigrationSQL() returned empty string")
	}
	// Should contain table name and expected columns.
	for _, substr := range []string{"dinosaurs", "id UUID", "species VARCHAR(255)", "created_at TIMESTAMPTZ", "deleted_at TIMESTAMPTZ"} {
		if !contains(sql, substr) {
			t.Errorf("SQL missing %q\nSQL:\n%s", substr, sql)
		}
	}
}

func TestHasSoftDelete(t *testing.T) {
	dao := &resourceDAO{
		resource: spec.ResourceDefinition{
			Fields: []spec.FieldDefinition{
				{Name: "deleted_at", Type: "timestamp", SoftDelete: true},
			},
		},
	}
	if !dao.hasSoftDelete() {
		t.Error("hasSoftDelete() = false, want true")
	}

	dao2 := &resourceDAO{resource: spec.ResourceDefinition{}}
	if dao2.hasSoftDelete() {
		t.Error("hasSoftDelete() = true, want false for empty resource")
	}
}

func TestIRTypeToSQL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"string", "TEXT"},
		{"int", "BIGINT"},
		{"float", "DOUBLE PRECISION"},
		{"bool", "BOOLEAN"},
		{"timestamp", "TIMESTAMPTZ"},
		{"uuid", "UUID"},
		{"unknown", "TEXT"},
	}
	for _, tc := range cases {
		got := irTypeToSQL(tc.in)
		if got != tc.want {
			t.Errorf("irTypeToSQL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
