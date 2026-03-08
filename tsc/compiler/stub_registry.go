package compiler

import "fmt"

// knownComponents is the development stub registry.
// These module paths and versions match the architecture plan.
// In production, these entries are signed and come from the trusted catalog.
var knownComponents = map[string]*RegistryEntry{
	"tsc-http": {
		Name:      "tsc-http",
		Version:   "v1.0.0",
		Module:    "github.com/openshift-online/rh-trex-ai/tsc/components/http",
		AuditHash: "stub-not-verified",
	},
	"tsc-postgres": {
		Name:      "tsc-postgres",
		Version:   "v1.0.0",
		Module:    "github.com/openshift-online/rh-trex-ai/tsc/components/postgres",
		AuditHash: "stub-not-verified",
	},
	"tsc-auth-jwt": {
		Name:      "tsc-auth-jwt",
		Version:   "v1.0.0",
		Module:    "github.com/openshift-online/rh-trex-ai/tsc/components/auth/jwt",
		AuditHash: "stub-not-verified",
	},
	"tsc-grpc": {
		Name:      "tsc-grpc",
		Version:   "v1.0.0",
		Module:    "github.com/openshift-online/rh-trex-ai/tsc/components/grpc",
		AuditHash: "stub-not-verified",
	},
	"tsc-health": {
		Name:      "tsc-health",
		Version:   "v1.0.0",
		Module:    "github.com/openshift-online/rh-trex-ai/tsc/components/health",
		AuditHash: "stub-not-verified",
	},
	"tsc-metrics": {
		Name:      "tsc-metrics",
		Version:   "v1.0.0",
		Module:    "github.com/openshift-online/rh-trex-ai/tsc/components/metrics",
		AuditHash: "stub-not-verified",
	},
	"tsc-events": {
		Name:      "tsc-events",
		Version:   "v1.0.0",
		Module:    "github.com/openshift-online/rh-trex-ai/tsc/components/events",
		AuditHash: "stub-not-verified",
	},
}

// StubRegistry is an in-memory registry for development and testing.
// It supports all components defined in the architecture plan.
// Audit hash verification is skipped (hashes are placeholder values).
type StubRegistry struct{}

// NewStubRegistry creates a development stub registry.
func NewStubRegistry() *StubRegistry {
	return &StubRegistry{}
}

// Lookup returns the stub registry entry for a component.
func (s *StubRegistry) Lookup(name, version string) (*RegistryEntry, error) {
	entry, ok := knownComponents[name]
	if !ok {
		return nil, fmt.Errorf("unknown component %q — not in stub registry (known: tsc-http, tsc-postgres, tsc-auth-jwt, tsc-grpc, tsc-health, tsc-metrics, tsc-events)", name)
	}
	if entry.Version != version {
		return nil, fmt.Errorf("component %q: requested version %q but stub registry only has %q", name, version, entry.Version)
	}
	return entry, nil
}
