// Package spec defines the core interfaces and types for the TSC (Trusted Software
// Components) platform. All trusted components must implement these interfaces.
//
// IMPORTANT: This file is owned by TSC-Architect. Do not modify without CTO approval.
// Changes to interfaces here may break TSC-Library and TSC-Compiler implementations.
package spec

import (
	"context"
)

// Version is a semver string pinned in the TSC spec's components block.
type Version string

// ComponentName is the registry name of a trusted component (e.g., "tsc-http").
type ComponentName string

// AuditRecord describes the audit state of a component version.
type AuditRecord struct {
	// Date is the ISO-8601 date the component version was audited.
	Date string `yaml:"date"`
	// Auditor is the team or individual who performed the audit.
	Auditor string `yaml:"auditor"`
	// SourceHash is the SHA-256 of the component source tree at audit time.
	SourceHash string `yaml:"source_hash"`
	// CVEScan is the result of the CVE scan ("passed", "failed", or "waived:<reason>").
	CVEScan string `yaml:"cve_scan"`
	// FIPSCompliant indicates whether the component meets FIPS 140-2 requirements.
	FIPSCompliant bool `yaml:"fips_compliant"`
	// Findings lists any audit findings. Empty means the component passed without issues.
	Findings []string `yaml:"findings,omitempty"`
}

// ComponentConfig is the configuration block passed to a component during Configure().
// It contains the full parsed TSC spec so components can read any section they need.
type ComponentConfig struct {
	// Spec is the full parsed application spec.
	Spec *AppSpec
	// Env provides environment variable resolution for ${VAR} references in the spec.
	Env func(key string) string
}

// Application is the runtime container that components register their capabilities into.
// The TSC compiler generates a main.go that creates an Application, registers all
// components, and starts it.
type Application struct {
	name       string
	components []Component
	hooks      applicationHooks
}

// applicationHooks holds the runtime hooks registered by components.
type applicationHooks struct {
	// onStart functions are called in registration order when the application starts.
	onStart []func(ctx context.Context) error
	// onStop functions are called in reverse registration order on shutdown.
	onStop []func(ctx context.Context) error
}

// NewApplication creates a new Application with the given name.
func NewApplication(name string) *Application {
	return &Application{name: name}
}

// Name returns the application name from the TSC spec metadata.
func (a *Application) Name() string {
	return a.name
}

// RegisterComponent adds a component to the application. Called by generated main.go.
func (a *Application) RegisterComponent(c Component) {
	a.components = append(a.components, c)
}

// OnStart registers a startup hook. Components call this from their Register() method.
func (a *Application) OnStart(fn func(ctx context.Context) error) {
	a.hooks.onStart = append(a.hooks.onStart, fn)
}

// OnStop registers a shutdown hook. Components call this from their Register() method.
func (a *Application) OnStop(fn func(ctx context.Context) error) {
	a.hooks.onStop = append(a.hooks.onStop, fn)
}

// Start runs all registered startup hooks in order.
func (a *Application) Start(ctx context.Context) error {
	for _, fn := range a.hooks.onStart {
		if err := fn(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Stop runs all registered shutdown hooks in reverse order.
func (a *Application) Stop(ctx context.Context) error {
	hooks := a.hooks.onStop
	for i := len(hooks) - 1; i >= 0; i-- {
		if err := hooks[i](ctx); err != nil {
			return err
		}
	}
	return nil
}

// Component is the interface every trusted component must implement.
// Components are registered into an Application and participate in the application
// lifecycle via Start/Stop hooks.
type Component interface {
	// Name returns the component's registry name (e.g., "tsc-http").
	Name() ComponentName

	// Version returns the semver version string (e.g., "v1.0.0").
	Version() Version

	// Audit returns the component's audit record. The compiler verifies this
	// matches the registry entry before generating wiring code.
	Audit() AuditRecord

	// Configure applies the spec section relevant to this component.
	// Called before Register. Should validate config and return error on invalid input.
	Configure(cfg ComponentConfig) error

	// Register hooks this component into the application.
	// Called after Configure. Should call app.OnStart / app.OnStop as needed.
	Register(app *Application) error
}

// ResourceProvider is an optional interface that data-layer components implement
// to expose resource CRUD operations to other components (e.g., HTTP handlers).
type ResourceProvider interface {
	Component
	// ResourceFor returns the DAO for the named resource (e.g., "Dinosaur").
	// Returns nil if this component does not manage that resource.
	ResourceFor(resourceName string) ResourceDAO
}

// ResourceDAO is the data access interface for a single resource type.
// The postgres component generates a ResourceDAO per resource defined in the spec.
type ResourceDAO interface {
	// Create inserts a new resource record. id is set on return.
	Create(ctx context.Context, obj interface{}) error
	// Get retrieves a resource by ID.
	Get(ctx context.Context, id string) (interface{}, error)
	// Update replaces a resource record.
	Update(ctx context.Context, obj interface{}) error
	// Delete soft-deletes a resource by ID (if soft_delete: true in spec).
	Delete(ctx context.Context, id string) error
	// List returns all non-deleted records with optional filter.
	List(ctx context.Context, filter ListFilter) ([]interface{}, error)
}

// ListFilter defines pagination and filtering for list operations.
type ListFilter struct {
	Page     int    `json:"page"`
	Size     int    `json:"size"`
	Search   string `json:"search"`
	OrderBy  string `json:"order_by"`
	OrderDir string `json:"order_dir"` // "asc" or "desc"
}
