// Package spec defines the core interfaces and types for the Trusted Software
// Components (TSC) platform. All trusted components must implement these
// interfaces. The component interface contract is frozen — bug fixes create
// new audited versions rather than modifying existing ones.
package spec

import "context"

// ComponentConfig carries the IR spec section for a single component,
// as parsed from the app.tsc.yaml spec file.
type ComponentConfig map[string]any

// Component is implemented by every trusted component in the TSC registry.
// All methods must be safe for concurrent use.
type Component interface {
	// Name returns the registry name, e.g. "tsc-http".
	Name() string

	// Version returns the semver string, e.g. "v1.0.0".
	Version() string

	// AuditHash returns the SHA-256 hex digest of the component source tree
	// at audit time. The compiler verifies this matches the registry record
	// before generating output — a mismatch causes a fatal compile error.
	AuditHash() string

	// Configure applies the IR spec section for this component.
	// Called once, before Register. Returns an error if the config is invalid.
	Configure(cfg ComponentConfig) error

	// Register wires this component into the application.
	// Called after Configure on all components. The component should attach
	// HTTP routes, gRPC services, middleware, or background goroutines to app.
	Register(app *Application) error

	// Start is called after all components have been registered.
	// Long-running work (servers, listeners) should begin here.
	// The component must respect ctx cancellation for clean shutdown.
	Start(ctx context.Context) error

	// Stop is called when the application is shutting down.
	// The component must release resources and return promptly.
	Stop(ctx context.Context) error
}

// ResourceDefinition describes a data resource declared in the IR spec.
// The compiler passes these to components (e.g. tsc-postgres) that need
// to generate migrations and CRUD handlers.
type ResourceDefinition struct {
	// Name is the singular resource name, e.g. "Dinosaur".
	Name string

	// Plural is the pluralised form used in API paths, e.g. "dinosaurs".
	Plural string

	// Fields describes the resource's data fields.
	Fields []FieldDefinition

	// Operations lists the CRUD operations to expose: create, read, update, delete, list.
	Operations []string

	// Events, when true, means the component must emit PostgreSQL LISTEN/NOTIFY
	// events on every mutation.
	Events bool
}

// FieldDefinition describes a single field in a ResourceDefinition.
type FieldDefinition struct {
	// Name is the field name in snake_case.
	Name string

	// Type is one of: string, int, float, bool, timestamp, uuid.
	Type string

	// Required, when true, disallows null/empty values.
	Required bool

	// MaxLength constrains string fields (0 = unlimited).
	MaxLength int

	// Auto, when non-empty, auto-populates the field:
	//   "created" — set on insert
	//   "updated" — set on insert and update
	Auto string

	// SoftDelete, when true, marks this field as the soft-delete timestamp.
	// The component must filter deleted records from list queries.
	SoftDelete bool
}

// Registrar is the write side of Application — exposed to components during
// Register so they can attach capabilities without accessing runtime state.
type Registrar interface {
	// AddHTTPHandler registers an HTTP handler at the given pattern.
	AddHTTPHandler(pattern string, handler HTTPHandler)

	// AddMiddleware appends an HTTP middleware to the global chain.
	AddMiddleware(mw HTTPMiddleware)

	// AddGRPCService registers a gRPC service descriptor and its implementation.
	AddGRPCService(desc GRPCServiceDesc, impl any)

	// SetDB provides a database connection pool to any component that needs it.
	// Only tsc-postgres calls this; other components receive it via DB().
	SetDB(db DB)

	// DB returns the shared database connection pool, or nil if not yet set.
	DB() DB

	// Resources returns the resource definitions declared in the IR spec.
	Resources() []ResourceDefinition
}

// HTTPHandler is a minimal abstraction over net/http.Handler.
type HTTPHandler interface {
	ServeHTTP(w ResponseWriter, r *Request)
}

// HTTPMiddleware wraps an HTTPHandler.
type HTTPMiddleware func(next HTTPHandler) HTTPHandler

// ResponseWriter mirrors net/http.ResponseWriter.
type ResponseWriter interface {
	Header() map[string][]string
	Write([]byte) (int, error)
	WriteHeader(statusCode int)
}

// Request mirrors net/http.Request (subset used by components).
type Request struct {
	Method  string
	URL     string
	Headers map[string][]string
	Body    []byte
	Context context.Context
}

// GRPCServiceDesc is an opaque handle to a gRPC service descriptor.
type GRPCServiceDesc any

// DB is a minimal interface over a SQL connection pool.
// tsc-postgres implements this; other components depend on it.
type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) error
	QueryContext(ctx context.Context, query string, args ...any) (Rows, error)
}

// Rows is returned by DB.QueryContext.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}
