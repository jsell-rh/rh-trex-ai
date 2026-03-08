package spec

import (
	"context"
	"fmt"
	"sync"
)

// Application is the runtime container that components register into.
// It implements Registrar so components can attach their capabilities.
// The compiler generates a main.go that constructs an Application,
// calls Configure+Register on each component, then calls Run.
type Application struct {
	mu           sync.RWMutex
	components   []Component
	httpHandlers []HTTPHandlerEntry
	middlewares  []HTTPMiddleware
	grpcServices []GRPCServiceEntry
	db           DB
	resources    []ResourceDefinition
}

// HTTPHandlerEntry is a registered HTTP handler with its URL pattern.
// Exported so tsc-http can retrieve and wire all registered handlers.
type HTTPHandlerEntry struct {
	Pattern string
	Handler HTTPHandler
}

// GRPCServiceEntry is a registered gRPC service descriptor and implementation.
// Exported so tsc-grpc can retrieve and register all services.
type GRPCServiceEntry struct {
	Desc GRPCServiceDesc
	Impl any
}

// NewApplication constructs an empty Application with the given resource
// definitions derived from the IR spec.
func NewApplication(resources []ResourceDefinition) *Application {
	return &Application{resources: resources}
}

// AddComponent registers a component with the application.
// Components are configured and registered in the order they are added.
// tsc-postgres must be added before components that depend on DB.
func (a *Application) AddComponent(c Component) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.components = append(a.components, c)
}

// Configure calls Configure on each component in registration order.
// configs maps component name to its IR config section.
func (a *Application) Configure(configs map[string]ComponentConfig) error {
	a.mu.RLock()
	components := a.components
	a.mu.RUnlock()

	for _, c := range components {
		cfg := configs[c.Name()]
		if cfg == nil {
			cfg = ComponentConfig{}
		}
		if err := c.Configure(cfg); err != nil {
			return fmt.Errorf("configure %s: %w", c.Name(), err)
		}
	}
	return nil
}

// Register calls Register on each component in registration order.
func (a *Application) Register() error {
	a.mu.RLock()
	components := a.components
	a.mu.RUnlock()

	for _, c := range components {
		if err := c.Register(a); err != nil {
			return fmt.Errorf("register %s: %w", c.Name(), err)
		}
	}
	return nil
}

// Run starts all components and blocks until ctx is cancelled,
// then stops all components in reverse registration order.
func (a *Application) Run(ctx context.Context) error {
	a.mu.RLock()
	components := a.components
	a.mu.RUnlock()

	for _, c := range components {
		if err := c.Start(ctx); err != nil {
			return fmt.Errorf("start %s: %w", c.Name(), err)
		}
	}

	<-ctx.Done()

	var stopErr error
	for i := len(components) - 1; i >= 0; i-- {
		if err := components[i].Stop(context.Background()); err != nil && stopErr == nil {
			stopErr = fmt.Errorf("stop %s: %w", components[i].Name(), err)
		}
	}
	return stopErr
}

// --- Registrar implementation ---

func (a *Application) AddHTTPHandler(pattern string, handler HTTPHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.httpHandlers = append(a.httpHandlers, HTTPHandlerEntry{Pattern: pattern, Handler: handler})
}

func (a *Application) AddMiddleware(mw HTTPMiddleware) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.middlewares = append(a.middlewares, mw)
}

func (a *Application) AddGRPCService(desc GRPCServiceDesc, impl any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.grpcServices = append(a.grpcServices, GRPCServiceEntry{Desc: desc, Impl: impl})
}

func (a *Application) SetDB(db DB) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.db = db
}

func (a *Application) DB() DB {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.db
}

func (a *Application) Resources() []ResourceDefinition {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.resources
}

// HTTPHandlers returns the registered HTTP handlers (used by tsc-http).
func (a *Application) HTTPHandlers() []HTTPHandlerEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.httpHandlers
}

// Middlewares returns the registered middleware chain (used by tsc-http).
func (a *Application) Middlewares() []HTTPMiddleware {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.middlewares
}

// GRPCServices returns the registered gRPC services (used by tsc-grpc).
func (a *Application) GRPCServices() []GRPCServiceEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.grpcServices
}
