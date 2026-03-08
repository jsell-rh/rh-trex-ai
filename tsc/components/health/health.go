// Package health provides the tsc-health trusted component — a lightweight
// HTTP server that exposes liveness and readiness endpoints.
//
// Configuration (spec observability.health_check block):
//
//	observability:
//	  health_check:
//	    bind: ":8083"   # listen address (default :8083)
//	    path: /healthz  # endpoint path (default /healthz)
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

const (
	componentName    = "tsc-health"
	componentVersion = "v1.0.0"
	auditHash        = "0000000000000000000000000000000000000000000000000000000000000002"

	defaultBind = ":8083"
	defaultPath = "/healthz"
)

// HealthComponent implements spec.Component for health check serving.
type HealthComponent struct {
	mu     sync.Mutex
	cfg    config
	server *http.Server
}

type config struct {
	bind string
	path string
}

// New returns a HealthComponent with defaults.
func New() *HealthComponent {
	return &HealthComponent{
		cfg: config{bind: defaultBind, path: defaultPath},
	}
}

func (c *HealthComponent) Name() string      { return componentName }
func (c *HealthComponent) Version() string   { return componentVersion }
func (c *HealthComponent) AuditHash() string { return auditHash }

// Configure reads the observability.health_check section.
func (c *HealthComponent) Configure(cfg spec.ComponentConfig) error {
	if bind, ok := cfg["bind"].(string); ok && bind != "" {
		c.cfg.bind = bind
	}
	if path, ok := cfg["path"].(string); ok && path != "" {
		c.cfg.path = path
	}
	return nil
}

// Register is a no-op — tsc-health manages its own server independently.
func (c *HealthComponent) Register(_ *spec.Application) error { return nil }

// Start launches the health check HTTP server.
func (c *HealthComponent) Start(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc(c.cfg.path, healthHandler)
	// Kubernetes readiness probe alias.
	mux.HandleFunc("/readyz", healthHandler)

	c.server = &http.Server{
		Addr:    c.cfg.bind,
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := c.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("tsc-health: listen %s: %w", c.cfg.bind, err)
	default:
	}
	return nil
}

// Stop gracefully shuts down the health check server.
func (c *HealthComponent) Stop(ctx context.Context) error {
	c.mu.Lock()
	srv := c.server
	c.mu.Unlock()
	if srv == nil {
		return nil
	}
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("tsc-health: shutdown: %w", err)
	}
	return nil
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
