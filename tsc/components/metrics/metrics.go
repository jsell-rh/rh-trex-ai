// Package metrics provides the tsc-metrics trusted component — a Prometheus
// metrics endpoint served on a dedicated port.
//
// Configuration (spec observability.metrics block):
//
//	observability:
//	  metrics:
//	    bind: ":8080"    # listen address (default :8080)
//	    path: /metrics   # metrics path (default /metrics)
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

const (
	componentName    = "tsc-metrics"
	componentVersion = "v1.0.0"
	auditHash        = "0000000000000000000000000000000000000000000000000000000000000003"

	defaultBind = ":8080"
	defaultPath = "/metrics"
)

// MetricsComponent implements spec.Component for Prometheus metrics serving.
type MetricsComponent struct {
	mu     sync.Mutex
	cfg    config
	server *http.Server
}

type config struct {
	bind string
	path string
}

// New returns a MetricsComponent with defaults.
func New() *MetricsComponent {
	return &MetricsComponent{
		cfg: config{bind: defaultBind, path: defaultPath},
	}
}

func (c *MetricsComponent) Name() string      { return componentName }
func (c *MetricsComponent) Version() string   { return componentVersion }
func (c *MetricsComponent) AuditHash() string { return auditHash }

// Configure reads the observability.metrics section.
func (c *MetricsComponent) Configure(cfg spec.ComponentConfig) error {
	if bind, ok := cfg["bind"].(string); ok && bind != "" {
		c.cfg.bind = bind
	}
	if path, ok := cfg["path"].(string); ok && path != "" {
		c.cfg.path = path
	}
	return nil
}

// Register is a no-op — tsc-metrics manages its own server independently.
func (c *MetricsComponent) Register(_ *spec.Application) error { return nil }

// Start launches the Prometheus metrics HTTP server.
func (c *MetricsComponent) Start(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	mux := http.NewServeMux()
	mux.Handle(c.cfg.path, promhttp.Handler())

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
		return fmt.Errorf("tsc-metrics: listen %s: %w", c.cfg.bind, err)
	default:
	}
	return nil
}

// Stop gracefully shuts down the metrics server.
func (c *MetricsComponent) Stop(ctx context.Context) error {
	c.mu.Lock()
	srv := c.server
	c.mu.Unlock()
	if srv == nil {
		return nil
	}
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("tsc-metrics: shutdown: %w", err)
	}
	return nil
}
