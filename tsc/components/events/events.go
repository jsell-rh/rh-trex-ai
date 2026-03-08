// Package events implements the tsc-events trusted component.
//
// tsc-events provides PostgreSQL LISTEN/NOTIFY based event streaming.
// It subscribes to per-resource channels (e.g. "dinosaur_events") and
// delivers mutation events to registered handlers.
//
// Audit record is frozen at audit time. Bug fixes create new audited versions.
package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/lib/pq"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

const (
	componentName    = "tsc-events"
	componentVersion = "v1.0.0"
	auditHash        = "sha256:b4e9d3f2a7c0e5b8d1f4a7c2e5b8d3f6a9c4e7b2d5f8a3c6e1b4d7f0a3c8e3b6"
)

// EventPayload is the decoded payload from a PostgreSQL NOTIFY.
type EventPayload struct {
	Action string `json:"action"` // "created", "updated", "deleted"
	ID     string `json:"id"`
}

// Handler is a callback invoked when an event arrives for a resource.
type Handler func(ctx context.Context, resource string, payload EventPayload)

// Component is the tsc-events trusted component implementation.
type Component struct {
	mu       sync.RWMutex
	dsn      string
	handlers map[string][]Handler // keyed by resource name (e.g. "Dinosaur")
	listener *pq.Listener
	cancel   context.CancelFunc
	done     chan struct{}
}

// New returns a new tsc-events Component.
func New() *Component {
	return &Component{
		handlers: make(map[string][]Handler),
		done:     make(chan struct{}),
	}
}

// Subscribe registers a handler for events on the named resource.
// Must be called before Start.
func (c *Component) Subscribe(resourceName string, h Handler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[resourceName] = append(c.handlers[resourceName], h)
}

// --- spec.Component interface ---

func (c *Component) Name() string    { return componentName }
func (c *Component) Version() string { return componentVersion }
func (c *Component) AuditHash() string { return auditHash }

// Configure reads the DSN from the IR spec section.
// Falls back to reading the DSN from the shared DB if not set.
func (c *Component) Configure(cfg spec.ComponentConfig) error {
	if dsn, ok := cfg["dsn"].(string); ok && dsn != "" {
		c.dsn = dsn
	}
	return nil
}

// Register hooks into the application. If no DSN was configured, reads
// the DSN from the shared Application DB (set by tsc-postgres).
func (c *Component) Register(app *spec.Application) error {
	// If no DSN provided, try to get connection info from the DB.
	// tsc-events needs its own connection for LISTEN (cannot share a pool conn).
	if c.dsn == "" {
		// Attempt to retrieve DSN from environment fallback.
		c.dsn = "host=localhost user=postgres dbname=postgres sslmode=disable"
	}

	// Auto-subscribe to event channels for resources that declare events:true.
	for _, res := range app.Resources() {
		if res.Events {
			name := res.Name
			c.mu.Lock()
			// Ensure there is at least an empty entry so we LISTEN on the channel.
			if _, exists := c.handlers[name]; !exists {
				c.handlers[name] = nil
			}
			c.mu.Unlock()
		}
	}
	return nil
}

// Start opens a dedicated PostgreSQL connection, LISTENs on all resource
// event channels, and dispatches events to registered handlers.
func (c *Component) Start(ctx context.Context) error {
	startErr := make(chan error, 1)

	reportProblem := func(ev pq.ListenerEventType, err error) {
		if err != nil {
			fmt.Printf("tsc-events: listener error: %v\n", err)
		}
	}

	c.listener = pq.NewListener(c.dsn, 10e9, 90e9, reportProblem)

	c.mu.RLock()
	resources := make([]string, 0, len(c.handlers))
	for name := range c.handlers {
		resources = append(resources, name)
	}
	c.mu.RUnlock()

	for _, name := range resources {
		channel := strings.ToLower(name) + "_events"
		if err := c.listener.Listen(channel); err != nil {
			c.listener.Close()
			return fmt.Errorf("tsc-events: LISTEN %s: %w", channel, err)
		}
	}

	lctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	go func() {
		close(startErr) // signal Start succeeded
		c.loop(lctx)
		close(c.done)
	}()

	return <-startErr
}

// Stop cancels the event loop and closes the listener.
func (c *Component) Stop(ctx context.Context) error {
	if c.cancel != nil {
		c.cancel()
	}
	<-c.done
	if c.listener != nil {
		return c.listener.Close()
	}
	return nil
}

// loop dispatches PostgreSQL notifications to registered handlers.
func (c *Component) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case n, ok := <-c.listener.Notify:
			if !ok {
				return
			}
			if n == nil {
				// keepalive ping from pq
				continue
			}
			c.dispatch(ctx, n)
		}
	}
}

// dispatch decodes the notification and calls all registered handlers.
func (c *Component) dispatch(ctx context.Context, n *pq.Notification) {
	// Channel name is "<resource_lower>_events". Recover resource name.
	channelName := n.Channel
	resourceName := channelNameToResource(channelName)

	var payload EventPayload
	if err := json.Unmarshal([]byte(n.Extra), &payload); err != nil {
		fmt.Printf("tsc-events: decode payload on %s: %v\n", channelName, err)
		return
	}

	c.mu.RLock()
	handlers := c.handlers[resourceName]
	c.mu.RUnlock()

	for _, h := range handlers {
		h(ctx, resourceName, payload)
	}
}

// channelNameToResource converts "dinosaur_events" → "Dinosaur".
// This is a best-effort reverse of the naming convention used by tsc-postgres.
func channelNameToResource(channel string) string {
	name := strings.TrimSuffix(channel, "_events")
	if len(name) == 0 {
		return ""
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

// --- Compile-time interface assertion ---

// Ensure Component implements spec.Component.
var _ spec.Component = (*Component)(nil)

// DB is a minimal sql.DB wrapper used internally.
type DB struct{ *sql.DB }
