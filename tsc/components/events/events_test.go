package events

import (
	"context"
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

func TestChannelNameToResource(t *testing.T) {
	cases := []struct{ channel, want string }{
		{"dinosaur_events", "Dinosaur"},
		{"user_events", "User"},
		{"_events", ""},
	}
	for _, tc := range cases {
		got := channelNameToResource(tc.channel)
		if got != tc.want {
			t.Errorf("channelNameToResource(%q) = %q, want %q", tc.channel, got, tc.want)
		}
	}
}

func TestSubscribe(t *testing.T) {
	c := New()
	called := false
	c.Subscribe("Dinosaur", func(ctx context.Context, resource string, payload EventPayload) {
		called = true
	})
	c.mu.RLock()
	handlers := c.handlers["Dinosaur"]
	c.mu.RUnlock()
	if len(handlers) != 1 {
		t.Errorf("expected 1 handler, got %d", len(handlers))
	}
	_ = called
}

func TestConfigure(t *testing.T) {
	c := New()
	cfg := spec.ComponentConfig{"dsn": "host=localhost dbname=test"}
	if err := c.Configure(cfg); err != nil {
		t.Fatalf("Configure() error: %v", err)
	}
	if c.dsn != "host=localhost dbname=test" {
		t.Errorf("dsn = %q, want %q", c.dsn, "host=localhost dbname=test")
	}
}
