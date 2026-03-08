// Package components provides the TSC component registry and audit verification.
// The registry is the trust boundary of the TSC platform: only components whose
// audit hash matches a known catalog entry may be registered.
package components

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

// AuditRecord is a catalog entry that binds a component name and version to
// the SHA-256 hash of its source tree at audit time. The registry rejects any
// component whose AuditHash() does not match the catalog record.
type AuditRecord struct {
	// Name is the component registry name, e.g. "tsc-http".
	Name string

	// Version is the semver string, e.g. "v1.0.0".
	Version string

	// Hash is the expected SHA-256 hex digest returned by Component.AuditHash().
	Hash string
}

// key returns a unique string for this record used as a map key.
func (r AuditRecord) key() string {
	return r.Name + "@" + r.Version
}

// Registry is the component registry for the TSC platform.
// It holds a catalog of approved audit records and the registered component
// instances. All methods are safe for concurrent use.
//
// Usage:
//
//	reg := components.New(
//	    components.AuditRecord{Name: "tsc-http",     Version: "v1.0.0", Hash: "<sha256>"},
//	    components.AuditRecord{Name: "tsc-postgres",  Version: "v1.0.0", Hash: "<sha256>"},
//	)
//	if err := reg.Register(myHTTPComponent); err != nil {
//	    log.Fatal(err)
//	}
type Registry struct {
	mu         sync.RWMutex
	catalog    map[string]AuditRecord // key → AuditRecord
	components map[string]spec.Component
}

// New constructs a Registry pre-loaded with the given audit catalog.
// The catalog is immutable after construction — it is the root of trust.
// Duplicate catalog entries (same name+version) are not allowed and will panic.
func New(catalog ...AuditRecord) *Registry {
	cat := make(map[string]AuditRecord, len(catalog))
	for _, rec := range catalog {
		k := rec.key()
		if _, exists := cat[k]; exists {
			panic(fmt.Sprintf("tsc/components: duplicate catalog entry %s", k))
		}
		if rec.Name == "" {
			panic("tsc/components: catalog entry has empty Name")
		}
		if rec.Version == "" {
			panic("tsc/components: catalog entry has empty Version")
		}
		if rec.Hash == "" {
			panic("tsc/components: catalog entry has empty Hash")
		}
		cat[k] = rec
	}
	return &Registry{
		catalog:    cat,
		components: make(map[string]spec.Component),
	}
}

// Register verifies a component's audit hash against the catalog and adds it
// to the registry. Returns an error if:
//   - the component name+version has no catalog entry (unknown component)
//   - the component's AuditHash() does not match the catalog entry (tampered)
//   - a component with the same name is already registered
func (r *Registry) Register(c spec.Component) error {
	name := c.Name()
	version := c.Version()
	hash := c.AuditHash()

	k := name + "@" + version
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.catalog[k]
	if !ok {
		return fmt.Errorf("tsc/components: %s is not in the audit catalog", k)
	}
	if hash != rec.Hash {
		return fmt.Errorf("tsc/components: audit hash mismatch for %s: got %s, want %s", k, hash, rec.Hash)
	}
	if _, exists := r.components[name]; exists {
		return fmt.Errorf("tsc/components: component %q is already registered", name)
	}

	r.components[name] = c
	return nil
}

// MustRegister is like Register but panics on error. Intended for use in
// generated main.go where a registration failure is always a programming error.
func (r *Registry) MustRegister(c spec.Component) {
	if err := r.Register(c); err != nil {
		panic(err)
	}
}

// Get returns the registered component with the given name, or false if not found.
func (r *Registry) Get(name string) (spec.Component, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.components[name]
	return c, ok
}

// All returns all registered components in deterministic (alphabetical) order.
func (r *Registry) All() []spec.Component {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.components))
	for name := range r.components {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]spec.Component, 0, len(names))
	for _, name := range names {
		out = append(out, r.components[name])
	}
	return out
}

// Len returns the number of registered components.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.components)
}

// CatalogSize returns the number of entries in the audit catalog.
func (r *Registry) CatalogSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.catalog)
}

// HashSourceDir computes the SHA-256 digest of a source directory for use
// when generating AuditRecord.Hash values at audit time. The hash is computed
// over the sorted, relative file paths and their contents, making it
// reproducible and independent of filesystem metadata.
//
// This function is intended for use by the audit tooling, not at runtime.
func HashSourceDir(dir string) (string, error) {
	type entry struct {
		path    string
		content []byte
	}
	var entries []entry

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Skip hidden files and non-Go source files.
		name := d.Name()
		if strings.HasPrefix(name, ".") {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{rel, content})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("tsc/components: hashing dir %s: %w", dir, err)
	}

	// Sort by path for determinism.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].path < entries[j].path
	})

	h := sha256.New()
	for _, e := range entries {
		// Include path and a null separator so path/content boundaries are clear.
		_, _ = io.WriteString(h, e.path+"\x00")
		_, _ = h.Write(e.content)
		_, _ = io.WriteString(h, "\x00")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
