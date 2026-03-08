// Package custom demonstrates how to integrate custom business logic with a
// TSC-compiled application without modifying trusted component source code.
//
// # The Custom Code Pattern
//
// The TSC compiler generates main.go (DO NOT EDIT). Custom code lives in
// separate .go files in the same package (or an imported package) and hooks
// into the application via the spec.Application API — the same API the compiler
// uses. Custom code is NOT audited as a trusted component; it is regular Go
// code owned by the team.
//
// Extension points available after app.Register():
//
//	app.AddHTTPHandler(pattern, handler)   — mount a custom HTTP handler
//	app.AddMiddleware(mw)                  — prepend middleware to all routes
//	app.AddGRPCService(desc, impl)         — register a custom gRPC service
//
// # Example: Dinosaur Registry Custom Validators
//
// This package shows three patterns:
//  1. validator.go — HTTP middleware that validates incoming requests
//  2. enricher.go  — custom HTTP handler that enriches resource responses
//  3. register.go  — wires custom code into the compiled application
package custom

import (
	"encoding/json"
	"strings"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

// handlerFunc is a local adapter that lets a plain function satisfy spec.HTTPHandler.
// (The frozen spec.Component interface does not expose a HandlerFunc type.)
type handlerFunc func(w spec.ResponseWriter, r *spec.Request)

func (f handlerFunc) ServeHTTP(w spec.ResponseWriter, r *spec.Request) { f(w, r) }

// SpeciesValidator is an HTTP middleware that validates species name constraints
// before forwarding requests to the trusted tsc-http component.
//
// This is NOT a modification to tsc-http. It is custom code that wraps requests
// using the public spec.HTTPMiddleware extension point.
type SpeciesValidator struct {
	// MaxLength is the maximum allowed species name length (default: 255).
	MaxLength int
	// ForbiddenNames is a list of species names that are not allowed.
	ForbiddenNames []string
}

// NewSpeciesValidator returns a SpeciesValidator with sensible defaults.
func NewSpeciesValidator() *SpeciesValidator {
	return &SpeciesValidator{
		MaxLength: 255,
		ForbiddenNames: []string{
			"undefined", "null", "test", // common placeholder values
		},
	}
}

// Middleware returns a spec.HTTPMiddleware that validates dinosaur create/update requests.
// Mount it via app.AddMiddleware(v.Middleware()) before app.Run().
func (v *SpeciesValidator) Middleware() spec.HTTPMiddleware {
	return func(next spec.HTTPHandler) spec.HTTPHandler {
		return handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
			// Only validate POST/PUT/PATCH to dinosaur resources.
			if !isDinosaurMutation(r) {
				next.ServeHTTP(w, r)
				return
			}

			var body map[string]any
			if err := json.Unmarshal(r.Body, &body); err != nil {
				// Let it through — tsc-postgres will handle malformed JSON.
				next.ServeHTTP(w, r)
				return
			}

			species, _ := body["species"].(string)
			if species == "" {
				next.ServeHTTP(w, r)
				return
			}

			if len(species) > v.MaxLength {
				writeJSONError(w, 400, "species name exceeds maximum length")
				return
			}

			for _, forbidden := range v.ForbiddenNames {
				if strings.EqualFold(species, forbidden) {
					writeJSONError(w, 400, "species name "+species+" is not allowed")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isDinosaurMutation(r *spec.Request) bool {
	return (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH") &&
		strings.Contains(r.URL, "/dinosaurs")
}

func writeJSONError(w spec.ResponseWriter, code int, msg string) {
	w.Header()["Content-Type"] = []string{"application/json"}
	w.WriteHeader(code)
	body, _ := json.Marshal(map[string]string{"error": msg})
	w.Write(body) //nolint:errcheck
}
