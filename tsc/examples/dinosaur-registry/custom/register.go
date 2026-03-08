package custom

import "github.com/openshift-online/rh-trex-ai/tsc/spec"

// Register wires all custom code into the compiled application.
//
// Call this in the GENERATED main.go (or a companion file in the same package)
// AFTER app.Register() and BEFORE app.Run(). This is the intended integration point.
//
// Example usage in the generated project (companion file, e.g. custom_hooks.go):
//
//	package main
//
//	import "github.com/openshift-online/rh-trex-ai/tsc/examples/dinosaur-registry/custom"
//
//	func init() {
//	    // Register is called after the compiler-generated init completes.
//	    // In practice, wire this explicitly after app.Register() in main().
//	}
//
// Or explicitly after app.Register():
//
//	if err := app.Register(); err != nil { ... }
//	custom.Register(app, "dinosaur-registry", "v1.0.0")
//	if err := app.Run(ctx); err != nil { ... }
func Register(app *spec.Application, serviceName, version string) {
	// Pattern 1: Validation middleware.
	// Runs before every request to dinosaur mutation endpoints.
	validator := NewSpeciesValidator()
	app.AddMiddleware(validator.Middleware())

	// Pattern 2: Response enrichment middleware.
	// Adds _meta block to all GET /dinosaurs responses.
	enricher := NewDescriptionEnricher(serviceName, version)
	app.AddMiddleware(enricher.Middleware())

	// Pattern 3: Custom handler — a /api/v1/dinosaurs/health/custom endpoint
	// that returns the custom code version. Demonstrates that custom code can
	// mount its own HTTP handlers alongside component-generated ones.
	app.AddHTTPHandler("/custom/version", handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
		w.Header()["Content-Type"] = []string{"application/json"}
		w.WriteHeader(200)
		w.Write([]byte(`{"service":"` + serviceName + `","version":"` + version + `","custom_code":true}`)) //nolint:errcheck
	}))
}
