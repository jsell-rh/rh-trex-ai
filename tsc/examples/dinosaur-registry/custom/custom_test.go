package custom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

// --- SpeciesValidator tests ---

func TestSpeciesValidator_AllowsValidSpecies(t *testing.T) {
	v := NewSpeciesValidator()
	mw := v.Middleware()

	called := false
	next := handlerFunc(func(w spec.ResponseWriter, r *spec.Request) { called = true })
	handler := mw(next)

	body, _ := json.Marshal(map[string]string{"species": "Tyrannosaurus Rex"})
	req := &spec.Request{Method: "POST", URL: "/api/v1/dinosaurs", Body: body}
	handler.ServeHTTP(&nopWriter{}, req)

	if !called {
		t.Error("expected next handler to be called for valid species")
	}
}

func TestSpeciesValidator_RejectsForbiddenName(t *testing.T) {
	v := NewSpeciesValidator()
	mw := v.Middleware()

	called := false
	next := handlerFunc(func(w spec.ResponseWriter, r *spec.Request) { called = true })
	handler := mw(next)

	body, _ := json.Marshal(map[string]string{"species": "test"})
	req := &spec.Request{Method: "POST", URL: "/api/v1/dinosaurs", Body: body}
	rw := &nopWriter{}
	handler.ServeHTTP(rw, req)

	if called {
		t.Error("expected next handler NOT to be called for forbidden species")
	}
	if rw.statusCode != 400 {
		t.Errorf("expected 400 status, got %d", rw.statusCode)
	}
}

func TestSpeciesValidator_RejectsTooLongName(t *testing.T) {
	v := &SpeciesValidator{MaxLength: 5, ForbiddenNames: nil}
	mw := v.Middleware()

	called := false
	next := handlerFunc(func(w spec.ResponseWriter, r *spec.Request) { called = true })
	handler := mw(next)

	body, _ := json.Marshal(map[string]string{"species": "toolongname"})
	req := &spec.Request{Method: "POST", URL: "/api/v1/dinosaurs", Body: body}
	rw := &nopWriter{}
	handler.ServeHTTP(rw, req)

	if called {
		t.Error("expected next handler NOT to be called for too-long species")
	}
	if rw.statusCode != 400 {
		t.Errorf("expected 400 status, got %d", rw.statusCode)
	}
}

func TestSpeciesValidator_PassesThroughNonMutation(t *testing.T) {
	v := NewSpeciesValidator()
	mw := v.Middleware()

	called := false
	next := handlerFunc(func(w spec.ResponseWriter, r *spec.Request) { called = true })
	handler := mw(next)

	req := &spec.Request{Method: "GET", URL: "/api/v1/dinosaurs"}
	handler.ServeHTTP(&nopWriter{}, req)

	if !called {
		t.Error("expected GET requests to pass through validator unchanged")
	}
}

// --- DescriptionEnricher tests ---

func TestDescriptionEnricher_AddsMetaToGetResponse(t *testing.T) {
	e := NewDescriptionEnricher("dinosaur-registry", "v1.0.0")
	mw := e.Middleware()

	next := handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
		w.WriteHeader(200)
		body, _ := json.Marshal(map[string]string{"id": "123", "species": "Rex"})
		w.Write(body) //nolint:errcheck
	})
	handler := mw(next)

	req := &spec.Request{Method: "GET", URL: "/api/v1/dinosaurs/123"}
	rw := &capturingResponseWriter{headers: make(map[string][]string), statusCode: 200}
	handler.ServeHTTP(rw, req)

	var result map[string]any
	if err := json.Unmarshal(rw.body, &result); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := result["_meta"]; !ok {
		t.Error("expected _meta field in enriched response")
	}
	meta, _ := result["_meta"].(map[string]any)
	if meta["served_by"] != "dinosaur-registry" {
		t.Errorf("_meta.served_by = %v, want dinosaur-registry", meta["served_by"])
	}
}

func TestDescriptionEnricher_PassesThroughNonJSON(t *testing.T) {
	e := NewDescriptionEnricher("svc", "v1")
	mw := e.Middleware()

	rawBody := []byte("not json")
	next := handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
		w.WriteHeader(200)
		w.Write(rawBody) //nolint:errcheck
	})
	handler := mw(next)

	req := &spec.Request{Method: "GET", URL: "/api/v1/dinosaurs"}
	rw := &capturingResponseWriter{headers: make(map[string][]string), statusCode: 200}
	handler.ServeHTTP(rw, req)

	if string(rw.body) != string(rawBody) {
		t.Errorf("expected non-JSON body to pass through unchanged, got %q", rw.body)
	}
}

// --- Register smoke test ---

func TestRegister_MountsExtensions(t *testing.T) {
	app := spec.NewApplication(nil)
	Register(app, "test-svc", "v0.1.0")

	handlers := app.HTTPHandlers()
	var hasCustomVersion bool
	for _, h := range handlers {
		if strings.Contains(h.Pattern, "/custom/version") {
			hasCustomVersion = true
		}
	}
	if !hasCustomVersion {
		t.Error("expected /custom/version handler to be registered")
	}

	if len(app.Middlewares()) < 2 {
		t.Errorf("expected at least 2 middlewares registered, got %d", len(app.Middlewares()))
	}
}

// --- helpers ---

type nopWriter struct {
	statusCode int
	body       []byte
}

func (n *nopWriter) Header() map[string][]string { return make(map[string][]string) }
func (n *nopWriter) Write(b []byte) (int, error) { n.body = append(n.body, b...); return len(b), nil }
func (n *nopWriter) WriteHeader(code int)         { n.statusCode = code }
