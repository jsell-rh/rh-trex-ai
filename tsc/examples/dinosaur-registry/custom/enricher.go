package custom

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

// DescriptionEnricher is a custom HTTP middleware that annotates GET /dinosaurs
// responses with service metadata.
//
// This demonstrates Pattern 2: middleware that wraps the tsc-http response
// pipeline without touching tsc-http or tsc-postgres source code.
type DescriptionEnricher struct {
	ServiceName string
	Version     string
}

// NewDescriptionEnricher returns an enricher that annotates responses.
func NewDescriptionEnricher(serviceName, version string) *DescriptionEnricher {
	return &DescriptionEnricher{
		ServiceName: serviceName,
		Version:     version,
	}
}

// Middleware returns a spec.HTTPMiddleware that enriches dinosaur GET responses.
func (e *DescriptionEnricher) Middleware() spec.HTTPMiddleware {
	return func(next spec.HTTPHandler) spec.HTTPHandler {
		return handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
			// Only enrich GET responses for dinosaur resources.
			if r.Method != "GET" || !strings.Contains(r.URL, "/dinosaurs") {
				next.ServeHTTP(w, r)
				return
			}

			// Capture the response.
			captured := &capturingResponseWriter{
				headers:    make(map[string][]string),
				statusCode: 200,
			}
			next.ServeHTTP(captured, r)

			// Try to enrich the JSON response.
			enriched := e.enrich(captured.body)

			// Write the (possibly enriched) response.
			for k, vs := range captured.headers {
				w.Header()[k] = vs
			}
			w.WriteHeader(captured.statusCode)
			w.Write(enriched) //nolint:errcheck
		})
	}
}

// enrich adds a _meta block to the JSON response body if it is a valid JSON object.
func (e *DescriptionEnricher) enrich(body []byte) []byte {
	if len(body) == 0 {
		return body
	}

	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body // not JSON — pass through unchanged
	}

	obj["_meta"] = map[string]any{
		"served_by":   e.ServiceName,
		"version":     e.Version,
		"enriched_at": time.Now().UTC().Format(time.RFC3339),
	}

	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// capturingResponseWriter buffers the response so the enricher can inspect and
// modify it before forwarding to the actual ResponseWriter.
type capturingResponseWriter struct {
	headers    map[string][]string
	statusCode int
	body       []byte
}

func (c *capturingResponseWriter) Header() map[string][]string { return c.headers }
func (c *capturingResponseWriter) Write(b []byte) (int, error) {
	c.body = append(c.body, b...)
	return len(b), nil
}
func (c *capturingResponseWriter) WriteHeader(code int) { c.statusCode = code }
