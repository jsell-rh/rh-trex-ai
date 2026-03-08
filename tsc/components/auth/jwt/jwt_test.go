package jwt_test

import (
	"context"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v4"

	authjwt "github.com/openshift-online/rh-trex-ai/tsc/components/auth/jwt"
	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

// handlerFunc adapts a function to spec.HTTPHandler for use in tests.
type handlerFunc func(w spec.ResponseWriter, r *spec.Request)

func (f handlerFunc) ServeHTTP(w spec.ResponseWriter, r *spec.Request) { f(w, r) }

func makeToken(t *testing.T, secret string, claims gojwt.MapClaims) string {
	t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func TestConfigure_MissingBoth(t *testing.T) {
	c := authjwt.New()
	err := c.Configure(spec.ComponentConfig{})
	if err == nil {
		t.Fatal("expected error when neither jwks_url nor secret is set")
	}
}

func TestConfigure_BothSet(t *testing.T) {
	c := authjwt.New()
	err := c.Configure(spec.ComponentConfig{
		"jwks_url": "https://example.com/.well-known/jwks.json",
		"secret":   "mysecret",
	})
	if err == nil {
		t.Fatal("expected error when both jwks_url and secret are set")
	}
}

func TestHMACFlow(t *testing.T) {
	const secret = "test-secret-key"
	c := authjwt.New()
	if err := c.Configure(spec.ComponentConfig{
		"secret":   secret,
		"issuer":   "test-issuer",
		"audience": "test-audience",
	}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop(context.Background())

	tok := makeToken(t, secret, gojwt.MapClaims{
		"sub": "user-123",
		"iss": "test-issuer",
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"roles": []interface{}{"admin"},
	})

	var called bool
	var captured *authjwt.Claims
	mw := c.Middleware()
	wrapped := mw(handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
		called = true
		captured = authjwt.ClaimsFromContext(r.Context)
	}))

	req := &spec.Request{
		Method:  "GET",
		URL:     "/api/v1/dinosaurs",
		Headers: map[string][]string{"Authorization": {"Bearer " + tok}},
		Context: context.Background(),
	}
	wrapped.ServeHTTP(&fakeResponseWriter{}, req)

	if !called {
		t.Fatal("handler was not called")
	}
	if captured == nil {
		t.Fatal("claims not in context")
	}
	if captured.Subject != "user-123" {
		t.Errorf("subject: got %q, want %q", captured.Subject, "user-123")
	}
	if len(captured.Roles) != 1 || captured.Roles[0] != "admin" {
		t.Errorf("roles: got %v, want [admin]", captured.Roles)
	}
}

func TestExpiredToken(t *testing.T) {
	const secret = "test-secret-key"
	c := authjwt.New()
	_ = c.Configure(spec.ComponentConfig{"secret": secret})
	_ = c.Start(context.Background())
	defer c.Stop(context.Background())

	tok := makeToken(t, secret, gojwt.MapClaims{
		"sub": "user-123",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	fw := &fakeResponseWriter{}
	mw := c.Middleware()
	wrapped := mw(handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
		t.Error("handler should not be called for expired token")
	}))

	req := &spec.Request{
		Method:  "GET",
		URL:     "/api/v1/dinosaurs",
		Headers: map[string][]string{"Authorization": {"Bearer " + tok}},
		Context: context.Background(),
	}
	wrapped.ServeHTTP(fw, req)

	if fw.code != 401 {
		t.Errorf("expected 401, got %d", fw.code)
	}
}

func TestSkipPath(t *testing.T) {
	c := authjwt.New()
	_ = c.Configure(spec.ComponentConfig{
		"secret":     "s",
		"skip_paths": []interface{}{"/healthz"},
	})
	_ = c.Start(context.Background())
	defer c.Stop(context.Background())

	var called bool
	mw := c.Middleware()
	wrapped := mw(handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
		called = true
	}))

	req := &spec.Request{
		Method:  "GET",
		URL:     "/healthz",
		Headers: map[string][]string{},
		Context: context.Background(),
	}
	wrapped.ServeHTTP(&fakeResponseWriter{}, req)
	if !called {
		t.Fatal("handler should be called for skipped path")
	}
}

func TestMissingAuthHeader(t *testing.T) {
	c := authjwt.New()
	_ = c.Configure(spec.ComponentConfig{"secret": "s"})
	_ = c.Start(context.Background())
	defer c.Stop(context.Background())

	fw := &fakeResponseWriter{}
	mw := c.Middleware()
	wrapped := mw(handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
		t.Error("handler should not be called without auth")
	}))

	req := &spec.Request{
		Method:  "GET",
		URL:     "/api/v1/data",
		Headers: map[string][]string{},
		Context: context.Background(),
	}
	wrapped.ServeHTTP(fw, req)
	if fw.code != 401 {
		t.Errorf("expected 401, got %d", fw.code)
	}
}

// fakeResponseWriter implements spec.ResponseWriter for testing.
type fakeResponseWriter struct {
	code    int
	headers map[string][]string
	body    []byte
}

func (f *fakeResponseWriter) Header() map[string][]string {
	if f.headers == nil {
		f.headers = make(map[string][]string)
	}
	return f.headers
}

func (f *fakeResponseWriter) Write(b []byte) (int, error) {
	f.body = append(f.body, b...)
	return len(b), nil
}

func (f *fakeResponseWriter) WriteHeader(code int) {
	f.code = code
}
