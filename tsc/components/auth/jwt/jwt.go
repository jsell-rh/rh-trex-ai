// Package jwt provides the tsc-auth-jwt trusted component.
//
// tsc-auth-jwt validates JWT bearer tokens and enforces RBAC on HTTP requests.
// It registers an HTTP middleware that extracts the Authorization header,
// validates the token signature and claims, and attaches the parsed claims
// to the request context. Downstream handlers receive the verified identity
// via context — they never touch raw tokens.
//
// Configuration (ComponentConfig keys):
//
//	jwks_url     string   URL of the JWKS endpoint (mutually exclusive with secret)
//	secret       string   HMAC shared secret (mutually exclusive with jwks_url)
//	issuer       string   Expected "iss" claim (optional; any issuer accepted if empty)
//	audience     string   Expected "aud" claim (optional)
//	algorithms   []string Accepted signing algorithms (default: ["RS256"] with jwks_url, ["HS256"] with secret)
//	skip_paths   []string URL path prefixes that bypass authentication (e.g. ["/healthz"])
package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v4"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

// auditHash is the SHA-256 of the source tree at the time this version was audited.
// The TSC compiler verifies this value against the component registry before
// generating wiring code.
const auditHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// contextKey is unexported to prevent collisions with other context values.
type contextKey string

const (
	// ClaimsKey is the context key under which validated JWT claims are stored.
	ClaimsKey contextKey = "tsc-auth-jwt:claims"
)

// Claims is the set of standard + custom claims extracted from a validated token.
type Claims struct {
	Subject  string
	Issuer   string
	Audience []string
	Expiry   time.Time
	Roles    []string
	Raw      map[string]interface{}
}

// Component implements spec.Component for JWT authentication.
type Component struct {
	mu sync.RWMutex

	// config
	jwksURL    string
	secret     []byte
	issuer     string
	audience   string
	algorithms []string
	skipPaths  []string

	// runtime
	keyFunc gojwt.Keyfunc
	keys    map[string]*rsa.PublicKey
	keysMu  sync.RWMutex
	cancel  context.CancelFunc
}

// New returns an unconfigured tsc-auth-jwt component.
func New() *Component {
	return &Component{}
}

func (c *Component) Name() string      { return "tsc-auth-jwt" }
func (c *Component) Version() string   { return "v1.0.0" }
func (c *Component) AuditHash() string { return auditHash }

// Configure reads the ComponentConfig and validates the configuration.
// Exactly one of jwks_url or secret must be provided.
func (c *Component) Configure(cfg spec.ComponentConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.jwksURL, _ = cfg["jwks_url"].(string)
	secret, _ := cfg["secret"].(string)
	if secret != "" {
		c.secret = []byte(secret)
	}
	c.issuer, _ = cfg["issuer"].(string)
	c.audience, _ = cfg["audience"].(string)

	if algos, ok := cfg["algorithms"].([]interface{}); ok {
		for _, a := range algos {
			if s, ok := a.(string); ok {
				c.algorithms = append(c.algorithms, s)
			}
		}
	}

	if skipPaths, ok := cfg["skip_paths"].([]interface{}); ok {
		for _, p := range skipPaths {
			if s, ok := p.(string); ok {
				c.skipPaths = append(c.skipPaths, s)
			}
		}
	}

	if c.jwksURL == "" && len(c.secret) == 0 {
		return fmt.Errorf("tsc-auth-jwt: exactly one of jwks_url or secret must be configured")
	}
	if c.jwksURL != "" && len(c.secret) > 0 {
		return fmt.Errorf("tsc-auth-jwt: jwks_url and secret are mutually exclusive")
	}

	if len(c.algorithms) == 0 {
		if c.jwksURL != "" {
			c.algorithms = []string{"RS256"}
		} else {
			c.algorithms = []string{"HS256"}
		}
	}

	return nil
}

// Register attaches the JWT validation middleware to the application.
func (c *Component) Register(app *spec.Application) error {
	app.AddMiddleware(c.middleware())
	return nil
}

// Start fetches the initial JWKS keys (for RS256 mode) and starts a
// background refresh goroutine.
func (c *Component) Start(ctx context.Context) error {
	if c.jwksURL != "" {
		if err := c.refreshKeys(); err != nil {
			return fmt.Errorf("tsc-auth-jwt: initial JWKS fetch: %w", err)
		}
		ctx2, cancel := context.WithCancel(ctx)
		c.cancel = cancel
		go c.refreshLoop(ctx2)
		c.keyFunc = c.rsaKeyFunc
	} else {
		c.keyFunc = c.hmacKeyFunc
	}
	return nil
}

// Stop cancels the JWKS refresh goroutine.
func (c *Component) Stop(_ context.Context) error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// handlerFunc adapts a function to spec.HTTPHandler.
type handlerFunc func(w spec.ResponseWriter, r *spec.Request)

func (f handlerFunc) ServeHTTP(w spec.ResponseWriter, r *spec.Request) { f(w, r) }

// Middleware returns an HTTPMiddleware that validates JWT tokens.
// It is also called internally by Register().
func (c *Component) Middleware() spec.HTTPMiddleware {
	return c.middleware()
}

// middleware returns an HTTPMiddleware that validates JWT tokens.
func (c *Component) middleware() spec.HTTPMiddleware {
	return func(next spec.HTTPHandler) spec.HTTPHandler {
		return handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
			// Skip configured paths (e.g. /healthz, /readyz).
			for _, prefix := range c.skipPaths {
				if strings.HasPrefix(r.URL, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}

			claims, err := c.validate(r)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized","message":"` + sanitize(err.Error()) + `"}`))
				return
			}

			// Attach verified claims to context — clone the request with enriched context.
			enriched := *r
			enriched.Context = context.WithValue(r.Context, ClaimsKey, claims)
			next.ServeHTTP(w, &enriched)
		})
	}
}

// sanitize strips characters that would break JSON string embedding.
func sanitize(s string) string {
	s = strings.ReplaceAll(s, `"`, `'`)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return s
}

// validate extracts and validates the JWT from the Authorization header.
func (c *Component) validate(r *spec.Request) (*Claims, error) {
	authHeader := ""
	if vals := r.Headers["Authorization"]; len(vals) > 0 {
		authHeader = vals[0]
	}
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("Authorization header must use Bearer scheme")
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	parser := gojwt.NewParser(
		gojwt.WithValidMethods(c.algorithms),
	)

	mapClaims := gojwt.MapClaims{}
	token, err := parser.ParseWithClaims(tokenStr, mapClaims, c.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, err := c.extractClaims(mapClaims)
	if err != nil {
		return nil, err
	}

	// Require exp claim — reject tokens with no expiry.
	if claims.Expiry.IsZero() {
		return nil, fmt.Errorf("token has no expiry claim")
	}

	// Issuer check.
	if c.issuer != "" && claims.Issuer != c.issuer {
		return nil, fmt.Errorf("token issuer %q does not match expected %q", claims.Issuer, c.issuer)
	}

	// Audience check.
	if c.audience != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == c.audience {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("token audience does not include %q", c.audience)
		}
	}

	return claims, nil
}

func (c *Component) extractClaims(mc gojwt.MapClaims) (*Claims, error) {
	raw := map[string]interface{}(mc)
	claims := &Claims{Raw: raw}

	if sub, ok := raw["sub"].(string); ok {
		claims.Subject = sub
	}
	if iss, ok := raw["iss"].(string); ok {
		claims.Issuer = iss
	}
	switch aud := raw["aud"].(type) {
	case string:
		claims.Audience = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				claims.Audience = append(claims.Audience, s)
			}
		}
	}
	if exp, ok := raw["exp"].(float64); ok {
		claims.Expiry = time.Unix(int64(exp), 0)
	}

	// Extract roles from common claim names.
	for _, key := range []string{"roles", "realm_roles", "groups"} {
		if rolesRaw, ok := raw[key]; ok {
			if roles, ok := rolesRaw.([]interface{}); ok {
				for _, role := range roles {
					if s, ok := role.(string); ok {
						claims.Roles = append(claims.Roles, s)
					}
				}
				break
			}
		}
	}

	return claims, nil
}

// rsaKeyFunc returns the RSA public key for the given token's "kid" header.
func (c *Component) rsaKeyFunc(token *gojwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*gojwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	kid, _ := token.Header["kid"].(string)
	c.keysMu.RLock()
	key, ok := c.keys[kid]
	c.keysMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown key id: %q", kid)
	}
	return key, nil
}

// hmacKeyFunc returns the HMAC shared secret.
func (c *Component) hmacKeyFunc(token *gojwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*gojwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return c.secret, nil
}

// refreshLoop periodically refetches the JWKS keys.
func (c *Component) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.refreshKeys()
		}
	}
}

// refreshKeys fetches and parses the JWKS from jwks_url.
func (c *Component) refreshKeys() error {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Get(c.jwksURL)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			return fmt.Errorf("parse key %q: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}

	c.keysMu.Lock()
	c.keys = keys
	c.keysMu.Unlock()
	return nil
}

func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// ClaimsFromContext retrieves the validated JWT claims from the request context.
// Returns nil if no claims are present (e.g. unauthenticated request on a skipped path).
func ClaimsFromContext(ctx context.Context) *Claims {
	v, _ := ctx.Value(ClaimsKey).(*Claims)
	return v
}

// RequireRole returns an HTTPMiddleware that enforces that the caller has at
// least one of the specified roles. Must be chained after the JWT middleware.
func RequireRole(roles ...string) spec.HTTPMiddleware {
	return func(next spec.HTTPHandler) spec.HTTPHandler {
		return handlerFunc(func(w spec.ResponseWriter, r *spec.Request) {
			claims := ClaimsFromContext(r.Context)
			if claims == nil {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden","message":"no authenticated identity"}`))
				return
			}
			for _, required := range roles {
				for _, have := range claims.Roles {
					if have == required {
						next.ServeHTTP(w, r)
						return
					}
				}
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden","message":"insufficient role"}`))
		})
	}
}
