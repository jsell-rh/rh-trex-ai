// Package grpc provides the tsc-grpc trusted component.
//
// tsc-grpc starts a gRPC server and wires in services registered by other
// components via app.AddGRPCService. It provides:
//
//   - Configurable listen address (default ":9000")
//   - Recovery interceptor (panics → Internal status code)
//   - Logging interceptor (method + duration)
//   - Optional TLS via cert/key paths
//   - Pre-auth interceptor slot for tsc-auth-jwt integration
//
// Startup order: Register() stores the app reference and creates the base
// server. Start() wires in all services registered by other components (which
// have their own Register() calls before Start() begins) and opens the listener.
//
// Configuration (ComponentConfig keys):
//
//	listen_addr   string   gRPC listen address (default: ":9000")
//	tls_cert_file string   Path to TLS certificate PEM (optional)
//	tls_key_file  string   Path to TLS private key PEM (optional)
//	max_recv_mb   int      Maximum receive message size in MiB (default: 4)
//	max_send_mb   int      Maximum send message size in MiB (default: 4)
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

// auditHash is the SHA-256 of the source tree at the time this version was audited.
const auditHash = "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576f4b73829e80cbf56"

// Component implements spec.Component for the gRPC server.
type Component struct {
	mu sync.Mutex

	// config
	listenAddr  string
	tlsCertFile string
	tlsKeyFile  string
	maxRecvMB   int
	maxSendMB   int

	// preAuthInterceptors run before the standard recovery/logging chain.
	// tsc-auth-jwt calls AddPreAuthInterceptor from its own Register().
	preAuthInterceptors []grpc.UnaryServerInterceptor

	// runtime — set in Register()
	app *spec.Application

	// runtime — set in Start()
	server   *grpc.Server
	listener net.Listener
}

// New returns an unconfigured tsc-grpc component.
func New() *Component {
	return &Component{
		listenAddr: ":9000",
		maxRecvMB:  4,
		maxSendMB:  4,
	}
}

func (c *Component) Name() string      { return "tsc-grpc" }
func (c *Component) Version() string   { return "v1.0.0" }
func (c *Component) AuditHash() string { return auditHash }

// Configure reads the ComponentConfig and sets server options.
func (c *Component) Configure(cfg spec.ComponentConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if v, ok := cfg["listen_addr"].(string); ok && v != "" {
		c.listenAddr = v
	}
	if v, ok := cfg["tls_cert_file"].(string); ok {
		c.tlsCertFile = v
	}
	if v, ok := cfg["tls_key_file"].(string); ok {
		c.tlsKeyFile = v
	}
	if v, ok := cfg["max_recv_mb"].(int); ok && v > 0 {
		c.maxRecvMB = v
	}
	if v, ok := cfg["max_send_mb"].(int); ok && v > 0 {
		c.maxSendMB = v
	}

	if (c.tlsCertFile == "") != (c.tlsKeyFile == "") {
		return fmt.Errorf("tsc-grpc: tls_cert_file and tls_key_file must both be set or both be empty")
	}

	return nil
}

// AddPreAuthInterceptor registers a unary interceptor that runs before the
// standard recovery/logging chain. Intended for use by tsc-auth-jwt: call
// this from tsc-auth-jwt's Register() method to enforce token validation on
// every gRPC call before any handler logic executes.
func (c *Component) AddPreAuthInterceptor(i grpc.UnaryServerInterceptor) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.preAuthInterceptors = append(c.preAuthInterceptors, i)
}

// Register stores the application reference so that Start() can read the
// full set of registered gRPC services after all other components have
// completed their own Register() calls.
func (c *Component) Register(app *spec.Application) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.app = app
	return nil
}

// Start builds the gRPC server with all registered services, opens the TCP
// listener, and begins serving in a background goroutine.
//
// Services registered via app.AddGRPCService() by other components during
// their Register() calls are all available at this point because Start() is
// called after all Register() calls complete.
func (c *Component) Start(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	opts, err := c.serverOptions()
	if err != nil {
		return fmt.Errorf("tsc-grpc: build server options: %w", err)
	}

	server := grpc.NewServer(opts...)

	// Wire in all gRPC services registered by other components.
	for _, entry := range c.app.GRPCServices() {
		sd, ok := entry.Desc.(*grpc.ServiceDesc)
		if !ok {
			return fmt.Errorf("tsc-grpc: GRPCServiceDesc must be *grpc.ServiceDesc, got %T", entry.Desc)
		}
		server.RegisterService(sd, entry.Impl)
	}

	lis, err := net.Listen("tcp", c.listenAddr)
	if err != nil {
		return fmt.Errorf("tsc-grpc: listen on %s: %w", c.listenAddr, err)
	}

	c.server = server
	c.listener = lis

	go func() {
		log.Printf("tsc-grpc: serving on %s", c.listenAddr)
		if err := server.Serve(lis); err != nil {
			log.Printf("tsc-grpc: server stopped: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the gRPC server with a 15-second deadline.
func (c *Component) Stop(_ context.Context) error {
	c.mu.Lock()
	server := c.server
	c.mu.Unlock()

	if server == nil {
		return nil
	}

	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	select {
	case <-stopped:
		log.Printf("tsc-grpc: graceful shutdown complete")
	case <-timer.C:
		log.Printf("tsc-grpc: graceful stop timeout, forcing stop")
		server.Stop()
	}
	return nil
}

// serverOptions assembles the grpc.ServerOption slice from configuration.
func (c *Component) serverOptions() ([]grpc.ServerOption, error) {
	var opts []grpc.ServerOption

	opts = append(opts,
		grpc.MaxRecvMsgSize(c.maxRecvMB*1024*1024),
		grpc.MaxSendMsgSize(c.maxSendMB*1024*1024),
	)

	if c.tlsCertFile != "" {
		creds, err := loadTLS(c.tlsCertFile, c.tlsKeyFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(creds))
	}

	// Interceptor chain: pre-auth → recovery → logging.
	chain := make([]grpc.UnaryServerInterceptor, 0, len(c.preAuthInterceptors)+2)
	chain = append(chain, c.preAuthInterceptors...)
	chain = append(chain, recoveryInterceptor(), loggingInterceptor())
	opts = append(opts, grpc.ChainUnaryInterceptor(chain...))

	return opts, nil
}

func loadTLS(certFile, keyFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS key pair: %w", err)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// recoveryInterceptor catches panics in gRPC handlers and converts them to
// Internal status errors, preventing server crashes from bad handler code.
func recoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("tsc-grpc: panic in %s: %v\n%s", info.FullMethod, r, debug.Stack())
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

// loggingInterceptor logs each gRPC call with method name and duration.
func loggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}
		log.Printf("tsc-grpc: %s %s %v", info.FullMethod, code, time.Since(start))
		return resp, err
	}
}
