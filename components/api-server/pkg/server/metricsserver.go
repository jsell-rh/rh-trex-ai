package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/api"
	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/handlers"
)

type metricsServer struct {
	httpServer *http.Server
	config     ServerConfig
}

var _ Server = &metricsServer{}

func NewMetricsServer(cfg ServerConfig) Server {
	mainRouter := mux.NewRouter()
	mainRouter.NotFoundHandler = http.HandlerFunc(api.SendNotFound)

	prometheusMetricsHandler := handlers.NewPrometheusMetricsHandler()
	mainRouter.Handle("/metrics", prometheusMetricsHandler.Handler())

	var mainHandler http.Handler = mainRouter

	s := &metricsServer{config: cfg}
	s.httpServer = &http.Server{
		Addr:    cfg.BindAddress,
		Handler: mainHandler,
	}
	return s
}

func (s metricsServer) Listen() (listener net.Listener, err error) {
	return nil, nil
}

func (s metricsServer) Serve(listener net.Listener) {
}

func (s metricsServer) Start() {
	var err error
	if s.config.EnableHTTPS {
		if s.config.HTTPSCertFile == "" || s.config.HTTPSKeyFile == "" {
			Check(
				fmt.Errorf("unspecified required --https-cert-file, --https-key-file"),
				"Can't start https server",
			)
		}

		slog.Info("Serving Metrics with TLS", "address", s.config.BindAddress)
		err = s.httpServer.ListenAndServeTLS(s.config.HTTPSCertFile, s.config.HTTPSKeyFile)
	} else {
		slog.Info("Serving Metrics without TLS", "address", s.config.BindAddress)
		err = s.httpServer.ListenAndServe()
	}
	Check(err, "Metrics server terminated with errors")
	slog.Info("Metrics server terminated")
}

func (s metricsServer) Stop() error {
	return s.httpServer.Shutdown(context.Background())
}
