package server

import (
	"context"
	"log"
	"log/slog"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
)

type recordingHandler struct {
	mu   sync.Mutex
	ctxs []context.Context
	msgs []string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }
func (h *recordingHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ctxs = append(h.ctxs, ctx)
	h.msgs = append(h.msgs, r.Message)
	return nil
}

// TestGRPCLogsCarryCallContext shows that logs written by the gRPC
// interceptors reach a custom slog handler with the call's context, so the
// trace and span IDs set by OpenTelemetry instrumentation are reachable.
func TestGRPCLogsCarryCallContext(t *testing.T) {
	prev := slog.Default()
	w, flags := log.Writer(), log.Flags()
	t.Cleanup(func() { slog.SetDefault(prev); log.SetOutput(w); log.SetFlags(flags) })
	h := &recordingHandler{}
	slog.SetDefault(slog.New(h))

	tid, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	sid, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	info := &grpc.UnaryServerInfo{FullMethod: "/x.y/Z"}
	chain := func(ctx context.Context, req interface{}) (interface{}, error) {
		return LoggingUnaryInterceptor()(ctx, req, info, func(ctx context.Context, req interface{}) (interface{}, error) {
			return RecoveryUnaryInterceptor()(ctx, req, info, func(context.Context, interface{}) (interface{}, error) {
				panic("boom")
			})
		})
	}
	if _, err := chain(ctx, nil); err == nil {
		t.Fatal("want an error from the recovered panic")
	}

	if len(h.ctxs) != 2 {
		t.Fatalf("got %d records %v, want the panic and the call log", len(h.ctxs), h.msgs)
	}
	for i, c := range h.ctxs {
		got := trace.SpanContextFromContext(c)
		if got.TraceID() != tid || got.SpanID() != sid {
			t.Errorf("record %q: handler saw trace %s span %s", h.msgs[i], got.TraceID(), got.SpanID())
		}
	}
}
