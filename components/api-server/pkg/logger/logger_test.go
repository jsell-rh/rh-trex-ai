package logger

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

// captured is one record seen by captureHandler, with the context it came with.
type captured struct {
	ctx    context.Context
	record slog.Record
}

func (c captured) attrs() map[string]any {
	m := map[string]any{}
	c.record.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.Any()
		return true
	})
	return m
}

// captureHandler is a custom slog handler, the kind a program installs with
// slog.SetDefault. It accepts every level.
type captureHandler struct {
	mu      sync.Mutex
	records []captured
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *captureHandler) WithGroup(string) slog.Handler            { return h }
func (h *captureHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, captured{ctx: ctx, record: r.Clone()})
	return nil
}

func (h *captureHandler) all() []captured {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]captured{}, h.records...)
}

// restoreSlogDefault puts the standard library default back after the test.
func restoreSlogDefault(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	w, flags := log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(w)
		log.SetFlags(flags)
	})
}

func installCapture(t *testing.T) *captureHandler {
	t.Helper()
	restoreSlogDefault(t)
	h := &captureHandler{}
	slog.SetDefault(slog.New(h))
	return h
}

func TestLevelMapping(t *testing.T) {
	h := installCapture(t)
	exited := -1
	exit = func(code int) { exited = code }
	t.Cleanup(func() { exit = os.Exit })

	l := NewLogger(context.Background())
	l.Infof("infof")
	l.Info("info")
	l.V(0).Info("v0")
	l.V(1).Infof("v1")
	l.V(2).Infof("v2")
	l.V(5).Info("v5")
	l.Warning("warning")
	l.Error("error")
	l.Fatal("fatal")

	want := []struct {
		msg   string
		level slog.Level
	}{
		{"infof", slog.LevelInfo},
		{"info", slog.LevelInfo},
		{"v0", slog.LevelInfo},
		{"v1", slog.LevelInfo},
		{"v2", slog.LevelDebug},
		{"v5", slog.LevelDebug},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"fatal", slog.LevelError},
	}
	got := h.all()
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].record.Message != w.msg || got[i].record.Level != w.level {
			t.Errorf("record %d: got %q at %v, want %q at %v",
				i, got[i].record.Message, got[i].record.Level, w.msg, w.level)
		}
	}
	if exited != 1 {
		t.Errorf("Fatal exit code: got %d, want 1", exited)
	}
}

func TestAttributesAndExtra(t *testing.T) {
	h := installCapture(t)

	ctx := context.WithValue(context.Background(), OpIDKey, "op-1")
	ctx = context.WithValue(ctx, "accountID", "acct-1") //nolint:staticcheck // key used by util.GetAccountIDFromContext
	ctx = context.WithValue(ctx, "txid", int64(7))      //nolint:staticcheck // key read by the logger

	l := NewLogger(ctx)
	l.Extra("lockID", "abc").Extra("owner", 3).Error("unlock failed")
	// V used to drop the Extra fields.
	l.V(2).Info("verbose keeps extras")
	NewLogger(context.Background()).Info("no attributes")

	got := h.all()
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3", len(got))
	}
	want := map[string]any{"opid": "op-1", "accountID": "acct-1", "tx_id": int64(7), "lockID": "abc", "owner": int64(3)}
	for i := 0; i < 2; i++ {
		a := got[i].attrs()
		for k, v := range want {
			if a[k] != v {
				t.Errorf("record %d attr %s: got %v (%T), want %v (%T)", i, k, a[k], a[k], v, v)
			}
		}
		if len(a) != len(want) {
			t.Errorf("record %d: got attrs %v, want %v", i, a, want)
		}
	}
	if n := got[2].record.NumAttrs(); n != 0 {
		t.Errorf("logger without context values emitted %d attrs", n)
	}
}

func TestRecordSourceIsCaller(t *testing.T) {
	h := installCapture(t)
	_, _, line, _ := runtime.Caller(0)
	NewLogger(context.Background()).Info("where")

	r := h.all()[0].record
	f, _ := runtime.CallersFrames([]uintptr{r.PC}).Next()
	if !strings.HasSuffix(f.File, "logger_test.go") || f.Line != line+1 {
		t.Errorf("source: got %s:%d, want logger_test.go:%d", f.File, f.Line, line+1)
	}
}

// fakeSpanContext stands in for the span an OpenTelemetry HTTP or gRPC
// instrumentation starts for each request.
func fakeSpanContext(t *testing.T) trace.SpanContext {
	t.Helper()
	tid, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	if err != nil {
		t.Fatal(err)
	}
	return trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
}

// TestRequestContextReachesHandler shows that a record logged while serving
// a request reaches the slog handler with the request's context, so a
// handler such as the OpenTelemetry slog bridge can read the trace and span.
func TestRequestContextReachesHandler(t *testing.T) {
	h := installCapture(t)
	sc := fakeSpanContext(t)

	app := OperationIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		NewLogger(r.Context()).Infof("handling %s", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	req = req.WithContext(trace.ContextWithSpanContext(req.Context(), sc))
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	got := h.all()
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	span := trace.SpanContextFromContext(got[0].ctx)
	if span.TraceID() != sc.TraceID() || span.SpanID() != sc.SpanID() {
		t.Errorf("handler saw trace %s span %s, want trace %s span %s",
			span.TraceID(), span.SpanID(), sc.TraceID(), sc.SpanID())
	}
	if opid := rec.Header().Get(string(OpIDHeader)); got[0].attrs()["opid"] != opid {
		t.Errorf("opid attr %v, want %s", got[0].attrs()["opid"], opid)
	}
}

func TestSetDefaultIfUnset(t *testing.T) {
	t.Run("installs when unset", func(t *testing.T) {
		restoreSlogDefault(t)
		var buf strings.Builder
		log.SetOutput(&buf)
		log.SetFlags(0)
		if !SetDefaultIfUnset() {
			t.Fatal("want install")
		}
		if _, ok := slog.Default().Handler().(*glogHandler); !ok {
			t.Fatalf("default handler is %T", slog.Default().Handler())
		}
		// The standard log package keeps writing where it did before.
		log.Print("plain")
		if buf.String() != "plain\n" {
			t.Errorf("log package output changed: %q", buf.String())
		}
	})
	t.Run("keeps a program's default", func(t *testing.T) {
		h := installCapture(t)
		if SetDefaultIfUnset() {
			t.Fatal("replaced the program's default")
		}
		if slog.Default().Handler() != h {
			t.Fatalf("default handler is %T", slog.Default().Handler())
		}
	})
}

func traceCtx(ctx context.Context, sc trace.SpanContext) context.Context {
	return trace.ContextWithSpanContext(ctx, sc)
}

func spanOf(ctx context.Context) string {
	return trace.SpanContextFromContext(ctx).SpanID().String()
}
