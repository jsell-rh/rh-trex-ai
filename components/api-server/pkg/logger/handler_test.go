package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/slogtest"
	"time"

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

// restoreSlogDefault puts the previous default and log settings back after
// the test.
func restoreSlogDefault(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	prevInstalled := installed
	w, flags := log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(prev)
		installed = prevInstalled
		log.SetOutput(w)
		log.SetFlags(flags)
	})
}

// installCapture makes a capture handler, wrapped like trex wraps its own
// handler, the slog default.
func installCapture(t *testing.T) *captureHandler {
	t.Helper()
	restoreSlogDefault(t)
	h := &captureHandler{}
	slog.SetDefault(slog.New(WithContextAttrs(h)))
	return h
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

func requestContext() context.Context {
	ctx := context.WithValue(context.Background(), OpIDKey, "op-1")
	ctx = context.WithValue(ctx, "accountID", "acct-1") //nolint:staticcheck // key used by util.GetAccountIDFromContext
	return context.WithValue(ctx, "txid", int64(7))     //nolint:staticcheck // key read by contextAttrs
}

func TestWithContextAttrs(t *testing.T) {
	h := installCapture(t)

	slog.ErrorContext(requestContext(), "unlock failed", "lock_id", "abc")
	slog.InfoContext(context.Background(), "no request values")
	slog.Info("no context")

	got := h.all()
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3", len(got))
	}
	want := map[string]any{"opid": "op-1", "accountID": "acct-1", "tx_id": int64(7), "lock_id": "abc"}
	a := got[0].attrs()
	for k, v := range want {
		if a[k] != v {
			t.Errorf("attr %s: got %v (%T), want %v (%T)", k, a[k], a[k], v, v)
		}
	}
	if len(a) != len(want) {
		t.Errorf("got attrs %v, want %v", a, want)
	}
	for _, c := range got[1:] {
		if n := c.record.NumAttrs(); n != 0 {
			t.Errorf("%q: got %d attrs, want 0", c.record.Message, n)
		}
	}
}

func TestWithContextAttrsDoesNotChangeCallerRecord(t *testing.T) {
	inner := &captureHandler{}
	h := WithContextAttrs(inner)
	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.String("a", "1"))
	if err := h.Handle(requestContext(), r); err != nil {
		t.Fatal(err)
	}
	if r.NumAttrs() != 1 {
		t.Errorf("caller record changed: %d attrs", r.NumAttrs())
	}
	if n := inner.all()[0].record.NumAttrs(); n != 4 {
		t.Errorf("handled record: got %d attrs, want 4", n)
	}
}

// TestWithContextAttrsFollowsSlogRules runs the standard library's handler
// conformance tests against the wrapper.
func TestWithContextAttrsFollowsSlogRules(t *testing.T) {
	var buf bytes.Buffer
	h := WithContextAttrs(slog.NewJSONHandler(&buf, nil))
	results := func() []map[string]any {
		var ms []map[string]any
		for _, line := range bytes.Split(buf.Bytes(), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(line, &m); err != nil {
				t.Fatal(err)
			}
			ms = append(ms, m)
		}
		return ms
	}
	if err := slogtest.TestHandler(h, results); err != nil {
		t.Error(err)
	}
}

// TestRequestContextReachesHandler shows that a record logged while serving
// a request reaches the slog handler with the request's context, so a
// handler such as the OpenTelemetry slog bridge can read the trace and span.
func TestRequestContextReachesHandler(t *testing.T) {
	h := installCapture(t)
	sc := fakeSpanContext(t)

	app := OperationIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "handling request", "path", r.URL.Path)
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

func TestNewHandler(t *testing.T) {
	ctx := requestContext()
	t.Run("text", func(t *testing.T) {
		var buf bytes.Buffer
		h, err := NewHandler(&buf, FormatText, slog.LevelInfo)
		if err != nil {
			t.Fatal(err)
		}
		l := slog.New(WithContextAttrs(h))
		l.DebugContext(ctx, "hidden")
		l.InfoContext(ctx, "gRPC call", "method", "/x.y/Z", "code", "OK")
		out := buf.String()
		if strings.Contains(out, "hidden") {
			t.Errorf("debug record printed at info level: %q", out)
		}
		for _, want := range []string{"level=INFO", `msg="gRPC call"`, "method=/x.y/Z", "code=OK", "opid=op-1", "accountID=acct-1", "tx_id=7"} {
			if !strings.Contains(out, want) {
				t.Errorf("output %q does not contain %q", out, want)
			}
		}
		if strings.Contains(out, "\x1b[") {
			t.Errorf("output has ANSI color codes: %q", out)
		}
	})
	t.Run("json", func(t *testing.T) {
		var buf bytes.Buffer
		h, err := NewHandler(&buf, FormatJSON, slog.LevelDebug)
		if err != nil {
			t.Fatal(err)
		}
		slog.New(WithContextAttrs(h)).DebugContext(ctx, "shown", "n", 1)
		var m map[string]any
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", buf.String(), err)
		}
		if m["msg"] != "shown" || m["level"] != "DEBUG" || m["opid"] != "op-1" {
			t.Errorf("unexpected record %v", m)
		}
	})
	t.Run("unknown format", func(t *testing.T) {
		if _, err := NewHandler(&bytes.Buffer{}, "xml", slog.LevelInfo); err == nil {
			t.Error("want an error")
		}
	})
}

func TestSetDefaultIfUnset(t *testing.T) {
	t.Run("installs when unset and keeps log package output", func(t *testing.T) {
		restoreSlogDefault(t)
		slog.SetDefault(stdDefault)
		installed = nil
		var buf strings.Builder
		log.SetOutput(&buf)
		log.SetFlags(0)
		h := &captureHandler{}
		if !SetDefaultIfUnset(h) {
			t.Fatal("want install")
		}
		if slog.Default().Handler() != h {
			t.Fatalf("default handler is %T", slog.Default().Handler())
		}
		log.Print("plain")
		if buf.String() != "plain\n" {
			t.Errorf("log package output changed: %q", buf.String())
		}
		// trex may replace its own default, for example once flags are parsed.
		h2 := &captureHandler{}
		if !SetDefaultIfUnset(h2) || slog.Default().Handler() != h2 {
			t.Error("did not replace the handler trex installed")
		}
	})
	t.Run("keeps a program's default", func(t *testing.T) {
		restoreSlogDefault(t)
		program := &captureHandler{}
		slog.SetDefault(slog.New(program))
		if SetDefaultIfUnset(&captureHandler{}) {
			t.Fatal("replaced the program's default")
		}
		if slog.Default().Handler() != program {
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
