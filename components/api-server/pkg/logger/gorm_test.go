package logger

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	gormlogger "gorm.io/gorm/logger"
)

func TestGormLogger(t *testing.T) {
	h := installCapture(t)
	sc := fakeSpanContext(t)
	ctx := context.WithValue(context.Background(), OpIDKey, "op-g")
	ctx = traceCtx(ctx, sc)
	query := func() (string, int64) { return `SELECT * FROM "dinosaurs" WHERE id = 'a'`, 1 }

	g := NewGormLogger()
	// Default level is Warn: plain statements are not logged.
	g.Trace(ctx, time.Now(), query, nil)
	g.Trace(ctx, time.Now().Add(-time.Second), query, nil)
	g.Trace(ctx, time.Now(), query, errors.New("boom"))
	g.Info(ctx, "info %d", 1)
	g.Warn(ctx, "warn %d", 2)

	// Debug() and --enable-db-debug use the Info level.
	g.LogMode(gormlogger.Info).Trace(ctx, time.Now(), query, nil)
	// Sessions run Silent by default.
	g.LogMode(gormlogger.Silent).Trace(ctx, time.Now(), query, errors.New("silent"))

	got := h.all()
	want := []struct {
		msg   string
		level slog.Level
	}{
		{"slow sql", slog.LevelWarn},
		{"sql error", slog.LevelError},
		{"warn 2", slog.LevelWarn},
		{"sql", slog.LevelInfo},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i, w := range want {
		r := got[i]
		if r.record.Message != w.msg || r.record.Level != w.level {
			t.Errorf("record %d: got %q at %v, want %q at %v", i, r.record.Message, r.record.Level, w.msg, w.level)
		}
		if spanOf(r.ctx) != sc.SpanID().String() {
			t.Errorf("record %d lost the statement context", i)
		}
	}
	if a := got[1].attrs(); a["error"] != "boom" || a["rows"] != int64(1) || !strings.HasPrefix(a["sql"].(string), "SELECT") {
		t.Errorf("sql error attrs: %v", a)
	}
}

func TestGormLoggerNoColor(t *testing.T) {
	restoreSlogDefault(t)
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{AddSource: true})))
	g := NewGormLogger().LogMode(gormlogger.Info)
	g.Trace(context.Background(), time.Now(), func() (string, int64) { return "SELECT 1", 1 }, nil)
	g.Trace(context.Background(), time.Now(), func() (string, int64) { return "SELECT 2", 0 }, errors.New("bad"))

	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Errorf("output has ANSI color codes: %q", out)
	}
	if !strings.Contains(out, "msg=sql ") || !strings.Contains(out, `rows=1 sql="SELECT 1"`) {
		t.Errorf("unexpected output: %q", out)
	}
	// The source names this file, the code that ran the query.
	if !strings.Contains(out, "gorm_test.go:") {
		t.Errorf("source does not name the caller: %q", out)
	}
}
