package logger

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestGlogHandlerSlogRecords(t *testing.T) {
	setGlogFlags(t, "0")
	l := slog.New(NewGlogHandler())

	got := captureStderr(t, func() {
		l.Info("started", "port", 8000)
		l.With("opid", "op-9").WarnContext(context.Background(), "slow", "err", errors.New("x"))
		l.WithGroup("db").Error("failed", "table", "t", slog.Group("q", "rows", 2))
		l.Debug("hidden at -v=0")
	})
	want := "I started port=8000|\n" +
		"W [opid=op-9] slow err=x|\n" +
		"E failed db.table=t db.q.rows=2|\n"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestGlogHandlerHonorsV(t *testing.T) {
	setGlogFlags(t, "2")
	l := slog.New(NewGlogHandler())
	got := captureStderr(t, func() {
		l.Debug("debug at v=2")
		l.Log(context.Background(), slog.LevelDebug-1, "needs v=3")
	})
	if got != "I debug at v=2|\n" {
		t.Errorf("got %q", got)
	}
}

// TestGlogHandlerFileLine checks that the glog header names the code that
// called the logger, not the handler or the logger internals.
func TestGlogHandlerFileLine(t *testing.T) {
	setGlogFlags(t, "0")
	restoreSlogDefault(t)
	SetDefaultIfUnset()

	var line int
	out := captureRawStderr(t, func() {
		_, _, line, _ = runtime.Caller(0)
		NewLogger(context.Background()).V(0).Info("via logger")
		slog.Info("via slog")
	})
	got := strings.Split(strings.TrimSpace(out), "\n")
	if len(got) != 2 {
		t.Fatalf("got %d lines: %q", len(got), out)
	}
	for i, l := range got {
		want := "glog_handler_test.go:" + strconv.Itoa(line+1+i) + "]"
		if !strings.Contains(l, want) {
			t.Errorf("%q does not contain %q", l, want)
		}
	}
}
