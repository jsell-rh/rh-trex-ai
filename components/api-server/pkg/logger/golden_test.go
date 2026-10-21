package logger

import (
	"bufio"
	"context"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
)

// goldenCases drives the logger through the calls that exist in the
// codebase. The expected output was recorded from the glog-backed logger
// that predates slog, so this test proves the default text did not change.
func goldenCases() {
	ctx := context.WithValue(context.Background(), OpIDKey, "op-123")
	ctx = context.WithValue(ctx, "accountID", "acct-9") //nolint:staticcheck // key used by util.GetAccountIDFromContext
	ctx = context.WithValue(ctx, "txid", int64(42))     //nolint:staticcheck // key read by the logger

	full := NewLogger(ctx)
	full.Infof("gRPC %s %s %s", "/x.y/Z", "OK", "29ms")
	full.Info("plain info")
	full.Warning("plain warning")
	full.Error("plain error")
	full.Extra("error", "boom").Error("with extra")
	full.V(2).Infof("verbose %d shown", 2)
	full.V(5).Infof("verbose %d hidden", 5)

	opOnly := NewLogger(context.WithValue(context.Background(), OpIDKey, "op-456"))
	opOnly.Infof("op only %s", "f")
	opOnly.Info("op only")

	bare := NewLogger(context.Background())
	bare.Infof("no context %d", 1)
	bare.Info("no context")
	bare.Warning("no context warning")
}

// captureStderr runs fn and returns what it wrote to os.Stderr, with the
// glog header ("I1021 08:25:17.913474 1 file.go:97] ") reduced to its
// severity letter, so the comparison does not depend on time, pid or line.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(captureRawStderr(t, fn)))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "] "); i > 0 {
			line = line[:1] + " " + line[i+2:]
		}
		b.WriteString(line)
		b.WriteString("|\n")
	}
	return b.String()
}

// captureRawStderr runs fn and returns what it wrote to os.Stderr.
func captureRawStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stderr = orig
	_ = w.Close()
	return <-done
}

func setGlogFlags(t *testing.T, v string) {
	t.Helper()
	for k, val := range map[string]string{"logtostderr": "true", "v": v} {
		old := flag.Lookup(k).Value.String()
		if err := flag.Set(k, val); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
		t.Cleanup(func() { _ = flag.Set(k, old) })
	}
}

func TestGoldenDefaultOutput(t *testing.T) {
	// "fallback": nothing called slog.SetDefault (tests, library users).
	// "installed": pkg/cmd installed the glog handler as the slog default.
	for _, mode := range []string{"fallback", "installed"} {
		for _, v := range []string{"0", "2"} {
			t.Run(mode+"/v="+v, func(t *testing.T) {
				setGlogFlags(t, v)
				if mode == "installed" {
					restoreSlogDefault(t)
					if !SetDefaultIfUnset() {
						t.Fatal("SetDefaultIfUnset did not install the handler")
					}
				}
				got := captureStderr(t, goldenCases)
				checkGolden(t, "testdata/golden_v"+v+".txt", got)
			})
		}
	}
}

func checkGolden(t *testing.T, path, got string) {
	t.Helper()
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("default output changed.\n--- want\n%s--- got\n%s", want, got)
	}
}
