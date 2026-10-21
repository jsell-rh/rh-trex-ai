package config

import (
	"flag"
	"log/slog"
	"testing"

	"github.com/spf13/pflag"
)

func parseLogging(t *testing.T, fs *pflag.FlagSet, args ...string) *LoggingConfig {
	t.Helper()
	c := NewLoggingConfig()
	c.AddFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return c
}

func TestLoggingLevel(t *testing.T) {
	cases := []struct {
		args []string
		want slog.Level
	}{
		{nil, slog.LevelInfo},
		{[]string{"--log-level=debug"}, slog.LevelDebug},
		{[]string{"--log-level=warn"}, slog.LevelWarn},
		{[]string{"--log-level=ERROR"}, slog.LevelError},
		// Deprecated glog flags still work.
		{[]string{"-v=10"}, slog.LevelDebug},
		{[]string{"-v=2"}, slog.LevelDebug},
		{[]string{"-v=1"}, slog.LevelInfo},
		{[]string{"--logtostderr", "--alsologtostderr", "-v=0"}, slog.LevelInfo},
		// --log-level wins over -v.
		{[]string{"-v=10", "--log-level=warn"}, slog.LevelWarn},
	}
	for _, tc := range cases {
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		got, err := parseLogging(t, fs, tc.args...).SlogLevel()
		if err != nil || got != tc.want {
			t.Errorf("%v: got %v, %v; want %v", tc.args, got, err, tc.want)
		}
	}
}

// TestLoggingLevelWithGlogLinked covers a program that still links glog:
// glog has already registered -v on the Go flag set, so the logging config
// must reuse it instead of registering its own.
func TestLoggingLevelWithGlogLinked(t *testing.T) {
	goFlags := flag.NewFlagSet("glog", flag.ContinueOnError)
	goFlags.Int("v", 0, "glog verbosity")
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.AddGoFlagSet(goFlags)

	got, err := parseLogging(t, fs, "-v=4").SlogLevel()
	if err != nil || got != slog.LevelDebug {
		t.Errorf("got %v, %v; want debug", got, err)
	}
}

func TestLoggingValidate(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		valid bool
	}{
		{nil, true},
		{[]string{"--log-format=json"}, true},
		{[]string{"--log-format=xml"}, false},
		{[]string{"--log-level=loud"}, false},
		{[]string{"-v=lots"}, false},
	} {
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		c := NewLoggingConfig()
		c.AddFlags(fs)
		if err := fs.Parse(tc.args); err != nil {
			if tc.valid {
				t.Errorf("%v: parse: %v", tc.args, err)
			}
			continue
		}
		if err := c.Validate(); (err == nil) != tc.valid {
			t.Errorf("%v: Validate() = %v, want valid=%v", tc.args, err, tc.valid)
		}
	}
}
