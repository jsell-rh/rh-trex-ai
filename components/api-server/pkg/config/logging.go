package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/spf13/pflag"

	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/logger"
)

type LoggingConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`

	levelFlag *pflag.Flag
	vFlag     *pflag.Flag
}

const defaultLogLevel = "info"

func NewLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		Level:  defaultLogLevel,
		Format: logger.FormatText,
	}
}

// AddFlags registers --log-level and --log-format. It also accepts the old
// glog flags -v, -logtostderr and -alsologtostderr, marked deprecated, so
// existing deployments keep starting. A flag that is already in fs (for
// example because the program still links glog) is left alone.
func (c *LoggingConfig) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&c.Level, "log-level", c.Level, "Log level: debug, info, warn or error")
	fs.StringVar(&c.Format, "log-format", c.Format, "Log format: text or json")
	c.levelFlag = fs.Lookup("log-level")

	if fs.Lookup("v") == nil {
		fs.IntP("v", "v", 0, "Deprecated: use --log-level. 2 or more selects debug, otherwise info")
		_ = fs.MarkDeprecated("v", "use --log-level instead")
	}
	c.vFlag = fs.Lookup("v")
	for _, name := range []string{"logtostderr", "alsologtostderr"} {
		if fs.Lookup(name) == nil {
			fs.Bool(name, true, "Deprecated: logs always go to stderr")
			_ = fs.MarkDeprecated(name, "logs always go to stderr")
		}
	}
}

// SlogLevel returns the configured level. Sources, first match wins:
//  1. --log-level passed on the command line.
//  2. -v passed on the command line.
//  3. --log-level set by an environment's flag defaults.
//  4. -v set by an environment's flag defaults (or glog's own default).
//  5. The built-in default, info.
//
// -v maps to debug when it is 2 or more, and to info below that.
func (c *LoggingConfig) SlogLevel() (slog.Level, error) {
	switch {
	case c.levelFlag != nil && c.levelFlag.Changed:
		return parseLevel(c.Level)
	case c.vFlag != nil && c.vFlag.Changed:
		return levelFromV(c.vFlag.Value.String())
	case c.Level != defaultLogLevel:
		return parseLevel(c.Level)
	case c.vFlag != nil && c.vFlag.Value.String() != "0":
		return levelFromV(c.vFlag.Value.String())
	default:
		return parseLevel(c.Level)
	}
}

func parseLevel(s string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo, fmt.Errorf("invalid --log-level %q: %w", s, err)
	}
	return level, nil
}

func levelFromV(s string) (slog.Level, error) {
	v, err := strconv.Atoi(s)
	if err != nil {
		return slog.LevelInfo, fmt.Errorf("invalid -v value %q: %w", s, err)
	}
	if v >= 2 {
		return slog.LevelDebug, nil
	}
	return slog.LevelInfo, nil
}

func (c *LoggingConfig) ReadFiles() error {
	return nil
}

// Validate reports an invalid level or format.
func (c *LoggingConfig) Validate() error {
	if _, err := c.SlogLevel(); err != nil {
		return err
	}
	if c.Format != logger.FormatText && c.Format != logger.FormatJSON {
		return fmt.Errorf("invalid --log-format %q: use %q or %q", c.Format, logger.FormatText, logger.FormatJSON)
	}
	return nil
}

// Install makes a stderr handler with the configured level and format, wrapped
// with logger.WithContextAttrs, the slog default. It does nothing when the
// program has set its own slog default (see logger.SetDefaultIfUnset).
func (c *LoggingConfig) Install() error {
	level, err := c.SlogLevel()
	if err != nil {
		return err
	}
	h, err := logger.NewHandler(os.Stderr, c.Format, level)
	if err != nil {
		return err
	}
	logger.SetDefaultIfUnset(logger.WithContextAttrs(h))
	return nil
}
