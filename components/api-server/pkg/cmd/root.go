package cmd

import (
	"flag"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/logger"
)

func NewRootCommand(serviceName, description string) *cobra.Command {
	_ = flag.CommandLine.Parse([]string{})

	// Programs that still link glog keep their glog output on stderr.
	if f := flag.Lookup("logtostderr"); f != nil {
		_ = f.Value.Set("true")
	}

	// Install a text handler at info level until the environment applies
	// --log-level and --log-format. A program that already called
	// slog.SetDefault keeps its handler.
	logger.SetDefaultIfUnset(logger.WithContextAttrs(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}),
	))

	rootCmd := &cobra.Command{
		Use:  serviceName,
		Long: description,
	}

	return rootCmd
}
