package cmd

import (
	"flag"

	"github.com/golang/glog"
	"github.com/spf13/cobra"

	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/logger"
)

func NewRootCommand(serviceName, description string) *cobra.Command {
	_ = flag.CommandLine.Parse([]string{})

	if err := flag.Set("logtostderr", "true"); err != nil {
		glog.Infof("Unable to set logtostderr to true")
	}

	// Route log/slog records through glog, in trex's usual text format,
	// unless the program already called slog.SetDefault. A program can also
	// call slog.SetDefault later; the last call wins.
	logger.SetDefaultIfUnset()

	rootCmd := &cobra.Command{
		Use:  serviceName,
		Long: description,
	}

	return rootCmd
}
