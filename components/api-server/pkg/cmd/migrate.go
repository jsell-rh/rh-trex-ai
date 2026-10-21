package cmd

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/config"
	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/db"
	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/db/db_session"
)

func NewMigrateCommand(serviceName string) *cobra.Command {
	dbConfig := config.NewDatabaseConfig()
	logConfig := config.NewLoggingConfig()

	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Run " + serviceName + " service data migrations",
		Long:  "Run " + serviceName + " service data migrations",
		Run: func(cmd *cobra.Command, args []string) {
			if err := runMigrate(dbConfig, logConfig); err != nil {
				slog.Error("Migration failed", "error", err)
				os.Exit(1)
			}
		},
	}

	dbConfig.AddFlags(cmd.PersistentFlags())
	cmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
	logConfig.AddFlags(cmd.PersistentFlags())
	return cmd
}

func runMigrate(dbConfig *config.DatabaseConfig, logConfig *config.LoggingConfig) error {
	if err := logConfig.Install(); err != nil {
		return fmt.Errorf("configuring logging: %w", err)
	}
	if err := dbConfig.ReadFiles(); err != nil {
		return fmt.Errorf("reading database configuration: %w", err)
	}
	connection := db_session.NewProdFactory(dbConfig)
	if err := db.Migrate(connection.New(context.Background())); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}
