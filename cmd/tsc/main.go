// tsc is the Trusted Software Components compiler CLI.
//
// Usage:
//
//	tsc compile <spec.yaml> --output <dir> [--registry <dir>] [--source <dir>]
//
// The compiler reads an IR spec (app.tsc.yaml), resolves trusted components from
// the registry, verifies audit hashes, and generates the minimal wiring code needed
// to produce a working binary via `go build`.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/openshift-online/rh-trex-ai/tsc/compiler"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tsc",
		Short: "Trusted Software Components compiler",
		Long: `tsc compiles a TSC IR spec (app.tsc.yaml) into a deployable Go application.

AI agents write the IR spec. The compiler produces the source code.
All generated code is assembled from pre-audited, version-pinned trusted components.`,
	}
	cmd.AddCommand(compileCmd())
	return cmd
}

func compileCmd() *cobra.Command {
	var (
		outputDir   string
		registryDir string
		sourceDir   string
		rhtexAIPath string
	)

	cmd := &cobra.Command{
		Use:   "compile <spec.yaml>",
		Short: "Compile a TSC IR spec into a Go application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			specPath := args[0]

			if outputDir == "" {
				return fmt.Errorf("--output is required")
			}

			var registry compiler.Registry
			if registryDir != "" {
				registry = compiler.NewFileRegistry(registryDir)
			} else {
				// Use the embedded stub registry for development.
				// Production builds will require --registry pointing to the signed catalog.
				registry = compiler.NewStubRegistry()
			}

			c := compiler.New(registry, sourceDir, rhtexAIPath)
			if err := c.Compile(specPath, outputDir); err != nil {
				return fmt.Errorf("compilation failed: %w", err)
			}

			fmt.Printf("Compiled %q → %s\n", specPath, outputDir)
			if rhtexAIPath != "" {
				fmt.Println("Run: cd", outputDir, "&& go build -o app .")
			} else {
				fmt.Println("Run: cd", outputDir, "&& go build -o app . (ensure rh-trex-ai is published or use --rh-trex-ai)")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for generated project (required)")
	cmd.Flags().StringVar(&registryDir, "registry", "", "Path to local component registry index directory")
	cmd.Flags().StringVar(&sourceDir, "source", "", "Path to component source directory (enables audit hash verification)")
	cmd.Flags().StringVar(&rhtexAIPath, "rh-trex-ai", "", "Absolute path to local rh-trex-ai checkout (adds replace directive to generated go.mod)")

	return cmd
}
