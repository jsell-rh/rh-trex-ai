package compiler

import (
	"fmt"
	"os/exec"
)

// Compiler orchestrates the full TSC compilation pipeline.
// It operates like a build tool (go build, cargo build) — not a code generator.
//
// Pipeline:
//  1. Parse + validate the IR spec (app.tsc.yaml) using the canonical spec validator
//  2. Resolve component entries from the trusted registry
//  3. Verify audit hashes (when a local source dir is configured)
//  4. Generate wiring code using the frozen spec.Application API
type Compiler struct {
	registry    Registry
	sourceDir   string // optional; enables audit hash verification
	rhtexAIPath string // optional; local path to rh-trex-ai for go.mod replace directive
}

// New creates a Compiler backed by the given registry.
// sourceDir: non-empty enables audit hash verification against local component source.
// rhtexAIPath: non-empty adds a replace directive to the generated go.mod pointing to
// the local rh-trex-ai checkout, enabling the generated project to `go build` immediately.
func New(registry Registry, sourceDir, rhtexAIPath string) *Compiler {
	return &Compiler{
		registry:    registry,
		sourceDir:   sourceDir,
		rhtexAIPath: rhtexAIPath,
	}
}

// Compile compiles specPath and writes the generated project into outputDir.
func (c *Compiler) Compile(specPath, outputDir string) error {
	// Step 1: Parse + validate IR spec
	ir, err := Parse(specPath)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	// Step 2 + 3: Resolve components, verify audit hashes
	resolver := NewResolver(c.registry, c.sourceDir)
	components, err := resolver.ResolveAll(ir.Components)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	// Step 4: Generate wiring code
	gen := NewGenerator(outputDir, c.rhtexAIPath)
	if err := gen.Generate(ir, components); err != nil {
		return fmt.Errorf("generate: %w", err)
	}

	// Step 5: Run go mod tidy on the generated project so go.sum is populated
	// and the project is immediately buildable with `go build`.
	if c.rhtexAIPath != "" {
		cmd := exec.Command("go", "mod", "tidy")
		cmd.Dir = outputDir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go mod tidy in generated project: %w\noutput: %s", err, out)
		}
	}

	return nil
}
