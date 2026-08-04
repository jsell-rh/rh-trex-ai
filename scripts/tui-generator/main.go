package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	options := generateOptions{}
	flag.StringVar(&options.SpecPath, "spec", "", "path to the root OpenAPI document")
	flag.StringVar(&options.OutDir, "out", "", "standalone TUI output directory")
	flag.StringVar(&options.Module, "module", "github.com/example/trex-tui", "generated Go module path")
	flag.StringVar(&options.Binary, "binary", "trex-tui", "generated executable name")
	flag.Parse()
	if err := generate(options); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TUI generated in %s\n", options.OutDir)
}
