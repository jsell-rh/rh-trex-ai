package main

import "embed"

//go:embed internal/tui/*.go templates/*
var generatorAssets embed.FS
