# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

This is the **Trusted Software Components (TSC) Platform** — an IR-first application platform where AI agents write declarative YAML specs (`app.tsc.yaml`) and a deterministic compiler assembles working Go applications from pre-audited, version-pinned trusted components.

**AI agents write specs, not code.** The compiler does the rest.

## Key Directories

```
tsc/spec/           Core interfaces: Component, Application, Registrar, JSON Schema
tsc/components/     Trusted component library (7 components)
tsc/compiler/       TSC compiler: parse → resolve → generate
tsc/examples/       Reference applications
cmd/tsc/            tsc CLI entrypoint
TSC-ARCHITECTURE.md Full architecture reference
```

## Development Commands

### Build the TSC compiler

```bash
go build -o /tmp/tsc ./cmd/tsc
```

### Test

```bash
go test ./tsc/...
```

### Compile an example spec

```bash
/tmp/tsc compile tsc/examples/dinosaur-registry/app.tsc.yaml \
  --rh-trex-ai $(pwd) \
  -o /tmp/dinosaur-out

cd /tmp/dinosaur-out && go build -o app .
```

### Validate a spec

```bash
/tmp/tsc validate tsc/examples/dinosaur-registry/app.tsc.yaml
```

## IR Spec Format

All application specs follow `tsc/spec/schema.json`. Validate with `tsc validate`.

Key sections:
- `components` — SBOM: pinned trusted component versions
- `resources` — data entities (fields, operations, events)
- `api` — REST and gRPC configuration
- `auth` — JWT or none
- `database` — postgres with auto-migrations
- `observability` — health check and metrics ports

## Trusted Components

Components implement `tsc/spec.Component`. Each component:
- Has an `AuditHash()` that the compiler verifies against the registry
- Implements `Configure(ComponentConfig)`, `Register(*Application)`, `Start(ctx)`, `Stop(ctx)`
- Is immutable after audit — bug fixes create new versions

To add a new component: implement `spec.Component`, add an audit record to the registry, and add the component name to the JSON Schema's `components.propertyNames.enum`.

## What NOT to do

- Do not write business logic code — it belongs in components or in the IR spec
- Do not modify component implementations after they've been audited (create a new version)
- Do not add fields to `app.tsc.yaml` that aren't in `tsc/spec/schema.json` — the compiler validates strictly
- Do not use `additionalProperties: true` in the schema — strictness is a trust property

## Legacy Code

The `cmd/trex/`, `pkg/`, `plugins/`, `scripts/`, and `templates/` directories contain the original rh-trex template code that predates this project. They are kept as historical reference only. **Do not extend or use them for new work.** All new development goes in `tsc/`.

## Module

```
github.com/openshift-online/rh-trex-ai
```
