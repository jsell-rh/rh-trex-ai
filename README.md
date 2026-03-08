# Trusted Software Components (TSC) Platform

An IR-first application platform where **AI agents write declarative specs, not code**.

Enterprises adopting AI-driven development face a fundamental trust problem: AI agents produce non-deterministic code that cannot be formally audited. TSC solves this by inverting the model — AI writes a structured Intermediate Representation (IR), and a deterministic compiler assembles working applications from pre-audited, version-pinned trusted components.

## The Core Idea

```
AI Agent
  │
  │  edits only this file:
  ▼
app.tsc.yaml          ← the IR spec (declarative, schema-validated)
  │
  │  tsc compile app.tsc.yaml -o ./out
  ▼
Compiler
  │  resolves trusted components (audited, version-pinned)
  │  generates minimal wiring code (main.go, go.mod, migrations/)
  ▼
go build ./out        ← working binary
```

The AI never touches source code. Every line of generated code comes from audited, immutable trusted components.

## Quick Start

### 1. Write your application spec

```yaml
# app.tsc.yaml
apiVersion: tsc/v1
kind: Application

metadata:
  name: my-service
  version: 1.0.0

components:
  tsc-http:     v1.0.0
  tsc-postgres: v1.0.0
  tsc-auth-jwt: v1.0.0
  tsc-health:   v1.0.0
  tsc-metrics:  v1.0.0

resources:
  - name: Widget
    plural: widgets
    fields:
      - name: id
        type: uuid
        required: true
        auto: created
      - name: name
        type: string
        required: true
        max_length: 255
      - name: created_at
        type: timestamp
        auto: created
      - name: deleted_at
        type: timestamp
        soft_delete: true
    operations: [create, read, update, delete, list]

api:
  rest:
    base_path: /api/v1
    version_header: true

auth:
  type: jwt
  jwk_url: "${JWK_CERT_URL}"
  required: true
  allow_mock: "${OCM_MOCK_ENABLED}"

database:
  type: postgres
  migrations: auto

observability:
  health_check:
    port: 8083
    path: /healthz
  metrics:
    port: 8080
    path: /metrics
```

### 2. Compile

```bash
# Build the tsc compiler
go build -o /usr/local/bin/tsc ./cmd/tsc

# Compile your spec into a runnable Go project
tsc compile app.tsc.yaml \
  --rh-trex-ai ~/code/scratch/rh-trex-ai \
  -o ./my-service-out
```

### 3. Build and run

```bash
cd my-service-out
go build -o app .

# Run with a PostgreSQL database
export JWK_CERT_URL=...
export OCM_MOCK_ENABLED=true
./app
```

REST API on `:8000`, health check on `:8083`, metrics on `:8080`.

### 4. Add a new resource — zero code required

```yaml
# Edit app.tsc.yaml — add this resource block:
  - name: Fossil
    plural: fossils
    fields:
      - name: id
        type: uuid
        required: true
        auto: created
      - name: location
        type: string
        required: true
    operations: [create, read, update, delete, list]
```

```bash
# Recompile — the compiler handles everything
tsc compile app.tsc.yaml --rh-trex-ai . -o ./my-service-out
cd my-service-out && go build -o app .
# /api/v1/fossils endpoints now work. No code written.
```

## Repository Structure

```
tsc/
  spec/           IR type definitions — Component interface, Application, JSON Schema
  components/     Trusted component library (7 components, 62 tests)
    registry.go   Audit verification registry
    http/         HTTP server, routing, middleware
    postgres/     DB pool, CRUD DAOs, migrations, pg_notify
    auth/jwt/     JWT validation, RBAC
    grpc/         gRPC server, interceptors
    health/       Health check server
    metrics/      Prometheus metrics
    events/       PostgreSQL LISTEN/NOTIFY
  compiler/       TSC compiler: parse → resolve → generate
  examples/
    dinosaur-registry/
      app.tsc.yaml  Reference application (trex parity demo)
cmd/
  tsc/            tsc CLI entrypoint
TSC-ARCHITECTURE.md  Full architecture decision record
```

## Testing

```bash
go test ./tsc/...
# ok  tsc/compiler          (37 tests)
# ok  tsc/components        (9 tests)
# ok  tsc/components/auth/jwt (6 tests)
# ok  tsc/components/events (4 tests)
# ok  tsc/components/postgres (6 tests)
```

## Trusted Component Catalog

| Component | Version | Purpose | Ports |
|-----------|---------|---------|-------|
| `tsc-http` | v1.0.0 | HTTP server, routing, CORS middleware | :8000 |
| `tsc-postgres` | v1.0.0 | DB pool, CRUD DAOs, auto-migrations, soft delete | — |
| `tsc-auth-jwt` | v1.0.0 | JWT validation, RBAC middleware | — |
| `tsc-grpc` | v1.0.0 | gRPC server, pre-auth interceptor hook | :9000 |
| `tsc-health` | v1.0.0 | Liveness + readiness check | :8083 |
| `tsc-metrics` | v1.0.0 | Prometheus metrics | :8080 |
| `tsc-events` | v1.0.0 | PostgreSQL LISTEN/NOTIFY event loop | — |

Each component: audited, version-pinned, immutable after audit. Bug fixes create new versions.

## Why TSC?

| Traditional AI-Generated Code | TSC |
|-------------------------------|-----|
| AI writes arbitrary code | AI writes validated IR spec |
| No formal audit trail | Every component has audit record + hash |
| Non-deterministic output | Same spec + versions = same binary, always |
| Hard to SBOM | Components block IS the SBOM |
| New resource = code review | New resource = YAML field, zero code |

## IR Spec Reference

Full JSON Schema: `tsc/spec/schema.json`

Validate your spec:
```bash
tsc validate app.tsc.yaml
```

## Architecture

See [TSC-ARCHITECTURE.md](./TSC-ARCHITECTURE.md) for full architecture decisions, component interface contracts, and the compiler design.
