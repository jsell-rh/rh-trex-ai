# Trusted Software Components (TSC) Platform — Architecture

## Company Vision

Enterprises adopting AI-driven software development face a fundamental trust problem: AI agents produce non-deterministic code that cannot be formally audited, verified, or trusted at the component level. Traditional software supply-chain guarantees (SBOM, FIPS compliance, CVE tracking) require stable, audited artifacts — not generated code.

**TSC solves this by inverting the model:**

Instead of AI agents writing code, AI agents write an *Intermediate Representation* (IR) — a declarative application spec. The IR is then *deterministically compiled* into a working application by assembling pre-audited, version-pinned trusted components. The AI never touches source code.

### Key Properties

- **Trusted**: Every component is audited before inclusion in the registry. Audit records are immutable.
- **Deterministic**: Same IR + same component versions always produce the same binary.
- **Auditable**: The full bill-of-materials (which components, which versions) is part of the IR.
- **AI-native**: LLMs work with a structured, constrained IR — not unconstrained code. This is the user-friction solution that past IR attempts lacked.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         AI Agent Layer                          │
│                                                                 │
│   LLM reads/writes app.tsc.yaml (the IR spec)                  │
│   AI never touches source code directly                         │
└────────────────────┬────────────────────────────────────────────┘
                     │ app.tsc.yaml
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                       TSC Compiler                              │
│                                                                 │
│   1. Validates IR against JSON Schema                           │
│   2. Resolves components from the Component Registry            │
│   3. Generates minimal wiring code (main.go + go.mod only)     │
│   4. Produces a compilable, dependency-locked Go module         │
└────────────────────┬────────────────────────────────────────────┘
                     │ Generated project
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Trusted Component Registry                    │
│                                                                 │
│   tsc-http      v1.x   (HTTP server, routing, middleware)       │
│   tsc-postgres  v1.x   (DB session, CRUD DAO, migrations)       │
│   tsc-auth-jwt  v1.x   (JWT validation, RBAC middleware)        │
│   tsc-grpc      v1.x   (gRPC server, interceptors)             │
│   tsc-health    v1.x   (health check server)                    │
│   tsc-metrics   v1.x   (Prometheus metrics)                     │
│   tsc-events    v1.x   (PostgreSQL LISTEN/NOTIFY events)        │
│                                                                 │
│   Each component: interface + audited impl + tests + audit log  │
└─────────────────────────────────────────────────────────────────┘
```

---

## IR Specification (TSC Spec)

The IR is a YAML document that describes WHAT an application does — not HOW it does it.

### Example: Dinosaur Registry (trex parity target)

```yaml
apiVersion: tsc/v1
kind: Application

metadata:
  name: dinosaur-registry
  version: 1.0.0

# Trusted component versions (pinned, forms the SBOM)
components:
  tsc-http:     v1.0.0
  tsc-postgres: v1.0.0
  tsc-auth-jwt: v1.0.0
  tsc-grpc:     v1.0.0
  tsc-health:   v1.0.0
  tsc-metrics:  v1.0.0
  tsc-events:   v1.0.0

# Data resources — what the app stores and manages
resources:
  - name: Dinosaur
    plural: dinosaurs
    fields:
      - name: species
        type: string
        required: true
        max_length: 255
      - name: description
        type: string
      - name: created_at
        type: timestamp
        auto: created
      - name: updated_at
        type: timestamp
        auto: updated
      - name: deleted_at
        type: timestamp
        soft_delete: true
    operations: [create, read, update, delete, list]
    events: true  # emit PostgreSQL events on mutations

# API configuration
api:
  rest:
    base_path: /api/v1
    version_header: true
  grpc:
    enabled: true

# Authentication
auth:
  type: jwt
  jwk_url: "${JWK_CERT_URL}"
  required: true
  allow_mock: "${OCM_MOCK_ENABLED}"

# Database
database:
  type: postgres
  migrations: auto

# Observability
observability:
  health_check:
    port: 8083
  metrics:
    port: 8080
    path: /metrics
```

### IR Schema Rules

1. `apiVersion` and `kind` are required and versioned — enables forward compatibility.
2. `components` block is the SBOM — all component versions pinned explicitly.
3. `resources` describe data shapes; the compiler infers CRUD patterns.
4. AI agents may ONLY edit the IR file — never generated code.
5. The compiler rejects unknown component names (not in the registry).

---

## Trusted Component Interface Contract

Each component must implement the `tsc.Component` interface:

```go
// Component is implemented by every trusted component.
type Component interface {
    // Name returns the registry name (e.g., "tsc-http").
    Name() string

    // Version returns the semver string (e.g., "v1.0.0").
    Version() string

    // AuditHash returns the SHA-256 of the component source at audit time.
    // The compiler verifies this matches the registry record.
    AuditHash() string

    // Configure applies the IR spec section for this component.
    Configure(cfg ComponentConfig) error

    // Register hooks this component into the application.
    Register(app *Application) error
}
```

All component implementations live in `tsc/components/` and are never modified after passing audit. Bug fixes create new audited versions.

---

## TSC Compiler

The compiler is a CLI tool: `tsc compile <spec.yaml> --output <dir>`

### Compilation Steps

1. **Parse + Validate**: Read `app.tsc.yaml`, validate against JSON Schema.
2. **Resolve Components**: Look up each component version in the local registry index.
3. **Verify Audit Hashes**: Confirm component source hashes match audit records.
4. **Generate Wiring**: Write ONLY:
   - `main.go` — component registration and application bootstrap
   - `go.mod` — exact component dependency versions
   - `migrations/` — SQL migration files derived from `resources` block
5. **Output**: A directory that `go build` produces a working binary.

### What the Compiler NEVER Generates

- Business logic
- Handler implementations
- Service implementations
- DAO implementations
- Auth logic

All of these come from trusted component implementations, not generated code.

---

## Trusted Component Registry

The registry is a versioned catalog of components. Each entry contains:

```yaml
name: tsc-postgres
version: v1.0.0
module: github.com/openshift-online/tsc-components/postgres
audit:
  date: 2026-03-08
  auditor: security-team
  hash: sha256:abc123...
  findings: []  # empty = passed
  cve_scan: passed
  fips_compliant: true
```

Registry entries are append-only. A component version, once audited, is immutable.

---

## Repository Layout

Working in `github.com/openshift-online/rh-trex-ai` with `.worktrees/` for parallel development:

```
rh-trex-ai/
  TSC-ARCHITECTURE.md       # This document (CTO-owned)
  tsc/
    spec/                   # IR JSON Schema (TSC-Architect owns)
      schema.json
      validate.go
    compiler/               # TSC Compiler (TSC-Compiler owns)
      main.go
      parser.go
      resolver.go
      generator.go
    components/             # Trusted Component Library (TSC-Library owns)
      registry.go           # Registry index + audit verification
      http/                 # tsc-http component
      postgres/             # tsc-postgres component
      auth/jwt/             # tsc-auth-jwt component
      grpc/                 # tsc-grpc component
      health/               # tsc-health component
      metrics/              # tsc-metrics component
      events/               # tsc-events component
    examples/
      dinosaur-registry/    # The "trex parity" demo app
        app.tsc.yaml        # The only file an AI agent would write
  .worktrees/
    tsc-spec/               # TSC-Architect workspace
    tsc-components/         # TSC-Library workspace
    tsc-compiler/           # TSC-Compiler workspace
```

---

## Agent Organization

| Role | Agent | Branch | Mandate |
|------|-------|---------|---------|
| CTO | CTO | main | Strategy, architecture gates, team coordination |
| Chief Architect | TSC-Architect | feature/tsc-spec | IR JSON Schema design, component interface contracts |
| Component Library Lead | TSC-Library | feature/tsc-components | Trusted component implementations (http, postgres, auth, grpc, health, metrics, events) |
| Compiler Lead | TSC-Compiler | feature/tsc-compiler | TSC compiler: parse IR, resolve components, generate wiring |

---

## Definition of Done (Trex Parity)

The TSC platform is complete (at trex parity) when:

1. [ ] `app.tsc.yaml` describing the Dinosaur Registry compiles without errors
2. [ ] Generated binary starts and serves REST API on :8000
3. [ ] Generated binary serves gRPC API on :9000
4. [ ] CRUD operations on `/api/v1/dinosaurs` work end-to-end with PostgreSQL
5. [ ] JWT authentication enforced on all endpoints
6. [ ] Health check server responds on :8083
7. [ ] Prometheus metrics exposed on :8080/metrics
8. [ ] PostgreSQL LISTEN/NOTIFY events emitted on resource mutations
9. [ ] Compiler audit hash verification passes (no tampered components)
10. [ ] An AI agent (via Claude) can modify `app.tsc.yaml` to add a new resource and recompile successfully

---

## Standing Orders for All Agents

1. **Read this document before starting work.** Path: `~/code/scratch/rh-trex-ai/TSC-ARCHITECTURE.md`
2. **Post status updates every 10 minutes** during active work.
3. **Work in your assigned worktree** — do not modify files in other agents' worktrees.
4. **Component interface contracts** (defined by TSC-Architect) are frozen once posted. Compiler and Library agents must wait for contracts before implementing.
5. **Post blockers immediately** — do not spin on blocked work.
6. **Tag questions for CTO with `[?BOSS]`** and continue working on what you can.
7. Coordinator space: `TrustedSoftwareComponents` at `http://localhost:8899`
