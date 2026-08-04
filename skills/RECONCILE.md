# Reconciliation Checkpoint

**Last Updated:** 2026-08-04
**Last Run By:** Codex (reconcile skill — vertically anchored TUI service context)

---

## Coverage Summary

| Domain | Specs | Requirements | Covered | Partial | Missing | Coverage |
|--------|-------|-------------|---------|---------|---------|----------|
| framework | 4 | 24 | 24 | 0 | 0 | 100% |
| api | 2 | 20 | 20 | 0 | 0 | 100% |
| data | 2 | 14 | 13 | 1 | 0 | 92.9% |
| security | 3 | 17 | 17 | 0 | 0 | 100% |
| codegen | 6 | 88 | 78 | 9 | 1 | 88.6% |
| standards | 4 | 30 | 30 | 0 | 0 | 100% |
| **Total** | **21** | **193** | **182** | **10** | **1** | **94.3%** |

## Spec Dependency Order

Reconciliation MUST proceed in this order to respect dependencies:

- **Layer 0:** STD-001, STD-004, SEC-003
- **Layer 1:** FW-001
- **Layer 2:** FW-002, FW-003, FW-004
- **Layer 3:** DA-001, API-001, API-002
- **Layer 4:** DA-002, SEC-001, STD-002
- **Layer 5:** SEC-002, STD-003
- **Layer 6:** CG-001, CG-005
- **Layer 7:** CG-002, CG-003, CG-004, CG-006

## Gap Table

| ID | Spec | Requirement | Status | Severity | Notes |
|----|------|-------------|--------|----------|-------|
| GAP-001 | SEC-001 | JWK Key Loading: Multi-URL support on HTTP | closed | critical | Fixed: `JWTHandler.keysURL string` → `keysURLs []string`. `apiserver.go` now passes full `JwkCertURLs` slice via `WithKeysURLs()`. |
| GAP-002 | SEC-001 | JWK Key Loading: Additive file+URL merging on HTTP | closed | critical | Fixed: `loadKeys()` restructured to load file first, then iterate all URLs additively into a combined `newKeys` map. `parseJWKSet()` → `parseAndStoreKeys()` merges into target map. Mirrors gRPC `JWKKeyProvider` architecture. |
| GAP-003 | SEC-001 | Automatic Key Refresh: On-demand refresh from ALL sources on HTTP | closed | major | Auto-resolved by GAP-002: `validateToken()` calls `loadKeys()` which now loads from all configured sources (file + all URLs). |
| GAP-004 | SEC-001 | Multi-Issuer Support: HTTP/gRPC behavioral consistency | closed | major | Auto-resolved by GAP-001 + GAP-002: HTTP `JWTHandler` now has architectural parity with gRPC `JWKKeyProvider` — multi-URL, additive merging, all-source refresh. |
| GAP-005 | DA-002 | Advisory Lock for Migration Concurrency | partial | major | A reusable `db.Migrations` advisory-lock type exists in `pkg/db/advisory_locks.go`, but `pkg/db/migrations.go` still invokes gormigrate without using it. |
| GAP-006 | API-001 | OpenAPI Specification Compliance | closed | major | All registered dinosaur, fossil, and scientist CRUD methods, including DELETE, are documented in the split OpenAPI files and generated clients. |
| GAP-007 | API-001 | Stable Operation Identity | closed | major | The resolved root document has 15 unique semantic IDs (`list`, `create`, `get`, `update`, and `delete` for each entity), and all generated consumers compile against the migration. |
| GAP-008 | API-001 | Canonical OpenAPI Completeness | closed | major | The fully resolved root document matches every registered application route and method; generated embedded and Go-client specifications were regenerated from it. |
| GAP-033 | API-001 | Automated Route-Spec Parity | closed | major | `cmd/trex/route_openapi_parity_test.go` resolves split path-item references and compares normalized method/path sets against the discovered Gorilla router. |
| GAP-009 | CG-001 | Generated Operation Identity | closed | minor | Both entity OpenAPI templates emit semantic IDs and complete DELETE contracts; `entity_openapi_template_test.go` renders and resolves a synthetic entity to assert all five operations. |
| GAP-010 | CG-002 | OpenAPI-Driven Generation | partial | minor | The CLI discovers root schemas and assumes resources. It renders list/get/create commands only, rather than projecting exactly the operations present in OpenAPI. |
| GAP-011 | CG-002 | Shared IR Consumption | closed | minor | The CLI imports `scripts/openapi-ir`, projects resource views from the normalized document, and contains no raw YAML parser. |
| GAP-012 | CG-002 | Scoped Path Fidelity | missing | minor | CLI resources retain one `PathSegment`; nested scope parameters and exact route templates are discarded. |
| GAP-043 | CG-002 | Generated CLI Acceptance Tests | partial | minor | Tests now generate, test, build, and execute the CLI and inspect its exact repository route, but do not yet exercise scoped/query/body/auth requests against a mock server. |
| GAP-013 | CG-003 | Multi-Language Output | partial | minor | All three languages are generated, but methods are derived from inferred resources and selected heuristics rather than every documented operation. |
| GAP-014 | CG-003 | Shared IR Consumption | closed | minor | SDK projection is backed solely by `scripts/openapi-ir`; independent YAML traversal and schema-name resource discovery were removed. |
| GAP-015 | CG-003 | Operation and Path Fidelity | partial | minor | SDK models reduce routes to an API prefix plus one path segment; arbitrary nested parameters and general operation inputs are not retained. |
| GAP-016 | CG-003 | OpenAPI Specification Compliance | partial | minor | Basic types, requiredness, and limited `allOf` are handled, but the parser does not preserve the complete schema semantics required for exact fidelity. |
| GAP-044 | CG-003 | Generated SDK Acceptance Tests | partial | minor | Go is compiled and behavior-tested, Python is compiled/imported, and TypeScript is type-checked with pinned tooling; cross-language scoped/query/body behavioral parity remains absent. |
| GAP-017 | CG-004 | OpenShift Console Plugin Structure | partial | minor | Pages are generated from root schema names and forms are assumed, rather than being projected from displayable resource views and actual operations. |
| GAP-018 | CG-004 | Shared IR Consumption | closed | minor | Console resources are projected from canonical IR resource views and schemas; the generator no longer parses raw YAML. |
| GAP-019 | CG-004 | Scoped View and Action Fidelity | partial | minor | Patch/delete flags are detected for flat resources, but parent scopes, general actions, streams, and exact operation routes are not modeled. |
| GAP-045 | CG-004 | Generated Console Acceptance Tests | partial | minor | The pinned lock graph is installed and the generated production plugin builds; scoped components, unsupported actions, and exact authenticated requests still lack runtime assertions. |
| GAP-020 | CG-005 | Canonical OpenAPI Front End | closed | minor | `scripts/openapi-ir` is the shared normalized front end consumed by CLI, SDK, console, and TUI modules. |
| GAP-021 | CG-005 | Reference Resolution | closed | minor | The loader resolves split local references, preserves recursive schema identity, and diagnoses unresolved and cyclic non-schema references. |
| GAP-022 | CG-005 | Operation Identity | closed | minor | The IR rejects missing and duplicate IDs with source diagnostics; all current documented operations declare unique IDs. |
| GAP-023 | CG-005 | Operation Fidelity | closed | minor | Operations retain ordered routes, all input locations, serialization, request/response content, metadata, servers, and inherit/none/override security states. |
| GAP-024 | CG-005 | Schema Fidelity | closed | minor | Canonical schema nodes retain composition, constraints, access modes, nullability, discriminator data, defaults, examples, and reference identity. |
| GAP-025 | CG-005 | Usage-Based Schema Roles | closed | minor | Request, response, list-item, error, parameter, and event roles are derived from operation usage rather than names. |
| GAP-026 | CG-005 | Resource View Graph | closed | minor | Multi-scope collection/item views are distinct graph nodes and may share schema identities. |
| GAP-027 | CG-005 | Relationship Semantics | closed | minor | Link Objects and conservative inferred containment retain endpoints, full standard runtime-expression mappings, and explicit/inferred provenance; ambiguous inference remains disconnected. |
| GAP-028 | CG-005 | Operation-Derived Capabilities | closed | minor | Canonical capabilities represent only actual CRUD, action, and streaming operations. |
| GAP-029 | CG-005 | Extension Preservation | closed | minor | Document, path, operation, parameter, schema, and property extensions retain values and source locations. |
| GAP-030 | CG-005 | Deterministic Normalization | closed | minor | Repeated normalization and all target generation are byte-stable in tests. |
| GAP-031 | CG-005 | Actionable Diagnostics | closed | minor | Validation errors include source files, JSON Pointers, and operation/schema context before rendering begins. |
| GAP-032 | CG-005 | Loader Conformance Fixtures | closed | minor | Tracked fixtures cover single/split documents, recursion, unresolved references, invalid cycles, and root-boundary rejection. |
| GAP-034 | CG-005 | Bounded Reference Resolution | closed | minor | References are canonicalized and constrained by allowed roots, including symlink, traversal, absolute-path, and URI checks. |
| GAP-035 | CG-005 | Safe Target Projection | closed | minor | Shared identifier/path validation, safe joins, target escaping, and adversarial projection tests prevent output-root and interpolation escapes. |
| GAP-036 | CG-005 | Atomic Contract Evolution | closed | minor | `make test-generators` compiles and tests the IR and all four nested consumer modules; unit CI invokes that target. |
| GAP-041 | CG-005 | Pre-Migration Characterization Gate | closed | minor | Repository and shared-fixture characterization tests plus ignored pre-implementation SHA manifests prove legacy-compatible outcomes across parser migration. |
| GAP-042 | CG-005 | Repository OpenAPI Generation Gate | closed | minor | CLI, SDK, console, and TUI consumers generate the real split-file repository spec into temporary roots and run target acceptance without a database or API service. |
| GAP-037 | CG-005 | Operation and Security Conformance Fixtures | closed | minor | Fixtures assert flat/scoped operations, actions, streams, serialization, and inherited/none/override security. |
| GAP-038 | CG-005 | Schema and Role Conformance Fixtures | closed | minor | Fixtures assert recursive/composed schema semantics and all required usage roles without helper-resource promotion. |
| GAP-039 | CG-005 | Resource View and Metadata Conformance Fixtures | closed | minor | Fixtures assert multi-scope views, explicit and inferred relationships, ambiguity handling, parameter mappings, and extensions. |
| GAP-040 | CG-005 | Consumer Fixture Conformance | closed | minor | All four consumer suites load the shared fixture through the canonical IR; the TUI asserts supported operations, paths, relationships, security, and its required diagnostic for the fixture's unsupported OAuth operations. |
| GAP-055 | CG-006 | Canonical IR Consumption | closed | minor | `scripts/tui-generator` loads only `scripts/openapi-ir` and projects its normalized document; no independent YAML traversal exists. |
| GAP-056 | CG-006 | Descriptor-Driven Generic Runtime | closed | minor | OpenAPI resources project to stable descriptors consumed by one resource-agnostic Bubble Tea model with no entity-specific tables or clients. |
| GAP-057 | CG-006 | Standalone Generated Module | closed | minor | Generation emits a separately buildable Go module with pinned dependencies, embedded descriptors, runtime sources, tests, and a dedicated command. |
| GAP-078 | CG-006 | Full-Screen Application Shell | closed | major | `Shell.Render` exclusively owns the header, conditional command bar, framed semantic page, breadcrumb, contextual hints, modal overlay, and final-row alert rail; page transitions replace content without remounting chrome. |
| GAP-079 | CG-006 | Service-Neutral Header and Semantic Theme | closed | minor | The sanitized service title is anchored to the first left-region row, flexible middle rows remain blank, and active origin plus auth/scope/refresh state occupy the final two rows; page identity remains solely in the frame and breadcrumb. Applicable shortcuts flow through `KeyRegistry` and `ShortcutPalette`; `Theme` centrally owns semantic styling with no service-specific presentation source. |
| GAP-093 | CG-006 | Contextual Header Shortcut Palette | closed | minor | `ShortcutPalette` renders registry-derived fixed and generated actions as left-aligned entries in equal display-cell-width columns inside a terminal-right-aligned region sharing at most six rows with left metadata; it deterministically elides lower priorities, keeps Help discoverable, suppresses inapplicable modal actions, and has no duplicate bottom strip. |
| GAP-080 | CG-006 | Centralized Responsive Layout | closed | major | `CalculateShellLayout` continuously clamps and allocates every shell region without a minimum width or breakpoint, elides optional metadata and hints by measured fit, preserves the fixed alert row, and supplies child content dimensions. |
| GAP-081 | CG-006 | Reusable Presentation Component Architecture | closed | major | Dedicated theme, layout, keys, alert, page, table, detail/stream, command, modal, form, and shell components own their policies; a static architecture test rejects presentation rules outside the designated owner. |
| GAP-082 | CG-006 | Unified Page Contract | closed | major | One semantic `Page` contract supplies only title, scope, count, state, content, and local actions for resource-table, detail, stream, loading, empty, forbidden, stale, and fatal rendering while the persistent shell owns services and chrome. |
| GAP-083 | CG-006 | Shared Resource Table Page | closed | minor | `ResourceTableComponent` and `ResourceTablePage` provide descriptor-driven title/count/scope/state, table setup, sort/filter, identity-based selection restoration, adaptive columns, navigation, and loading/empty/forbidden/stale presentation for every collection. |
| GAP-092 | CG-006 | Content-Aware Column Sizing and Horizontal Overflow | closed | minor | A centralized runtime policy measures sanitized Unicode display cells across loaded rows, applies schema-aware bounds, expansion, and priority compression, preserves per-frame offsets, scrolls by column with arrow-key bindings, and renders tested directional off-screen counts and hints. |
| GAP-084 | CG-006 | Shared Detail and Stream Pages | closed | minor | `DetailStreamComponent` backs reusable detail and stream pages with one viewport, deterministic content, explicit connection/autoscroll state, cancelable stream lifecycle, and bounded event count and bytes inside shared shell framing. |
| GAP-085 | CG-006 | Command, Filter, and Help Chrome | closed | minor | `CommandBar` supplies shared input, history, and completion for switch/filter modes; the shell owns its bordered row and the shared help modal derives the same structured shortcuts as the header from `KeyRegistry`. |
| GAP-086 | CG-006 | Single Keybinding and Hint Registry | closed | major | `KeyRegistry` is authoritative for dispatch, structured header shortcuts, help, reserved-key checks, focus/navigation keys, priorities, and applicable generated action hotkeys; projection rejects conflicts with both operation locations. |
| GAP-087 | CG-006 | Consistent Alert and Error Rail | closed | major | `AlertManager` owns sanitized/redacted severity, deterministic priority, five-second transient expiry, persistent errors/warnings, related clearing, dismissal, and details; the shell always reserves the final row and tests assert its coordinate across modes and widths. |
| GAP-088 | CG-006 | Shared Dialog Host and Dialog Primitives | closed | major | `ModalHost` overlays one centered help, choice, confirmation, or form dialog only within the page frame; shared confirmation/form behavior owns cancellation, focus, validation, safe destructive focus, and duplicate-submit prevention. |
| GAP-089 | CG-006 | Schema-Driven Form Dialog | closed | major | `FormDialog` deterministically projects parameters and writable body fields, omits read-only fields, supports enums/defaults/zero values and raw JSON fallback, validates types/formats inline and in the alert rail, and blocks invalid or in-flight resubmission. |
| GAP-090 | CG-006 | Refresh and Stale-Data Lifecycle | closed | major | The generated `--refresh-interval` defaults to five seconds and accepts zero; active readable frames poll without overlap, streams/hidden frames are excluded, late results are ignored, post-action refresh is immediate, and stale/error/selection/last-success state is preserved and recovered. |
| GAP-091 | CG-006 | Presentation Component Conformance Gate | closed | major | Deterministic PlainTheme snapshots and behavioral tests cover first-row service placement, blank flexible padding, penultimate server and final status coordinates, shared-row header allocation, equal-width/right-aligned shortcut ordering/packing/elision/help parity, absence of bottom duplication, semantic page states, command/modal/error coordinates, alerts, forms, confirmations, refresh, selection, sort/history, Unicode columns, and overflow; the architecture gate rejects synthetic page-owned style and shortcut layout. |
| GAP-058 | CG-006 | Resource View Graph Projection | closed | minor | Descriptors retain global/scoped views, explicit and inferred edge provenance, explicit precedence, and diagnostics for ambiguous disconnected views. |
| GAP-059 | CG-006 | Multi-Parent Views and Navigation Stack | closed | minor | Runtime frames preserve the actual incoming edge, selected identity, bindings, and parent-specific selection across push/pop navigation. |
| GAP-060 | CG-006 | Deterministic Path-Parameter Binding | closed | major | Link mappings support the complete OpenAPI runtime-expression grammar; inherited and selected-row bindings are deterministic, location-aware, and reject missing or ambiguous values before HTTP. |
| GAP-061 | CG-006 | Typed Resource Presentation Extension | closed | minor | The grammar validates and preserves presentation metadata plus schema type/format; runtime priority now controls deterministic compression resistance without reordering or making any declared column inaccessible. |
| GAP-062 | CG-006 | Deterministic Presentation Defaults | closed | minor | Metadata-free resources derive stable labels, identity, readable columns, priority order, and sorting from normalized schemas. |
| GAP-063 | CG-006 | Typed Operation Presentation Metadata | closed | major | Projection validates and retains static labels, local hotkeys, and typed confirmations, rejects unknown/visibility/unsafe/conflicting metadata with both source pointers, and adds an unavoidable safe-focus destructive confirmation to every DELETE operation. |
| GAP-064 | CG-006 | Resource Switching, Tables, Filtering, and Detail | closed | minor | The generic runtime provides aliases, resource switching, filtering, responsive tables, detail views, relationship choice, breadcrumbs, and Enter/Esc navigation. |
| GAP-065 | CG-006 | Capability-Driven Operations | closed | major | Only normalized documented operations become controls; generic prompts collect typed path/query/header values and JSON bodies for actions and streams. |
| GAP-066 | CG-006 | Exact HTTP Request Construction | closed | major | Request tests cover path/query/header collisions, simple/label/matrix styles, form/deep-object serialization, `allowReserved`, JSON validation, status ranges, and no-request failures. |
| GAP-067 | CG-006 | Operation Security and Credential Safety | closed | major | Inherit/none/override and optional anonymous alternatives are preserved; unsupported required schemes fail, tokens use files, and credentials cannot cross origins without explicit trust. |
| GAP-068 | CG-006 | Terminal-Safe Rendering | closed | critical | Tables, details, breadcrumbs, errors, streams, labels, and statuses pass through idempotent sanitizers covering CSI, OSC, DCS, string controls, C0/C1, DEL, layout controls, and framework markup. |
| GAP-069 | CG-006 | Actionable Projection Diagnostics | closed | minor | Projection aggregates safe failures with file, JSON Pointer, operation/view, and field context before installing any output. |
| GAP-070 | CG-006 | Repository Generation Workflow | closed | major | `generate-tui`, `generate-all`, and `test-generators` are wired; atomic staging uses exact ownership markers and refuses unowned or symbolic-link outputs. |
| GAP-071 | CG-006 | Graph Conformance Gate | closed | minor | TUI fixtures assert flat/global and multiply scoped views, two explicit parents, explicit-over-inferred precedence, collection-item inference, and ambiguous disconnection. |
| GAP-072 | CG-006 | Parameter-Binding and Request Gate | closed | major | `httptest` cases exercise standard Link expressions, inherited frames, selected rows, multi-scope routes, styles, collisions, validation, exact bodies/headers/auth, and failure without a request. |
| GAP-073 | CG-006 | Capability Conformance Gate | closed | minor | A list/update/stream-only fixture and runtime chooser assertions prove documented partial capabilities are retained without inventing create/get/delete controls. |
| GAP-074 | CG-006 | Runtime Navigation Gate | closed | minor | `teatest` drives aliases, filtering, details, relationship choice, multi-parent push/pop, breadcrumbs, selection restoration, and inline errors against `httptest`. |
| GAP-075 | CG-006 | Terminal Injection Gate | closed | critical | Unit and `teatest` suites inject all specified terminal-control classes through table, detail, breadcrumb, error, and stream contexts and assert safe, idempotent output. |
| GAP-076 | CG-006 | Deterministic Generation Gate | closed | minor | Two isolated generations compare relative paths, modes, and SHA-256 digests, reject host paths/timestamps, and build/test both standalone modules. |
| GAP-077 | CG-006 | Repository OpenAPI Acceptance Gate | closed | minor | The real split repository specification generates all 15 CRUD operations into a temporary TUI module that passes tidy, test, and build under `make test-generators`. |
| GAP-046 | STD-004 | Exact Dependency Declarations | closed | major | Node acceptance and generated container images use exact tag+digest references; npm, TypeScript, and gotestsum versions are exact. |
| GAP-047 | STD-004 | Locked JavaScript Dependency Graph | closed | major | Console output includes a complete npm v3 lockfile and both acceptance and generated Docker builds use `npm ci --ignore-scripts`. |
| GAP-048 | STD-004 | Minimum Dependency Age | closed | major | The live checker admits only Go and npm versions at least 14 days old, including transitive lock entries and standalone tools. |
| GAP-049 | STD-004 | Audited Minimum-Age Exceptions | closed | major | The exact tuple allowlist validates mandatory reason and compensating-verification fields; the current list is empty. |
| GAP-050 | STD-004 | Dependency Policy Verification | closed | major | Nine offline policy tests cover parsing and boundary cases, while `ci-test-unit` runs the live gate. |
| GAP-051 | STD-004 | Actionable and Safe Metadata Access | closed | major | Metadata access is HTTPS-only with bounded retries/timeouts, no lifecycle execution, fail-closed behavior, and package-scoped diagnostics. |
| GAP-052 | STD-003 | Untrusted Pull Request Isolation | closed | major | Fixed: `.github/workflows/trex-pr-ci.yml` runs fork code on `pull_request` with only `contents: read`, no persisted checkout credentials, immutable action SHAs, draft-transition coverage, and no secrets. |
| GAP-053 | STD-003 | Privilege-Separated Review Comments | closed | major | Fixed: `.github/workflows/trex-auto-review.yml` consumes completed CI through `workflow_run`, verifies the current open PR/head SHA via GitHub APIs, treats patches as data, and creates or updates one marker-owned comment without checking out or executing fork content. |
| GAP-054 | STD-003 | Workflow Trust-Boundary Verification | closed | major | Fixed: `scripts/test_trex_review_workflows.py` validates triggers, exact permissions, immutable pins, valid expression operators, and prohibited privileged operations, with unsafe mutation cases. |

### Gap Execution Plan

Recommended implementation order for the remaining gaps:

1. **CLI operation fidelity:** GAP-010, GAP-012, and GAP-043 — project arbitrary capabilities and scopes and exercise exact requests against a mock server.
2. **SDK operation/schema fidelity:** GAP-013, GAP-015, GAP-016, and GAP-044 — render arbitrary scoped/action/stream operations and behavior-test all languages.
3. **Console view fidelity:** GAP-017, GAP-019, and GAP-045 — project scoped views/actions and component-test supported and absent capabilities.
4. **Independent data gap:** GAP-005 — connect the existing advisory-lock abstraction to migration execution.

API parity, CG-005, CG-006, STD-003, and STD-004 are fully covered. The remaining codegen gaps belong to CLI, SDK, and console fidelity, plus the independent migration-lock gap. GAP-001–004, GAP-006–009, GAP-020–042, GAP-052–093 remain closed and require no further action.

## Reconciliation History

| Date | Coverage | Delta | Agent |
|------|----------|-------|-------|
| 2026-07-06 | — | Initial seeding | Manual |
| 2026-07-06 | 96.2% (101/105) | First reconciliation run: 4 partial gaps in SEC-001 (HTTP JWTHandler multi-URL parity with gRPC) | Claude |
| 2026-07-06 | 100% (105/105) | Closed GAP-001–004: HTTP JWTHandler now supports multi-URL additive key loading with file+URL merging, matching gRPC JWKKeyProvider. Changed `pkg/auth/middleware.go` (~80 lines) and `pkg/server/apiserver.go` (1 line). All tests pass. | Claude |
| 2026-08-03 | 78.5% (102/130) | Added CG-005 and operation/view requirements across API and codegen specs; found 13 partial and 15 missing requirements, including one previously unreconciled migration-lock gap. | Codex |
| 2026-08-03 | 73.9% (102/138) | Hardened CG-005 after review with bounded references, safe projections, explicit security inheritance, atomic consumer evolution, grouped conformance requirements, automated API parity, and an explicit CG-006 TUI milestone. | Codex |
| 2026-08-03 | 71.3% (102/143) | Verified all three generator modules have no tests and CI skips their nested modules; added pre-migration characterization, real-spec generation, and target artifact acceptance requirements. | Codex |
| 2026-08-03 | 71.7% (104/145) | Covered reproducible test tooling and hermetic unit-test credentials: test targets use module-pinned `gotestsum`, CI no longer installs `@latest`, and configuration tests own temporary password fixtures. | Codex |
| 2026-08-03 | 71.7% (104/145) | Preserved test-tooling coverage while isolating pinned `gotestsum` from the root module graph so downstream consumers do not inherit development-only dependencies. | Codex |
| 2026-08-03 | 68.9% (104/151) | Added STD-004 for exact generator toolchain pins, locked npm graphs, a 14-day dependency cooldown, audited exceptions, and CI enforcement; identified six implementation gaps. | Codex |
| 2026-08-03 | 89.4% (135/151) | Fully reconciled CG-005 and STD-004: added the canonical bounded IR, migrated all three consumers, added shared and real-spec acceptance gates, proved deterministic generation with SHA-256 baselines, pinned the Node/npm graph, and enforced a 14-day dependency cooldown. | Codex |
| 2026-08-04 | 97.2% (105/108) | Added secure pull request execution, privilege-separated commenting, and workflow trust-boundary verification requirements; identified three implementation gaps. | Codex |
| 2026-08-04 | 100% (108/108) | Closed the three STD-003 workflow gaps with read-only PR CI, an API-only trusted commenter, immutable action pins, and offline trust-boundary mutation tests. | Codex |
| 2026-08-04 | 89.6% (138/154) | Merged the OpenAPI IR and secure pull request automation requirement sets, renumbered the CI gaps to preserve unique identifiers, and retained both implementations. | Codex |
| 2026-08-04 | 93.8% (166/177) | Closed API/entity-generator parity and all 23 CG-006 requirements with a canonical-IR TUI graph, descriptor-driven runtime, exact HTTP/auth and Link semantics, safe atomic output, deterministic generation, and real-spec acceptance. Reclassified the existing-but-unused migration lock as partial. | Codex |
| 2026-08-04 | 86.4% (165/191) | Added 14 CG-006 requirements for a service-neutral full-screen shell, reusable pages/components, centralized theme/layout/keys, fixed bottom alert rail, modal forms/dialogs, refresh lifecycle, and presentation conformance gates; promoted operation metadata from reserved to typed and identified 7 partial and 7 missing presentation requirements. | Codex |
| 2026-08-04 | 85.4% (164/192) | Added content-aware Unicode display-cell sizing, centralized width bounds and compression, horizontal column scrolling, directional overflow counts, and arrow-key hints; identified the equal-width, inaccessible-column behavior as partial and reopened priority semantics. | Codex |
| 2026-08-04 | 86.5% (166/192) | Closed GAP-061 and GAP-092 with schema-aware Unicode column measurement, bounded priority compression, per-frame horizontal offsets, arrow-key scrolling, off-screen counts and hints, regenerated standalone output, and focused generator/runtime tests. | Codex |
| 2026-08-04 | 94.3% (181/192) | Closed GAP-063 and GAP-078–091 with a reusable semantic shell and page system, continuous layout, centralized theme/keys/alerts/modals, shared table/detail/stream/command/form components, safe confirmations, refresh/stale lifecycle, deterministic snapshots, and architecture duplication gates. | Codex |
| 2026-08-04 | 94.3% (182/193) | Added and closed GAP-093 with a k9s-style contextual top shortcut palette, single-registry header/help parity, six-row measured packing, responsive priority elision, mode-correct visibility, and no duplicate bottom strip. | Codex |
| 2026-08-04 | 94.3% (182/193) | Refined GAP-079, GAP-091, and GAP-093 so the connected server anchors the upper-left while an equal-column shortcut grid shares those rows at the terminal-right edge, with coordinate and alignment regression tests. | Codex |
| 2026-08-04 | 94.3% (182/193) | Refined GAP-079 and GAP-091 to vertically anchor service title at the top and server/status on the final two left-region rows, reserve flexible blank padding between them, and keep page identity in the frame and breadcrumb. | Codex |
