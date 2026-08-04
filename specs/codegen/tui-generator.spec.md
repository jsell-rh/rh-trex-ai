# TUI Generator Specification

**Date:** 2026-08-04
**Status:** Active
**ID:** CG-006
**Related:** [OpenAPI Intermediate Representation](openapi-ir.spec.md), [REST Conventions](../api/rest-conventions.spec.md), [Authentication](../security/authentication.spec.md), [Testing Standards](../standards/testing.spec.md), [Dependency Supply Chain](../standards/dependency-supply-chain.spec.md)
**Implements:** `scripts/tui-generator/`, `generated/tui/`, `Makefile`

---

## Purpose

Define generation of a standalone, keyboard-driven terminal resource browser from the canonical OpenAPI intermediate representation. The generator projects resource views, relationships, operations, and presentation-only `x-trex-tui` metadata into deterministic descriptors consumed by one generic Bubble Tea runtime; it does not encode a fixed resource hierarchy or resource-specific client implementation.

## Conceptual Model

```text
resolved OpenAPI -> canonical IR -> TUI descriptors -> generic runtime
```

| Component | Responsibility |
|-----------|----------------|
| Canonical IR | Owns OpenAPI loading, operation and schema fidelity, resource views, relationships, capabilities, security state, and source diagnostics |
| TUI projection | Validates presentation metadata and produces deterministic view, operation, relationship, binding, and authentication descriptors |
| Generic runtime | Renders tables and details, executes descriptor-defined requests, manages filtering and the navigation stack, and sanitizes terminal content |
| Generated module | Packages the descriptors, runtime, entry point, pinned dependencies, and tests as a standalone Go module under `generated/tui` |

## Requirements

### Requirement: Canonical IR Consumption

The TUI generator SHALL be the fourth in-repository consumer of the canonical OpenAPI IR. It SHALL obtain operations, schemas, resource views, relationships, capabilities, servers, parameters, and security states from that IR and SHALL NOT traverse raw OpenAPI documents to reinterpret them. A breaking IR change SHALL update and test the TUI generator atomically with the SDK, CLI, and console consumers as required by CG-005.

#### Scenario: Generate from a normalized document

- GIVEN the canonical IR contains a global collection, a parent-scoped collection, and their operations
- WHEN the TUI projection builds its descriptors
- THEN every descriptor SHALL refer to canonical IR identities and semantics
- AND no TUI parser SHALL independently infer those semantics from raw YAML or URL strings

### Requirement: Descriptor-Driven Generic Runtime

The generated TUI SHALL use a generic runtime driven by generated descriptors. Descriptors SHALL retain each view's operations, represented schemas, ordered columns, relationships, parameter-binding plans, capabilities, servers, and security state. Runtime source SHALL NOT contain hard-coded resource kind names, fixed parent-child chains, or resource-specific fetch functions.

#### Scenario: Add a new resource without runtime code

- GIVEN an OpenAPI change adds a valid resource view and no new terminal interaction primitive
- WHEN the TUI is regenerated
- THEN generated descriptors SHALL be sufficient to browse the new view
- AND the generic runtime source SHALL remain unchanged

### Requirement: Standalone Generated Module

The generator SHALL produce a standalone Go module at `generated/tui` with its own `go.mod`, executable entry point, descriptors, generic runtime, and tests. The module SHALL build without importing TRex API-server implementation packages. Its direct and transitive dependencies SHALL be reproducibly pinned and admitted under STD-004.

#### Scenario: Build outside the API server module

- GIVEN a TUI generated from the repository OpenAPI document
- WHEN the generated directory is copied to an isolated temporary directory and its documented build command is run
- THEN the executable SHALL build successfully
- AND the build SHALL NOT require API-server source code, a database, or a running TRex service

### Requirement: Resource View Graph Projection

The TUI SHALL preserve resource views and navigation relationships as a directed graph rather than choosing one canonical tree. An explicit OpenAPI Link relationship SHALL take precedence over path-derived inference. The projection MAY expose a conservatively inferred containment edge only when the canonical IR marks one parent item and one child collection as unambiguous. It SHALL NOT connect an ambiguous relationship merely because route segments or schema names appear similar.

#### Scenario: Explicit link overrides path appearance

- GIVEN an explicit Link targets a child collection and maps its scope parameter
- AND route structure could imply a different parent
- WHEN TUI relationships are projected
- THEN the explicit relationship SHALL be the navigable edge
- AND no conflicting inferred parent edge SHALL be emitted

#### Scenario: Ambiguous path remains unconnected

- GIVEN two candidate parent views could supply a child collection's path parameter
- AND no explicit Link resolves the ambiguity
- WHEN TUI relationships are projected
- THEN neither candidate SHALL gain an inferred child edge
- AND generation SHALL report a non-fatal diagnostic identifying why explicit relationship metadata is required

### Requirement: Multi-Parent Views and Navigation Stack

A resource view MAY be reachable globally and through multiple parent relationships. Each navigation SHALL push an immutable frame containing the chosen edge, source view, selected item identity, bound scope values, and target view. `Esc` SHALL pop exactly one frame, and breadcrumbs SHALL be rendered from the actual stack rather than from a precomputed resource hierarchy. Reaching the same target through two parents SHALL preserve two distinct scope and back-navigation histories.

#### Scenario: Same child reached from different parents

- GIVEN a Messages view is reachable globally, from an Agent, and from a Session
- WHEN a user enters Messages from a selected Session and then presses `Esc`
- THEN the breadcrumb SHALL show the Session route used to enter the view
- AND `Esc` SHALL return to that Session context rather than a canonical Messages parent

### Requirement: Deterministic Path-Parameter Binding

Every navigable item or relationship descriptor SHALL contain a complete, generation-time binding plan for every target path parameter. The plan SHALL use the following precedence: an explicit Link parameter mapping; an already-bound navigation scope parameter with the same OpenAPI name and location; then the selected row's identity property only for the single item parameter introduced by an unambiguous collection-to-item or parent-to-child path edge. A selected-row property SHALL NOT be matched to a parameter through case folding, suffix stripping, singularization, or another naming heuristic.

An explicit Link mapping SHALL support standard literal values and OpenAPI runtime expressions available from the source request or response. A response-body expression used for row navigation SHALL resolve against the selected source representation defined by the source relationship; if that representation cannot supply the referenced value, the edge SHALL be non-navigable. All bound values SHALL be validated against the target parameter schema and serialized according to the target parameter's OpenAPI style and explode rules.

#### Scenario: Bind item and scoped child from a selected row

- GIVEN a collection row has `id: "agent-7"` as its validated identity property
- AND the unambiguous item path introduces `{agent_id}`
- AND a child collection extends that item path without introducing another unbound parent parameter
- WHEN the user selects the row and enters the item or child view
- THEN the binding plan SHALL bind `agent_id` to `agent-7`
- AND the exact target path SHALL contain the encoded value in the declared segment

#### Scenario: Explicit mapping is authoritative

- GIVEN a Link maps target `project_id` from `$request.path.project_id` and `agent_id` from `$response.body#/id`
- WHEN the relationship descriptor is generated and evaluated for a selected Agent
- THEN those two expressions SHALL be the only sources for those target parameters
- AND an absent or invalid mapped value SHALL produce an inline navigation error rather than falling back to a naming heuristic

#### Scenario: Multiple unbound target parameters

- GIVEN a target route requires two path parameters not supplied by explicit mappings or current scope
- AND selected-row identity could account for at most one of them
- WHEN the TUI projection validates the edge
- THEN it SHALL reject that edge as non-navigable
- AND the diagnostic SHALL identify the target operation and every unsatisfied parameter

### Requirement: Typed Resource Presentation Extension

The collection-operation form of `x-trex-tui` SHALL be an optional typed presentation block with only the following fields. It SHALL NOT define operations, relationships, authorization, or request semantics.

| Field | Type | Semantics |
|-------|------|-----------|
| `label` | non-empty string | Human-readable resource-view label |
| `aliases` | array of unique strings | Alternate resource-switcher commands |
| `identity-property` | string | Readable scalar property used to identify a selected row |
| `default-sort` | string | Readable scalar property used for the initial ascending sort |
| `columns` | ordered array | Explicit table columns in display order |
| `columns[].property` | string | Readable scalar item property |
| `columns[].label` | non-empty string | Column heading |
| `columns[].priority` | integer | Relative retention priority when terminal width is constrained; higher values are retained first |

```yaml
x-trex-tui:
  label: Agents
  aliases: [ag]
  identity-property: id
  default-sort: name
  columns:
    - property: name
      label: NAME
      priority: 100
    - property: status
      label: STATUS
      priority: 80
```

Aliases SHALL match `[a-z][a-z0-9-]*`. The generator SHALL reject a recognized field with the wrong type, duplicate aliases, unknown fields within this grammar revision, an empty explicit column list, duplicate column properties, references to missing or non-readable properties, a default sort absent from explicitly declared columns, conflicting aliases among simultaneously addressable views, and terminal control characters in presentation strings. The source file and JSON Pointer of invalid metadata SHALL appear in the diagnostic.

#### Scenario: Apply resource presentation metadata

- GIVEN a collection operation declares a label, alias, identity property, default sort property, and ordered columns
- WHEN the TUI descriptor is generated
- THEN it SHALL preserve the declared column order and labels
- AND it SHALL use priority only to choose which columns are hidden as available width shrinks
- AND the extension SHALL NOT change the operation's route, relationship, capability, or security state

#### Scenario: Reject a misspelled property

- GIVEN `default-sort` names a property absent from the list item schema
- WHEN the TUI projection validates `x-trex-tui`
- THEN generation SHALL fail before writing output
- AND the diagnostic SHALL identify the extension location and missing property

### Requirement: Deterministic Presentation Defaults

A collection view without `x-trex-tui` SHALL remain generatable. The projection SHALL derive a deterministic label from the canonical resource-view identity, SHALL assign no aliases, SHALL use a readable scalar `id` property as identity when present, and SHALL otherwise leave identity unset. It SHALL derive columns from readable scalar item properties in canonical deterministic order and SHALL choose the first displayed property as the default sort when no explicit sort is declared. A relationship that requires selected-row identity SHALL be non-navigable when no validated identity property exists.

#### Scenario: Metadata-free TRex resource

- GIVEN a collection view has readable scalar `id`, `kind`, and `name` properties but no TUI extension
- WHEN generation runs twice
- THEN both runs SHALL derive the same label, identity, columns, and default sort
- AND generated output SHALL be byte-for-byte identical

### Requirement: Reserved Operation Presentation Metadata

The `x-trex-tui` operation keys `label`, `hotkey`, `confirmation`, and `visibility` are reserved for a future typed action-presentation revision when used on non-collection operations. CG-006 SHALL NOT allow those keys to redefine whether an OpenAPI operation exists or whether the caller is authorized. Until their behavior is specified, the generator SHALL diagnose their use as unsupported rather than silently assigning unstable semantics.

#### Scenario: Reserved action hotkey

- GIVEN a non-collection operation declares `x-trex-tui.hotkey`
- WHEN the current TUI generator validates the operation
- THEN it SHALL report that the reserved key is not supported by this specification revision
- AND it SHALL NOT bind the hotkey or change the operation capability

### Requirement: Resource Switching, Tables, Filtering, and Detail

The runtime SHALL provide a resource switcher for globally addressable views and for scoped views whose required bindings are available in the current stack. It SHALL accept each validated alias, render list responses as selectable tables, apply `/` filtering across sanitized visible column values, and provide a scrollable item-detail view containing all readable response fields. `Enter` SHALL follow an available descriptor relationship from the selected row; when more than one edge is available it SHALL present a deterministic relationship chooser rather than choose a parent or child implicitly. A detail command SHALL remain available independently of child navigation.

#### Scenario: Browse without resource-specific code

- GIVEN generated descriptors define Dinosaurs and Fossils with different columns
- WHEN the user switches resources, filters rows, selects one, and opens detail
- THEN the generic runtime SHALL render the descriptor-defined table and detail fields
- AND no behavior SHALL depend on the literal names Dinosaur or Fossil

#### Scenario: Select among multiple child edges

- GIVEN a selected row has two explicit outgoing relationships
- WHEN the user presses `Enter`
- THEN the runtime SHALL display both targets in stable descriptor order
- AND choosing one SHALL push only that relationship onto the navigation stack

### Requirement: Capability-Driven Operations

The runtime SHALL derive available list, get, CRUD, non-CRUD action, and streaming controls exclusively from descriptor capabilities backed by canonical IR operations. It SHALL NOT synthesize CRUD controls or invoke an undocumented method. Generic operation labels SHALL derive deterministically from OpenAPI summary and `operationId` until the reserved operation-presentation grammar is specified. Request input controls SHALL honor requiredness, schema types, read-only and write-only semantics, and operation parameters.

#### Scenario: Read-only view with one action

- GIVEN a view has list, get, and interrupt capabilities but no create, update, or delete operation
- WHEN the runtime renders available controls
- THEN list, get, and interrupt SHALL be available
- AND create, update, and delete SHALL be absent

### Requirement: Exact HTTP Request Construction

The generated client SHALL construct requests from descriptor operations, using the exact HTTP method, server selection, ordered path segments, bound path values, query and header parameters, serialization rules, content type, and request-body schema retained by the IR. Dynamic values SHALL be encoded for their path, query, header, or body context and SHALL never be concatenated into an unparsed route template. The TUI SHALL communicate only through documented API operations.

#### Scenario: Multiply scoped request

- GIVEN the active stack binds organization, project, and agent identifiers
- AND the target operation is `GET /organizations/{organization_id}/projects/{project_id}/agents/{agent_id}/inbox`
- WHEN the runtime executes the operation
- THEN the test server SHALL receive that exact method and path with each value encoded in its declared segment
- AND no scope SHALL be dropped, reordered, or replaced by a selected row from another frame

### Requirement: Operation Security and Credential Safety

The client SHALL preserve the distinction among inherited document security, explicit `security: []`, and non-empty operation overrides. It SHALL apply runtime-supplied credentials only through a supported declared security alternative, SHALL support the TRex HTTP bearer scheme, and SHALL fail generation with an actionable diagnostic when a required operation has no supported security alternative. Credentials SHALL be bound to the user-configured API origin; the client SHALL refuse to attach them to a different operation-level server origin unless the user explicitly trusts that origin. Non-loopback plaintext HTTP SHALL require an explicit insecure runtime option. The client SHALL NOT embed credentials in generated source or descriptors, send credentials to an explicitly unauthenticated operation, or include credential values in rendered errors, logs, panic output, or test snapshots.

#### Scenario: Public and authenticated operations

- GIVEN document security requires HTTP bearer authentication
- AND one operation explicitly declares `security: []`
- WHEN both operations are invoked with a configured token
- THEN the inherited operation SHALL receive the bearer credential
- AND the explicitly unauthenticated operation SHALL receive no credential

#### Scenario: Unsupported required scheme

- GIVEN a required operation declares only an unsupported authentication scheme
- WHEN the TUI projection validates the operation
- THEN generation SHALL fail with the operation ID and scheme name
- AND it SHALL NOT silently generate an unauthenticated request

#### Scenario: Cross-origin server override

- GIVEN an authenticated operation overrides the configured API server with a different origin
- AND the user has not explicitly trusted that origin
- WHEN the runtime prepares the request
- THEN it SHALL refuse to attach or transmit the credential
- AND the inline diagnostic SHALL identify the untrusted origin without revealing credential data

### Requirement: Terminal-Safe Rendering

All OpenAPI-derived and API-returned strings SHALL be treated as untrusted at the final rendering boundary. Every table cell, detail value, breadcrumb, label, error, action result, stream event, and raw-mode field SHALL strip or neutralize ANSI CSI, OSC, DCS, C0, and C1 control sequences and any framework-specific markup before terminal output. Newline and tab handling SHALL be explicit for the destination view, and sanitized content SHALL NOT be able to move the cursor, set terminal titles, write clipboard data, create links, or inject key events. Sanitization SHALL be idempotent and SHALL occur in addition to the source-code and output-path protections required by CG-005.

#### Scenario: Escape injection in every view

- GIVEN an API value contains color escapes, an OSC terminal-title or clipboard command, control bytes, and framework markup
- WHEN the value appears in a table, detail view, breadcrumb, error, or stream/raw view
- THEN none of those control effects SHALL reach the terminal
- AND safe printable text SHALL remain visible

### Requirement: Actionable Projection Diagnostics

The generator SHALL validate the complete TUI projection before writing target files. A fatal diagnostic SHALL include the source file, JSON Pointer, affected operation or view identity, and a safe explanation for malformed metadata, incomplete bindings, unsupported required authentication, or descriptor conflicts. Ambiguous relationships that are valid in the canonical IR but intentionally unavailable for TUI navigation SHALL be reported as non-fatal diagnostics and SHALL remain absent from the generated navigation graph.

#### Scenario: Invalid projection writes nothing

- GIVEN a TUI extension selects an invalid identity property and a relationship lacks a required binding
- WHEN generation runs against an empty output directory
- THEN generation SHALL fail with both actionable diagnostics when safe to aggregate
- AND it SHALL leave no partially generated module

### Requirement: Repository Generation Workflow

The repository SHALL provide `make generate-tui`, SHALL include it in `make generate-all`, and SHALL include the TUI generator module and generated-artifact acceptance suite in `make test-generators`. Generation SHALL use an isolated temporary staging directory and replace the configured output only after successful validation and rendering. Output paths SHALL remain beneath the configured output root.

#### Scenario: Generate all clients

- GIVEN the repository OpenAPI document is valid for every generator
- WHEN `make generate-all` completes
- THEN SDK, CLI, console, and TUI artifacts SHALL have been generated
- AND a TUI failure SHALL prevent a partial staged TUI tree from replacing the previous output

### Requirement: Graph Conformance Gate

The TUI generator SHALL have fixture tests for flat resources, multiply scoped views, one view reachable through multiple parents, explicit Link precedence, conservative inference, and ambiguous relationships. Tests SHALL assert descriptor edges, provenance, scope, and addressability rather than only successful generation.

#### Scenario: Multi-parent and ambiguous fixture

- GIVEN a fixture contains a global view, two explicit parent paths to one child, and one ambiguous path-only candidate
- WHEN TUI descriptors are tested
- THEN both explicit parent edges and the global view SHALL be present
- AND the ambiguous candidate SHALL be absent with its expected diagnostic

### Requirement: Parameter-Binding and Request Gate

The TUI generator SHALL have `httptest` acceptance cases for item, child, action, and multiply scoped operations. The cases SHALL exercise explicit Link expressions, inherited stack scope, selected-row identity, missing values, validation, serialization, and exact method, route, query, header, body, and authentication behavior.

#### Scenario: Exact bound request test

- GIVEN a fixture provides values from a Link, two existing stack frames, and the selected row
- WHEN the generated runtime sends the target request to `httptest.Server`
- THEN the server SHALL observe the exact expected request and authentication state
- AND a test variant with an unsatisfied value SHALL make no request

### Requirement: Capability Conformance Gate

Fixture tests SHALL prove that controls and request inputs are projected only from documented capabilities, including a read-only view, partial CRUD, a non-CRUD action, and a streaming operation. The tests SHALL fail when the runtime invents an absent CRUD operation or omits a documented supported capability.

#### Scenario: Partial capability fixture

- GIVEN a fixture documents list, patch, and stream operations only
- WHEN descriptors and rendered controls are asserted
- THEN exactly those supported capabilities SHALL be available
- AND create, get, and delete SHALL be absent

### Requirement: Runtime Navigation Gate

Generated-runtime acceptance tests SHALL use `httptest` with `teatest` to send user keystrokes and assert resource switching, aliases, filtering, selected-row navigation, relationship choice, details, `Enter` push, `Esc` pop, breadcrumbs, multi-parent history, and inline API errors. The test SHALL exercise generated descriptors rather than a resource-specific fake runtime.

#### Scenario: Enter and Escape preserve scope

- GIVEN a test server serves two parent paths to the same child view
- WHEN `teatest` enters the child through one parent and then sends `Esc`
- THEN rendered breadcrumbs SHALL identify the chosen parent
- AND the restored table and selection SHALL belong to that same parent frame

### Requirement: Terminal Injection Gate

Automated tests SHALL inject ANSI, OSC, DCS, C0, C1, malformed escape sequences, newlines, tabs, Unicode, and framework-markup payloads through presentation metadata and API responses. Assertions SHALL cover tables, details, breadcrumbs, errors, and stream/raw output and SHALL verify both safe text preservation and absence of terminal effects.

#### Scenario: Malicious API fixture

- GIVEN every user-visible response field includes terminal-control payloads
- WHEN `teatest` renders every supported view type
- THEN captured output SHALL contain no prohibited control sequence
- AND repeated sanitization SHALL produce the same safe value

### Requirement: Deterministic Generation Gate

An unchanged resolved OpenAPI input SHALL produce byte-for-byte identical TUI output across repeated runs, regardless of YAML map iteration or referenced-file traversal order. The acceptance suite SHALL generate twice into separate temporary directories and compare sorted file paths, modes, and SHA-256 digests. Generated files SHALL carry stable generated-code notices and SHALL contain no timestamps or host-specific absolute paths.

#### Scenario: Compare generated trees

- GIVEN one resolved OpenAPI input and fixed generator dependencies
- WHEN the TUI is generated twice in isolated directories
- THEN both trees SHALL have identical relative paths, file modes, and SHA-256 digests
- AND both generated modules SHALL build successfully

### Requirement: Repository OpenAPI Acceptance Gate

Continuous integration SHALL run the TUI generator against the fully resolved repository `openapi/openapi.yaml`, generate into an isolated temporary directory, build and test the standalone module, and leave the working tree unchanged. This gate SHALL run with the shared IR conformance fixtures through `make test-generators` and SHALL require no database or external API service.

#### Scenario: Generate the real TRex TUI

- GIVEN the repository root OpenAPI document and all referenced entity documents
- WHEN generator CI runs
- THEN a standalone TUI SHALL be generated, built, and tested from that real document
- AND the same job SHALL verify the SDK, CLI, console, and TUI consumers against the current canonical IR

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Graph navigation, not a kind tree | A schema can be global, multiply scoped, or reachable through several semantic relationships |
| OpenAPI Links before conservative inference | Standard explicit mappings resolve meaning that path shape alone cannot establish |
| Stack frames retain edge and bindings | Breadcrumbs and `Esc` must return through the route actually used, especially for multi-parent views |
| Binding plans are generated, not guessed at runtime | Exact sources, validation, and serialization can be reviewed and fixture-tested before requests are sent |
| `x-trex-tui` is presentation-only | Standard OpenAPI remains authoritative for operations, relationships, security, and request semantics |
| Collection-operation metadata configures a view | One schema may have different global and scoped presentations without becoming different resource kinds |
| Operation presentation keys are reserved | Labels, hotkeys, confirmations, and visibility need a later security and interaction contract, not ad hoc semantics |
| Generic Bubble Tea runtime | A descriptor-driven Elm-style runtime supports consistent tables, input modes, navigation, and `teatest` coverage |
| API-only data path | The generated TUI works against documented REST operations and does not couple to a database, Kubernetes, or server internals |
| Sanitize at the rendering boundary | One mandatory boundary covers metadata, API data, errors, and future render modes without relying on every caller to remember |
| Standalone generated module | Consumers can build and distribute the TUI independently of the template service |
| Synthetic and real-spec gates | Focused fixtures prove hard graph semantics while repository generation proves end-to-end viability |
