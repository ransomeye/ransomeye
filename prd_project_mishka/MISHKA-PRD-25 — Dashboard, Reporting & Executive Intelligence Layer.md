# MISHKA-PRD-25 — Dashboard, Reporting & Executive Intelligence Layer

**Project:** Project Mishka
**Classification:** SUBORDINATE — ENTERPRISE DASHBOARD, REPORTING, AND EXECUTIVE PRESENTATION CONTRACT
**Status:** AUTHORITATIVE ONLY WITHIN SUBORDINATE UI-LAYER PRESENTATION SCOPE

---

```text
THIS PRD INHERITS GLOBAL RESOURCE BOUND LAW FROM PRD-01.

ALL COLLECTIONS IN THIS PRD ARE REQUIRED TO BE:

- EXPLICITLY BOUNDED
- OVERFLOW -> REJECT
```

```text
ALL FAILURES IN THIS PRD MUST BE CLASSIFIED AS:

TYPE 1 / TYPE 2 / TYPE 3

AND MUST FOLLOW PROPAGATION RULES FROM PRD-01.
```

```text
THIS PRD DOES NOT CREATE A NEW AUTHORITY DOMAIN.

PRD-25 DEFINES ONLY:
- ENTERPRISE DASHBOARD PRESENTATION CONTRACTS
- REPORT / EXECUTIVE VIEW COMPOSITION RULES
- UI-LAYER ENTERPRISE UX REQUIREMENTS

PRD-25 DOES NOT REDEFINE:
- STORAGE AUTHORITY
- QUERY EXECUTION AUTHORITY
- UI GOVERNANCE AUTHORITY
- EXECUTION / CONTROL AUTHORITY
- ASSET INTELLIGENCE AUTHORITY
- AI / OPAIF AUTHORITY
```

```text
PRD-25 IS SUBORDINATE PRESENTATION LAW ONLY.

PRD-25 MUST NOT BE INTERPRETED AS:
- TOP-LEVEL DASHBOARD GOVERNANCE AUTHORITY
- QUERY / STORAGE / REPORT AUTHORITY
- CONTROL / EXECUTION / OVERRIDE AUTHORITY
- ASSET INTELLIGENCE AUTHORITY
- AI / OPAIF AUTHORITY
```

---

# 1. PURPOSE

This document defines the deterministic presentation contract for dashboard surfaces, reporting surfaces, and executive intelligence surfaces in Project Mishka.

PRD-25 exists to ensure that all dashboards and reports:

* remain subordinate to PRD-13 storage authority, PRD-21 UI authority, PRD-20 execution governance, PRD-22 non-authoritative AI isolation, and PRD-23 asset intelligence authority
* render only from committed authoritative records or authorized deterministic projections rebuildable from committed authoritative records
* preserve replay correctness, evidence lineage, and fail-closed behavior
* provide enterprise-grade, role-aware, high-signal / low-noise user experience without introducing alternate truth, hidden state, or consumer-style ambiguity
* keep executive summaries and operational dashboards on the same underlying truth model
* remain implementation-ready without redefining ownership already assigned to PRD-13, PRD-20, PRD-21, PRD-22, or PRD-23

PRD-25 MUST NOT:

* redefine the canonical `query_object`, `query_record`, `query_result_record`, `report_record`, `report_delivery_record`, or `ui_action_record` schemas owned by PRD-13
* redefine dashboard/search/investigation/policy-simulation/UI-action semantics owned by PRD-21
* redefine execution approval, override, rollback, or kill-switch semantics owned by PRD-20
* redefine coverage-state computation, entity registry semantics, or asset investigation logic owned by PRD-23
* redefine OPAIF / Shadow Intelligence behavior owned by PRD-22
* introduce a parallel dashboard truth model, parallel report authority, or hidden personalization state
* define entitlement logic, workflow state authority, summary-metric semantics, or execution semantics outside the owning PRDs

---

# 2. AUTHORITY MAP

## 2.1 Precedence

The following authority bindings are mandatory:

* PRD-01 owns system laws, fail-closed behavior, determinism, hidden-state prohibition, and boundary law
* PRD-13 owns authoritative storage, record schemas, canonical query semantics, report semantics, and derived projection law
* PRD-20 owns execution governance, approvals, overrides, kill switches, and authoritative control records
* PRD-21 owns SOC UI behavior, dashboard/search/investigation/policy-simulation workflows, UI_ACTION recording, and UI governance
* PRD-22 owns Shadow Intelligence / OPAIF isolation and non-authoritative AI report behavior
* PRD-23 owns asset intelligence, coverage-state logic, entity registry control semantics, and asset-specific workflows
* PRD-24 owns deterministic execution / replay architecture and cache non-authority constraints

```text
IF PRD-25 CONFLICTS WITH PRD-01 / PRD-13 / PRD-20 / PRD-21 / PRD-22 / PRD-23 / PRD-24:

THE OWNING PRD WINS.

THE CONFLICTING PRD-25 SCOPE IS INVALID.
```

## 2.2 PRD-25 Ownership And Interpretation

PRD-25 owns only:

* enterprise dashboard composition rules
* deterministic panel layout and drill-down contract
* executive summary view rules
* report / export presentation rules subordinate to PRD-13 and PRD-22
* role-aware presentation scoping rules subordinate to PRD-21
* enterprise UX constraints for high-signal Mishka interfaces

PRD-25 MUST be read as subordinate presentation law over already-owned Mishka objects and workflows.

PRD-25 MUST be implemented under the following interpretation rules:

* dashboard navigation, workflow routing, saved view workflow binding, and role visibility decisions MUST remain subordinate to PRD-21
* query identity, query execution, result identity, report object identity, and export verifiability MUST remain subordinate to PRD-13
* approval, rejection, override, rollback, and kill-switch semantics MUST remain subordinate to PRD-20
* asset coverage, expected registry meaning, observed and managed state, and asset investigation meaning MUST remain subordinate to PRD-23
* AI panel behavior, persisted shadow output handling, and non-authoritative availability semantics MUST remain subordinate to PRD-22

PRD-25 sections MUST NOT be used to justify a product or implementation decision that contradicts the owning PRDs.

## 2.3 Terminology Normalization

For this PRD, the following vocabulary is mandatory:

* `dashboard` = one named collection of panels within one dashboard family
* `panel` = one deterministic presentation unit inside one dashboard
* `view` = one rendered dashboard or panel state under one explicit scope, filter set, and sort definition
* `summary metric` = one deterministic scalar, scorecard, or compact summary derived from one canonical query result or one authorized deterministic projection
* `evidence lineage` = the full deterministic path from a rendered claim to committed source records, committed query identity, committed query result identity, and governing hashes where applicable
* `drill-down` = deterministic navigation from one summary or aggregate view into the lower-level committed evidence view while preserving inherited scope, filter set, sort definition, and evidence lineage
* `saved view` = explicit persisted visible presentation state permitted by PRD-21
* `scope` = the explicit tenant, hierarchy, entity, sequence, version, and read-scope time boundaries bound into the canonical query
* `filter` = one explicit typed predicate bound into the canonical query
* `sort key` = one explicit deterministic ordering field or deterministic tie-break field
* `authorized deterministic projection` = one PRD-13-authorized rebuildable projection derived only from committed authoritative records
* `presentation state` = one explicit rendered state such as loading, redacted, unavailable, stale, degraded, empty, or unknown commit lineage state
* `unknown commit lineage state` = a presentation state used when the required committed evidence path for a rendered claim cannot be proven

---

# 3. CORE LAWS

The following laws are mandatory:

* every dashboard view MUST be a deterministic presentation over canonical query results or authorized deterministic projections rebuildable from committed authoritative records
* every dashboard and report MUST resolve to the same authoritative truth model used by operators, analysts, executives, replay validation, and export verification
* dashboards, executive summaries, scorecards, and reports MUST NOT introduce hidden ranking rules, hidden filters, or local-only truth
* every drill-down MUST preserve evidence lineage back to committed records, committed query identity, committed query result identity, and governing hashes where applicable
* all write-capable UI interactions MUST route through PRD-21 / PRD-20 / PRD-13 control paths and MUST NOT mutate execution state directly
* caches, layout optimizations, and pre-aggregations MUST remain non-authoritative and disposable
* AI content MUST remain explicitly non-authoritative and visually isolated
* every executive summary metric MUST resolve to the same canonical query result or authorized deterministic projection used by operator-grade evidence views
* dashboard presentation state MUST remain explicit and replay-compatible under PRD-15 for loading, redaction, unavailable, stale, degraded, empty, and unknown commit lineage state

```text
AUTHORITATIVE STORAGE / REBUILDABLE DETERMINISTIC PROJECTION
    -> PRD-13 CANONICAL QUERY_OBJECT
    -> QUERY_RECORD
    -> QUERY_RESULT_RECORD
    -> PRD-25 PANEL / DASHBOARD / REPORT PRESENTATION
```

```text
DASHBOARDS MUST NOT:
- BYPASS PRD-13 QUERY LAW
- BYPASS PRD-21 UI GOVERNANCE
- BYPASS PRD-20 CONTROL AUTHORITY
- USE WALL CLOCK AS AUTHORITATIVE ORDER
- INVENT NON-COMMITTED METRICS
- PRESENT AI OUTPUT AS AUTHORITATIVE EVIDENCE
```

---

# 4. READ BOUNDARY

## 4.1 Permitted Authoritative Inputs

PRD-25 presentations MUST resolve only from:

* committed PRD-13 record families
* authorized deterministic projections explicitly allowed by PRD-13 and rebuildable from committed authoritative records
* committed signed snapshots / hashes referenced by authoritative records
* committed `query_record`
* committed `query_result_record`
* committed `report_record`
* committed `report_delivery_record`
* committed `ui_action_record`
* committed `investigation_record`
* committed `case_record`
* committed `group_record`
* committed `risk_record`
* committed `simulation_record`

When a dashboard view requires convenience indexes, materialized projections, or redacted views, those structures:

* MUST be derived only from committed authoritative records
* MUST be rebuildable from authoritative storage alone
* MUST NOT change result identity, result ordering, or authoritative meaning

## 4.2 Forbidden Inputs

PRD-25 presentations MUST NOT treat any of the following as authority:

* uncommitted writes
* in-memory caches
* browser local state
* UI-only transient buffers
* Kafka topics
* WAL buffers
* external enrichment APIs
* heuristic recency views
* AI / OPAIF outputs
* non-committed telemetry

---

# 5. QUERY AND RENDER CONTRACT

## 5.1 Canonical Query Ownership

The canonical `query_object` is owned by PRD-13.

PRD-25 MUST reference PRD-13 query semantics exactly and MUST NOT redefine:

* query schema
* query identity
* result-hash construction
* data-source authority
* query execution law
* report object schema

Each dashboard panel MUST bind to:

* one `dashboard_id`
* one `panel_id`
* one canonical `query_object` as defined by PRD-13
* one committed `query_record`
* one committed `query_result_record`
* one deterministic render transform

## 5.2 Dashboard Registry Contract

Every dashboard definition governed by PRD-25 MUST declare:

* one `dashboard_id`
* one `dashboard_family`
* owning PRD references
* role-scoped visibility inputs sourced from PRD-21 entitlements or workflow state
* default panel order
* default visible filters
* permitted saved view state fields
* deterministic drill-down targets

The dashboard registry MUST NOT:

* define entitlement logic
* define workflow authority
* define alternate summary-metric formulas for different audiences
* hide default filters, scope constraints, or evidence-routing rules

## 5.3 Panel Contract

Every panel definition governed by PRD-25 MUST declare:

* one `panel_id`
* one `panel_kind`
* one canonical query binding
* one committed result binding
* one deterministic render transform identifier
* explicit sort keys and explicit tie-break keys if ordered output is shown
* explicit drill-down target or explicit no-drill reason
* explicit display behavior for loading, redacted, unavailable, stale, degraded, empty, and unknown commit lineage state

Panel definitions MUST NOT:

* embed hidden thresholds or hidden ranking logic
* embed alternate metric definitions for executive versus operator surfaces
* depend on experimentation state, adaptive personalization, or browser-only state for visible meaning

## 5.4 Render Transform Law

Panel render transforms MUST be:

* pure
* deterministic
* replay-reconstructable
* total-order-preserving where rows are displayed

If a presentation needs additional derived fields:

* the derivation MUST be deterministic
* the derivation MUST use only committed authoritative inputs or authorized deterministic projections permitted by PRD-13
* the derivation MUST NOT change row membership, authoritative ordering, or hash identity of the underlying result set

## 5.5 Time Scope Law

`time_range` in PRD-25 is a read-layer query scope only.

`time_range` MUST NOT be used as:

* authoritative ordering identity
* authoritative first-seen / last-seen authority
* implicit wall-clock truth
* substitute for sequence bounds when sequence-bound identity exists
* implicit freshness ranking or implicit severity ranking

If a record family exposes authoritative ordering, authoritative first-observed reference, or authoritative sequence bounds, the dashboard MUST display and drill on those fields rather than local wall-clock interpretation.

When a view uses `time_range`, the UI MUST also preserve and display the deterministic scope definition bound into the canonical query.

## 5.6 Ordering Law

Every dashboard table, leaderboard, queue, heatmap, scorecard, or executive ranking MUST have:

* explicit primary sort fields
* explicit tie-break fields
* total deterministic order

Metric prominence, panel order, row order, and exception ordering MUST derive only from explicit deterministic sort keys already declared in the dashboard or panel contract.

If total deterministic order cannot be proven:

```text
REJECT QUERY SPEC -> FAIL-CLOSED -> ALERT
```

---

# 6. DASHBOARD FAMILY CONTRACT

PRD-25 defines presentation families only. Functional ownership remains with the owning PRDs.

## 6.1 SOC Command And Operations

These views MUST present deterministic summaries over authoritative operational records such as `SIGNAL`, `DETECTION`, `DECISION`, `SAFETY_EVALUATION`, `ACTION`, `EXECUTION_RESULT`, `CASE`, `INVESTIGATION`, and `RISK`, but the workflow semantics remain owned by PRD-21 / PRD-20 / PRD-13.

## 6.2 Asset Intelligence And Coverage

These views MUST remain subordinate to PRD-23 and PRD-21.

They MUST:

* derive coverage and asset state only from PRD-23-authorized committed records and authorized deterministic projections
* treat expected asset registry state as reconstructable from committed `UI_ACTION_RECORD` payloads containing `ENTITY_REGISTRY`
* present coverage-state counts and drill-downs without redefining PRD-23 coverage logic

They MUST NOT:

* invent new authoritative asset record families
* redefine expected / observed / managed / unknown logic
* mutate registry or group state outside PRD-21 / PRD-23 control paths

## 6.3 Detection, Risk, Policy, Safety, And Response

These views MUST summarize already-committed authority and MUST NOT redefine detection, risk, policy, safety, or action semantics.

## 6.4 Investigations, Search, Simulation, And Reporting

These views MUST remain subordinate to PRD-21 and PRD-13.

They MUST:

* use canonical `query_object`
* map every displayed result to committed `query_result_record`
* preserve exact evidence references and lineage

They MUST NOT:

* define parallel search semantics
* define parallel simulation semantics
* define UI-only investigation state

## 6.5 Platform Integrity, Replay, And Build Assurance

These views MUST present deterministic summaries over committed integrity, replay, and build evidence. They MUST NOT treat non-authoritative caches or execution logs as storage authority.

## 6.6 Executive Intelligence

Executive dashboards MUST be summary-first projections over the same underlying authoritative record families used by operator dashboards.

Executive dashboards MUST:

* compress scope and complexity without compressing authority
* preserve drill-down path from every summary metric to committed evidence
* preserve identical truth across executive, operational, and forensic views
* bind every summary metric, scorecard, trend, and exception count to one canonical query or one authorized deterministic projection and one deterministic drill-down path
* disclose the active scope, active filters, and evidence lineage for every summary metric
* preserve identical metric definitions across board, CEO, CISO, CTO, CIO, regional, datacenter, operator, and forensic surfaces

Executive dashboards MUST NOT:

* use a parallel data mart as authority
* use approximate roll-ups that cannot be reconstructed deterministically
* hide the evidence path behind narrative-only panels
* redefine a metric formula under a different label for a different audience
* present narrative summary without linked evidence index, linked query identity, or linked drill-down target

## 6.7 Screen Family Minimum Requirements

Each dashboard family MUST preserve one stable screen grammar with explicit scope disclosure, explicit filters, deterministic panel order, and direct evidence access.

| Family | Required First Emphasis | Required Main Analysis Surface | Required Evidence / Action Constraint |
| --- | --- | --- | --- |
| SOC / Operations | operational summary row plus active exception or workload queue | dense operator tables for detections, cases, investigations, actions, and risk | case, approval, and override actions remain intent-routed only |
| Asset Intelligence / Coverage | coverage summary row plus coverage-state distribution | uncovered, mismatched, or onboarding-exception views by asset or group scope | registry, group, and onboarding actions remain subordinate to PRD-23 / PRD-21 |
| Detection / Risk / Policy / Response | summary metrics plus pending control or exception queues | risk concentration, safety state, execution outcome, and linked evidence views | no direct control mutation; approval / rejection / override remain routed intents |
| Investigation / Search / Reporting | committed result set and active query context | evidence review, report composition, report history, and delivery status views | search and reporting remain canonical PRD-21 / PRD-13 workflows only |
| Platform Integrity / Replay | integrity or replay summary row | signed evidence, replay outcome, build assurance, and runtime verification views | non-authoritative runtime convenience state MUST NOT replace committed evidence |
| Executive Intelligence | scorecard and summary metric row | trends, scoped hot spots, and mapped operator drill-through entry points | every executive claim MUST drill to the same operator-grade evidence model |

---

# 7. ENTERPRISE UX CONTRACT

## 7.1 Enterprise Design Law

Mishka dashboards MUST be enterprise-grade, clean, role-aware, high-signal, and operationally unambiguous.

The interface MUST:

* prioritize summary-first comprehension
* maintain high information density without clutter
* use stable layout regions and deterministic panel ordering
* use consistent enterprise design system components across all dashboard families
* keep navigation, filters, sort definition, and evidence lineage explicit at all times
* use one consistent layout grammar across executive, operational, investigative, and reporting surfaces
* use professional typography scale and restrained semantic color only
* keep executive summary ribbons and status boards compact, scannable, and evidence-linked
* keep operator evidence tables first-class, legible, and immediately reachable

## 7.2 Deterministic Layout Law

Dashboard layout MUST be deterministic for a given:

* dashboard definition
* tenant / scope entitlement
* saved view state
* viewport class

The layout engine MUST NOT:

* reorder panels based on recency, popularity, click-rate, or adaptive heuristics
* inject promotional or decorative panels
* change panel presence based on hidden experimentation state
* change metric prominence based on local usage patterns

## 7.3 Summary-First Executive Design

Executive dashboards MUST implement the following hierarchy:

* summary metric / scorecard row
* trend and distribution row
* scoped exceptions / hot spots row
* evidence-backed drill-down entry points

Executive views MUST NOT begin with raw detail tables when a deterministic summary can be presented first.

Executive summary panels MUST NOT terminate the evidence path. Every summary panel MUST expose drill-down into operator-grade evidence views backed by canonical query results.

## 7.4 Filter Visibility And Navigation Law

Every active filter MUST be:

* visible
* named
* reconstructable
* removable explicitly
* included in saved view and investigation state where applicable

Navigation MUST preserve:

* current scope
* current filter set
* current evidence context
* current redaction state
* current sort definition
* current dashboard family context

Hidden filters are FORBIDDEN.

Ambiguous navigation, ambiguous scope labels, and ambiguous breadcrumb state are FORBIDDEN.

Navigation structure MUST also satisfy the following rules:

* the top-level work-mode split MUST separate Executive, Operator, Investigation, and Platform concerns visibly
* left navigation MUST group dashboards by authority-aligned family rather than novelty, popularity, or convenience buckets
* every dashboard header MUST disclose active scope, active filters, active sort definition, and active redaction state
* search, reports, and saved views MUST be reachable from every dashboard family without creating alternate workflow authority
* drill-back from evidence MUST restore the exact parent dashboard family, panel context, scope, filter set, sort definition, and redaction state
* AI or shadow surfaces MUST NOT appear as first-class authoritative navigation families and MAY appear only as explicitly segregated companion panes where PRD-21 and PRD-22 allow them

## 7.5 Drill-Down Hierarchy

Every panel that summarizes multiple committed records MUST expose deterministic drill-down into:

* the exact query result rows
* the exact record references
* the exact governing snapshot / version hashes when relevant
* the exact UI action or report lineage when relevant
* the exact inherited filter set and sort definition

## 7.6 Evidence Lineage

Every dashboard family MUST provide an evidence lineage panel or equivalent evidence path showing:

* source record references
* query hash
* query result hash
* report hash when a report is rendered
* authoritative status versus non-authoritative status
* governing snapshot / execution-context hash when the source record family exposes it
* explicit redaction status when redaction is active

## 7.7 Accessibility And Operator Reliability

The enterprise UI MUST:

* preserve keyboard access for all interactive controls
* preserve deterministic focus order
* preserve readable contrast and status distinguishability
* preserve non-color-only status encoding
* preserve explicit redaction markers
* preserve assistive-technology-readable control labels and state labels
* preserve deterministic empty-state and unavailable-state messaging

## 7.8 Scoped Personalization Without Hidden State

Scoped personalization is allowed only through committed or replayable Mishka state such as:

* saved view state bound into PRD-21 / PRD-13 workflows
* investigation state
* explicit user-bound layout preference state governed by PRD-21

Personalization MUST NOT:

* create alternate truth
* hide active filters
* change ranking logic
* change authoritative scope without explicit operator action
* persist invisible state that changes panel meaning, metric meaning, or drill-down routing

Saved views MUST persist only explicit visible state such as filters, scope, sort, density, and panel expansion state authorized by PRD-21.

## 7.9 Forbidden UI Patterns

The following are forbidden:

* amateur visual clutter
* decorative panels without operational, governance, or evidence purpose
* inconsistent layouts for the same dashboard definition and scope
* non-deterministic ranking widgets
* ambiguous breadcrumbs or missing scope labels
* hidden drill-down constraints
* consumer-app styling that obscures governance or evidence lineage
* novelty UI patterns in authoritative dashboard surfaces
* animation that delays evidence access or obscures current state
* gamified, playful, or consumer-social interaction patterns

## 7.10 Presentation State Contract

The UI MUST render distinct, explicitly labeled presentation states for:

* loading
* redacted
* unavailable
* stale
* degraded
* empty
* unknown commit lineage state

A presentation state MUST NOT visually resemble authoritative success when the required authoritative evidence path is unavailable.

## 7.11 Empty, Redacted, And Unavailable Behavior

Empty, redacted, unavailable, stale, degraded, and unknown commit lineage states MUST:

* preserve the active scope and active filters visibly
* preserve the panel title and metric identity visibly
* explain why evidence is absent, redacted, unavailable, stale, degraded, empty, or not commit-bound
* avoid placeholder numbers, synthetic trends, or decorative filler charts

## 7.12 Visual And Interaction Quality Bar

Authoritative Mishka dashboard surfaces MUST use:

* one consistent enterprise design system
* professional typography hierarchy
* restrained semantic color usage only
* dense but legible operational layouts
* evidence-linked tables for operator surfaces
* compact status boards and summary ribbons for executive surfaces

Authoritative Mishka dashboard surfaces MUST NOT use:

* decorative-only visualization
* playful animation
* consumer-social interaction patterns
* novelty navigation patterns that hide scope or evidence

---

# 8. FILTER CONTRACT

## 8.1 Filter Law

All filters used by PRD-25 presentations MUST be:

* explicit
* typed
* canonicalized
* bound into the canonical `query_object`
* visible in the UI
* replay-visible where PRD-21 requires replayable workflow state

Unknown filters are FORBIDDEN.

Null filters are FORBIDDEN.

Implicit defaults inside query identity are FORBIDDEN.

## 8.2 Supported Filter Classes

PRD-25 supports only filter classes that map to committed record fields, committed snapshot hashes, or deterministic derived projection fields authorized by owning PRDs.

The allowed classes for this PRD are:

* scope identifiers
* entity / asset identifiers
* group and hierarchy identifiers
* record-type and domain-type discriminators
* state and status enums
* committed sequence bounds
* explicit read-scope time bounds
* version / snapshot / execution-context hashes
* report delivery state
* PRD-23-authorized coverage and asset projection fields

If a proposed filter cannot be tied to a committed authoritative field or an authorized deterministic derived projection field:

```text
REJECT FILTER -> FAIL-CLOSED -> ALERT
```

## 8.3 Inheritance And Saved Views

Drill-down filter inheritance MUST be explicit.

Saved views MUST persist exact filter state.

Saved views MUST persist exact visible sort definition and explicit dashboard density or expansion state when PRD-21 permits those fields.

Saved views MUST NOT broaden role scope, data scope, or evidence scope beyond the explicit state visible to the operator at save time.

Removing a filter MUST remove the bound field from the next canonical query.

---

# 9. UI ACTION AND WRITE CONTRACT

## 9.1 Write Routing Law

PRD-25 dashboards are allowed to initiate only UI-layer requests already authorized by PRD-21 / PRD-20 / PRD-13 / PRD-23.

Every write-capable interaction MUST follow:

```text
UI_ACTION_INTENT
    -> AUTHORITATIVE BACKEND FINALIZATION
    -> UI_ACTION_RECORD
    -> DOWNSTREAM AUTHORITATIVE SERVICE / RECORD FAMILY
```

PRD-25 dashboards MUST NOT directly mutate:

* `SIGNAL`
* `DETECTION`
* `DECISION`
* `SAFETY_EVALUATION`
* `ACTION`
* `EXECUTION_RESULT`
* `ROLLBACK`
* `ROLLBACK_OVERRIDE`

## 9.2 Allowed UI-Initiated Request Classes

The following request classes are allowed only through existing owning PRDs:

* query initiation
* report generation
* report delivery requests
* saved view / investigation state changes
* case workflow intents
* group / entity-registry control intents
* PRD-23-authorized asset investigation / onboarding intents
* PRD-20-governed approval / rejection / override intents
* PRD-21 policy-simulation requests

## 9.3 Asset Intelligence Action Boundary

Asset-related dashboard actions MUST remain subordinate to PRD-23 and PRD-21.

PRD-25 MUST present and route only:

* group assignment intents
* entity-registry intents
* investigation trigger intents
* onboarding / deployment intents when another owning PRD authorizes them

PRD-25 MUST NOT redefine:

* asset investigation semantics
* asset onboarding semantics
* deployment semantics
* enforcement semantics

---

# 10. REPORTING AND EXPORT CONTRACT

## 10.1 Report Ownership

PRD-13 owns the report object and report-record schema.

PRD-25 owns only presentation and enterprise-report composition rules.

Reports rendered through PRD-25 MUST:

* derive from committed `query_result_record`
* link to the exact committed `query_record`
* preserve `query_hash` and `query_result_hash`
* remain deterministic for identical committed inputs
* preserve export verifiability

## 10.2 Executive Reporting

Executive reports MUST:

* summarize the same truth model used by operational dashboards
* provide deterministic scope, period, filter, and sort-definition disclosure
* provide evidence-backed drill-down or attached evidence index
* preserve authoritative / non-authoritative labeling exactly
* preserve the same metric definitions used by corresponding executive and operator dashboards

## 10.3 Shadow / OPAIF Report Handling

If PRD-22 output is rendered through PRD-25:

* it MUST be labeled non-authoritative
* it MUST remain visually segregated from authoritative evidence
* persisted output MUST appear only through PRD-13 `report_record`
* `shadow_metadata` handling MUST follow PRD-13 and PRD-22 exactly

---

# 11. AI / OPAIF ISOLATION IN THE DASHBOARD

## 11.1 Ownership

The AI Assistant Panel is owned by PRD-21 and PRD-22.

PRD-25 MUST define only presentation constraints for that panel.

## 11.2 Mandatory Separation

AI / OPAIF content MUST be:

* explicitly labeled NON-AUTHORITATIVE
* visually separated from authoritative evidence
* incapable of directly triggering control actions
* incapable of changing filters, ranking, priority, or execution state without an explicit separate UI action routed through authoritative pathways

## 11.3 Forbidden AI Presentation Behavior

AI / OPAIF content MUST NOT be presented as:

* proof
* evidence
* authoritative conclusion
* execution instruction
* hidden prioritization engine

If separation is ambiguous:

```text
REJECT PANEL RENDER -> FAIL-CLOSED -> ALERT
```

---

# 12. REPLAY, CACHE, AND REBUILD CONTRACT

## 12.1 Replay Law

For identical committed authoritative inputs, identical query objects, identical redaction state, identical presentation state inputs, and identical panel specifications:

```text
IDENTICAL INPUTS -> IDENTICAL DASHBOARD OUTPUT
```

## 12.2 Cache Law

If PRD-25 uses caches:

* they MUST be keyed deterministically
* they MUST remain non-authoritative
* they MUST NOT change result membership, ordering, or identity
* they MUST be disposable and rebuildable
* they MUST NOT change visible loading, stale, degraded, or unavailable state semantics

## 12.3 Pre-Aggregation Law

Pre-aggregations used by PRD-25 MUST be authorized deterministic projections only.

They MUST NOT become a second source of truth.

---

# 13. FAILURE MODEL

PRD-25 MUST fail closed on:

* hidden filters
* ambiguous authoritative / non-authoritative labeling
* missing committed evidence references required for a rendered claim
* missing total order
* query or report render paths that bypass PRD-13 records
* UI actions that bypass `UI_ACTION_INTENT` / `UI_ACTION_RECORD` flow
* presentation logic that depends on uncommitted or external state
* presentation state that cannot be justified from explicit committed or derived inputs

```text
AMBIGUOUS VIEW OR UNPROVABLE RENDER
    -> REJECT
    -> FAIL-CLOSED
    -> ALERT
```

---

# 14. SUMMARY

```text
PRD-25 DEFINES THE ENTERPRISE DASHBOARD AND REPORTING PRESENTATION CONTRACT ONLY.

- PRD-13 REMAINS STORAGE / QUERY / REPORT AUTHORITY.
- PRD-21 REMAINS UI WORKFLOW / SEARCH / INVESTIGATION / DASHBOARD GOVERNANCE AUTHORITY.
- PRD-20 REMAINS CONTROL / APPROVAL / OVERRIDE AUTHORITY.
- PRD-22 REMAINS NON-AUTHORITATIVE AI / OPAIF AUTHORITY.
- PRD-23 REMAINS ASSET INTELLIGENCE AUTHORITY.

PRD-25 REQUIRES:
- ENTERPRISE-GRADE, HIGH-SIGNAL UX
- DETERMINISTIC LAYOUT AND FILTERING
- EVIDENCE LINEAGE
- ROLE-AWARE PRESENTATION WITHOUT ALTERNATE TRUTH
- EXECUTIVE SUMMARIES OVER THE SAME AUTHORITATIVE DATA MODEL
```

---

# APPENDIX A. DASHBOARD IMPLEMENTATION MATRIX

This appendix is normative within PRD-25 presentation scope only.

Representative rows below define the minimum dashboard-family implementation contract and do not create new authority outside the owning PRDs.

All appendix rows inherit the following shared mapping rules:

* each rendered panel MUST bind to one canonical `query_object`, one committed `query_record`, and one committed `query_result_record`
* report-capable views MUST preserve linkage to committed `report_record` and `report_delivery_record` when those objects are rendered or delivered
* write-capable interactions MUST remain inside `UI_ACTION_INTENT -> AUTHORITATIVE BACKEND FINALIZATION -> UI_ACTION_RECORD -> DOWNSTREAM AUTHORITATIVE SERVICE / RECORD FAMILY`
* AI / OPAIF output MUST NEVER be treated as an authoritative read source

| Dashboard Family | Dashboard Name | Primary Persona | Authoritative Read Sources | Allowed Write Intents | Required Filters | Required Drill-Down Target | Evidence Lineage Requirements | Executive Summary Allowed | Non-Authoritative AI Allowed | Governing PRDs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SOC / Operations | SOC Command Dashboard | SOC analyst / duty lead | committed PRD-13 operational records for `SIGNAL`, `DETECTION`, `DECISION`, `SAFETY_EVALUATION`, `ACTION`, `EXECUTION_RESULT`, `CASE`, `INVESTIGATION`, `RISK`; committed `query_record`; committed `query_result_record` | query initiation; case workflow intents; saved view / investigation state changes; PRD-20 approval / override intents through PRD-21 | scope; status / state; record or domain discriminator; committed sequence bounds; explicit read-scope time bounds | exact committed `query_result_record` rows and underlying committed record references | `query_hash`; `query_result_hash`; source record references; governing snapshot or execution-context hash when exposed; explicit redaction state | Yes | No | PRD-25, PRD-21, PRD-20, PRD-13, PRD-15, PRD-01 |
| Asset Intelligence / Coverage | Asset Coverage Dashboard | asset analyst / coverage lead | committed PRD-23-authorized asset and coverage records; committed `ui_action_record` payloads carrying `ENTITY_REGISTRY`; committed `group_record`; committed `query_record`; committed `query_result_record` | group assignment intents; entity-registry intents; investigation trigger intents; onboarding intents when separately authorized | scope; entity or asset identifier; group hierarchy identifier; coverage-state filter; committed sequence bounds; explicit read-scope time bounds | exact committed `query_result_record` rows, proving signal references, expected registry references, governing group references | `query_hash`; `query_result_hash`; first-observed and coverage references when exposed; expected registry reference; governing group lineage; explicit redaction state | Yes | No | PRD-25, PRD-23, PRD-21, PRD-13, PRD-15, PRD-01 |
| Detection / Risk / Policy / Response | Detection, Risk, Policy, Safety, And Response Dashboard | detection analyst / incident commander / approver | committed PRD-13 and PRD-20 authoritative records for `DETECTION`, `DECISION`, `RISK`, `SAFETY_EVALUATION`, `ACTION`, `EXECUTION_RESULT`, `ROLLBACK`, `ROLLBACK_OVERRIDE`; committed `query_record`; committed `query_result_record` | query initiation; case workflow intents; PRD-20-governed approval / rejection / override intents; report generation | scope; state / status; record or domain discriminator; committed sequence bounds; version or execution-context hash | exact committed `query_result_record` rows, linked control references, linked execution or rollback references | `query_hash`; `query_result_hash`; control-record references; execution or rollback references; governing snapshot or execution-context hash | Yes | No | PRD-25, PRD-20, PRD-21, PRD-13, PRD-15, PRD-01 |
| Investigation / Search / Reporting | Investigation Workspace And Search / Reporting Views | analyst / investigator | committed `investigation_record`, `query_record`, `query_result_record`, `report_record`, `report_delivery_record`, `case_record`, `ui_action_record` | query initiation; report generation; report delivery requests; saved view / investigation state changes; case workflow intents; PRD-21 policy-simulation requests | scope; explicit query filters; committed sequence bounds; explicit read-scope time bounds; report delivery state; version or execution-context hash | exact committed `query_result_record` rows; exact committed report lineage; exact committed `ui_action_record` lineage when applicable | `query_hash`; `query_result_hash`; `report_hash`; report-delivery references; source record references; explicit redaction state | No | Yes, segregated PRD-22 panel only | PRD-25, PRD-21, PRD-13, PRD-22, PRD-15, PRD-01 |
| Platform Integrity / Replay | Integrity, Replay, And Build Assurance Dashboard | platform operator / auditor | committed integrity, replay, and build evidence referenced by PRD-13, PRD-15, PRD-19, PRD-24; committed `query_record`; committed `query_result_record`; committed `report_record` when rendered | query initiation; report generation | scope; state / status; committed sequence bounds; version, snapshot, or execution-context hash | exact committed `query_result_record` rows and exact signed evidence references | `query_hash`; `query_result_hash`; signed snapshot or version hashes; `report_hash` when rendered; explicit authoritative-status labeling | Yes | No | PRD-25, PRD-24, PRD-15, PRD-19, PRD-13, PRD-01 |
| Executive Intelligence | Executive Summary Dashboard | board / CEO / CIO / CTO / CISO / regional / datacenter leader | the same committed authoritative record families used by corresponding operator dashboards; committed `query_record`; committed `query_result_record`; committed `report_record` when rendered | query initiation; report generation; report delivery requests | scope; explicit visible filters; committed sequence bounds; explicit read-scope time bounds; version, snapshot, or execution-context hash | operator-grade evidence view backed by exact committed `query_result_record` rows and committed record references | `query_hash`; `query_result_hash`; source record references; governing hashes; explicit filter disclosure; explicit redaction state | Yes | Yes, segregated PRD-22 panel only | PRD-25, PRD-21, PRD-13, PRD-22, PRD-15, PRD-01 |

---

# APPENDIX B. PHASED DELIVERY SEQUENCING

Implementation sequencing MUST remain subordinate to the owning PRDs and MUST preserve evidence lineage from the first shipped dashboard family.

1. Phase 1: shared dashboard shell, scope and filter grammar, saved-view visible state, lineage drawer, and the operator-first dashboard families for SOC, coverage, detection, risk, policy, safety, and response.
2. Phase 2: Investigation Workspace continuity, canonical search entry, report generation, report history, delivery status, and reporting flows that preserve exact `query_record` / `query_result_record` lineage.
3. Phase 3: platform integrity and replay surfaces, executive summary and executive reporting surfaces, and final drill-through validation proving executive views remain summary projections over the same operator truth model.

No phase exit is complete unless route behavior is deterministic, visible filters remain explicit and removable, presentation states fail closed, and drill-down or drill-back preserves inherited context.

---

# APPENDIX C. ALIGNMENT NOTES

* PRD-25 is subordinate presentation law only and MUST NOT be used to claim storage, query, workflow, control, asset-intelligence, or AI authority.
* PRD-25 is out of scope for canonical query or report schema ownership, execution or override semantics, entitlement governance, asset-semantic definition, and non-authoritative AI behavior beyond presentation isolation.
* PRD-25 depends on PRD-13 for storage / query / report authority, PRD-20 for control authority, PRD-21 for UI workflow authority, PRD-22 for non-authoritative AI authority, and PRD-23 for asset intelligence authority.
