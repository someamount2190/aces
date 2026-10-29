# ACES — Roadmap and Subagent Execution Plan

[SPEC.md](SPEC.md) is the acceptance authority. [ARCHITECTURE.md](ARCHITECTURE.md) is the design. This
document is the **build order, the work decomposition, and the rules under which subagents execute**.

The work is parallel by design: most phases decompose into workstreams that touch disjoint files and meet at
a frozen interface. The rule that makes that safe is simple — **contracts are frozen before fan-out, and
each file has exactly one owner at a time.**

---

## 1. Execution model

| Concern | Rule |
|---|---|
| Unit of work | A **workstream** (WS): one objective, one owner, a fixed file set, one gate |
| Parallelism | Workstreams in the same phase run concurrently **only** if their file sets are disjoint |
| Contract changes | Only the coordinating agent may change `schema.py`, `views.py` public signatures, or the event catalog — and only between phases |
| Evidence | A workstream reports *executed* results: commands run, output observed, tests passed. Never "should work" |
| Forbidden | Editing tests to make them pass; claiming a live-model result from a mock; touching another WS's files; committing secrets |
| Gate | The phase's exit criterion from SPEC §19, expressed as runnable checks |
| Report format | What changed · what was run · what passed · what is unproven · open risks |

A workstream that cannot meet its gate must report the failure and stop. Silent partial success is the
default failure mode of parallel agent work and is treated as a defect.

## 2. Phase 0 — Contracts (serial, single owner)

Nothing parallel happens until this is done. It is deliberately small and deliberate.

| # | Deliverable | File | Gate |
|---|---|---|---|
| 0.1 | Extract DDL + numbered migrations | `aces/schema.py` | fresh DB builds; existing DB migrates forward; `PRAGMA foreign_keys=ON` |
| 0.2 | Extract VM | `aces/vm.py` | existing VM tests pass unchanged, byte-identical behaviour |
| 0.3 | Freeze role projection signatures | `aces/views.py` | every role's view documented as a typed shape; no row pass-through |
| 0.4 | Freeze tool schemas + permissions table | `aces/tools.py` | unknown tool → `Denied`; schema violations → `ValueError` |
| 0.5 | Freeze event catalog | `aces/events.py` | event kinds enumerated; payload keys asserted in tests |
| 0.6 | Extract provider client | `aces/provider.py` | no-redirect opener; HTTPS-or-loopback check retained |
| 0.7 | Extract prompts | `aces/prompts.py` | prompts are data, versioned by digest |

**Exit:** `python -m unittest discover -s tests` passes; the package imports with no behaviour change; the
four contract modules are frozen for the rest of Phase 1.

## 3. Phases

### Phase 1 — Foundation and persistence

*Exit: core runtime and persistence tests pass.*

| WS | Objective | Files | Notes |
|---|---|---|---|
| 1A | Complete the schema: all 18 SPEC §12 entities, constraints, indexes | `schema.py`, `tests/test_schema.py` | includes `metrics`, `audit_records`, `lineage`, `research_sources` |
| 1B | Engine state machines incl. candidate versions and status registry (SPEC §13) | `core.py`, `tests/test_core.py` | version immutability enforced by unique constraint, not convention |
| 1C | Event sequencing: `(aggregate, aggregate_seq)`, dedup on replay | `events.py`, `tests/test_events.py` | depends on 1A |
| 1D | Migration test harness: build v0 DB, migrate, assert data preserved | `tests/test_migrations.py` | depends on 1A |
| 1E | Config + agent identity records (SPEC §12 `agents`) | `config.example.json`, `core.py` | no behaviour change |

Order within phase: 1A first (everyone imports it), then 1B/1C/1D in parallel, 1E anytime.

### Phase 2 — Shared sandbox

*Exit: a toy cryptographic challenge can be published and evaluated.*

| WS | Objective | Files | Notes |
|---|---|---|---|
| 2A | Challenge versioning + both access modes (open, black-box) | `core.py`, `schema.py` | fixes defect 9: black-box needs an oracle path or an explicit unsupported error |
| 2B | Sanitized breach/failure projection for the Integrator | `views.py` | fixes defect 8: never the target plaintext |
| 2C | Oracle interface, query-budgeted, counted in `metrics` | `tools.py`, `core.py` | chosen-plaintext only in this phase |
| 2D | Difficulty record per challenge version (search space, key bits, oracle budget, access mode) | `schema.py`, `core.py` | SPEC §20: difficulty measured, not assumed |
| 2E | Blindness test suite: a table-driven proof that no role view contains forbidden fields | `tests/test_blindness.py` | negative tests, not prose |

### Phase 3 — Verification and candy

*Exit: false submissions rejected; a confirmed breach yields exactly one reward and escalation.*

| WS | Objective | Files | Notes |
|---|---|---|---|
| 3A | `verify.py` core: plaintext recovery, key recovery, forgery | `verify.py`, `tests/test_verify.py` | pure functions, no I/O |
| 3B | Transactional breach commit: verdict + state + reward + breach record + 3 events in one commit | `core.py`, `verify.py` | fixes defect 4 (candy inflation) alongside versioning |
| 3C | Rejection path: invalid and duplicate submissions produce `ATTACK_REJECTED`, no candy, no escalation | `core.py` | duplicate returns prior verdict |
| 3D | Restart/idempotency: replay a completed breach, assert no second reward | `tests/test_restart.py` | SPEC §18 |
| 3E | Adversary evidence bundle: `script`, `tool_trace`, reproducible | `schema.py`, `tools.py` | prerequisite for Phase 8 replay |

**Gate (explicitly tested):** no-breach → no escalation; invalid attack → no candy; verified attack →
exactly one breach, one reward, escalation authorized; duplicate → no second reward.

### Phase 4 — Autonomous four-agent operation

*Exit: the agents function without a human passing messages between them.*

| WS | Objective | Files | Notes |
|---|---|---|---|
| 4A | Scheduler rewrite: post-commit idle snapshot, domain-event cursor, no polling of idle agents | `runtime.py` | **fixes defect 1** — the highest-value change in the project |
| 4B | Dispatch exclusivity: one in-flight item per role | `core.py`, `runtime.py` | **fixes defect 2** |
| 4C | Provider hardening: no-redirect opener, timeouts, size caps, per-role error taxonomy | `provider.py` | **fixes defect 3** |
| 4D | Crash recovery sweep: orphaned `PENDING` → `ABANDONED` + audit record | `runtime.py`, `core.py` | **fixes defect 7** |
| 4E | Budgets: turns, tokens, wall-clock, oracle queries; exhaustion is a recorded event | `runtime.py`, `schema.py` | replaces silent `continue` |
| 4F | Live acceptance harness: run N ticks against a real provider, record every call | `tools/run_cycle.py`, `docs/live-runs/` | must distinguish mock from live |

**Gate:** a live run in which all four roles are called, no role is called while it has no relevant work,
and the turn budget is not exhausted by error turns.

### Phase 5 — Observer intelligence

*Exit: verified failures influence subsequent Generator proposals.*

| WS | Objective | Files | Notes |
|---|---|---|---|
| 5A | Finding classification: weakness class, confidence, evidence link | `observer.py`, `schema.py` | cannot exist without a `breach_verifications` row |
| 5B | Lineage analysis: shared weakness across constructions, inheritance detection | `observer.py` | SPEC §6 intelligence functions |
| 5C | Feedback pipeline into the Generator's view, deduplicated | `views.py`, `observer.py` | persistent, survives restart |
| 5D | Held-out challenge support (anti-specialisation, SPEC §20) | `core.py` | metric only; does not alter breach gating |
| 5E | Optional public-source monitoring, allowlisted and cited | `observer.py` | outbound fetch is a policy decision; default off |

### Phase 6 — Dashboard and controls

*Exit: activity and state can be inspected without violating agent blindness.*

| WS | Objective | Files | Notes |
|---|---|---|---|
| 6A | Single request-validation path: Host, CSRF, admin token, strict JSON shapes | `web.py` | fixes defect 5 |
| 6B | Audit surface: authenticated export, breach plaintext behind admin token | `web.py`, `core.py` | |
| 6C | Panels: agent states, challenge history, lineage, findings, resource use | `web.py` | read-only first, controls second |
| 6D | CSP, `X-Frame-Options`, no-inline-script policy | `web.py` | |

### Phase 7 — Autonomous evolutionary demonstration

*Exit: a verified breach yields candy, Observer learning, and a successor challenge.*

Single workstream, no parallelism: run the ecosystem against deliberately vulnerable toy ciphers until a
real breach occurs, then verify the full chain end to end and publish the run record.

The demonstration must show: four independent sessions · a real candidate · a real publication · a real
breach verified by code (not by a model's claim) · exactly one candy · an Observer finding · a successor
challenge whose difficulty record is comparable to its predecessor's.

### Phase 8 — Advanced mathematical experimentation

*Exit: reproducible evidence of meaningful findings beyond basic functional tests.*

Blocked on an execution sandbox. This host cannot provide one (no working namespace creation, no container
runtime), so Phase 8 begins with a container/microVM decision, not with code.

Prerequisites: arbitrary-code isolation · reproducible attack script replay · statistical verification
(§8 of ARCHITECTURE) · formal property checking where a tool exists · independent held-out evaluation.

## 4. File ownership

One owner per file per phase. A file may not be edited by two workstreams in the same phase.

| File | Phase owner(s) |
|---|---|
| `schema.py` | 0, 1A, then 2A/2D via coordinator only |
| `vm.py` | 0.2, frozen thereafter |
| `events.py` | 0.5, 1C, frozen |
| `views.py` | 0.3, 2B, 5C |
| `tools.py` | 0.4, 2C, 3E |
| `provider.py` | 0.6, 4C |
| `core.py` | 1B, 2A, 3B, 3C, 4B, 4D |
| `verify.py` | 3A, 3B |
| `runtime.py` | 4A, 4D, 4E |
| `observer.py` | 5A, 5B, 5C |
| `web.py` | 6A–6D |
| `prompts.py` | 0.7, then coordinator only |

## 5. Dependency graph

```
Phase 0 ──> 1A ──> 1B ──┬──> 2A ──> 2B ──> 3B ──┬──> 4A ──> 4B ──> 4D ──> 4E ──> Phase 7
                 │      │        │              │
                 │      ├──> 1C ──┤              ├──> 4C
                 │      ├──> 1D ──┤              │
                 │      └──> 1E  │              └──> 3A ──> 3C ──> 3D
                 │                ├──> 2C ──> 3A
                 │                ├──> 2D
                 │                └──> 2E
                 └──> 5A ──> 5B ──> 5C           6A ──> 6B ──> 6C ──> 6D
```

Parallel-safe pairs in the near term: `(1B, 1C)`, `(1B, 1D)`, `(2A, 2C)`, `(2B, 2E)`, `(3A, 3E)`,
`(4C, 4A)` — each pair touches disjoint files.

## 6. Risk register

| Risk | Where it bites | Mitigation |
|---|---|---|
| Parallel agents edit the same file and produce a plausible but broken merge | any phase | the ownership table; contract freeze in Phase 0 |
| Tests are weakened to pass a gate | every gate | tests are owned by the coordinator; a gate requires the *pre-existing* suite to pass unmodified |
| "Live" results are actually mocked | Phase 4, 7 | the run record must include provider identity, per-call latency, and raw responses; mocks are labelled |
| Provider quota exhausts mid-run | Phase 4, 7 | budget accounting; runs are resumable and bounded; quota failure is a recorded event, not a silent stall |
| Difficulty inflation is mistaken for progress | Phase 7, 8 | difficulty record per version (2D); lineage comparison required in the demo |
| No sandbox on this host | Phase 8 | Phase 8 starts with the isolation decision; until then arbitrary code is a hard non-goal |
| Self-assessment drift: the system's own reports are treated as evidence | everywhere | verifier is deterministic; Observer findings are hypotheses; only `breach_verifications` rows are facts |

## 7. Handoff template

Every workstream prompt should carry these fields, and nothing vague:

```
WORKSTREAM: <id and title>
PHASE / EXIT CRITERION: <from SPEC §19>
OBJECTIVE: <one sentence>
FILES YOU OWN: <exact list, from §4>
FILES YOU MAY READ: <everything, but never edit outside your list>
FROZEN CONTRACTS: <signatures/schemas that must not change; if a change is needed, stop and report>
DELIVERABLES: <code + tests + a short report>
GATE / EVIDENCE REQUIRED: <commands to run, output to paste>
DO NOT: edit tests to pass; touch other WS files; add dependencies without asking; claim a live result from a mock
REPORT: what changed · what you ran · what passed · what is unproven · risks
```

## 8. Immediate next step

Phase 0, serially, by one agent. Everything else is speculative until `schema.py`, `vm.py`, `views.py`,
`tools.py`, `events.py`, `provider.py` and `prompts.py` exist as frozen contracts with the existing suite
still green.
