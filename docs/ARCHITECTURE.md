# ACES — Target Architecture

How ACES is built, how the trust boundaries are enforced, and how today's prototype maps onto the target.
[SPEC.md](SPEC.md) defines *what*; [ROADMAP.md](ROADMAP.md) defines *order and ownership*.

> **Status.** This is the target architecture. The repository contains a working vertical slice of it — a
> single-process prototype with a real VM, real SQLite transactions, real role isolation at the service
> layer, and a dashboard. It is **not** yet the system SPEC.md describes: no breach has ever been produced
> by live models, arbitrary code execution is not available, and ten of eighteen required data entities do
> not exist. Deviations are enumerated in §11 and traced back to requirements in §13.
>
> **Role embodiment.** The four roles are currently staffed by **harness subagent sessions**, not by provider
> models, because the targets in SPEC §1 are not available on this host. The Engine, verifier and breach gate
> are unchanged by that substitution; the independence and autonomy claims are not. See [AGENTS.md](AGENTS.md).

---

## 1. Design principles

1. **The verifier is deterministic and owns truth.** No LLM decides whether a breach happened. Candy,
   escalation permission and `BREACH_VERIFIED` are all consequences of one transactional database commit.
2. **Escalation is gated by a database predicate, not by agent intent.** A successor challenge can only be
   inserted by a transaction that observes a `BREACHED` predecessor. Prompt instructions are advisory; the
   constraint is not.
3. **Blindness is service-layer projection.** Each role receives a distinct view and a distinct tool
   allowlist. There is no shared conversation. This is enforceable in one process today; process and
   filesystem isolation arrive with containers (Phase 8).
4. **Model output is untrusted data.** It may only enter the system through a validated tool schema. It is
   never executed, interpolated into SQL, or granted filesystem or network authority.
5. **Everything that matters is an event.** State changes append an event in the same transaction. The
   event log is the audit trail and the basis for Observer memory.
6. **Difficulty is measured, not assumed** (SPEC §20). Every challenge version records its search space,
   key size, oracle budget and attack-access mode, so a successor that merely raises parameters is visible
   as such in the lineage.
7. **Budgets are explicit.** Turns, wall-clock, CPU/memory per tool call, and oracle queries are configured
   per role and consumed atomically.

## 2. Process and trust model

```
                ┌──────────────────────────── trusted host process ────────────────────────────┐
                │                                                                              │
  admin browser │   dashboard (web.py)          coordinator (runtime.py)                       │
  ──────────────┼──> loopback, CSRF, Host        │  schedule → dispatch → record               │
                │   validation, admin-only       │                                             │
                │        │                       ▼                                             │
                │        │                 ┌──────────┐    tools      ┌────────────┐           │
                │        └────────────────>│  Engine  │<─────────────>│ role tool  │           │
                │                          │ core.py  │               │ dispatcher │           │
                │                          └────┬─────┘               └────────────┘           │
                │                               │  transactions only                           │
                │                          ┌────▼─────┐    verifier   ┌────────────┐           │
                │                          │ SQLite   │<─────────────>│  verify.py │           │
                │                          │   WAL    │    (pure)     │  deterministic│        │
                │                          └──────────┘               └────────────┘           │
                └───────────────────────────────────────┬──────────────────────────────────────┘
                                                        │ HTTPS / loopback HTTP
                                          ┌─────────────▼──────────────┐
                                          │ provider (provider.py)     │  four independent
                                          │ per-role model + session   │  sessions, no fallback
                                          └────────────────────────────┘
```

**Trusted:** the coordinator, the Engine, the verifier, the dashboard process, and the administrator.
**Untrusted:** every model response, every submitted attack artifact, every event payload rendered in the
UI.
**Semi-trusted:** the Observer — it may read supervisory data but may not mutate truth (no candy, no
escalation).

**Role embodiment.** A model is reached through `RoleDriver` (`agents.py`). Today the only live
implementation is `SubagentDriver`: the coordinator publishes a prompt as a work item, an orchestrating
agent carries it to that role's persistent subagent session, and the reply is delivered back and validated.
The coordinator still never calls a model directly, so the trust model above is unchanged — the orchestrator
is a transport, not a participant, and it holds no authority over the breach gate. [AGENTS.md](AGENTS.md)
defines that protocol, the four charters, and the limits it introduces.

## 3. Module layout

Current files are small enough to split; the split below is what makes parallel work possible without
merge collisions. Each module has exactly one owner (see ROADMAP §4).

| Module | Responsibility | Status |
|---|---|---|
| `aces/schema.py` | DDL, migrations, indexes, constraints | **to create** (extract from `core.py`) |
| `aces/core.py` | Engine: transactions, state machines, event append, queries | exists (179 lines) |
| `aces/vm.py` | Bounded byte-permutation VM: `validate`, `transform` | **to extract** from `core.py` |
| `aces/verify.py` | Deterministic verifier: correctness, attack evaluation, statistical tests | **to create** |
| `aces/views.py` | Role projections and redaction | **to extract** from `core.view` |
| `aces/tools.py` | Permission-scoped tool dispatch and argument schemas | **to extract** from `core.tool` |
| `aces/runtime.py` | Coordinator: scheduling, dispatch, budgets, crash recovery | exists (62 lines) |
| `aces/provider.py` | HTTP client: per-role config, redirect policy, timeouts, size caps | **deferred** — no provider; `runtime.py` holds the current code until one exists |
| `aces/agents.py` | `RoleDriver` protocol; `SubagentDriver` (today), `HttpDriver` (future), `MockDriver` (tests) | **to create** |
| `aces/pump.py` | In-the-loop dispatch CLI: `dispatch`, `deliver`, `status`, `recover` | **to create** |
| `aces/observer.py` | Lineage, pattern detection, feedback generation | **deferred** — findings exist; analysis is Phase 5+ |
| `aces/web.py` | Dashboard, lifecycle controls, audit export | exists (37 lines); **deferred** beyond read-only status |
| `aces/prompts.py` | Role system prompts (versioned, reviewable) | **to extract** from `runtime.py` |

`runtime.py` and `core.py` stay import-compatible during the split: no caller outside the package may need
to change in a single step.

## 4. Data model

### 4.1 Required entities and current coverage

SPEC §12 lists eighteen entities. Current schema has ten tables.

| Spec entity | Current table | Gap |
|---|---|---|
| Agents | — | roles are a module constant; no configuration or identity row |
| Sessions | `sessions` | OK (messages, turns, cursor) |
| Permissions | — | hardcoded dict in `tool()`; not inspectable, not versioned |
| Candidates | `candidates` | single row per digest; no version chain |
| Candidate versions | — | **missing**; edits are impossible by design, but versions have no identity |
| Tools | — | **missing**; tool availability is implicit in code |
| Challenges | `challenges` | OK, but no `version`, no `mode` column (buried in `public`), no difficulty record |
| Challenge versions | — | **missing**; `parent` chains challenges, not versions of one construction |
| Attack attempts | `submissions` | stores only the plaintext guess; no script, no evidence bundle, no tool trace |
| Breach verification | — | **missing**; evidence lives inside an event payload |
| Candy rewards | `rewards` | OK (`challenge` PK, `submission` UNIQUE, `amount`) |
| Observer findings | `findings` | OK, minimal (no classification, no confidence, no source links) |
| Research sources | — | **missing** |
| Construction lineage | `challenges.parent` | **missing** as first-class graph (candidate → candidate inheritance) |
| Feedback | `feedback` | OK, minimal |
| Event logs | `events` | append-only, but no aggregate id / sequence number; dedup is rowid-only |
| Metrics | — | **missing**; token and CPU cost are not persisted |
| Audit records | — | **missing**; secret-bearing evidence has no admin-only home |

### 4.2 Target schema (Phase 1–3)

```sql
agents(id TEXT PRIMARY KEY, role TEXT UNIQUE, config TEXT, created REAL)
permissions(role TEXT, tool TEXT, PRIMARY KEY(role, tool))
tools(id TEXT PRIMARY KEY, name TEXT UNIQUE, schema TEXT, enabled INTEGER)
candidates(id INTEGER PRIMARY KEY, name TEXT, status TEXT, created REAL)
candidate_versions(id INTEGER PRIMARY KEY,
                   candidate INTEGER REFERENCES candidates(id),
                   version INTEGER, spec TEXT, digest TEXT UNIQUE,
                   test_vectors TEXT, created REAL,
                   UNIQUE(candidate, version))
challenges(id INTEGER PRIMARY KEY, candidate_version INTEGER REFERENCES candidate_versions(id),
           version INTEGER, state TEXT, mode TEXT, public TEXT, secret TEXT,
           difficulty TEXT, parent INTEGER UNIQUE, published REAL)
challenge_versions(id INTEGER PRIMARY KEY, challenge INTEGER, artifact TEXT, created REAL)
submissions(id INTEGER PRIMARY KEY, challenge INTEGER, evidence TEXT, script TEXT,
            tool_trace TEXT, valid INTEGER, UNIQUE(challenge, evidence))
breach_verifications(id INTEGER PRIMARY KEY, challenge INTEGER UNIQUE, submission INTEGER UNIQUE,
                     method TEXT, detail TEXT, created REAL)
rewards(challenge INTEGER PRIMARY KEY, submission INTEGER UNIQUE, amount INTEGER, created REAL)
findings(id INTEGER PRIMARY KEY, challenge INTEGER, classification TEXT, confidence REAL,
         data TEXT, created REAL)
research_sources(id INTEGER PRIMARY KEY, url TEXT, published REAL, retrieved REAL,
                 confidence REAL, note TEXT)
lineage(child_candidate INTEGER, parent_candidate INTEGER, reason TEXT,
        PRIMARY KEY(child_candidate, parent_candidate))
feedback(id INTEGER PRIMARY KEY, finding INTEGER, target TEXT, data TEXT, created REAL)
events(seq INTEGER PRIMARY KEY AUTOINCREMENT, aggregate TEXT, aggregate_seq INTEGER,
       kind TEXT, data TEXT, created REAL, UNIQUE(aggregate, aggregate_seq))
metrics(id INTEGER PRIMARY KEY, role TEXT, work_id TEXT, tokens_in INTEGER, tokens_out INTEGER,
        cpu_ms INTEGER, cost REAL, created REAL)
audit_records(id INTEGER PRIMARY KEY, kind TEXT, payload TEXT, created REAL)
```

Invariants that must hold as constraints, not conventions:

- `one_active` partial unique index on `challenges` where `state='ACTIVE'`.
- A successor insert must observe `parent` in `BREACHED` — enforced in the same transaction.
- `rewards.challenge` is a primary key, so a second candy for one challenge is impossible.
- `submissions` unique on `(challenge, evidence)`, so a replay is a duplicate, not a new attempt.
- `breach_verifications.challenge` unique, so one breach record per challenge.
- `events(aggregate, aggregate_seq)` unique, so replaying a recovered log cannot double-insert.

### 4.3 Migration policy

`schema.py` owns a `migrations` table and numbered idempotent steps. No `CREATE TABLE IF NOT EXISTS`
scattered through the Engine. Existing databases must migrate forward without data loss; a downgrade path
is not required.

## 5. State machines

```
challenge:  DRAFT ──publish──> ACTIVE ──verified breach──> BREACHED ──successor──> SUPERSEDED
                                 └──────admin cancel──────> CANCELLED

candidate:  PROPOSED ──correctness──> CORRECTNESS_TESTED ──published──> UNDER_ATTACK
                                          └────────────broken──────────> BROKEN
            any ──observer/deprecate──> DEPRECATED ──> ARCHIVED

work item:  PENDING ──provider ok─────> DONE (turns+1, cursor advanced, history written)
                 └──provider error────> DONE (turns+1, error_type recorded, no retry storm)
```

A challenge in `BREACHED` no longer accepts submissions. Only a transaction that writes
`breach_verifications` may move `ACTIVE → BREACHED`, and only that same commit may insert the reward and
append `BREACH_VERIFIED` + `CANDY_AWARDED` + `ESCALATION_AUTHORIZED`.

## 6. Role projections and blindness

`aces/views.py` produces one projection per role. Projections are built by explicit selection — never by
serialising a row and deleting fields.

| Data | Generator | Integrator | Adversary | Observer | Admin |
|---|---|---|---|---|---|
| Own session history | ✅ | ✅ | ✅ | ✅ | ✅ |
| Candidate catalog (specs) | ✅ | ✅ | ❌ | ✅ | ✅ |
| Active challenge public view | ❌ | ✅ | ✅ | ✅ | ✅ |
| Challenge secret (key, target plaintext) | ❌ | ❌ | ❌ | ❌ | ✅ |
| Verified breach — sanitized summary | ❌ | ✅ | ✅ | ✅ | ✅ |
| Verified breach — raw evidence incl. plaintext | ❌ | ❌ | ❌ | ✅ | ✅ |
| Adversary submissions / tool trace | ❌ | ❌ | own only | ✅ | ✅ |
| Observer findings / feedback | received | ❌ | ❌ | ✅ | ✅ |
| Resource metrics, cost | own | own | own | all | all |
| Event log | ❌ | ❌ | ❌ | ✅ | ✅ |

Known leak channels to close (see §11): the Integrator currently receives `breach_confirmed` event payloads
verbatim, which include the recovered plaintext; and "sanitized" failure notifications are not yet
sanitized.

**The Warden** is a fifth, supervisory projection: the dispatch ledger — what each role was actually shown —
plus the event trail, and exactly one tool (`report_leak`). It holds no authority over truth, which is what
makes it safe to let it see everything. The matrix above is enforced in code; the ledger (§10) is what makes
that enforcement auditable rather than merely asserted.

## 7. Tool surface

One dispatcher per role; a tool is available only if it is in `permissions` for that role. Every tool has a
declared JSON argument schema, a resource budget, and an audit event.

| Tool | Role | Phase | Notes |
|---|---|---|---|
| `register` | generator | 1 | validate → exhaustive reversibility → digest → version |
| `publish` | integrator | 2 | requires `DRAFT` correctness evidence and a `BREACHED` predecessor (or none) |
| `submit` | adversary | 3 | evidence bundle, idempotent |
| `compute` | adversary | 3 | key-space enumeration over a known pair; bounded |
| `oracle_encrypt` | adversary | 5 | chosen-plaintext, query-budgeted, counted in metrics |
| `oracle_decrypt` | adversary | 8 | chosen-ciphertext; only where the challenge permits it |
| `record_finding` | observer | 5 | requires a linked `breach_verifications` row |
| `read_public_source` | observer | 5 | outbound fetch, allowlisted, cached, cited |

No tool may accept raw Python. Arbitrary code execution is a Phase 8 feature that requires a container and
is explicitly out of scope until then.

## 8. Verifier design

`aces/verify.py` is pure: it takes a challenge record, a submission, and the secret material, and returns a
verdict plus evidence. It performs no I/O and calls no model.

**Correctness verification** (`register`, `publish`): exhaustive over the declared domain where the domain is
small (8-bit keys, 0..4096-byte inputs sampled at boundaries), plus storage of the exact test vectors used.

**Attack verification**, per category:

| Category | Verification method | Phase |
|---|---|---|
| Plaintext recovery | constant-time exact comparison against the committed target | 3 (exists) |
| Key recovery | submitted key must equal the committed key; verifier independently re-encrypts | 3 |
| Authentication forgery | verifier recomputes the tag/MAC under the secret key | 3 |
| Chosen-plaintext / known-plaintext | verifier re-runs the attack script against a holdout instance | 5 / 8 |
| Distinguishing | pre-registered sample size, advantage estimate, one-sided binomial test, p < 1e-3 | 8 |
| Randomness analysis | pre-registered statistical battery over verifier-generated output | 8 |
| Protocol / implementation | replay inside the sandbox, diff against intended behaviour | 8 |

**Statistical honesty rule:** a distinguishing result is only a breach if the experiment was specified before
the data was collected, used verifier-generated randomness, and clears a multiple-comparison-corrected
threshold. Otherwise it is recorded as an `ATTACK_REJECTED` with the measured advantage, not as a breach.

**Provenance gate.** `compute` persists every solution set it produces (`derivations`). A submission is a
breach only when one of those sets contains the submitted plaintext. A correct answer reached any other
way — worked out in the session, computed with the session's own tools, or read from somewhere it should not
have been — is rejected with `no_derivation_trace`: no candy, no state change, and the challenge stays
ACTIVE so a traced attempt can still succeed.

**Method gate.** A breach is a claim about *how* a construction fails, not merely that it did. A submission
must therefore name a method from a fixed vocabulary (`known_plaintext_key_search`,
`chosen_plaintext_search`, `algebraic_inversion`, `distinguishing_statistic`, `implementation_defect`), and
the name must agree with the derivation: a claim of known-plaintext search whose recorded permutation is not
the published one is rejected as `method_mismatch`. A correct answer with no method is rejected as
`no_method`; an unknown method as `unverified_method`. The method is written to `methods` and appears in
`breach_confirmed`, and the Generator's projection carries `failures` — one entry per challenge that fell,
naming the method that broke it — so the next construction can be aimed at that method rather than at
something that merely looks harder.

This exists because a subagent can run its own arithmetic. Without the gate, a legitimate offline solve and
a leaked secret are the same event to the verifier (run 002 demonstrated exactly that). With it, the answer
is re-derived by our code from the challenge itself, so correctness rests on the tool's search rather than
the session's assertion, and `breach_confirmed` records `method: tool_compute`.

**Admission gate.** Before publishing, the Integrator may `reject{candidate, reason, detail}`. The refusal
binds: `publish` refuses a rejected candidate, the reason is recorded in `rejections` and appears in the
Generator's projection, and `candidate_rejected` is a wake-up event, so the Generator is re-dispatched to
produce a different construction rather than the same one again. The Integrator sees a measured
`assessment` per candidate — key bits, known-plaintext work, byte-locality, key-op count — so the refusal
rests on a number rather than on taste. A second rejection reason is available by design: a standard
construction whose break is already published produces a foregone conclusion, and a challenge whose answer
is already known teaches nothing.

**Consequence to be honest about.** Under the current VM every construction measures the same: 8-bit key,
256-trial known-plaintext search, byte-local operations. A faithful Integrator therefore rejects everything,
and the loop stalls at the gate. That is not a fault in the gate — it is the VM reporting what it can
express. Lifting it requires the construction language to gain parameters that actually raise the cost of a
known-plaintext search: a wider key, cross-byte mixing, or a state that carries between blocks.

**Construction language (v4).** Eight operations: five byte-local (`xor_key`, `add_key`, `xor`, `add`,
`rol`), two forward chains (`chain_add`, `chain_xor`), and one whole-buffer rotation (`rot_bytes`). The key
is 32 bits by default, consumed round-robin by byte position; the width is a per-run parameter.

Two defects in the language, found by running it, define what a construction must now satisfy:

1. **Causality.** With only position-local and forward-chaining operations, output byte *i* depends only on
   input bytes `0..i`. One known pair then fixes key byte 0 in 256 trials, then byte 1, and so on — about
   `key_bytes × 256` evaluations for the whole key, independent of key width. RUN-007's Generator proved
   this and stopped proposing. `rot_bytes` is the operation that breaks it: a buffer rotation carries later
   bytes back to earlier positions. `is_causal()` reports whether a program still has the defect, and
   `assess()` uses the causal bound for `known_plaintext_work` when it does.
2. **Linearity.** A program built only from `xor`, `xor_key`, `chain_xor`, `rol` and `rot_bytes` is affine
   over GF(2), so one known pair fixes the key by Gaussian elimination — 33 evaluations for a 32-bit key.
   `rot_bytes` is itself GF(2)-linear, so diffusion alone does not escape this; an addition is required
   too.

A construction therefore needs a diffusion op **and** a non-linear one. Neither is sufficient alone, and the
Integrator can check both properties before publishing.

`compute` now carries an explicit search budget: at most 2^20 keys per call, returning
`{"solutions": [], "exhausted": true, "searched": 1048576}` when the space is wider than that. Exhaustion is
reported rather than hidden, because a tool that silently gives up is indistinguishable from a tool that
searched everything.

**The consequence, stated plainly.** At 32 bits an exhaustive known-plaintext search costs 2^32 trials;
`compute` reaches 2^20 and stops. So the Adversary's only implementable method no longer produces breaches.
The gate will now accept a construction that is not byte-local, and nothing can break it — the bottleneck
has moved from construction to attack capability. That is the honest state of a system whose solver is an
enumerator and whose cipher now has a key space the enumerator cannot cross.

**Enumeration is not a breach.** `compute` records its derivations with `strategy='enumeration'`; a
submission grounded only in such a derivation is rejected as `enumeration_is_not_a_breach`, even when the
answer is correct. Trying every key is labour, and labour does not teach the Generator anything about the
construction. A breach requires a derivation whose `strategy` is structural, and the named method must be
that strategy.

The first structural attack is `solve` / `gf2_linear`: if a program contains only `xor`, `xor_key`,
`chain_xor` and `rol`, the map is affine over GF(2) in (key, data), so a single known pair determines the key
by Gaussian elimination — 33 evaluations for a 32-bit key instead of 2^32. A program containing any addition
(`add`, `add_key`, `chain_add`) is not affine and `solve` returns no strategy. This is the pressure that makes
the construction space interesting: linearity is free to detect and fatal to ship, and non-linearity plus
cross-byte mixing is the minimum for a construction to survive.

**Exactly-once:** the verdict, the state transition, the reward insert, the breach record and the events are
one `BEGIN IMMEDIATE` transaction. Duplicate submissions short-circuit on the `(challenge, evidence)` unique
index and return the prior verdict without charging candy again.

## 9. Event catalog

Events carry small, typed payloads. Secret material never appears in an event payload; it lives in
`audit_records` (admin-only) and is referenced by id.

| Event | Aggregate | Payload (no secrets) |
|---|---|---|
| `CANDIDATE_REGISTERED` | candidate | candidate, version, digest |
| `CHALLENGE_PUBLISHED` | challenge | challenge, mode, difficulty |
| `CHALLENGE_ACTIVE` | challenge | challenge |
| `ATTACK_SUBMITTED` | challenge | challenge, submission, category |
| `ATTACK_REJECTED` | challenge | challenge, submission, reason, measured_advantage |
| `BREACH_VERIFIED` | challenge | challenge, verification, method |
| `CANDY_AWARDED` | challenge | challenge, amount, balance_after |
| `ESCALATION_AUTHORIZED` | challenge | challenge |
| `CHALLENGE_SUPERSEDED` | challenge | challenge, successor |
| `OBSERVER_FINDING_CREATED` | candidate | finding, classification, confidence |
| `GENERATOR_FEEDBACK_AVAILABLE` | feedback | feedback, finding |
| `AGENT_EXECUTION_FAILED` | role | role, work_id, error_type |
| `SYSTEM_PAUSED` | system | by (admin) |

`model_turn` and `model_error` stay operational events but are excluded from the wake-up cursor, so
scheduling is driven by domain events only.

## 10. Concurrency, recovery and budgets

- **Single writer, many readers.** One coordinator process per database (already required by the README).
  SQLite in WAL, `BEGIN IMMEDIATE` for every mutation, 15 s busy timeout.
- **Dispatch intent precedes the provider call.** `work_items` is written before the request and marked
  `DONE` after; a crash leaves a `PENDING` item that recovery must reconcile on start-up (currently missing —
  see §11, defect 7).
- **Idle gating must be evaluated on a snapshot taken after the work item is committed** (defect 1). The
  correct order is: read cursor → decide → `begin_work` (which bumps the event sequence) → dispatch. Idle
  detection compares the role's cursor against the last *domain* event, and the cursor must only advance
  when a turn is actually consumed.
- **Budgets** are per role: lifetime turns, wall-clock per call, tokens, oracle queries. Exhaustion is a
  recorded `AGENT_EXECUTION_FAILED` with `error_type='budget_exhausted'`, not a silent `continue`.
- **Recovery on start-up:** mark orphaned `PENDING` items `ABANDONED` with an audit record; never re-issue a
  provider call automatically (that would be a duplicate charge); require the next tick to create a new item.

## 11. Current defects and their architectural fixes

These are measured against the prototype by an executed audit (see `docs/CONTEXT.md`). Each maps to an
owning phase.

| # | Defect (observed) | Root cause | Architectural fix | Phase |
|---|---|---|---|---|
| 1 | Idle gating is dead code; idle agents burn their lifetime turn budget (`runtime.py:44-45` vs `core.py:85/98`) | cursor compared against an event maximum that `begin_work`/`finish_work` themselves advance | scheduler evaluates idleness on a post-commit snapshot; cursor advances only on a consumed turn; idle is recorded as a domain event, not inferred from prompt output | 4 |
| 2 | Work items shared across concurrent dispatches (`core.py:81-82`) | `begin_work` returns an existing `PENDING` row instead of refusing | one item per dispatch, or `Denied` if a dispatch for that role is in flight; provider calls never run concurrently for one role | 4 |
| 3 | API key forwarded across a redirect (`runtime.py:23`) | default `urlopen` redirect handler | `provider.py` uses a no-redirect opener and refuses cross-origin redirects | 4 |
| 4 | Candy inflation: re-publishing a breached candidate, and secret-free/identity programs | `register` accepts any reversible program; `publish` does not require a new candidate version | verifier rejects programs whose published challenge has no secret-dependent term; a successor must reference a *new* `candidate_version` with a recorded `lineage` reason | 3 |
| 5 | Web hardening gaps: `POST /control` skips Host validation, `/audit` unauthenticated and contains plaintext, `TypeError` on non-object JSON, no CSP | `web.py` ad-hoc parsing | single request-validation path; audit behind an admin token; strict JSON shape check; CSP + `X-Frame-Options: DENY` | 6 |
| 6 | Docs and demo drift: test count stale, demo re-run leaks a candidate event | no generated documentation, non-idempotent demo | tests publish their own count; demo uses a fresh DB and refuses otherwise | 1 |
| 7 | No crash reconciliation: a `PENDING` item survives a crash with no owner | start-up scan absent | recovery sweep marks orphans `ABANDONED`, emits audit record (see §10) | 4 |
| 8 | Integrator receives raw breach payload including target plaintext | projection serialises the event row | sanitized failure projection: category, method, which property failed — **never** the secret | 2 |
| 9 | Black-box mode is unsolvable: `public` omits `spec`, but `compute` requires a program | single attack path | black-box challenges must expose an oracle and a bounded `compute` variant that does not need the program, or the mode must be disabled with an explicit error | 5 |

**Status (2026-10-29, after the thin slice).** Closed: **1** (the pump evaluates idleness on a
post-claim snapshot and never re-dispatches an idle role), **2** (`claim_work` refuses a second in-flight
item for a role), **7** (`abandon_stale` marks orphans and never re-issues them), **8** (the Integrator's
failure projection strips the recovered plaintext). Partial: **4** — keyless constructions are now rejected
at publication, but re-publishing a breached candidate is still allowed until candidate versioning exists.
Open: **3**, **5**, **6**, **9**.

A fifth supervisory session (the Warden) now audits the dispatch ledger for data-boundary leaks, so
defect-8-class regressions are detected rather than assumed absent. It cannot observe **3** (a redirect on
the network path), **5** (HTTP request validation) or **9** (a missing attack path): those are network,
protocol and design issues, not data-boundary leaks, and remain open.

## 12. Security boundaries: now, next, later

| Boundary | Now (single process) | Phase 8 (containers) |
|---|---|---|
| Agent ↔ agent data | service-layer projections + tool allowlist | separate processes, per-role filesystem, no shared mounts |
| Model output ↔ host | never executed; JSON schema validated | unchanged |
| Agent ↔ network | none: no tools perform outbound I/O except the role driver | allowlisted egress proxy with per-role policy |
| Agent ↔ filesystem | **policy only** under subagent embodiment: role prompts disclose no path and request no file work | per-role container with no mount of the project or database |
| Agent ↔ secrets | secrets only in Engine memory/DB | secrets in coordinator only; workers receive derived material |
| Dashboard ↔ agents | loopback + CSRF + Host checks | admin token, separate listener, no route reachable from worker context |
| Arbitrary code | **not available** (no OS sandbox on this host; bubblewrap cannot create namespaces here) | microVM/container per submission |

**Explicit non-goals until Phase 8:** running model-authored Python, evaluating untrusted attack scripts,
calling decryption oracles on arbitrary input, and any claim of OS-level isolation.

## 13. SPEC coverage

| SPEC | Requirement | Where addressed | Status |
|---|---|---|---|
| §2 | Four independent agents; mutual blindness | §6, [AGENTS.md](AGENTS.md) | four separate sessions over **one shared model**: contextual isolation, not statistical independence |
| §3 | Generator outputs 12 required fields | §4.2 `candidate_versions`, §7 `register` | partial (spec has 5 fields today) |
| §4 | Breach-gated escalation | §5 state machine, §4.2 successor constraint | ✅ enforced |
| §5 | Ten attack categories | §8 verification table | 1 of 10 implemented |
| §6 | Observer intelligence | §3 `observer.py`, Phase 5 | not implemented |
| §7 | Mutual blindness | §6 projection matrix | ✅ service-layer; leak 8 open |
| §8 | Immutable versioned challenges, both modes | §4.2, §5 | partial (open only) |
| §9 | Candy rules | §4.2 `rewards`, §8 exactly-once | ✅ |
| §10 | Independent verifier | §8 | ✅ for plaintext recovery only |
| §11 | Evolutionary feedback loop | §9 events, Phase 5 | partial |
| §12 | 18 entities | §4.1 gap table | 8 of 18 (4 partial) |
| §13 | Candidate status registry | §5 candidate machine | partial |
| §14 | Tool catalog | §7 | 4 of ~8 tools |
| §15 | Execution boundaries | §12 | service-layer only |
| §16 | Event-driven autonomy | §9, §10, AGENTS.md §9 | **broken twice**: dead idle gating (defect 1), plus one orchestrator turn per tick under subagent embodiment |
| §17 | Dashboard | Phase 5 (deferred) | minimal; not on the critical path |
| §18 | 13 acceptance criteria | ROADMAP gates | all but three hold under deterministic tests; real-provider execution, unattended operation and the full evolutionary cycle are not demonstrated |
| §19 | 8 phases | ROADMAP | phases 1–3 collapse into one thin slice; 4 relayed; 5–8 deferred |
| §20 | Evaluation + risks | §4.2 difficulty field, §8 statistical rule | designed, not built |
