# ACES — Roadmap and Subagent Execution Plan

[SPEC.md](SPEC.md) is the acceptance authority. [ARCHITECTURE.md](ARCHITECTURE.md) is the design.
[AGENTS.md](AGENTS.md) is the embodiment contract. This document is the build order.

---

## 1. The principle

**The code holds state. The agents hold capability.**

Every function in SPEC §3–§6 — inventing a construction, choosing a candidate, attacking it, noticing a
pattern — is judgement, and judgement belongs to a subagent. The program's job is only to make sure that a
thing which claims to be a breach actually is one, and that nothing can be awarded twice.

That yields a hard test for any proposed feature:

- "Make the agent smarter / more creative / more systematic" → it is a **prompt**, not code.
- "Make cheating or double-award impossible" → it is **code**, and it must be small enough to trust.

A research system that needs 20k lines to be interesting is usually a research system whose agents aren't
doing the work.

## 2. What must exist

The whole first slice, in six files:

| Capability | File | Rough size | Gate |
|---|---|---|---|
| Durable state: candidates, challenges, submissions, rewards, events, sessions, work items | `aces/schema.py` | ~90 lines | fresh DB builds; constraints enforced by the DB, not by convention |
| State machine + events: register, publish, submit, view, tool dispatch | `aces/core.py` | ~250 lines | every transition is one transaction |
| Deterministic verification: reversibility, exact comparison, duplicate rejection | `aces/verify.py` | ~120 lines | a wrong plaintext can never be rewarded |
| Dispatch: `dispatch` / `deliver` / `status` / `recover` | `aces/pump.py` | ~150 lines | at most one pending item per role; delivery idempotent |
| The four charters | `aces/prompts.py` | ~60 lines of data | each role returns one JSON object |
| Proof | `tests/` | ~300 lines | the six gates in §6 |

Production code lands around **650 lines**. That is the entire system needed to run the loop — not a
prototype of the system, the system, minus the science.

## 3. What we are deliberately not building

| Not now | Why | What would bring it back |
|---|---|---|
| Provider HTTP client | no provider available; subagents are the model | a real endpoint, or a funded key |
| Containers, arbitrary code, oracles | no working OS sandbox on this host | a container runtime; this is the Phase 8 gate |
| The full 18-entity schema | 10 entities exist; 12 of the 18 are unused by the loop | when lineage or research ingestion is actually studied |
| Separate candidate/challenge version tables | a `version` column plus `parent` carries lineage for now | when you need to compare many generations |
| Statistical verifier, formal checks | needs reproducible code execution first | Phase 8 |
| A real scheduler | the orchestrator's turn *is* the tick | a native dispatch API |
| Dashboard | inspection can be `status --json` and the DB | when a human needs to watch it live |
| Migration framework | single writer, disposable research DBs | when a DB must survive schema change |

Each of these is a real part of SPEC. None is needed to answer the only question the first slice is asking:
**can four agents, feeding a real gate, produce one verified breach and one better challenge?**

## 4. The loop, concretely

One tick = one orchestrator turn.

1. `pump dispatch --json` → pending work for each role that has relevant work (integrator: no active
   challenge; adversary: an active challenge; generator/observer: new domain events).
2. The orchestrator sends each prompt to that role's persistent subagent session — four sessions, four
   contexts, no cross-talk.
3. Each session returns one JSON object.
4. `pump deliver --work-id … --answer …` → validated, executed, committed, one turn charged.
5. Repeat until the gate shows a breach, a budget is exhausted, or the tick limit is reached.

Nothing here is novel engineering. It is a queue with a validator.

## 5. Phases, mapped to reality

| SPEC phase | What actually happens | Status |
|---|---|---|
| 1 Foundation | thin core: schema, engine, events | this slice |
| 2 Shared sandbox | publish + both modes; adversary sees one projection | this slice |
| 3 Verification and candy | `verify.py` + transactional breach | this slice |
| 4 Autonomous operation | four subagent sessions driven by the pump | this slice, **relayed** (AGENTS.md §9) |
| 5 Observer intelligence | findings exist; pattern detection deferred | partial |
| 6 Dashboard | deferred | — |
| 7 Evolutionary demonstration | **the goal of this slice**: one breach → candy → finding → successor challenge | target |
| 8 Advanced mathematics | blocked on isolation | — |

Phases 1–3 are not three phases of work. They are one vertical slice, because the gate is what makes the
other two meaningful, and splitting them produces the state this repo is already in: a sandbox nothing has
ever broken.

## 6. The six gates

The slice is done when these are executed, not asserted:

1. **Roles fire.** Four sessions are dispatched in one tick; no role is dispatched without relevant work.
2. **No publication without a candidate.** Integrator cannot publish an unknown or untested candidate.
3. **Invalid attack.** Wrong plaintext → `ATTACK_REJECTED`, no candy, challenge stays `ACTIVE`.
4. **Verified attack.** Correct plaintext → one breach record, one candy, one event triad, escalation
   authorized, challenge `BREACHED`.
5. **Duplicate.** Same plaintext again → no second candy, no second breach record.
6. **Restart.** Kill and reopen the DB mid-run → state intact, no duplicated reward, sessions resume.

Gates 3–6 are deterministic and must pass without any agent in the loop. Gate 1 and the final demonstration
require the subagents, and are labelled *subagent-embodied* wherever reported.

## 7. Ownership

Six files, so ownership is trivial until the system is bigger than the team.

| File | Owner |
|---|---|
| `schema.py` | one agent — must land first |
| `core.py` | one agent — depends on schema |
| `verify.py`, `prompts.py` | one agent — independent of core internals |
| `pump.py` | one agent — depends on core's work-item API |
| `tests/` | the coordinator only; workstreams may add, never weaken |

Parallel-safe: `(schema) ‖ (prompts)`, then `(core) ‖ (verify)` — two streams, not six. The system is too
small for more.

## 8. Handoff template

```
WORKSTREAM: <id and title>
OBJECTIVE: <one sentence>
FILES YOU OWN: <exact list>
FROZEN: <signatures that must not change; stop and report if a change is needed>
DELIVERABLES: <code + tests + short report>
GATE: <the commands to run and the output to paste>
DO NOT: edit tests to pass; touch files you don't own; add dependencies; claim an agent result you did not observe
REPORT: what changed · what you ran · what passed · what is unproven · risks
```

## 9. Definition of done for the first slice

A fresh database, four subagent sessions, one orchestrator turn per tick, and within a bounded number of
ticks: a real candidate, a real publication, a real attack, a **breach verified by code rather than by a
claim**, exactly one candy, one Observer finding, and a successor challenge with a recorded parent. Reported
as *subagent-embodied*, with the provider limitation stated.

That is SPEC §19 Phase 7, reached without writing the 20k-line system it sounds like it needs.
