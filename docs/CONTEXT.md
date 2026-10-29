# Project context

Provenance and current status of this codebase. Written 2026-10-29 after an audit and a live run so that
later sessions (human or model) do not have to rediscover it.

The target system is specified in [SPEC.md](SPEC.md); the design and its mapping onto this prototype, in
[ARCHITECTURE.md](ARCHITECTURE.md); the build order, in [ROADMAP.md](ROADMAP.md). This file records where the
code came from and what has actually been executed.

## What this is

A runnable first implementation of the **Autonomous Cryptographic Evolution Sandbox**: a SQLite-backed
trusted coordinator drives four LLM roles (generator, integrator, adversary, observer) through a loop that
registers toy byte-permutation candidates, publishes one as a challenge, attempts recovery, and rewards a
verified breach.

**Experimental toy cryptography.** No security, novelty, or "evolving cipher" claim is made. Keys are
8-bit, the VM is bounded, and the docs are explicit about the scientific limits.

- Python 3.10+ (README recommends 3.12), standard library only, SQLite, loopback dashboard on 127.0.0.1:8765.
- `python -m unittest discover -s tests -v` → 11 tests.
- `python demo.py --db demo.sqlite3` → deterministic integration demo (not autonomous operation).
- `python -m aces --db live.sqlite3 --config config.json` → live-model coordinator.
- `docs/PLAN.md` holds the intended build order; `docs/VALIDATION.md` holds the master-acceptance status.

## Provenance

Executed on 2026-10-29 16:47–17:33 (Asia/Taipei) by **OpenCode Desktop** running `deepseek-v4.1-flash-free`
(provider `opencode`, variant `high`). Four sessions, stored in `~/.local/share/opencode/opencode.db`:

| Session | Role |
|---|---|
| `ses_e79289935ffeqJdLGauPJXoHHc` | main — delegated the three workstreams |
| `ses_e792796f8ffejTFfhheenS7PQU` | independent correctness + security audit (executed probes) |
| `ses_e792796fdffeIsvX8ko2a6D8bK` | test suite + demo |
| `ses_e792796fbffeaBkrUctPR4gCTP` | live dashboard HTTP smoke test |

The code itself predates those sessions (files carry a single 16:46:22 timestamp).

## What was verified by execution

11/11 tests pass. The demo produces 1 reward, 2 chained challenges, 1 breach event and 1 feedback item.
10/10 dashboard HTTP checks behave (CSRF 403s, 404, control change, Host 403).

- **VM invertibility is genuinely correct.** All 256 keys × 256 byte values × 16 adversarial programs
  round-trip; every operand 0..255 of all five ops round-trips; the `rol` inverse math is right.
- **Rewards are exactly-once** under 32 concurrent correct submissions (`BEGIN IMMEDIATE` serializes).
- **Immutability holds**: no publishing over an ACTIVE challenge, wrong/stale parent denied, `one_active`
  partial index enforced.
- **Role isolation holds**: blackbox view omits `spec`, cross-role tool calls denied, no key/plaintext in
  any role view.
- **The full cycle is reachable** under a mock provider (register → publish → solve → breach → republish in
  ~3 ticks).

## Known defects (unfixed)

Deliberately left unfixed: the operator forbade code changes during the live run. Ranked:

1. **HIGH — idle gating is dead code** (`aces/runtime.py:44-45` vs `aces/core.py:85/98`). `begin_work`/
   `finish_work` write events *after* `last_event` is read, so `cursor == last_event` never holds. Idle
   models are called every tick and burn the 50-turn lifetime budget in ~150 s, then never act again.
2. **MEDIUM — work items shared across concurrent dispatches** (`aces/core.py:81-82`). 16 threads → 1 work
   id; two provider calls run, the second result is silently dropped.
3. **MEDIUM — API key leaks on redirect** (`aces/runtime.py:23`). `urlopen` follows a 302 and forwards
   `Authorization` to a different origin over plain HTTP (confirmed with a two-hop probe).
4. **MEDIUM — candy inflation.** Re-publishing the same breached candidate is allowed; a secret-free
   (`[["xor",5]]`) or identity program earns candy for zero cryptanalysis.
5. **LOW** — `POST /control` skips the Host allowlist; `/audit` is unauthenticated and contains breach
   plaintext; non-object JSON raises an uncaught `TypeError` and drops the connection; no CSP or
   `X-Frame-Options`; `compute` allows ~7 s CPU per turn.
6. **INFO** — `docs/VALIDATION.md` says 10 tests, there are 11; a demo re-run against a used DB crashes with
   a raw traceback and leaks one `candidate_registered` event per attempt.

## The live run (2026-10-29, 17:30–17:31)

Goal: 8 coordinator ticks against a fresh DB using DeepSeek V4.1 Flash, project code untouched.

Because the free public API key was quota-limited, ACES's unmodified OpenAI-compatible call path was pointed
at a throwaway local shim (`bridge.py`, `127.0.0.1:8770`) that forwarded each role prompt to the OpenCode
desktop server's `/api/session/{id}/generate`.

| Tick | Candidates | Outcome |
|---|---|---|
| 1 | 1 | generator registered `SBX-Fold-12` (12 ops); integrator published it, open mode, no parent; adversary returned an empty string (JSONDecodeError); observer returned `{"idle": true}` |
| 2 | 2 | generator registered `SBX-Weave-16` (16 ops); adversary returned empty again; observer HTTP 503 |
| 3–8 | 2 | generator, adversary and observer all HTTP 503 every tick |

**Final state:** challenge 1 ACTIVE (candidate 1, `parent = null`), 2 candidates, **0 submissions, 0 rewards,
0 breaches, 0 findings, 0 feedback**, 79 events, control still `running`. Turns: generator 8, adversary 8,
observer 8, integrator 1.

**Root cause:** not the code. 19 of 25 provider calls returned `503 ServiceUnavailableError: "Free usage
limit reached"`. The adversary's only two real attempts came back as empty strings, so the cycle never
reached a solve, submission or breach.

**Defect #1 confirmed in the wild:** after the quota died, generator/adversary/observer kept being
dispatched and spent every remaining turn on 503s instead of idling.

**Therefore: an end-to-end live autonomous cycle has still never been demonstrated.** Three of four roles
were demonstrably model-driven; the breach half of the loop was not.

## Next steps

1. Fix defect #1 (or raise the turn budget) — otherwise every long live run wastes its budget on error turns.
2. Validate the adversary's JSON parsing in isolation; it silently swallowed both attempts.
3. Re-run bounded, on a fresh DB, with a provider that will not hit a free-tier limit.
4. Treat a successful toy-cipher breach as neither evidence of security nor of improvement — it is a
   plumbing test.

## Repro notes

`config.json` is git-ignored and holds provider settings. Never commit it. The bridge shim used for the live
run is a local harness, not part of ACES, and reads the OpenCode service password at startup; it should not
be committed either.
