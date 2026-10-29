# Validation

> **Current count: 26 tests** (this record says 10). The suite now covers the dispatch pump and the six
> gates in [ROADMAP.md](ROADMAP.md) §6, not only the engine. Documentation drift is tracked as defect 6 in
> [ARCHITECTURE.md](ARCHITECTURE.md) §11. For the 2026-10-29 live-model run and its outcome, see
> [CONTEXT.md](CONTEXT.md).

Build environment run: 10 unittest tests PASS (Python standard library).

- Exhaustive reversible byte transformation checks across all 256 keys.
- API role allowlist and projection checks (limited interface isolation, not proof of mutual blindness).
- Active challenge cannot be replaced without breach; invalid recovery earns no reward.
- Concurrent repeated correct recovery: exactly one reward and one breach event.
- Restart retains active challenge, rewards and progression.
- Confirmed breach supports recorded observer hypothesis and generator feedback.
- Dispatch stop does not authorize challenge replacement.
- VM rejects filesystem/import operations and oversized programs.
- Mock provider invocation stores distinct role sessions; not live-LLM evidence.
- Durable work dispatch persists a pending work item; completion atomically updates session messages, cursor and turn count, and duplicate completion is ignored.
- HTTP dashboard loads, lifecycle controls reject missing CSRF token, valid control works and audit exports.

Executed `demo.py` with a fresh temporary database: verified plaintext recovery, candy=1, next challenge=2, one evidence-linked feedback item. This demonstration uses real VM execution, database transactions and persisted events, but deterministic drivers, not autonomous model decisions.

Master acceptance status: B–E core properties demonstrated; F and G partial; A limited to trusted coordinator interfaces; H restricted VM capabilities tested, OS sandbox unavailable; I NOT RUN; J only deterministic tool integration, live autonomous cycle NOT RUN. Work-item bookkeeping does not guarantee exactly-once model calls or tool side effects after crashes. Other attack categories and full schema are deferred as listed in README.
