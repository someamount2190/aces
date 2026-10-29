# Implementation plan and acceptance

1. Foundation → SQLite state, event trail and role interfaces. Acceptance: restart preserves challenge and rewards.
2. Sandbox (depends on 1) → executable bounded VM, candidate correctness, immutable-by-interface publication. Acceptance: toy recovery evaluated objectively.
3. Reward engine (depends on 2) → transactional breach, reward and replacement gate. Acceptance: invalid and concurrent duplicate attempts cannot escalate or duplicate candy.
4. Four-session coordinator (depends on 1–3) → configurable real provider, persisted separate histories, bounded dispatch, durable work-item bookkeeping. Acceptance: completed turn history/cursor/turn count commit atomically; duplicate completion is idempotent. Real-provider demonstration remains blocked.
5. Observer and dashboard (depends on 1–4) → evidence-linked feedback, audit, controls. Acceptance: full tool integration cycle and local HTTP smoke test.
6. Hostile code isolation and expanded science (depends on supported container runtime) → arbitrary code and additional attack classes. Deferred: no working OS sandbox in this host; never replace with unsafe subprocess execution.

## Architectural boundaries

Trusted Python coordinator owns SQLite, verification and provider credentials. Models only receive projections produced by `Engine.view`; all actions pass a role allowlist in `Engine.tool`. Public toy programs are declarative data interpreted by the finite VM. The administrator dashboard is a separate trust surface and is not an agent tool. SQLite transactions serialize publication and verification. Agent contexts and events persist; an interrupted model call can be retried after restart and is not exactly-once, while database reward effects are exactly-once per challenge.

Coordinator reliability increment: dispatch intent is recorded before provider work. Completion atomically stores the new session history, cursor and turn charge and marks the work item done. This protects session bookkeeping against duplicate completion, but a crash between provider completion, tool execution, and recording completion may still cause a repeated provider call or tool action. Full crash-safe reconciliation requires idempotency keys across every tool effect and provider-specific request semantics.
