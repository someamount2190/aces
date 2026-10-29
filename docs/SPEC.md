# ACES — Complete System Specification

**Normative.** This document states what ACES is required to be. It is the acceptance authority for the
system. Where this document and any implementation disagree, this document wins until it is deliberately
amended.

Implementation status, mapping to the current prototype, and known deviations live in
[ARCHITECTURE.md](ARCHITECTURE.md). Build order and work decomposition live in [ROADMAP.md](ROADMAP.md).

ACES is a proposed autonomous, self-reinforcing cryptographic ecosystem: four specialized LLM agents, a
shared sandbox, an independent verification engine, and persistent evolutionary memory.

Its central principle:

> **Cryptographic complexity increases only when a challenge is successfully breached.**

The system generates experimental encryption mechanisms, combines them into functional challenges,
subjects them to independent adversarial attack, and learns from outcomes without a human-directed research
process.

---

## 1. System overview

| Attribute | Specification |
|---|---|
| Project name | Autonomous Cryptographic Evolution Sandbox |
| Acronym | ACES |
| System type | Autonomous multi-agent cryptographic ecosystem |
| Core architecture | Four independent LLM agents |
| Shared environment | Cryptographic sandbox with isolated interfaces |
| Operating principle | Breach-triggered evolution |
| Advancement mechanism | Independently verified challenge breach |
| Reward mechanism | Candy |
| Knowledge mechanism | Persistent observational and evolutionary memory |
| Execution model | Event-driven, autonomous, stateful |
| Initial target model | GPT-6.1 Sol, low reasoning effort |
| Initial implementation | Python-based orchestration |
| Primary output | Experimental cryptographic constructions and verified attack findings |
| Security classification | Experimental research system, not production encryption |

## 2. Four-agent intelligence architecture

| Agent | Role |
|---|---|
| Brain 1 | **Mathematical Generator** — creates new mathematical mechanisms and cryptographic tools |
| Brain 2 | **Integrator** — selects tools, constructs and upgrades challenges |
| Brain 3 | **Adversary** — waits for challenges, attempts breaches, earns candy |
| Brain 4 | **Observer** — observes outcomes, identifies weaknesses, maintains memory, informs the Generator |

The Integrator and Adversary are **mutually blind** and never communicate directly. The Generator supplies
mechanisms, the Integrator constructs from them, the Adversary attacks the result, the Observer learns from
the ecosystem's behaviour and feeds the Generator.

The sandbox is the intermediary. The four LLMs do not hold a shared conversation.

## 3. Brain 1 — Mathematical Generator

**Primary objective:** create and explore mathematical constructions capable of supporting experimental
cryptographic systems.

### Responsibilities

1. Generate mathematical transformations.
2. Design reversible functions.
3. Investigate keyed permutations.
4. Develop encryption and decryption procedures.
5. Experiment with substitution and permutation networks.
6. Explore finite fields, number theory, modular arithmetic, and polynomial systems.
7. Develop candidate key schedules.
8. Explore evolving secret state.
9. Propose new cryptographic compositions.
10. Produce executable reference implementations.
11. Generate test vectors.
12. Formulate mathematical conjectures.
13. Analyse feedback from the Observer.
14. Investigate weaknesses inherited from previous constructions.
15. Publish candidate tools to a versioned registry.

### Inputs

Mathematical knowledge; existing cryptographic constructions; approved computation tools; the cryptographic
candidate database; Observer feedback; historical failures and findings.

### Outputs

Each proposed construction must contain:

| Field | Description |
|---|---|
| Candidate ID | Unique identity |
| Version | Immutable construction version |
| Specification | Formal description |
| Encryption function | Defined transformation |
| Decryption function | Defined inverse |
| Parameters | Key size, input length, other requirements |
| Assumptions | Mathematical security assumptions |
| Reference code | Executable implementation |
| Test vectors | Known inputs and expected outputs |
| Dependencies | Required mathematical or cryptographic tools |
| Known weaknesses | Documented limitations |
| Verification status | Experimental, failed, or validated for specific properties |

**The Generator must not label a construction secure simply because it works.** Mathematical correctness and
cryptographic security are separate requirements.

## 4. Brain 2 — Integrator

**Primary objective:** construct functioning cryptographic challenges using the tools available in its
sandbox.

The Integrator is **not informed about the Adversary**. It sees an engineering environment containing
objectives, tools, and cryptographic construction capabilities.

### Responsibilities

1. Inspect available cryptographic tools.
2. Select compatible mechanisms.
3. Combine mechanisms into functioning systems.
4. Generate challenge instances.
5. Check encryption and decryption correctness.
6. Ensure challenge conditions are well-defined.
7. Publish the active challenge.
8. Enter a waiting state.
9. Receive a sanitized failure notification after a verified breach.
10. Investigate the reported defect.
11. Select replacement or improved tools.
12. Construct the next challenge.
13. Preserve previous challenge versions.

### Strict advancement condition

> **Escalation is allowed if and only if a breach has been verified.**

The Integrator may not:

- Increase difficulty simply because time passes.
- Replace an active challenge without a breach.
- Change challenge success conditions after publication.
- Inspect the Adversary's identity, tools, or private workspace.
- Secretly repair the active challenge during an attack.

### Initial challenge construction

At startup the Integrator receives available tools and a general construction objective. It selects a
combination, validates that it functions, publishes the challenge, and waits. After a verified breach it is
permitted to escalate.

Escalation is **permission, not proof of improvement**. The replacement must be tested and its difficulty
measured rather than assumed.

## 5. Brain 3 — Adversary

**Primary objective:** solve cryptographic challenges independently using mathematical reasoning and
available tools.

The Adversary **does not know that an Integrator LLM exists**. Its experience is that of a solver entering a
cryptographic challenge environment.

### Responsibilities

1. Wait for available challenges.
2. Inspect the active challenge.
3. Understand the published success criteria.
4. Select analytical tools.
5. Develop attack hypotheses.
6. Perform bounded experiments.
7. Analyse ciphertext and permitted oracle responses.
8. Attempt mathematical attacks.
9. Attempt applicable implementation-level attacks.
10. Submit reproducible evidence.
11. Receive candy for verified breaches.
12. Wait for the next challenge.

### Supported attack categories

| Category | Objective |
|---|---|
| Ciphertext analysis | Extract useful information from encrypted data |
| Known-plaintext attack | Exploit available plaintext/ciphertext pairs |
| Chosen-plaintext attack | Query encryption on selected messages |
| Chosen-ciphertext attack | Query permitted decryption interfaces |
| Distinguishing attack | Differentiate encryption behaviour from an appropriate security ideal |
| Key recovery | Recover all or relevant parts of a secret key |
| Authentication forgery | Produce an unauthorized valid authenticated output |
| Randomness analysis | Detect predictable or repeated values |
| Protocol attack | Exploit composition, state, or message-order weaknesses |
| Implementation attack | Exploit defects within the authorized challenge implementation |

The Adversary operates solely on authorized sandbox targets.

### Waiting behaviour

The Adversary is event-driven. When no challenge is available it remains idle. An unbreached challenge
remains eligible for continued investigation, but individual computational sessions have bounded resources.
**The Adversary does not automatically win after a large number of attempts.**

## 6. Brain 4 — Observer

**Primary objective:** maintain the intelligence and evolutionary memory of the ecosystem.

Unlike the Integrator and Adversary, the Observer understands the full structure.

### Observation functions

The Observer monitors: construction history; selected tools; challenge versions; attack attempts and
outcomes; verified breaches; resource usage; repeated weaknesses; successful repairs; construction
lineages; mathematical assumptions; relevant external cryptanalytic developments.

### Intelligence functions

The Observer should identify relationships such as:

- Different constructions failing because of the same mathematical weakness.
- A new mechanism inheriting a vulnerability from an older design.
- A class of tools introducing implementation errors.
- A challenge becoming more computationally expensive without demonstrably becoming more secure.
- Repeated failure to achieve a specified security property.
- A public cryptanalytic discovery affecting internal constructions.

### Feedback authority

The Observer **may**: update the research database; classify verified weaknesses; send findings to the
Generator; suggest mathematical directions; flag deprecated or broken constructions; correlate attacks with
construction dependencies; recommend additional testing.

The Observer **may not**: fabricate a breach; award candy; directly escalate an active challenge; reveal
agent identities through the blind interfaces; declare a candidate mathematically secure based solely on
failed attacks.

## 7. The sandbox

A single logical environment with two isolated agent-facing experiences.

### Integrator experience

Cryptographic tools; construction workspace; mathematical functions; reference implementations; testing
utilities; active challenge state; sanitized breach findings; challenge submission controls.

### Adversary experience

Published challenges; public algorithm information when applicable; ciphertext oracles; available attack
tools; challenge success criteria; attack submission controls; candy balance; completed challenges.

### What neither sees

Neither blind agent may obtain: the other's private prompts; the other's model session; the other's
reasoning or private artifacts; the other's identity; hidden supervisory instructions; Observer-only data;
unrelated private system files.

**Important:** the Adversary may still receive the public cryptographic specification. *Hiding an algorithm
is not a substitute for a secure secret key.*

## 8. Challenge mechanics

A challenge is an immutable, versioned cryptographic task with defined success conditions.

### Challenge data

Challenge ID; version number; construction dependencies; cryptographic specification; attack access mode;
public parameters; hidden test material; permitted oracle access; success conditions; resource limits;
publication timestamp; current lifecycle state; associated verified breach evidence, if any.

### Challenge types

- **Open-design** — the Adversary can inspect the complete public construction but not the hidden key.
- **Black-box** — the Adversary receives only permitted oracle behaviour and outputs.

Results must distinguish the two modes.

### Lifecycle

| State | Meaning | Transitions out |
|---|---|---|
| `DRAFT` | Constructed, correctness checked, not yet published | → `ACTIVE` |
| `ACTIVE` | Published and unbreached; eligible for attack | → `BREACHED`, `CANCELLED` |
| `BREACHED` | A verified breach exists; escalation permitted | → superseded by a successor `ACTIVE` challenge |
| `SUPERSEDED` | Replaced by a successor after a breach | terminal (historical) |
| `CANCELLED` | Administratively abandoned | terminal; grants no candy |

Progression is **transactional** and cannot be caused by a user-interface state change alone. Real breach
verification must be performed by executable, independent tests.

## 9. Candy reward system

Candy is the Adversary's incentive and a quantitative indicator of confirmed challenge successes.

### Initial rules

- One confirmed breach grants one candy.
- Failed submissions grant no candy.
- Duplicate valid submissions grant no additional candy.
- Administrative challenge cancellation grants no candy.
- Rewards are persisted permanently.
- Reward balances survive restarts.

A future version could introduce weighted rewards based on challenge complexity or verified attack
efficiency. **The baseline stays simple** so the agent cannot exploit an unnecessarily complicated reward
formula.

Candy is not a security certification or a measurement of mathematical difficulty.

## 10. Independent verification engine

The verifier is a **deterministic software subsystem, not a fifth LLM**. It is responsible for:

1. Validating challenge specifications.
2. Checking encryption/decryption correctness.
3. Preserving immutable challenge versions.
4. Evaluating submitted attacks.
5. Reproducing breach evidence.
6. Enforcing predetermined success conditions.
7. Rejecting duplicates.
8. Publishing authenticated breach events.
9. Issuing candy transactionally.
10. Unlocking the Integrator's escalation permission.
11. Preserving audit evidence.

The verifier must not rely exclusively on an LLM's judgment. For statistical attacks it must distinguish
meaningful advantage from random guessing with suitable experimental design. Formal proof checking, where
possible, is conducted by independent mathematical tools.

## 11. Self-reinforcing evolution

The feedback mechanism:

```
G_t → I_t → C_t → A_t          G: available constructions, I: selected implementation,
                                C: published challenge,  A: attack activity

B_t → O_t → G_(t+1)            B: independently verified breach, O: Observer interpretation,
                                G_(t+1): Generator's next proposals
```

This represents information flow, not fixed sequencing. The Generator and Observer may work continuously or
periodically, while **Integrator escalation remains strictly breach-gated**.

### What reinforces the system

The Generator accumulates mathematical insight; the Integrator selects constructions informed by verified
failures; the Adversary accumulates attack experience; the Observer preserves knowledge across generations.

The system can develop more sophisticated behaviour over time, although **stronger cryptography is not
guaranteed simply by repeated evolution**.

## 12. Memory and database

ACES requires persistent memory for all agents and a separate auditable ecosystem record.

### Primary data entities

| Entity | Contents |
|---|---|
| Agents | Agent role, identity, configuration |
| Sessions | Separate model histories and execution state |
| Permissions | Authorized tools and resources |
| Candidates | Generated cryptographic constructions |
| Candidate versions | Immutable specifications and code |
| Tools | Available mathematical and cryptographic utilities |
| Challenges | Challenge identifiers and lifecycle |
| Challenge versions | Published immutable artifacts |
| Attack attempts | Submitted scripts and evidence |
| Breach verification | Independent verification results |
| Candy rewards | Verified reward transactions |
| Observer findings | Identified patterns and weaknesses |
| Research sources | External publications and advisories |
| Construction lineage | Relationships between candidate generations |
| Feedback | Observer-to-Generator knowledge |
| Event logs | State transitions |
| Metrics | Runtime and computation costs |
| Audit records | Security-relevant activity |

### Database requirements

SQLite initially; transactional writes; persistent storage; unique event identifiers; versioned artifacts;
event deduplication; restart recovery; referential integrity; access controls at service boundaries;
secure handling of experimental secret material; migration support.

**Historical evidence must remain available even after a construction is superseded.**

## 13. Cryptographic candidate registry

Every generated construction has an explicit status.

| Status | Meaning |
|---|---|
| Proposed | Initial mathematical idea |
| Correctness tested | Specified operations passed selected tests |
| Under attack | Published or available for cryptanalysis |
| Broken | A reproducible attack defeats a stated property |
| Unverified | Security claims remain unestablished |
| Formally verified property | A particular formally stated claim has a checked proof |
| Independently reviewed | External cryptographic review has occurred |
| Deprecated | Use discouraged by a relevant standards or project decision |
| Archived | Retained for historical comparison |

A candidate can hold multiple property-specific findings: an algorithm may be proven reversible while also
being broken for confidentiality. **These classifications must not imply production suitability.**

## 14. Available computational tools

| Agent | Tools |
|---|---|
| Generator | Python execution; SymPy; NumPy; finite-field utilities; algebra libraries; SMT solvers (Z3); optional SageMath; proof assistants where available; candidate compilation and testing; mathematical benchmarking |
| Integrator | Crypto primitive registry; encryption/decryption APIs; key generation; key derivation; nonce generation; cryptographic composition; correctness test execution; challenge publishing; performance benchmarking |
| Adversary | Python analysis; statistical analysis; mathematical solvers; public challenge specifications; permitted oracles; attack script execution; bounded computational experiments; reproducible submission tools |
| Observer | Event database access; lineage analysis; attack evidence inspection; mathematical finding summaries; public research retrieval; vulnerability and deprecation databases; Generator feedback interface |

**Tools must be exposed through specific permission-scoped APIs rather than unrestricted shell access.**

## 15. Operational security

### Execution boundaries

Separate agent sessions; independent writable workspaces; no shared private filesystem mounts;
resource-limited execution containers; no unrestricted host access; no unauthorized outbound networking;
separate secrets and credentials; permission-scoped tool calls; bounded CPU, memory, and execution time;
secure cancellation; auditable tool activity.

### Blindness guarantees

Mutual blindness must be enforced through: API authorization; filesystem isolation; database views or
service-layer filtering; sanitized error messages; redacted event payloads; independent model contexts; no
cross-agent private logs.

The human administrator and Observer may access appropriate supervisory information; blind agents must not.

## 16. Event-driven autonomy

ACES must not require a human to instruct each LLM after every action.

### System events

`CANDIDATE_REGISTERED` · `TOOL_AVAILABLE` · `CHALLENGE_PUBLISHED` · `CHALLENGE_ACTIVE` ·
`ATTACK_SUBMITTED` · `ATTACK_REJECTED` · `BREACH_VERIFIED` · `CANDY_AWARDED` · `ESCALATION_AUTHORIZED` ·
`CHALLENGE_SUPERSEDED` · `OBSERVER_FINDING_CREATED` · `GENERATOR_FEEDBACK_AVAILABLE` ·
`AGENT_EXECUTION_FAILED` · `SYSTEM_PAUSED`

### Scheduling principles

- The Integrator **sleeps** while its challenge is active and unbreached.
- The Adversary **waits** when no challenge exists but may continue bounded investigation of an unsolved one.
- The Observer **wakes on relevant new information** and may perform configured periodic public-source
  monitoring.
- The Generator may explore new constructions independently, subject to budgets.
- **The entire system must resume coherently after interruption.**

## 17. Dashboard

The initial application includes a local administrative dashboard with challenge history, cryptographic
lineages, attack findings, resource consumption, Observer intelligence, and safe start/pause/stop controls.

Required panels: per-agent state (Generator exploring / Integrator waiting for breach / Adversary analysing /
Observer monitoring); active challenge number; breach count; candy total; challenge history; lineage view;
attack findings; resource consumption; audit export.

The dashboard is an administrative surface. It **must not** become a channel that violates agent blindness,
and it must never be reachable from an agent context.

## 18. Core acceptance criteria

| Test | Required result |
|---|---|
| Mutual blindness | Both agents denied access to each other's private state |
| Initial challenge | Integrator publishes a valid challenge |
| No breach | No challenge escalation |
| Invalid attack | No candy or escalation |
| Verified attack | Exactly one confirmed breach |
| Candy reward | Exactly one reward transaction |
| Escalation | Authorized only after verified breach |
| Observer memory | Weakness recorded persistently |
| Generator feedback | Observer findings become available |
| Restart | State restored without duplication |
| Sandboxed execution | Unauthorized access denied |
| Real model execution | Four independent LLM sessions demonstrated |
| Full evolutionary cycle | At least one real toy-cipher breach and subsequent challenge |

**Testing must distinguish mocked demonstrations from actual LLM-driven execution.**

## 19. Development roadmap

| Phase | Goal | Exit criterion |
|---|---|---|
| 1 | Foundation and persistence — Python application, database, event model, configuration, agent identities | Core runtime and persistence tests pass |
| 2 | Shared sandbox — independent interfaces, challenge publishing, versioning, permitted tool access | A toy cryptographic challenge can be published and evaluated |
| 3 | Verification and candy — independent attack verification, rewards, breach events, escalation permissions | False submissions rejected; confirmed breaches trigger exactly one reward and escalation |
| 4 | Autonomous four-agent operation — real LLM sessions, independent contexts, event dispatching, resource budgets | Agents function without manually passing messages between them |
| 5 | Observer intelligence — weakness detection, candidate lineages, persistent feedback, optional external monitoring | Verified failures influence subsequent Generator proposals |
| 6 | Dashboard and controls — local administrative monitoring and lifecycle controls | Activity and state can be inspected without violating agent blindness |
| 7 | Autonomous evolutionary demonstration — full ecosystem against deliberately vulnerable toy ciphers | A verified breach leads to candy, Observer learning, and a successor challenge |
| 8 | Advanced mathematical experimentation — sophisticated candidates, property-specific security testing, formal methods, independent adversarial evaluation | Reproducible evidence demonstrates meaningful findings beyond basic functional tests |

## 20. Long-term evaluation

**Success is not determined by the number of generations or the amount of candy.** ACES is evaluated on:
verified attack discoveries; mathematical novelty of candidates; reproducibility of findings; accuracy of
weakness classifications; computational efficiency; independence of adversarial evaluations; reduction in
repeated known mistakes; formal correctness coverage; quality of external mathematical review; ability to
recover and continue after interruption.

### Known systemic risks

- **Parameter inflation masquerading as progress.** The Integrator could make challenges harder by changing
  parameters or restricting attack access rather than improving cryptographic security. Challenge
  difficulty, attack-access conditions, and security claims must therefore be **measured separately**.
- **Adversary specialisation.** The Adversary may become specialised in the Integrator's constructions
  without becoming a stronger general cryptanalyst. Independent held-out challenges and previously unseen
  attack models can reveal that limitation without interfering with breach-triggered escalation.

## 21. Final definition of ACES

ACES has five defining features:

1. **Four distinct intelligences** — mathematical creation, construction, adversarial problem-solving,
   observation.
2. **Genuine mutual blindness** — the Integrator and Adversary never directly know or communicate with one
   another.
3. **A shared sandbox** — independent agent decisions produce real, measurable consequences through a common
   environment.
4. **Breach-triggered escalation** — the Integrator changes the active challenge only after an independently
   verified breach; candy rewards the Adversary for that success.
5. **Persistent evolutionary learning** — the Observer retains findings and feeds weaknesses back to the
   Generator, allowing mathematical knowledge to develop across generations.

The architecture is intended to operate as an evolving environment rather than a scripted succession of
research tasks. Its ultimate ambition is to determine whether independent AI agents, subjected to
persistent cryptographic construction and attack pressures, can develop increasingly sophisticated
mathematical mechanisms and discover weaknesses not explicitly anticipated by their designers.

This describes the intended system. It does not by itself establish that the proposed agents or
cryptographic discoveries have been implemented or validated.

## Amendments

Recorded deviations from the text above. The four-agent definition, mutual blindness and breach-gated
escalation in §2, §4 and §7 are unchanged by both.

| Date | Amendment | Rationale |
|---|---|---|
| 2026-10-29 | **Role embodiment.** The four agents are staffed by four persistent harness subagent sessions rather than provider models ([AGENTS.md](AGENTS.md)). Autonomy is relayed: one orchestrator turn per tick, so §16 is not satisfied by this embodiment. | No provider and no adequate local model is available on the host. |
| 2026-10-29 | **Supervisory Warden.** A fifth session audits a ledger of what each role was actually shown and reports boundary leaks ([AGENTS.md](AGENTS.md) §4.5). It has one tool, no authority over truth, and cannot award candy, escalate or publish. | Blindness was asserted by code; the ledger lets it be audited against a record. Detection is deliberately separated from control. |
