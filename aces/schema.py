"""Schema and migrations. The only file allowed to define tables, constraints or indexes.

Constraints are where ACES keeps its promises: one active challenge, one reward per challenge,
one breach per challenge, one submission per (challenge, evidence). If a rule matters, it is here,
not in a prompt.
"""

SCHEMA = '''
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS candidates(
    id INTEGER PRIMARY KEY,
    spec TEXT NOT NULL,
    digest TEXT UNIQUE NOT NULL);

CREATE TABLE IF NOT EXISTS challenges(
    id INTEGER PRIMARY KEY,
    candidate INTEGER NOT NULL,
    state TEXT NOT NULL,
    public TEXT NOT NULL,
    secret TEXT NOT NULL,
    parent INTEGER UNIQUE,
    published REAL NOT NULL);

CREATE UNIQUE INDEX IF NOT EXISTS one_active ON challenges((1)) WHERE state='ACTIVE';

CREATE TABLE IF NOT EXISTS submissions(
    id INTEGER PRIMARY KEY,
    challenge INTEGER,
    evidence TEXT,
    valid INTEGER,
    UNIQUE(challenge,evidence));

CREATE TABLE IF NOT EXISTS rewards(
    challenge INTEGER PRIMARY KEY,
    submission INTEGER UNIQUE,
    amount INTEGER NOT NULL DEFAULT 1);

CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY,
    kind TEXT,
    data TEXT,
    created REAL);

CREATE TABLE IF NOT EXISTS sessions(
    role TEXT PRIMARY KEY,
    messages TEXT NOT NULL,
    turns INTEGER DEFAULT 0,
    cursor INTEGER DEFAULT 0);

CREATE TABLE IF NOT EXISTS work_items(
    id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    event_cursor INTEGER NOT NULL,
    status TEXT NOT NULL,
    created REAL NOT NULL,
    answer TEXT,
    outcome TEXT,
    error_type TEXT);

CREATE INDEX IF NOT EXISTS work_by_role ON work_items(role,status);

CREATE TABLE IF NOT EXISTS findings(
    id INTEGER PRIMARY KEY,
    challenge INTEGER,
    data TEXT);

CREATE TABLE IF NOT EXISTS feedback(
    id INTEGER PRIMARY KEY,
    data TEXT);

CREATE TABLE IF NOT EXISTS control(
    id INTEGER PRIMARY KEY CHECK(id=1),
    state TEXT NOT NULL);

-- Run-wide settings that must survive process restarts. The key width is one: every CLI invocation
-- builds a fresh Engine, and a fresh Engine that cannot read the width will silently default to 32
-- bits and mis-describe every challenge it touches.
CREATE TABLE IF NOT EXISTS settings(
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL);

-- What each role was actually shown. Without this ledger, blindness is a claim about code;
-- with it, a supervisory session can audit what really crossed each boundary.
CREATE TABLE IF NOT EXISTS dispatches(
    id INTEGER PRIMARY KEY,
    work_id TEXT UNIQUE,
    role TEXT NOT NULL,
    projection TEXT NOT NULL,
    created REAL NOT NULL);

CREATE TABLE IF NOT EXISTS leaks(
    id INTEGER PRIMARY KEY,
    channel TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence TEXT NOT NULL,
    created REAL);

-- What the bounded search actually produced. A submission is only a breach if one of these
-- derivations contains it: the answer must come from the declared tool path, not from the
-- adversary's own arithmetic or from anything it should not have seen.
CREATE TABLE IF NOT EXISTS derivations(
    id INTEGER PRIMARY KEY,
    challenge INTEGER,
    role TEXT NOT NULL,
    program TEXT NOT NULL,
    solutions TEXT NOT NULL,
    created REAL NOT NULL);

-- How a breach was achieved, named by the attacker and checked against the derivation.
-- A breach without a method is not a result: it teaches the Generator nothing, so the next
-- construction cannot be built against it.
CREATE TABLE IF NOT EXISTS methods(
    id INTEGER PRIMARY KEY,
    challenge INTEGER NOT NULL,
    submission INTEGER NOT NULL,
    method TEXT NOT NULL,
    detail TEXT,
    created REAL NOT NULL);

-- A candidate refused before publication, with the reason. Rejection is a gate, not a suggestion:
-- a rejected candidate cannot be published, and the reason is shown to the Generator.
CREATE TABLE IF NOT EXISTS rejections(
    id INTEGER PRIMARY KEY,
    candidate INTEGER NOT NULL,
    reason TEXT NOT NULL,
    detail TEXT,
    created REAL NOT NULL);

-- A role's question to the outside world, and the answer it was given. The engine cannot browse, so
-- a request waits for the orchestrator to fill it; the point is that the query and its source are
-- recorded rather than happening invisibly inside a session.
CREATE TABLE IF NOT EXISTS research_requests(
    id INTEGER PRIMARY KEY,
    challenge INTEGER,
    role TEXT NOT NULL,
    query TEXT NOT NULL,
    result TEXT,
    status TEXT NOT NULL,
    created REAL NOT NULL,
    answered REAL);

-- Every chosen plaintext the Adversary asked for. The budget is counted from here, so the limit is
-- a fact about the record rather than a promise in a prompt.
CREATE TABLE IF NOT EXISTS oracle_queries(
    id INTEGER PRIMARY KEY,
    challenge INTEGER NOT NULL,
    role TEXT NOT NULL,
    plaintext TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created REAL NOT NULL);

-- Investigate before searching. A hypothesis names the weakness, the attack it implies, and the
-- evidence that would confirm it; the outcome is recorded so a dead end is not walked twice.
CREATE TABLE IF NOT EXISTS hypotheses(
    id INTEGER PRIMARY KEY,
    challenge INTEGER,
    role TEXT NOT NULL,
    weakness TEXT NOT NULL,
    attack TEXT NOT NULL,
    predicted TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence TEXT,
    created REAL NOT NULL,
    resolved REAL);

INSERT OR IGNORE INTO control VALUES(1,'paused');
'''

# Domain events a role may wake on. model_turn / model_error are operational only: if they counted,
# a role would wake itself every tick, which is exactly the idle-gating defect this design avoids.
DOMAIN_EVENTS = (
    'candidate_registered', 'candidate_rejected', 'published', 'submission_evaluated',
    'breach_confirmed', 'feedback_recorded', 'finding_recorded', 'administrative_control',
)


def apply(db):
    """Create or migrate. Idempotent; safe to call on every open."""
    db.executescript(SCHEMA)
    columns = {row[1] for row in db.execute('PRAGMA table_info(derivations)')}
    if 'strategy' not in columns:
        # Older databases recorded derivations without saying how they were obtained. Everything
        # they hold came from the enumerator, which is the honest default.
        db.execute("ALTER TABLE derivations ADD COLUMN strategy TEXT NOT NULL DEFAULT 'enumeration'")
        db.commit()
