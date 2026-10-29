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

INSERT OR IGNORE INTO control VALUES(1,'paused');
'''

# Domain events a role may wake on. model_turn / model_error are operational only: if they counted,
# a role would wake itself every tick, which is exactly the idle-gating defect this design avoids.
DOMAIN_EVENTS = (
    'candidate_registered', 'published', 'submission_evaluated', 'breach_confirmed',
    'feedback_recorded', 'finding_recorded', 'administrative_control',
)


def apply(db):
    """Create or migrate. Idempotent; safe to call on every open."""
    db.executescript(SCHEMA)
