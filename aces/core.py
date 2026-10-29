"""Trusted state engine. Never execute model-authored Python in this process.

The Engine is the only writer. It owns transactions, the challenge state machine and the event log.
Verification lives in `verify.py`; scheduling and dispatch live in `pump.py`.
"""
import contextlib, hashlib, json, secrets, sqlite3, time

from .schema import apply, DOMAIN_EVENTS
from .verify import transform, validate, is_reversible, has_secret_term, verify_plaintext

ROLES = ('generator', 'integrator', 'adversary', 'observer')
WARDEN = 'warden'                    # supervisory: audits projections, holds no authority
ALL_ROLES = ROLES + (WARDEN,)
CANDIDATE_FIELDS = {'name', 'program', 'limitations', 'math', 'assumptions'}


def packed(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'))


class Denied(ValueError):
    pass


class Engine:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as db:
            apply(db)
            for role in ALL_ROLES:
                db.execute('INSERT OR IGNORE INTO sessions(role,messages) VALUES(?,?)', (role, '[]'))

    # ---- plumbing -------------------------------------------------------------------------
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        return db

    @contextlib.contextmanager
    def tx(self):
        db = self.connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def event(self, db, kind, data):
        db.execute('INSERT INTO events(kind,data,created) VALUES(?,?,?)', (kind, packed(data), time.time()))

    def last_domain_event(self):
        """Highest id among events a role can legitimately wake on."""
        marks = ','.join('?' * len(DOMAIN_EVENTS))
        with self.connect() as db:
            return db.execute(f'SELECT COALESCE(MAX(id),0) FROM events WHERE kind IN ({marks})',
                              DOMAIN_EVENTS).fetchone()[0]

    def control_state(self):
        with self.connect() as db:
            return db.execute('SELECT state FROM control').fetchone()[0]

    def session(self, role):
        if role not in ALL_ROLES:
            raise Denied('unknown role')
        with self.connect() as db:
            return dict(db.execute('SELECT * FROM sessions WHERE role=?', (role,)).fetchone())

    # ---- work items -----------------------------------------------------------------------
    def begin_work(self, role, event_cursor):
        """Get-or-create a pending item. Legacy idempotent form, kept for the in-process coordinator."""
        if role not in ALL_ROLES:
            raise Denied('unknown role')
        with self.tx() as db:
            active = db.execute("SELECT id FROM work_items WHERE role=? AND status='PENDING'", (role,)).fetchone()
            if active:
                return active['id']
            work_id = secrets.token_hex(16)
            db.execute("INSERT INTO work_items(id,role,event_cursor,status,created) VALUES(?,?,?,'PENDING',?)",
                       (work_id, role, event_cursor, time.time()))
            self.event(db, 'work_started', {'role': role, 'work_id': work_id, 'cursor': event_cursor})
            return work_id

    def claim_work(self, role, event_cursor):
        """Exclusive dispatch. Refuses if this role already has work in flight.

        Two provider calls for one role used to share a single item, so the second result was
        silently dropped. A refusal is the honest outcome.
        """
        if role not in ALL_ROLES:
            raise Denied('unknown role')
        with self.tx() as db:
            active = db.execute("SELECT id FROM work_items WHERE role=? AND status='PENDING'", (role,)).fetchone()
            if active:
                raise Denied(f'work already pending for {role}')
            work_id = secrets.token_hex(16)
            db.execute("INSERT INTO work_items(id,role,event_cursor,status,created) VALUES(?,?,?,'PENDING',?)",
                       (work_id, role, event_cursor, time.time()))
            self.event(db, 'work_started', {'role': role, 'work_id': work_id, 'cursor': event_cursor})
            return work_id

    def work_item(self, work_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM work_items WHERE id=?', (work_id,)).fetchone()
            return dict(row) if row else None

    def pending_work(self, role=None):
        with self.connect() as db:
            if role:
                rows = db.execute("SELECT * FROM work_items WHERE status='PENDING' AND role=?", (role,))
            else:
                rows = db.execute("SELECT * FROM work_items WHERE status='PENDING'")
            return [dict(r) for r in rows]

    def finish_work(self, work_id, answer, outcome=None, error_type=None, messages=None):
        """Idempotently commit a completed result and charge exactly one turn."""
        with self.tx() as db:
            item = db.execute('SELECT * FROM work_items WHERE id=?', (work_id,)).fetchone()
            if not item:
                raise ValueError('unknown work item')
            if item['status'] == 'DONE':
                return False
            db.execute("UPDATE work_items SET status='DONE',answer=?,outcome=?,error_type=? WHERE id=?",
                       (answer, outcome, error_type, work_id))
            if messages is None:
                db.execute('UPDATE sessions SET turns=turns+1,cursor=? WHERE role=?',
                           (item['event_cursor'], item['role']))
            else:
                db.execute('UPDATE sessions SET messages=?,turns=turns+1,cursor=? WHERE role=?',
                           (packed(messages), item['event_cursor'], item['role']))
            self.event(db, 'work_finished', {'role': item['role'], 'work_id': work_id,
                                             'outcome': outcome, 'error_type': error_type})
            return True

    def abandon_stale(self, seconds):
        """Mark orphaned dispatches abandoned. Never re-issues anything itself."""
        cutoff = time.time() - seconds
        with self.tx() as db:
            rows = db.execute("SELECT id,role FROM work_items WHERE status='PENDING' AND created<?",
                              (cutoff,)).fetchall()
            for r in rows:
                db.execute("UPDATE work_items SET status='ABANDONED',outcome='abandoned' WHERE id=?", (r['id'],))
                self.event(db, 'work_abandoned', {'role': r['role'], 'work_id': r['id'], 'reason': 'stale'})
            return len(rows)

    # ---- domain ---------------------------------------------------------------------------
    def register(self, spec):
        if set(spec) != CANDIDATE_FIELDS:
            raise ValueError('candidate fields required')
        validate(spec['program'])
        if any(not isinstance(spec[k], str) or len(spec[k]) > 8000
               for k in ('name', 'limitations', 'math', 'assumptions')):
            raise ValueError('invalid specification')
        if not is_reversible(spec['program']):
            raise ValueError('not reversible')
        record = dict(spec, status='experimental', keygen='uniform byte using secrets.randbelow(256)',
                      input_size='0..4096 bytes', security_claim='none; toy 8-bit key', dependencies=[],
                      test_vector={'key': 7, 'plaintext': '0001ff',
                                   'ciphertext': transform(bytes.fromhex('0001ff'), 7, spec['program']).hex()})
        digest = hashlib.sha256(packed(record).encode()).hexdigest()
        with self.tx() as db:
            db.execute('INSERT OR IGNORE INTO candidates(spec,digest) VALUES(?,?)', (packed(record), digest))
            cid = db.execute('SELECT id FROM candidates WHERE digest=?', (digest,)).fetchone()[0]
            self.event(db, 'candidate_registered', {'candidate': cid})
        return {'candidate': cid, 'status': 'experimental'}

    def publish(self, candidate, mode='open', parent=None):
        if mode not in ('open', 'blackbox'):
            raise ValueError('invalid mode')
        with self.tx() as db:
            last = db.execute('SELECT * FROM challenges ORDER BY id DESC LIMIT 1').fetchone()
            if last and (last['state'] != 'BREACHED' or parent != last['id']):
                raise Denied('replacement requires verified breach of latest version')
            if not last and parent is not None:
                raise Denied('invalid predecessor')
            row = db.execute('SELECT spec FROM candidates WHERE id=?', (candidate,)).fetchone()
            if not row:
                raise ValueError('unknown candidate')
            spec = json.loads(row[0])
            if not has_secret_term(spec['program']):
                raise Denied('candidate has no secret-dependent term')
            key = secrets.randbelow(256)
            plain = secrets.token_bytes(24)
            public = {'mode': mode, 'category': 'plaintext_recovery',
                      'ciphertext': transform(plain, key, spec['program']).hex(),
                      'known_plaintext': '00010203',
                      'known_ciphertext': transform(bytes(range(4)), key, spec['program']).hex(),
                      'rules': 'Recover exact target plaintext. Toy 8-bit key. No external targets.',
                      'oracle_budget': 0}
            if mode == 'open':
                public['spec'] = spec
            cur = db.execute('INSERT INTO challenges(candidate,state,public,secret,parent,published) VALUES(?,?,?,?,?,?)',
                             (candidate, 'ACTIVE', packed(public),
                              packed({'plaintext': plain.hex(), 'key': key}), parent, time.time()))
            cid = cur.lastrowid
            self.event(db, 'published', {'challenge': cid, 'parent': parent, 'mode': mode})
        return {'challenge': cid}

    def submit(self, challenge, plaintext):
        """One transactional verdict: state change, reward, breach record, events — or nothing."""
        if not isinstance(plaintext, str) or len(plaintext) > 8192:
            raise ValueError('invalid submission')
        try:
            plaintext = bytes.fromhex(plaintext).hex()
        except ValueError:
            raise ValueError('hex required')
        with self.tx() as db:
            row = db.execute('SELECT * FROM challenges WHERE id=?', (challenge,)).fetchone()
            if not row:
                raise ValueError('unknown challenge')
            prior = db.execute('SELECT valid FROM submissions WHERE challenge=? AND evidence=?',
                               (challenge, plaintext)).fetchone()
            if prior:
                return {'verified': bool(prior[0]), 'duplicate': True}
            if row['state'] != 'ACTIVE':
                raise Denied('challenge unavailable')
            valid = verify_plaintext(json.loads(row['secret'])['plaintext'], plaintext)
            sid = db.execute('INSERT INTO submissions(challenge,evidence,valid) VALUES(?,?,?)',
                             (challenge, plaintext, int(valid))).lastrowid
            self.event(db, 'submission_evaluated', {'challenge': challenge, 'verified': valid})
            if valid:
                db.execute("UPDATE challenges SET state='BREACHED' WHERE id=?", (challenge,))
                db.execute('INSERT INTO rewards(challenge,submission) VALUES(?,?)', (challenge, sid))
                self.event(db, 'breach_confirmed', {'challenge': challenge, 'category': 'plaintext_recovery',
                                                    'verification': 'exact comparison with committed target',
                                                    'escalation_authorized': True})
        return {'verified': valid, 'duplicate': False}

    # ---- projections ----------------------------------------------------------------------
    def view(self, role):
        """What one role is allowed to know. Built by selection, never by row pass-through."""
        if role not in ALL_ROLES:
            raise Denied('unknown role')
        with self.connect() as db:
            if role == WARDEN:
                # Supervisory: the ledger of what each role was shown, plus the event trail.
                # This is the only view that can compare a projection against the secret it should
                # not contain, which is precisely why it cannot act on the experiment.
                ledger = db.execute('SELECT id,role,work_id,projection,created FROM dispatches '
                                    'ORDER BY id DESC LIMIT 20').fetchall()
                return {'dispatches': [{'id': r['id'], 'role': r['role'], 'work_id': r['work_id'],
                                        'projection': r['projection'][:6000], 'created': r['created']}
                                       for r in ledger],
                        'events': [dict(r) for r in db.execute('SELECT * FROM events ORDER BY id DESC LIMIT 60')],
                        'leaks': [dict(r) for r in db.execute('SELECT * FROM leaks ORDER BY id')]}
            latest = db.execute('SELECT id,state,public,parent FROM challenges ORDER BY id DESC LIMIT 1').fetchone()
            challenge = None if not latest else dict(latest)
            if challenge:
                challenge['public'] = json.loads(challenge['public'])
            candy = db.execute('SELECT COALESCE(SUM(amount),0) FROM rewards').fetchone()[0]
            if role == 'adversary':
                return {'challenge': challenge, 'candy': candy}
            catalog = [dict(id=r[0], spec=json.loads(r[1])) for r in db.execute('SELECT id,spec FROM candidates')]
            if role == 'integrator':
                # Sanitized: the recovered plaintext is the secret just broken. The Integrator learns
                # that a property failed, not what the answer was.
                failures = [{k: v for k, v in json.loads(r[0]).items() if k != 'plaintext'}
                            for r in db.execute("SELECT data FROM events WHERE kind='breach_confirmed'")]
                return {'challenge': challenge, 'catalog': catalog, 'verified_failures': failures}
            if role == 'generator':
                return {'catalog': catalog,
                        'feedback': [json.loads(r[0]) for r in db.execute('SELECT data FROM feedback')]}
            return {'events': [dict(r) for r in db.execute('SELECT * FROM events')],
                    'findings': [dict(r) for r in db.execute('SELECT * FROM findings')]}

    # ---- tools ----------------------------------------------------------------------------
    ALLOWED = {'generator': {'register'}, 'integrator': {'publish'},
               'adversary': {'submit', 'compute'}, 'observer': {'record_finding'},
               WARDEN: {'report_leak'}}

    def tool(self, role, name, args):
        if name not in self.ALLOWED.get(role, set()):
            raise Denied('tool unavailable')
        if name == 'register':
            return self.register(**args)
        if name == 'publish':
            return self.publish(**args)
        if name == 'submit':
            return self.submit(**args)
        if name == 'compute':
            # Bounded cryptanalysis: no interpreter, no filesystem, no network.
            program = validate(args['program'])
            known = bytes.fromhex(args['known_plaintext'])
            cipher = bytes.fromhex(args['known_ciphertext'])
            target = bytes.fromhex(args['ciphertext'])
            if max(len(known), len(cipher), len(target)) > 4096:
                raise ValueError('input too large')
            return {'solutions': [{'plaintext': transform(target, k, program, True).hex(), 'key': k}
                                  for k in range(256) if transform(known, k, program) == cipher]}
        if name == 'record_finding':
            if set(args) != {'challenge', 'finding'} or not isinstance(args['finding'], str) \
                    or len(args['finding']) > 8000:
                raise ValueError('invalid finding')
            with self.tx() as db:
                row = db.execute("SELECT id FROM challenges WHERE id=? AND state='BREACHED'",
                                 (args['challenge'],)).fetchone()
                if not row:
                    raise Denied('verified breach required')
                db.execute('INSERT INTO findings(challenge,data) VALUES(?,?)', (args['challenge'], packed(args)))
                db.execute('INSERT INTO feedback(data) VALUES(?)',
                           (packed({'finding': args['finding'], 'status': 'hypothesis',
                                    'evidence_challenge': args['challenge']}),))
                self.event(db, 'feedback_recorded', {'challenge': args['challenge']})
            return {'recorded': True}
        if name == 'report_leak':
            if set(args) != {'channel', 'severity', 'evidence'}:
                raise ValueError('invalid leak report')
            if args['severity'] not in ('low', 'medium', 'high'):
                raise ValueError('invalid severity')
            if not isinstance(args['channel'], str) or not isinstance(args['evidence'], str) \
                    or len(args['channel']) > 200 or len(args['evidence']) > 4000:
                raise ValueError('invalid leak report')
            with self.tx() as db:
                db.execute('INSERT INTO leaks(channel,severity,evidence,created) VALUES(?,?,?,?)',
                           (args['channel'], args['severity'], args['evidence'], time.time()))
                self.event(db, 'leak_reported', {'channel': args['channel'], 'severity': args['severity']})
            return {'reported': True}

    # ---- ledger ---------------------------------------------------------------------------
    def record_dispatch(self, work_id, role, projection):
        """Persist the exact projection a role was shown. Cheap, and it makes blindness auditable."""
        with self.tx() as db:
            db.execute('INSERT OR IGNORE INTO dispatches(work_id,role,projection,created) VALUES(?,?,?,?)',
                       (work_id, role, packed(projection), time.time()))
