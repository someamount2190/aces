"""Trusted state engine. Never execute model-authored Python in this process.

The Engine is the only writer. It owns transactions, the challenge state machine and the event log.
Verification lives in `verify.py`; scheduling and dispatch live in `pump.py`.
"""
import contextlib, hashlib, json, secrets, sqlite3, time

from .schema import apply, DOMAIN_EVENTS
from .verify import (transform, validate, is_reversible, has_secret_term, verify_plaintext,
                     valid_method, key_bytes, gf2_linear_attack, is_gf2_linear, is_causal,
                     DEFAULT_KEY_BITS, COMPUTE_BUDGET, CHAIN_OPS)
from . import workbench

ROLES = ('generator', 'integrator', 'adversary', 'observer')
REVIEWER = 'reviewer'                # red-teams the Adversary's process; no authority over truth
WARDEN = 'warden'                    # supervisory: audits projections, holds no authority
ALL_ROLES = ROLES + (REVIEWER, WARDEN)
CANDIDATE_FIELDS = {'name', 'program', 'limitations', 'math', 'assumptions'}
SPEC_FIELDS = ('name', 'program', 'limitations', 'math', 'assumptions')
EVENT_WINDOW = 60


def packed(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'))


def contract(spec):
    """The fields a role may rely on — never the bookkeeping around them.

    The catalog used to expose status, security_claim, dependencies, keygen, input_size and
    test_vector. A generator copied them into its spec and the register tool rejected the result:
    an environment that shows more than the contract invites answers that break it.
    """
    return {k: spec[k] for k in SPEC_FIELDS if k in spec}


def assess(spec, key_bits=DEFAULT_KEY_BITS):
    """Structural facts about a construction, so a difficulty judgement has a number under it.

    These are properties of the VM and the run, not opinions: the key is `key_bits` wide, so a
    known-plaintext search costs at most 2^key_bits trials, and a construction with no chain operation
    decomposes into independent per-byte maps, which makes that search cheaper still in practice.
    """
    program = spec.get('program', [])
    mixes = any(str(op) in CHAIN_OPS for op, _ in program)
    # A causal construction (every op position-local or forward-chaining) gives up one key byte per
    # position, so the real known-plaintext cost is key_bytes * 256, not 2^key_bits.
    causal = is_causal(program)
    sequential = (key_bits // 8) * 256
    return {'key_bits': key_bits,
            'known_plaintext_work': min(1 << key_bits, sequential) if causal else (1 << key_bits),
            'causal': causal,
            'byte_local': not mixes,
            'key_ops': sum(1 for op, _ in program if str(op).endswith('_key')),
            'program_length': len(program)}


class Denied(ValueError):
    pass


class _ClosingConnection(sqlite3.Connection):
    """sqlite3's context manager commits but does not close. On Windows an unclosed handle keeps
    the database file locked, which breaks cleanup and, over a long run, leaks descriptors."""

    def __exit__(self, exc_type, exc, tb):
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


class Engine:
    def __init__(self, path, key_bits=None):
        self.path = str(path)
        with self.connect() as db:
            apply(db)
            stored = db.execute("SELECT v FROM settings WHERE k='key_bits'").fetchone()
            if stored is not None:
                # An existing database wins: the width is a property of the run, not of the caller.
                key_bits = int(stored['v'])
            else:
                key_bits = DEFAULT_KEY_BITS if key_bits is None else key_bits
                db.execute("INSERT OR REPLACE INTO settings(k,v) VALUES('key_bits',?)", (str(key_bits),))
            self.key_bits = key_bits
            for role in ALL_ROLES:
                db.execute('INSERT OR IGNORE INTO sessions(role,messages) VALUES(?,?)', (role, '[]'))

    # ---- plumbing -------------------------------------------------------------------------
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15, factory=_ClosingConnection)
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

    def abandon_work(self, work_id):
        """Abandon exactly one dispatch. `abandon_stale` sweeps by age, which is a blunt instrument:
        using it to drop one stale item also dropped four live ones."""
        with self.tx() as db:
            row = db.execute("SELECT role FROM work_items WHERE id=? AND status='PENDING'",
                             (work_id,)).fetchone()
            if not row:
                return 0
            db.execute("UPDATE work_items SET status='ABANDONED',outcome='abandoned' WHERE id=?", (work_id,))
            self.event(db, 'work_abandoned', {'role': row['role'], 'work_id': work_id, 'reason': 'explicit'})
            return 1

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
    def survey(self):
        """The active challenge and its public projection. Raises if there is nothing to attack."""
        with self.connect() as db:
            row = db.execute("SELECT id,public FROM challenges WHERE state='ACTIVE' "
                             "ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            raise Denied('no active challenge')
        public = json.loads(row['public'])
        if 'spec' not in public:
            raise Denied('blackbox challenge: no construction to analyse')
        return row['id'], public

    def hypotheses_awaiting_review(self):
        """Resolved hypotheses nobody has reviewed yet. That is the Reviewer's work queue."""
        with self.connect() as db:
            return db.execute("SELECT COUNT(*) FROM hypotheses h WHERE h.status IN ('confirmed','refuted') "
                              "AND NOT EXISTS (SELECT 1 FROM reviews v WHERE v.hypothesis=h.id)").fetchone()[0]

    def challenge_secret(self, challenge):
        with self.connect() as db:
            row = db.execute('SELECT secret FROM challenges WHERE id=?', (challenge,)).fetchone()
        if not row:
            raise ValueError('unknown challenge')
        return row['secret']

    def register(self, spec):
        if set(spec) != CANDIDATE_FIELDS:
            raise ValueError('candidate fields required')
        validate(spec['program'])
        if any(not isinstance(spec[k], str) or len(spec[k]) > 8000
               for k in ('name', 'limitations', 'math', 'assumptions')):
            raise ValueError('invalid specification')
        if not is_reversible(spec['program'], self.key_bits):
            raise ValueError('not reversible')
        probe = (7).to_bytes(self.key_bits // 8, 'big')
        record = dict(spec, status='experimental', keygen=f'uniform {self.key_bits}-bit key',
                      input_size='0..4096 bytes', security_claim=f'none; toy {self.key_bits}-bit key',
                      dependencies=[],
                      test_vector={'key': 7, 'plaintext': '0001ff',
                                   'ciphertext': transform(bytes.fromhex('0001ff'), probe,
                                                           spec['program']).hex()})
        digest = hashlib.sha256(packed(record).encode()).hexdigest()
        with self.tx() as db:
            db.execute('INSERT OR IGNORE INTO candidates(spec,digest) VALUES(?,?)', (packed(record), digest))
            cid = db.execute('SELECT id FROM candidates WHERE digest=?', (digest,)).fetchone()[0]
            self.event(db, 'candidate_registered', {'candidate': cid})
        return {'candidate': cid, 'status': 'experimental'}

    def reject(self, candidate, reason, detail=None):
        """Refuse a candidate before publication. The refusal binds: it cannot then be published."""
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise ValueError('invalid rejection reason')
        with self.tx() as db:
            row = db.execute('SELECT id FROM candidates WHERE id=?', (candidate,)).fetchone()
            if not row:
                raise ValueError('unknown candidate')
            db.execute('INSERT INTO rejections(candidate,reason,detail,created) VALUES(?,?,?,?)',
                       (candidate, reason.strip(), (detail or '')[:2000], time.time()))
            self.event(db, 'candidate_rejected', {'candidate': candidate, 'reason': reason.strip()})
        return {'rejected': candidate, 'reason': reason.strip()}

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
            refused = db.execute('SELECT reason FROM rejections WHERE candidate=? ORDER BY id DESC LIMIT 1',
                                 (candidate,)).fetchone()
            if refused:
                raise Denied(f"candidate rejected: {refused['reason']}")
            spec = json.loads(row[0])
            if not has_secret_term(spec['program']):
                raise Denied('candidate has no secret-dependent term')
            key = secrets.token_bytes(self.key_bits // 8)
            plain = secrets.token_bytes(24)
            public = {'mode': mode, 'category': 'plaintext_recovery', 'key_bits': self.key_bits,
                      'ciphertext': transform(plain, key, spec['program']).hex(),
                      'known_plaintext': '00010203',
                      'known_ciphertext': transform(bytes(range(4)), key, spec['program']).hex(),
                      'rules': 'Recover exact target plaintext. Toy 8-bit key. No external targets.',
                      'oracle_budget': 0}
            if mode == 'open':
                public['spec'] = contract(spec)
            cur = db.execute('INSERT INTO challenges(candidate,state,public,secret,parent,published) VALUES(?,?,?,?,?,?)',
                             (candidate, 'ACTIVE', packed(public),
                              packed({'plaintext': plain.hex(), 'key': key.hex()}), parent, time.time()))
            cid = cur.lastrowid
            self.event(db, 'published', {'challenge': cid, 'parent': parent, 'mode': mode})
        return {'challenge': cid}

    def submit(self, challenge, plaintext, method=None, detail=None):
        """One transactional verdict: state change, method record, reward, events — or nothing.

        A breach now needs three things, not one: the right answer, a derivation that produced it,
        and a named method the verifier can check against that derivation. An answer with no method
        is not a result — it tells the Generator nothing about what to defend against.
        """
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
            matched = verify_plaintext(json.loads(row['secret'])['plaintext'], plaintext)

            derivation_program, derived, strategy = None, False, None
            for r in db.execute('SELECT program,solutions,strategy FROM derivations WHERE challenge=?',
                                (challenge,)):
                if plaintext in {s.get('plaintext') for s in json.loads(r['solutions'])}:
                    derivation_program, derived, strategy = json.loads(r['program']), True, r['strategy']
                    break

            def reject(reason):
                self.event(db, 'submission_rejected', {'challenge': challenge, 'reason': reason})
                return {'verified': False, 'reason': reason}

            if matched and not derived:
                return reject('no_derivation_trace')
            if matched and not method:
                return reject('no_method')
            if matched and not valid_method(method):
                return reject('unverified_method')
            if matched and strategy == 'enumeration':
                # Trying every key is labour, not knowledge. It is recorded, it costs turns, and it
                # does not pay: a breach has to show a method that does better than the search space.
                return reject('enumeration_is_not_a_breach')
            required = {'gf2_linear': 'gf2_linear', 'sequential_recovery': 'sequential_recovery'}
            if matched and required.get(strategy, method) != method:
                return reject('method_mismatch')

            valid = matched and derived
            sid = db.execute('INSERT INTO submissions(challenge,evidence,valid) VALUES(?,?,?)',
                             (challenge, plaintext, int(valid))).lastrowid
            self.event(db, 'submission_evaluated', {'challenge': challenge, 'verified': valid})
            if valid:
                db.execute("UPDATE challenges SET state='BREACHED' WHERE id=?", (challenge,))
                db.execute('INSERT INTO rewards(challenge,submission) VALUES(?,?)', (challenge, sid))
                db.execute('INSERT INTO methods(challenge,submission,method,detail,created) VALUES(?,?,?,?,?)',
                           (challenge, sid, method, (detail or '')[:2000], time.time()))
                self.event(db, 'breach_confirmed', {'challenge': challenge, 'category': 'plaintext_recovery',
                                                    'verification': 'exact comparison with committed target',
                                                    'method': method,
                                                    'escalation_authorized': True})
        return {'verified': valid, 'duplicate': False, 'method': method if valid else None}

    # ---- projections ----------------------------------------------------------------------
    def view(self, role):
        """What one role is allowed to know. Built by selection, never by row pass-through."""
        if role not in ALL_ROLES:
            raise Denied('unknown role')
        with self.connect() as db:
            if role == REVIEWER:
                # Everything needed to judge process: what was claimed, what was predicted, what
                # happened, and what previous reviews already said.
                hypotheses = [{'id': r['id'], 'weakness': r['weakness'], 'attack': r['attack'],
                               'predicted': r['predicted'], 'status': r['status'],
                               'evidence': r['evidence'],
                               'reviewed': r['reviewed']}
                              for r in db.execute(
                                  'SELECT h.id,h.weakness,h.attack,h.predicted,h.status,h.evidence,'
                                  ' (SELECT COUNT(*) FROM reviews v WHERE v.hypothesis=h.id) AS reviewed '
                                  'FROM hypotheses h ORDER BY h.id DESC LIMIT 10')]
                reviews = [{'hypothesis': r['hypothesis'], 'verdict': r['verdict'],
                            'flaw': r['flaw'], 'advice': r['advice']}
                           for r in db.execute('SELECT hypothesis,verdict,flaw,advice FROM reviews '
                                               'ORDER BY id DESC LIMIT 10')]
                return {'hypotheses': hypotheses, 'reviews': reviews}
            if role == WARDEN:
                # Supervisory: the ledger of what each role was shown, plus the event trail.
                # This is the only view that can compare a projection against the secret it should
                # not contain, which is precisely why it cannot act on the experiment.
                ledger = db.execute(
                    'SELECT d.id,d.role,d.work_id,d.projection,d.created FROM dispatches d '
                    'JOIN (SELECT role, MAX(id) AS mid FROM dispatches GROUP BY role) m ON d.id=m.mid '
                    'ORDER BY d.id DESC').fetchall()
                return {'dispatches': [{'id': r['id'], 'role': r['role'], 'work_id': r['work_id'],
                                        'projection': r['projection'][:2500], 'created': r['created']}
                                       for r in ledger],
                        'events': [dict(r) for r in db.execute('SELECT * FROM events ORDER BY id DESC LIMIT 12')],
                        'leaks': [dict(r) for r in db.execute('SELECT * FROM leaks ORDER BY id')]}
            latest = db.execute('SELECT id,state,public,parent FROM challenges ORDER BY id DESC LIMIT 1').fetchone()
            challenge = None if not latest else dict(latest)
            if challenge:
                challenge['public'] = json.loads(challenge['public'])
            candy = db.execute('SELECT COALESCE(SUM(amount),0) FROM rewards').fetchone()[0]
            if role == 'adversary':
                # Its own hypothesis log and the Observer's reviews of how it worked, so a refuted
                # dead end and a flagged habit are both visible next turn.
                hypotheses = [{'id': r['id'], 'weakness': r['weakness'], 'attack': r['attack'],
                               'status': r['status']}
                              for r in db.execute('SELECT id,weakness,attack,status FROM hypotheses '
                                                  'ORDER BY id DESC LIMIT 10')]
                reviews = [{'hypothesis': r['hypothesis'], 'verdict': r['verdict'],
                            'flaw': r['flaw'], 'advice': r['advice']}
                           for r in db.execute('SELECT hypothesis,verdict,flaw,advice FROM reviews '
                                               'ORDER BY id DESC LIMIT 5')]
                return {'challenge': challenge, 'candy': candy,
                        'hypotheses': hypotheses, 'reviews': reviews}
            catalog = [dict(id=r[0], spec=contract(json.loads(r[1])))
                       for r in db.execute('SELECT id,spec FROM candidates')]
            if role == 'integrator':
                # Sanitized: the recovered plaintext is the secret just broken. The Integrator learns
                # that a property failed, not what the answer was.
                failures = [{k: v for k, v in json.loads(r[0]).items() if k != 'plaintext'}
                            for r in db.execute("SELECT data FROM events WHERE kind='breach_confirmed'")]
                catalog = [dict(entry, assessment=assess(entry['spec'], self.key_bits))
                           for entry in catalog]
                return {'challenge': challenge, 'catalog': catalog, 'verified_failures': failures}
            if role == 'generator':
                # How each challenge fell, so the next construction can be built against the method
                # rather than against the answer. A breach without a method would teach nothing.
                failures = [{'challenge': r['challenge'], 'method': r['method']}
                            for r in db.execute('SELECT challenge,method FROM methods ORDER BY id')]
                rejections = [{'candidate': r['candidate'], 'reason': r['reason']}
                              for r in db.execute('SELECT candidate,reason FROM rejections '
                                                  'ORDER BY id DESC LIMIT 5')]
                return {'catalog': catalog, 'failures': failures, 'rejections': rejections,
                        'feedback': [json.loads(r[0]) for r in db.execute('SELECT data FROM feedback')]}
            return {'events': [dict(r) for r in db.execute(
                        'SELECT * FROM events WHERE id > ? ORDER BY id LIMIT ?',
                        (db.execute("SELECT cursor FROM sessions WHERE role=?", (role,)).fetchone()[0],
                         EVENT_WINDOW))],
                    'findings': [dict(r) for r in db.execute('SELECT * FROM findings')],
                    'hypotheses': [{'id': r['id'], 'weakness': r['weakness'], 'attack': r['attack'],
                                    'predicted': r['predicted'], 'status': r['status'],
                                    'evidence': r['evidence']}
                                   for r in db.execute('SELECT id,weakness,attack,predicted,status,evidence '
                                                       'FROM hypotheses ORDER BY id DESC LIMIT 10')],
                    'reviews': [{'hypothesis': r['hypothesis'], 'verdict': r['verdict'],
                                 'flaw': r['flaw'], 'advice': r['advice']}
                                for r in db.execute('SELECT hypothesis,verdict,flaw,advice FROM reviews '
                                                    'ORDER BY id DESC LIMIT 10')]}

    # ---- tools ----------------------------------------------------------------------------
    ALLOWED = {'generator': {'register'}, 'integrator': {'publish', 'reject'},
               'adversary': {'submit', 'compute', 'solve', 'oracle', 'analyse',
                             'hypothesize', 'resolve'},
               'observer': {'record_finding'},
               REVIEWER: {'critique'},
               WARDEN: {'report_leak'}}

    FLAW_LABELS = ('ignored_own_analysis', 'unfalsifiable_prediction', 'no_fallback_after_refutation',
                   'enumeration_as_analysis', 'untested_assumption', 'premature_stop', 'other')

    def tool(self, role, name, args):
        if name not in self.ALLOWED.get(role, set()):
            raise Denied('tool unavailable')
        if name == 'register':
            return self.register(**args)
        if name == 'publish':
            return self.publish(**args)
        if name == 'reject':
            return self.reject(**args)
        if name == 'submit':
            return self.submit(**args)
        if name == 'solve':
            # Structural attacks. Knowledge rather than labour: each strategy either works in a
            # handful of evaluations or reports that the construction offers no such handle.
            challenge, public = self.survey()
            program = public['spec']['program']
            bits = public.get('key_bits', self.key_bits)
            pair = (bytes.fromhex(public['known_plaintext']), bytes.fromhex(public['known_ciphertext']))
            result = workbench.solve(program, bits, pair)
            if result['strategy'] is None:
                with self.tx() as db:
                    self.event(db, 'attack_failed', {'challenge': challenge,
                                                     'reason': 'no implemented strategy applies'})
                return {'strategy': None, 'reason': 'no implemented strategy applies to this construction',
                        'evaluations': result['evaluations'], 'seconds': result['seconds']}
            width = max(1, bits // 8)
            plaintext = transform(bytes.fromhex(public['ciphertext']),
                                  result['key'].to_bytes(width, 'big'), program, True).hex()
            with self.tx() as db:
                db.execute('INSERT INTO derivations(challenge,role,program,solutions,created,strategy) '
                           'VALUES(?,?,?,?,?,?)',
                           (challenge, role, packed(program),
                            packed([{'plaintext': plaintext, 'key': result['key']}]), time.time(),
                            result['strategy']))
                self.event(db, 'derivation_recorded', {'challenge': challenge, 'role': role,
                                                       'solutions': 1, 'strategy': result['strategy'],
                                                       'evaluations': result['evaluations'],
                                                       'seconds': result['seconds']})
            return {'strategy': result['strategy'], 'key': result['key'], 'plaintext': plaintext,
                    'evaluations': result['evaluations'], 'seconds': result['seconds']}

        if name == 'oracle':
            challenge, public = self.survey()
            plaintexts = args.get('plaintexts') or []
            if not isinstance(plaintexts, list) or not 1 <= len(plaintexts) <= workbench.ORACLE_BATCH:
                raise Denied(f'oracle takes 1..{workbench.ORACLE_BATCH} plaintexts per call')
            with self.connect() as db:
                used = db.execute('SELECT COUNT(*) FROM oracle_queries WHERE challenge=?',
                                  (challenge,)).fetchone()[0]
            if used + len(plaintexts) > workbench.ORACLE_LIMIT:
                raise Denied(f'oracle budget exhausted: {used}/{workbench.ORACLE_LIMIT} used')
            key = bytes.fromhex(json.loads(self.challenge_secret(challenge))['key'])
            raw = [bytes.fromhex(p) for p in plaintexts]
            out = workbench.encrypt_batch(public['spec']['program'], key, raw)
            with self.tx() as db:
                for p, c in zip(plaintexts, out):
                    db.execute('INSERT INTO oracle_queries(challenge,role,plaintext,ciphertext,created) '
                               'VALUES(?,?,?,?,?)', (challenge, role, p, c, time.time()))
                self.event(db, 'oracle_queried', {'challenge': challenge, 'role': role,
                                                  'count': len(out), 'used': used + len(out)})
            return {'ciphertexts': out, 'used': used + len(out), 'limit': workbench.ORACLE_LIMIT}

        if name == 'analyse':
            kind = args.get('kind')
            challenge, public = self.survey()
            program = public['spec']['program']
            bits = public.get('key_bits', self.key_bits)
            if kind == 'key_schedule':
                key_bits_default = bits // 8
                return workbench.key_schedule(program, key_bits_default)
            if kind == 'frequency':
                samples = [bytes.fromhex(s) for s in (args.get('samples') or [])][:16] or \
                          [bytes.fromhex(public['ciphertext'])]
                return workbench.frequency(samples)
            if kind == 'differential':
                difference = bytes.fromhex(args.get('difference', '01'))
                pairs = min(int(args.get('pairs', workbench.DIFF_PAIRS)), workbench.DIFF_PAIRS)
                with self.connect() as db:
                    used = db.execute('SELECT COUNT(*) FROM oracle_queries WHERE challenge=?',
                                      (challenge,)).fetchone()[0]
                if used + pairs * 2 > workbench.ORACLE_LIMIT:
                    raise Denied(f'oracle budget exhausted: {used}/{workbench.ORACLE_LIMIT} used')
                key = bytes.fromhex(json.loads(self.challenge_secret(challenge))['key'])
                result = workbench.differential(program, key, difference, pairs)
                with self.tx() as db:
                    db.execute('INSERT INTO oracle_queries(challenge,role,plaintext,ciphertext,created) '
                               'VALUES(?,?,?,?,?)',
                               (challenge, role, f'differential x{pairs}', 'internal', time.time()))
                    self.event(db, 'oracle_queried', {'challenge': challenge, 'role': role,
                                                      'count': pairs * 2, 'used': used + pairs * 2})
                return result
            if kind == 'pairs':
                candidate = int(args.get('key', 0))
                width = max(1, bits // 8)
                key = bytes.fromhex(json.loads(self.challenge_secret(challenge))['key'])
                known = [(bytes.fromhex(public['known_plaintext']),
                          bytes.fromhex(public['known_ciphertext']))]
                for _ in range(3):
                    probe = bytes.fromhex(hashlib.sha256(str(candidate).encode()).hexdigest()[:2 * len(known[0][0])])
                    known.append((probe, transform(probe, key, program)))
                return workbench.test_key(program, candidate.to_bytes(width, 'big'), known)
            raise ValueError('unknown analysis kind')

        if name == 'hypothesize':
            for field in ('weakness', 'attack', 'predicted'):
                value = args.get(field)
                if not isinstance(value, str) or not 1 <= len(value) <= 600:
                    raise ValueError(f'invalid hypothesis field: {field}')
            challenge, _ = self.survey()
            with self.tx() as db:
                hid = db.execute('INSERT INTO hypotheses(challenge,role,weakness,attack,predicted,status,created) '
                                 "VALUES(?,?,?,?,?,'open',?)",
                                 (challenge, role, args['weakness'], args['attack'],
                                  args['predicted'], time.time())).lastrowid
                self.event(db, 'hypothesis_opened', {'challenge': challenge, 'role': role,
                                                     'hypothesis': hid, 'attack': args['attack']})
            return {'hypothesis': hid, 'status': 'open'}

        if name == 'resolve':
            hid = int(args.get('hypothesis', 0))
            status = args.get('status')
            if status not in ('confirmed', 'refuted'):
                raise ValueError('status must be confirmed or refuted')
            with self.tx() as db:
                row = db.execute('SELECT * FROM hypotheses WHERE id=?', (hid,)).fetchone()
                if not row:
                    raise ValueError('unknown hypothesis')
                if row['status'] != 'open':
                    return {'hypothesis': hid, 'status': row['status'], 'note': 'already resolved'}
                db.execute('UPDATE hypotheses SET status=?,evidence=?,resolved=? WHERE id=?',
                           (status, (args.get('evidence') or '')[:2000], time.time(), hid))
                self.event(db, 'hypothesis_resolved', {'hypothesis': hid, 'status': status})
            return {'hypothesis': hid, 'status': status}

        if name == 'compute':
            # Bounded cryptanalysis: no interpreter, no filesystem, no network. The search is capped
            # and says so, rather than running until the turn budget dies.
            program = validate(args['program'])
            known = bytes.fromhex(args['known_plaintext'])
            cipher = bytes.fromhex(args['known_ciphertext'])
            target = bytes.fromhex(args['ciphertext'])
            if max(len(known), len(cipher), len(target)) > 4096:
                raise ValueError('input too large')
            with self.connect() as db:
                active = db.execute("SELECT id,public FROM challenges WHERE state='ACTIVE' "
                                    "ORDER BY id DESC LIMIT 1").fetchone()
            bits = self.key_bits
            if active:
                bits = json.loads(active['public']).get('key_bits', bits)
            space = 1 << bits
            budget = min(space, COMPUTE_BUDGET)
            width = max(1, bits // 8)
            solutions = []
            for k in range(budget):
                probe = k.to_bytes(width, 'big')
                if transform(known, probe, program) == cipher:
                    solutions.append({'plaintext': transform(target, probe, program, True).hex(), 'key': k})
            with self.tx() as db:
                if active:
                    db.execute('INSERT INTO derivations(challenge,role,program,solutions,created,strategy) '
                               'VALUES(?,?,?,?,?,?)',
                               (active['id'], role, packed(program), packed(solutions), time.time(),
                                'enumeration'))
                    self.event(db, 'derivation_recorded', {'challenge': active['id'], 'role': role,
                                                           'solutions': len(solutions),
                                                           'searched': budget,
                                                           'exhausted': budget < space})
            return {'solutions': solutions, 'searched': budget, 'exhausted': budget < space}
        if name == 'critique':
            # A process review, not a cryptographic one. Sound reasoning that ends in "I cannot break
            # this" is a good result; a lucky guess is not.
            hypothesis = int(args.get('hypothesis', 0))
            verdict = args.get('verdict')
            flaw = args.get('flaw')
            advice = args.get('advice')
            if verdict not in ('sound', 'flawed'):
                raise ValueError('verdict must be sound or flawed')
            if not isinstance(advice, str) or not 1 <= len(advice) <= 800:
                raise ValueError('advice is required')
            if verdict == 'flawed' and flaw not in self.FLAW_LABELS:
                raise ValueError(f'unknown flaw label: {flaw}')
            with self.tx() as db:
                row = db.execute('SELECT id FROM hypotheses WHERE id=?', (hypothesis,)).fetchone()
                if not row:
                    raise ValueError('unknown hypothesis')
                rid = db.execute('INSERT INTO reviews(hypothesis,role,verdict,flaw,advice,created) '
                                 'VALUES(?,?,?,?,?,?)',
                                 (hypothesis, role, verdict, flaw, advice, time.time())).lastrowid
                self.event(db, 'critique_recorded', {'hypothesis': hypothesis, 'verdict': verdict,
                                                     'flaw': flaw})
            return {'review': rid, 'verdict': verdict, 'flaw': flaw}

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
