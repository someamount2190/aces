"""Trusted state engine. Never execute model-authored Python in this process."""
import contextlib, hashlib, json, secrets, sqlite3, time

ROLES = ('generator', 'integrator', 'adversary', 'observer')

def packed(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'))

class Denied(ValueError): pass

# Bounded straight-line byte permutation language. No names, imports, loops or IO.
def validate(program):
    if not isinstance(program, list) or not 1 <= len(program) <= 32:
        raise ValueError('program must have 1..32 operations')
    for step in program:
        if not isinstance(step, list) or len(step) != 2 or step[0] not in ('xor_key','add_key','xor','add','rol'):
            raise ValueError('invalid operation')
        if type(step[1]) is not int or not 0 <= step[1] <= 255:
            raise ValueError('invalid operand')
    return program

def transform(data, key, program, inverse=False):
    validate(program)
    if not isinstance(data, bytes) or len(data) > 4096 or type(key) is not int or not 0 <= key <= 255:
        raise ValueError('invalid VM input')
    out=[]
    for b in data:
        for op,n in (reversed(program) if inverse else program):
            v = key if op.endswith('_key') else n
            if op in ('xor_key','xor'): b ^= v
            elif op in ('add_key','add'): b = (b + (-v if inverse else v)) & 255
            else:
                r = n % 8
                if inverse: r = (-r) % 8
                b = ((b << r) | (b >> ((8-r)%8))) & 255
        out.append(b)
    return bytes(out)

SCHEMA='''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS candidates(id INTEGER PRIMARY KEY, spec TEXT NOT NULL, digest TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS challenges(id INTEGER PRIMARY KEY, candidate INTEGER NOT NULL, state TEXT NOT NULL, public TEXT NOT NULL, secret TEXT NOT NULL, parent INTEGER UNIQUE, published REAL NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS one_active ON challenges((1)) WHERE state='ACTIVE';
CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY, challenge INTEGER, evidence TEXT, valid INTEGER, UNIQUE(challenge,evidence));
CREATE TABLE IF NOT EXISTS rewards(challenge INTEGER PRIMARY KEY, submission INTEGER UNIQUE, amount INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, kind TEXT, data TEXT, created REAL);
CREATE TABLE IF NOT EXISTS sessions(role TEXT PRIMARY KEY, messages TEXT NOT NULL, turns INTEGER DEFAULT 0, cursor INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS work_items(id TEXT PRIMARY KEY, role TEXT NOT NULL, event_cursor INTEGER NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, answer TEXT, outcome TEXT, error_type TEXT);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, challenge INTEGER, data TEXT);
CREATE TABLE IF NOT EXISTS feedback(id INTEGER PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS control(id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL);
INSERT OR IGNORE INTO control VALUES(1,'paused');
'''

class Engine:
    def __init__(self, path):
        self.path=str(path)
        with self.connect() as db:
            db.executescript(SCHEMA)
            for role in ROLES: db.execute('INSERT OR IGNORE INTO sessions(role,messages) VALUES(?,?)',(role,'[]'))
    def connect(self):
        db=sqlite3.connect(self.path, timeout=15)
        db.row_factory=sqlite3.Row
        return db
    @contextlib.contextmanager
    def tx(self):
        db=self.connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback(); raise
        finally: db.close()
    def event(self,db,kind,data):
        db.execute('INSERT INTO events(kind,data,created) VALUES(?,?,?)',(kind,packed(data),time.time()))
    def begin_work(self,role,event_cursor):
        """Persist dispatch intent before external model work; one active item per role."""
        if role not in ROLES: raise Denied('unknown role')
        with self.tx() as db:
            active=db.execute("SELECT id FROM work_items WHERE role=? AND status='PENDING'",(role,)).fetchone()
            if active: return active['id']
            work_id=secrets.token_hex(16)
            db.execute('INSERT INTO work_items(id,role,event_cursor,status,created) VALUES(?,?,?,\'PENDING\',?)',(work_id,role,event_cursor,time.time()))
            self.event(db,'work_started',{'role':role,'work_id':work_id,'cursor':event_cursor})
            return work_id
    def finish_work(self,work_id,answer,outcome=None,error_type=None,messages=None):
        """Idempotently commit a completed provider/action result and charge its turn."""
        with self.tx() as db:
            item=db.execute('SELECT * FROM work_items WHERE id=?',(work_id,)).fetchone()
            if not item: raise ValueError('unknown work item')
            if item['status']=='DONE': return False
            db.execute("UPDATE work_items SET status='DONE',answer=?,outcome=?,error_type=? WHERE id=?",(answer,outcome,error_type,work_id))
            if messages is None:
                db.execute('UPDATE sessions SET turns=turns+1,cursor=? WHERE role=?',(item['event_cursor'],item['role']))
            else:
                db.execute('UPDATE sessions SET messages=?,turns=turns+1,cursor=? WHERE role=?',(packed(messages),item['event_cursor'],item['role']))
            self.event(db,'work_finished',{'role':item['role'],'work_id':work_id,'outcome':outcome,'error_type':error_type})
            return True
    def register(self,spec):
        if set(spec) != {'name','program','limitations','math','assumptions'}: raise ValueError('candidate fields required')
        validate(spec['program'])
        if any(not isinstance(spec[k],str) or len(spec[k])>8000 for k in ('name','limitations','math','assumptions')): raise ValueError('invalid specification')
        # Exhaustive correctness over the complete byte/key domain.
        domain=bytes(range(256))
        for key in range(256):
            if transform(transform(domain,key,spec['program']),key,spec['program'],True)!=domain: raise ValueError('not reversible')
        record=dict(spec,status='experimental',keygen='uniform byte using secrets.randbelow(256)',input_size='0..4096 bytes',security_claim='none; toy 8-bit key',dependencies=[],test_vector={'key':7,'plaintext':'0001ff','ciphertext':transform(bytes.fromhex('0001ff'),7,spec['program']).hex()})
        digest=hashlib.sha256(packed(record).encode()).hexdigest()
        with self.tx() as db:
            db.execute('INSERT OR IGNORE INTO candidates(spec,digest) VALUES(?,?)',(packed(record),digest))
            cid=db.execute('SELECT id FROM candidates WHERE digest=?',(digest,)).fetchone()[0]
            self.event(db,'candidate_registered',{'candidate':cid})
        return {'candidate':cid,'status':'experimental'}
    def publish(self,candidate,mode='open',parent=None):
        if mode not in ('open','blackbox'): raise ValueError('invalid mode')
        with self.tx() as db:
            last=db.execute('SELECT * FROM challenges ORDER BY id DESC LIMIT 1').fetchone()
            if last and (last['state']!='BREACHED' or parent!=last['id']): raise Denied('replacement requires verified breach of latest version')
            if not last and parent is not None: raise Denied('invalid predecessor')
            row=db.execute('SELECT spec FROM candidates WHERE id=?',(candidate,)).fetchone()
            if not row: raise ValueError('unknown candidate')
            spec=json.loads(row[0]); key=secrets.randbelow(256); plain=secrets.token_bytes(24)
            public={'mode':mode,'category':'plaintext_recovery','ciphertext':transform(plain,key,spec['program']).hex(),'known_plaintext':'00010203','known_ciphertext':transform(bytes(range(4)),key,spec['program']).hex(),'rules':'Recover exact target plaintext. Toy 8-bit key. No external targets.','oracle_budget':0}
            if mode=='open': public['spec']=spec
            cur=db.execute('INSERT INTO challenges(candidate,state,public,secret,parent,published) VALUES(?,?,?,?,?,?)',(candidate,'ACTIVE',packed(public),packed({'plaintext':plain.hex(),'key':key}),parent,time.time()))
            cid=cur.lastrowid
            self.event(db,'published',{'challenge':cid,'parent':parent})
        return {'challenge':cid}
    def submit(self,challenge,plaintext):
        if not isinstance(plaintext,str) or len(plaintext)>8192: raise ValueError('invalid submission')
        try: plaintext=bytes.fromhex(plaintext).hex()
        except ValueError: raise ValueError('hex required')
        with self.tx() as db:
            row=db.execute('SELECT * FROM challenges WHERE id=?',(challenge,)).fetchone()
            if not row: raise ValueError('unknown challenge')
            prior=db.execute('SELECT valid FROM submissions WHERE challenge=? AND evidence=?',(challenge,plaintext)).fetchone()
            if prior: return {'verified':bool(prior[0]),'duplicate':True}
            if row['state']!='ACTIVE': raise Denied('challenge unavailable')
            valid=secrets.compare_digest(plaintext,json.loads(row['secret'])['plaintext'])
            sid=db.execute('INSERT INTO submissions(challenge,evidence,valid) VALUES(?,?,?)',(challenge,plaintext,int(valid))).lastrowid
            self.event(db,'submission_evaluated',{'challenge':challenge,'verified':valid})
            if valid:
                db.execute("UPDATE challenges SET state='BREACHED' WHERE id=?",(challenge,))
                db.execute('INSERT INTO rewards(challenge,submission) VALUES(?,?)',(challenge,sid))
                self.event(db,'breach_confirmed',{'challenge':challenge,'category':'plaintext_recovery','plaintext':plaintext,'verification':'exact comparison with committed target','escalation_authorized':True})
        return {'verified':valid,'duplicate':False}
    def view(self,role):
        if role not in ROLES: raise Denied('unknown role')
        with self.connect() as db:
            latest=db.execute('SELECT id,state,public,parent FROM challenges ORDER BY id DESC LIMIT 1').fetchone()
            challenge=None if not latest else dict(latest)
            if challenge: challenge['public']=json.loads(challenge['public'])
            if role=='adversary': return {'challenge':challenge,'candy':db.execute('SELECT COALESCE(SUM(amount),0) FROM rewards').fetchone()[0]}
            if role=='integrator':
                breaches=[json.loads(r[0]) for r in db.execute("SELECT data FROM events WHERE kind='breach_confirmed'")]
                return {'challenge':challenge,'catalog':[dict(id=r[0],spec=json.loads(r[1])) for r in db.execute('SELECT id,spec FROM candidates')],'verified_failures':breaches}
            if role=='generator': return {'catalog':[dict(id=r[0],spec=json.loads(r[1])) for r in db.execute('SELECT id,spec FROM candidates')],'feedback':[json.loads(r[0]) for r in db.execute('SELECT data FROM feedback')]}
            return {'events':[dict(r) for r in db.execute('SELECT * FROM events')],'findings':[dict(r) for r in db.execute('SELECT * FROM findings')]}
    def tool(self,role,name,args):
        allowed={'generator':{'register'},'integrator':{'publish'},'adversary':{'submit','compute'},'observer':{'record_finding'}}
        if name not in allowed.get(role,set()): raise Denied('tool unavailable')
        if name=='register': return self.register(**args)
        if name=='publish': return self.publish(**args)
        if name=='submit': return self.submit(**args)
        if name=='compute':
            # Executed bounded cryptanalysis, no Python interpreter or filesystem API.
            program=validate(args['program']); known=bytes.fromhex(args['known_plaintext']); cipher=bytes.fromhex(args['known_ciphertext']); target=bytes.fromhex(args['ciphertext'])
            if max(len(known),len(cipher),len(target))>4096: raise ValueError('input too large')
            return {'solutions':[{'plaintext':transform(target,k,program,True).hex(),'key':k} for k in range(256) if transform(known,k,program)==cipher]}
        if name=='record_finding':
            if set(args)!={'challenge','finding'} or not isinstance(args['finding'],str) or len(args['finding'])>8000: raise ValueError('invalid finding')
            with self.tx() as db:
                row=db.execute("SELECT id FROM challenges WHERE id=? AND state='BREACHED'",(args['challenge'],)).fetchone()
                if not row: raise Denied('verified breach required')
                db.execute('INSERT INTO findings(challenge,data) VALUES(?,?)',(args['challenge'],packed(args)))
                db.execute('INSERT INTO feedback(data) VALUES(?)',(packed({'finding':args['finding'],'status':'hypothesis','evidence_challenge':args['challenge']}),))
                self.event(db,'feedback_recorded',{'challenge':args['challenge']})
            return {'recorded':True}
