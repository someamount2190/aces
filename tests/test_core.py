import concurrent.futures, json, tempfile, unittest
from pathlib import Path
from aces.core import Engine, Denied, transform, validate
from aces.runtime import Coordinator

SPEC={'name':'toy xor','program':[['xor_key',0]],'limitations':'8-bit key brute force','math':'c=p xor k','assumptions':'none'}
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'db'; self.e=Engine(self.path)
        self.cid=self.e.tool('generator','register',{'spec':SPEC})['candidate']
    def tearDown(self): self.tmp.cleanup()
    def publish(self): return self.e.tool('integrator','publish',{'candidate':self.cid})['challenge']
    def solve(self):
        ch=self.e.view('adversary')['challenge']; public=ch['public']
        args={k:public[k] for k in ('known_plaintext','known_ciphertext','ciphertext')}; args['program']=public['spec']['program']
        return ch['id'],self.e.tool('adversary','compute',args)['solutions'][0]['plaintext']
    def test_correctness(self):
        for prog in ([['add_key',0],['rol',3],['xor',81]],[['xor_key',0]]):
            for k in range(256): self.assertEqual(bytes(range(256)),transform(transform(bytes(range(256)),k,prog),k,prog,True))
    def test_blind_interfaces(self):
        self.publish()
        for role in ('integrator','adversary'):
            other='adversary' if role=='integrator' else 'integrator'
            self.assertNotIn(other,json.dumps(self.e.view(role)))
            with self.assertRaises(Denied): self.e.tool(role,'record_finding',{})
        self.assertNotIn('secret',self.e.view('adversary')['challenge'])
    def test_no_escalation_invalid(self):
        cid=self.publish()
        for _ in range(3):
            with self.assertRaises(Denied): self.e.publish(self.cid,parent=cid)
        self.assertFalse(self.e.submit(cid,'00')['verified'])
        self.assertEqual(self.e.view('adversary')['candy'],0)
        self.assertEqual(self.e.view('integrator')['verified_failures'],[])
    def test_cycle_duplicate_restart_feedback(self):
        cid=self.publish(); cid,plain=self.solve()
        self.assertTrue(self.e.submit(cid,plain)['verified'])
        self.assertTrue(self.e.submit(cid,plain)['duplicate'])
        self.assertEqual(self.e.view('adversary')['candy'],1)
        self.e=Engine(self.path)
        self.assertEqual(self.e.view('adversary')['candy'],1)
        self.e.tool('observer','record_finding',{'challenge':cid,'finding':'Known pair permits 256-key enumeration.'})
        self.assertEqual(len(self.e.view('generator')['feedback']),1)
        self.e.publish(self.cid,parent=cid)
        self.assertEqual(self.e.view('adversary')['challenge']['state'],'ACTIVE')
    def test_concurrent_rewards(self):
        self.publish(); cid,plain=self.solve()
        with concurrent.futures.ThreadPoolExecutor(8) as pool: list(pool.map(lambda _:self.e.submit(cid,plain),range(16)))
        self.assertEqual(self.e.view('adversary')['candy'],1)
        self.assertEqual(len(self.e.view('integrator')['verified_failures']),1)
    def test_vm_rejects_io_and_unbounded_code(self):
        for p in ([["import",0]],[["open",0]],[["xor",True]],[["xor",1]]*33):
            with self.assertRaises(ValueError): validate(p)
        with self.assertRaises(Denied): self.e.tool('adversary','shell',{'cmd':'cat /etc/passwd'})
    def test_active_restart(self):
        self.publish(); before=self.e.view('adversary'); self.assertEqual(before,Engine(self.path).view('adversary'))
    def test_suspend_never_unlocks(self):
        cid=self.publish()
        with self.e.tx() as db: db.execute("UPDATE control SET state='stopped'")
        with self.assertRaises(Denied): self.e.publish(self.cid,parent=cid)
    def test_mock_provider_sessions(self):
        class Mock:
            def complete(s,role,messages):
                s.calls.append((role,messages)); return '{"idle":true}'
            calls=[]
        c=Coordinator(self.e,{'agents':{},'max_turns_per_agent':2}); c.provider=Mock()
        with self.e.tx() as db: db.execute("UPDATE control SET state='running'")
        c.tick()
        with self.e.connect() as db:
            self.assertEqual(db.execute("SELECT turns FROM sessions WHERE role='generator'").fetchone()[0],1)
        self.assertTrue(all(messages[0]['role']=='system' for _,messages in c.provider.calls))
    def test_durable_work_item_charges_once(self):
        work=self.e.begin_work('generator',17)
        self.assertEqual(work,self.e.begin_work('generator',17))
        self.assertTrue(self.e.finish_work(work,'{}','idle',messages=[{'role':'user','content':'{}'}]))
        self.assertFalse(self.e.finish_work(work,'{}','idle'))
        with self.e.connect() as db:
            row=db.execute("SELECT turns,cursor,messages FROM sessions WHERE role='generator'").fetchone()
            item=db.execute('SELECT status FROM work_items WHERE id=?',(work,)).fetchone()
        self.assertEqual((row['turns'],row['cursor']), (1,17))
        self.assertEqual(item['status'],'DONE')
if __name__=='__main__': unittest.main()
