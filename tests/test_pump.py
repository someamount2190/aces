import contextlib, io, json, tempfile, unittest
from pathlib import Path

from aces.core import Denied, Engine, WARDEN
from aces.pump import audit, deliver, dispatch, main, status
from aces.verify import is_reversible, transform, validate, verify_plaintext

SPEC = {'name': 'toy xor', 'program': [['xor_key', 0]], 'limitations': '8-bit key brute force',
        'math': 'c = p xor k', 'assumptions': 'none'}


class PumpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'db.sqlite3'
        self.e = Engine(self.path)
        with self.e.tx() as db:
            db.execute("UPDATE control SET state='running'")

    def tearDown(self):
        self.tmp.cleanup()

    def by_role(self, work):
        return {w['role']: w for w in work}

    def register(self):
        work = self.by_role(dispatch(self.e))['generator']
        out = deliver(self.e, work['work_id'], json.dumps({'tool': 'register', 'args': {'spec': SPEC}}))
        self.assertEqual(out['status'], 'ok', out)
        return out['result']['candidate']

    # gate 1 -------------------------------------------------------------------------------
    def test_dispatch_only_relevant_roles(self):
        work = self.by_role(dispatch(self.e))
        self.assertIn('generator', work)          # nothing exists yet
        self.assertIn('observer', work)
        self.assertNotIn('integrator', work)      # no catalog to construct from
        self.assertNotIn('adversary', work)       # no active challenge

    def test_one_pending_item_per_role(self):
        first = dispatch(self.e)
        self.assertEqual(len(first), 2)
        self.assertEqual(dispatch(self.e), [])    # both roles already have work in flight
        with self.assertRaises(Denied):
            self.e.claim_work('generator', 0)

    # gate 2 -------------------------------------------------------------------------------
    def test_publication_requires_a_real_candidate(self):
        with self.assertRaises(ValueError):
            self.e.publish(999)
        cid = self.register()
        out = self.by_role(dispatch(self.e))['integrator']
        published = deliver(self.e, out['work_id'],
                            json.dumps({'tool': 'publish', 'args': {'candidate': cid}}))
        self.assertEqual(published['status'], 'ok', published)
        self.assertEqual(self.e.view('adversary')['challenge']['state'], 'ACTIVE')

    def test_keyless_candidate_cannot_be_published(self):
        # defect 4: a construction that ignores the key is invertible from public information,
        # so it would award candy for no cryptanalysis.
        keyless = dict(SPEC, program=[['xor', 5]])
        self.assertTrue(is_reversible(keyless['program']))
        cid = self.e.register(keyless)['candidate']
        with self.assertRaises(Denied):
            self.e.publish(cid)

    # gates 3 and 4 ------------------------------------------------------------------------
    def cycle(self):
        cid = self.register()
        integrator = self.by_role(dispatch(self.e))['integrator']
        deliver(self.e, integrator['work_id'],
                json.dumps({'tool': 'publish', 'args': {'candidate': cid, 'mode': 'open'}}))
        return cid

    def attack(self):
        public = self.e.view('adversary')['challenge']['public']
        args = {'program': public['spec']['program'],
                'known_plaintext': public['known_plaintext'],
                'known_ciphertext': public['known_ciphertext'],
                'ciphertext': public['ciphertext']}
        return self.e.tool('adversary', 'compute', args)['solutions'][0]['plaintext']

    def test_invalid_attack_earns_nothing(self):
        cid = self.cycle()
        adversary = self.by_role(dispatch(self.e))['adversary']
        out = deliver(self.e, adversary['work_id'],
                      json.dumps({'tool': 'submit', 'args': {'challenge': cid, 'plaintext': '00'}}))
        self.assertEqual(out['status'], 'ok')
        self.assertFalse(out['result']['verified'])
        self.assertEqual(self.e.view('adversary')['candy'], 0)
        self.assertEqual(self.e.view('adversary')['challenge']['state'], 'ACTIVE')

    def test_verified_attack_pays_exactly_once(self):
        cid = self.cycle()
        adversary = self.by_role(dispatch(self.e))['adversary']
        plain = self.attack()
        out = deliver(self.e, adversary['work_id'],
                      json.dumps({'tool': 'submit', 'args': {'challenge': cid, 'plaintext': plain}}))
        self.assertTrue(out['result']['verified'])
        self.assertEqual(self.e.view('adversary')['candy'], 1)
        self.assertEqual(self.e.view('adversary')['challenge']['state'], 'BREACHED')
        with self.e.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM rewards').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM submissions').fetchone()[0], 1)
            kinds = [r[0] for r in db.execute('SELECT kind FROM events')]
        self.assertIn('breach_confirmed', kinds)
        # exactly-once: same evidence again is a duplicate verdict, never a second reward
        self.assertTrue(self.e.submit(cid, plain)['duplicate'])
        with self.e.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM rewards').fetchone()[0], 1)

    # gate 5 -------------------------------------------------------------------------------
    def test_delivery_is_idempotent(self):
        work = self.by_role(dispatch(self.e))['generator']
        first = deliver(self.e, work['work_id'], '{"idle": true}')
        self.assertEqual(first['status'], 'idle')
        self.assertEqual(deliver(self.e, work['work_id'], '{"idle": true}')['status'], 'already_done')
        self.assertEqual(self.e.session('generator')['turns'], 1)

    def test_malformed_reply_charges_one_turn_and_records_the_type(self):
        work = self.by_role(dispatch(self.e))['generator']
        out = deliver(self.e, work['work_id'], 'not json at all')
        self.assertEqual(out['error'], 'SchemaViolation')
        self.assertEqual(self.e.session('generator')['turns'], 1)
        item = self.e.work_item(work['work_id'])
        self.assertEqual((item['status'], item['error_type']), ('DONE', 'SchemaViolation'))

    def test_tool_not_available_to_role_is_refused(self):
        work = self.by_role(dispatch(self.e))['generator']
        out = deliver(self.e, work['work_id'],
                      json.dumps({'tool': 'publish', 'args': {'candidate': 1}}))
        self.assertEqual(out['error'], 'ToolDenied')
        self.assertEqual(self.e.view('adversary')['challenge'], None)

    def test_idle_role_sleeps_until_something_new(self):
        work = self.by_role(dispatch(self.e))
        deliver(self.e, work['generator']['work_id'], '{"idle": true}')
        deliver(self.e, work['observer']['work_id'], '{"idle": true}')
        # defect 1: an idle agent must not be polled again until a domain event it did not cause
        self.assertEqual(dispatch(self.e), [])

    # gate 6 -------------------------------------------------------------------------------
    def test_restart_preserves_state_without_duplication(self):
        cid = self.cycle()
        plain = self.attack()
        self.assertTrue(self.e.submit(cid, plain)['verified'])
        reopened = Engine(self.path)
        self.assertEqual(reopened.view('adversary')['candy'], 1)
        self.assertEqual(reopened.view('adversary')['challenge']['state'], 'BREACHED')
        with reopened.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM rewards').fetchone()[0], 1)

    def test_stale_dispatch_is_abandoned_not_retried(self):
        dispatch(self.e)
        self.assertEqual(self.e.abandon_stale(0), 2)   # generator + observer were in flight
        roles = [w['role'] for w in dispatch(self.e)]
        self.assertIn('generator', roles)              # a new item, not a resurrected one

    def test_sanitized_failure_hides_the_recovered_secret(self):
        cid = self.cycle()
        plain = self.attack()
        self.e.submit(cid, plain)
        failures = self.e.view('integrator')['verified_failures']
        self.assertEqual(len(failures), 1)
        self.assertNotIn('plaintext', failures[0])
        self.assertNotIn(plain, json.dumps(self.e.view('integrator')))

    # CLI ----------------------------------------------------------------------------------
    def test_cli_dispatch_and_status(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(['--db', str(self.path), 'dispatch'])
            main(['--db', str(self.path), 'status'])
        lines = buf.getvalue().strip().split('\n')
        self.assertGreaterEqual(len(lines), 1)
        self.assertIn('generator', buf.getvalue())

    # the warden ---------------------------------------------------------------------------
    def test_ledger_records_the_exact_projection(self):
        work = self.by_role(dispatch(self.e))
        with self.e.connect() as db:
            rows = {r['role']: json.loads(r['projection']) for r in db.execute('SELECT * FROM dispatches')}
        self.assertEqual(set(rows), {'generator', 'observer'})
        self.assertEqual(rows['generator'], self.e.view('generator'))

    def test_warden_needs_a_ledger_before_it_is_called(self):
        self.assertEqual(audit(self.e), [])
        dispatch(self.e)
        self.assertEqual(audit(self.e)[0]['role'], WARDEN)

    def test_warden_reports_a_leak_and_holds_no_authority(self):
        self.cycle()                                  # produces a publication and a ledger
        item = audit(self.e)[0]
        self.assertIn('dispatches', json.loads(item['prompt'])['environment'])
        out = deliver(self.e, item['work_id'], json.dumps(
            {'tool': 'report_leak',
             'args': {'channel': 'adversary_projection', 'severity': 'high',
                      'evidence': 'environment.challenge.public.spec present in blackbox mode'}}))
        self.assertEqual(out['status'], 'ok', out)
        self.assertEqual(status(self.e)['leaks'], 1)
        # a fresh pass: the warden still cannot touch the experiment itself
        again = audit(self.e)
        self.assertTrue(again)
        blocked = deliver(self.e, again[0]['work_id'],
                          json.dumps({'tool': 'publish', 'args': {'candidate': 1}}))
        self.assertEqual(blocked['error'], 'ToolDenied')

    def test_no_projection_carries_the_target_secret(self):
        """The invariant the Warden audits, asserted deterministically so a leak cannot ship."""
        cid = self.cycle()
        plain = self.attack()
        self.e.submit(cid, plain)
        with self.e.connect() as db:
            secret = json.loads(db.execute('SELECT secret FROM challenges WHERE id=?', (cid,)).fetchone()[0])
            rows = db.execute('SELECT role,projection FROM dispatches').fetchall()
        self.assertTrue(rows)
        for r in rows:
            if r['role'] == 'observer':
                continue                      # supervisory: sees the breach evidence by design
            self.assertNotIn(secret['plaintext'], r['projection'], f'secret leaked to {r["role"]}')

    def test_verify_helpers(self):
        self.assertTrue(is_reversible([['xor_key', 0]]))
        self.assertTrue(is_reversible([['add', 1], ['rol', 3], ['xor', 81]]))
        self.assertEqual(transform(b'\x00', 0, [['xor_key', 0]]), b'\x00')
        self.assertTrue(verify_plaintext('00ff', '00FF'))
        self.assertFalse(verify_plaintext('00ff', '00fe'))
        with self.assertRaises(ValueError):
            validate([['xor', 999]])


if __name__ == '__main__':
    unittest.main()
