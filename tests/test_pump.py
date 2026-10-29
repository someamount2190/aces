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
        self.e = Engine(self.path, key_bits=16)
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
        """The structural attack: one known pair, 33 evaluations, no enumeration."""
        return self.e.tool('adversary', 'solve', {})['plaintext']

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
                      json.dumps({'tool': 'submit', 'args': {'challenge': cid, 'plaintext': plain,
                                                             'method': 'gf2_linear',
                                                             'detail': 'exhaustive 8-bit key scan on the known pair'}}))
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
        self.assertTrue(self.e.submit(cid, plain, method='gf2_linear')['verified'])
        reopened = Engine(self.path, key_bits=16)
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
        self.e.submit(cid, plain, method='gf2_linear')
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
        self.e.submit(cid, plain, method='gf2_linear')
        with self.e.connect() as db:
            secret = json.loads(db.execute('SELECT secret FROM challenges WHERE id=?', (cid,)).fetchone()[0])
            rows = db.execute('SELECT role,projection FROM dispatches').fetchall()
        self.assertTrue(rows)
        for r in rows:
            if r['role'] == 'observer':
                continue                      # supervisory: sees the breach evidence by design
            self.assertNotIn(secret['plaintext'], r['projection'], f'secret leaked to {r["role"]}')

    def test_catalog_exposes_only_the_contract_fields(self):
        """The run-001 defect: bookkeeping fields invited a spec the tool must reject."""
        fields = {'name', 'program', 'limitations', 'math', 'assumptions'}
        cid = self.register()
        self.assertEqual(set(self.e.view('generator')['catalog'][0]['spec']), fields)
        work = self.by_role(dispatch(self.e))['integrator']
        deliver(self.e, work['work_id'],
                json.dumps({'tool': 'publish', 'args': {'candidate': cid, 'mode': 'open'}}))
        self.assertEqual(set(self.e.view('adversary')['challenge']['public']['spec']), fields)

    def test_observer_receives_only_events_since_its_cursor(self):
        work = self.by_role(dispatch(self.e))['observer']
        deliver(self.e, work['work_id'], '{"idle": true}')
        cursor = self.e.session('observer')['cursor']
        ids = [e['id'] for e in self.e.view('observer')['events']]
        self.assertTrue(all(i > cursor for i in ids), ids)

    def test_recover_by_work_id_leaves_other_dispatches_alone(self):
        """run-002: recover --minutes 0 swept four live items when one was meant."""
        work = self.by_role(dispatch(self.e))
        target = work['generator']['work_id']
        self.assertEqual(self.e.abandon_work(target), 1)
        self.assertEqual(self.e.work_item(target)['status'], 'ABANDONED')
        self.assertEqual([w['role'] for w in self.e.pending_work()], ['observer'])
        self.assertEqual(self.e.abandon_work(target), 0)   # idempotent, not an error

    def test_correct_answer_without_a_tool_trace_is_not_a_breach(self):
        """run 002: a right answer arrived with no compute behind it. Right is not enough."""
        cid = self.cycle()
        plain = self.attack()
        with self.e.tx() as db:
            db.execute('DELETE FROM derivations')      # simulate solving by another route
        out = self.e.submit(cid, plain)
        self.assertFalse(out['verified'])
        self.assertEqual(out['reason'], 'no_derivation_trace')
        self.assertEqual(self.e.view('adversary')['candy'], 0)
        self.assertEqual(self.e.view('adversary')['challenge']['state'], 'ACTIVE')
        # rejection does not consume the challenge: a traced answer still counts
        self.attack()
        self.assertTrue(self.e.submit(cid, plain, method='gf2_linear')['verified'])

    def test_breach_records_how_it_was_reached(self):
        cid = self.cycle()
        self.e.submit(cid, self.attack(), method='gf2_linear',
                      detail='exhaustive key scan against the published pair')
        with self.e.connect() as db:
            event = json.loads(db.execute(
                "SELECT data FROM events WHERE kind='breach_confirmed'").fetchone()[0])
            methods = [dict(r) for r in db.execute('SELECT method,detail FROM methods')]
        self.assertEqual(event['method'], 'gf2_linear')
        self.assertEqual(len(methods), 1)
        self.assertIn('exhaustive key scan', methods[0]['detail'])

    def test_breach_requires_a_named_verifiable_method(self):
        """An answer with no method teaches the Generator nothing, so it is not a breach."""
        cid = self.cycle()
        plain = self.attack()
        self.assertEqual(self.e.submit(cid, plain)['reason'], 'no_method')
        self.assertEqual(self.e.submit(cid, plain, method='divination')['reason'], 'unverified_method')
        self.assertEqual(self.e.view('adversary')['candy'], 0)
        self.assertEqual(self.e.view('adversary')['challenge']['state'], 'ACTIVE')

    def test_named_method_must_match_the_derivation(self):
        cid = self.cycle()
        plain = self.attack()          # this derivation came from the structural attack
        out = self.e.submit(cid, plain, method='known_plaintext_key_search')
        self.assertEqual(out['reason'], 'method_mismatch')

    def test_enumeration_is_not_a_breach(self):
        """Trying every key is labour. Finding structure is knowledge, and only that pays."""
        cid = self.cycle()
        public = self.e.view('adversary')['challenge']['public']
        found = self.e.tool('adversary', 'compute', {
            'program': public['spec']['program'],
            'known_plaintext': public['known_plaintext'],
            'known_ciphertext': public['known_ciphertext'],
            'ciphertext': public['ciphertext']})['solutions']
        self.assertTrue(found)                     # the search did find the key
        out = self.e.submit(cid, found[0]['plaintext'], method='known_plaintext_key_search')
        self.assertEqual(out['reason'], 'enumeration_is_not_a_breach')
        self.assertEqual(self.e.view('adversary')['candy'], 0)
        self.assertEqual(self.e.view('adversary')['challenge']['state'], 'ACTIVE')

    def test_a_non_linear_construction_resists_the_linear_attack(self):
        nl = dict(SPEC, name='nonlinear', program=[['xor_key', 0], ['chain_add', 0], ['add_key', 0]])
        cid = self.e.register(nl)['candidate']
        self.e.publish(cid)
        out = self.e.tool('adversary', 'solve', {})
        self.assertIsNone(out['strategy'])
        self.assertEqual(self.e.view('adversary')['challenge']['state'], 'ACTIVE')

    def test_generator_learns_which_method_broke_each_challenge(self):
        cid = self.cycle()
        self.e.submit(cid, self.attack(), method='gf2_linear')
        self.assertEqual(self.e.view('generator')['failures'],
                         [{'challenge': cid, 'method': 'gf2_linear'}])

    def test_rejection_blocks_publication(self):
        """The Integrator's gate binds: a refused candidate cannot be published at all."""
        cid = self.register()
        out = self.e.reject(cid, 'no diffusion between bytes; a 256-trial scan is the whole attack')
        self.assertEqual(out['rejected'], cid)
        with self.assertRaises(Denied):
            self.e.publish(cid)
        work = self.by_role(dispatch(self.e))
        if 'integrator' in work:
            deny = deliver(self.e, work['integrator']['work_id'],
                           json.dumps({'tool': 'publish', 'args': {'candidate': cid}}))
            self.assertEqual(deny['error'], 'ToolDenied')
        self.assertEqual(self.e.view('adversary')['challenge'], None)

    def test_rejection_reaches_the_generator(self):
        cid = self.register()
        self.e.reject(cid, 'no diffusion between bytes', 'byte-local, 256 trials')
        rejections = self.e.view('generator')['rejections']
        self.assertEqual(rejections[0]['candidate'], cid)
        self.assertIn('no diffusion', rejections[0]['reason'])

    def test_integrator_sees_a_measured_assessment(self):
        self.register()
        entry = self.e.view('integrator')['catalog'][0]
        # 16-bit test engine: the causal bound (2 key bytes x 256) beats the 2^16 key space
        self.assertEqual(entry['assessment']['known_plaintext_work'], 512)
        self.assertEqual(entry['assessment']['key_bits'], 16)
        self.assertTrue(entry['assessment']['causal'])
        self.assertTrue(entry['assessment']['byte_local'])     # this spec has no chain op
        self.assertGreaterEqual(entry['assessment']['key_ops'], 1)

    def test_every_program_in_the_op_set_is_causal(self):
        """RUN-007: the Generator proved a 2^10 key recovery for every construction, and stopped."""
        from aces.verify import is_causal
        self.assertTrue(is_causal([['xor_key', 0], ['rol', 3], ['chain_add', 0]]))
        self.assertTrue(is_causal([['xor', 1], ['chain_xor', 0], ['add_key', 0]]))
        self.assertTrue(is_causal([['chain_add', 0], ['chain_xor', 0], ['rol', 7]]))

    def test_chain_ops_mix_across_positions_and_invert(self):
        from aces.verify import is_reversible, transform
        program = [['xor_key', 0], ['chain_add', 0], ['rol', 3], ['chain_xor', 0], ['add_key', 0]]
        self.assertTrue(is_reversible(program))
        data = bytes(range(24))
        for key in (0, 1, 0x1234, 0xFFFF):
            self.assertEqual(transform(transform(data, key, program), key, program, True), data)
        # a change in byte 0 must reach later positions, or the map is still byte-local
        plain = bytes(8)
        changed = bytes([1]) + bytes(7)
        self.assertNotEqual(transform(plain, 7, [['chain_add', 0]]),
                            transform(changed, 7, [['chain_add', 0]]))

    def test_a_mixing_candidate_is_not_byte_local(self):
        cid = self.e.register(dict(SPEC, name='mixing', program=[['xor_key', 0], ['chain_add', 0],
                                                                 ['rol', 3], ['add_key', 0]]))['candidate']
        entry = [e for e in self.e.view('integrator')['catalog'] if e['id'] == cid][0]
        self.assertFalse(entry['assessment']['byte_local'])

    def test_compute_searches_the_whole_16_bit_space(self):
        cid = self.cycle()
        public = self.e.view('adversary')['challenge']['public']
        solutions = self.e.tool('adversary', 'compute', {
            'program': public['spec']['program'],
            'known_plaintext': public['known_plaintext'],
            'known_ciphertext': public['known_ciphertext'],
            'ciphertext': public['ciphertext']})['solutions']
        self.assertEqual(len(solutions), 1)
        self.assertTrue(0 <= solutions[0]['key'] < 65536)

    def test_only_the_integrator_may_reject(self):
        cid = self.register()
        out = deliver(self.e, self.by_role(dispatch(self.e))['generator']['work_id'],
                      json.dumps({'tool': 'reject', 'args': {'candidate': cid, 'reason': 'no'}}))
        self.assertEqual(out['error'], 'ToolDenied')

    def test_a_32_bit_key_is_out_of_reach_of_the_search(self):
        """The default width: compute exhausts its budget, finds nothing, and says so."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        wide = Engine(Path(tmp.name) / 'wide.sqlite3')      # default 32-bit key
        wide.register(SPEC)
        wide.publish(1)
        public = wide.view('adversary')['challenge']['public']
        out = wide.tool('adversary', 'compute', {
            'program': public['spec']['program'],
            'known_plaintext': public['known_plaintext'],
            'known_ciphertext': public['known_ciphertext'],
            'ciphertext': public['ciphertext']})
        self.assertEqual(out['solutions'], [])
        self.assertTrue(out['exhausted'])
        self.assertEqual(out['searched'], 1 << 20)
        self.assertEqual(wide.view('adversary')['candy'], 0)
        self.assertEqual(wide.view('integrator')['catalog'][0]['assessment']['key_bits'], 32)

    def test_diffusion_breaks_causality_but_not_linearity(self):
        """Diffusion alone is not an escape: rot_bytes is GF(2)-linear, so xor-only still falls."""
        from aces.verify import is_causal, is_gf2_linear
        both = [['xor_key', 0], ['chain_add', 0], ['rot_bytes', 5], ['add_key', 0], ['rol', 3]]
        self.assertFalse(is_causal(both))
        self.assertFalse(is_gf2_linear(both))          # survives the sequential attack and the linear one
        linear_only = [['xor_key', 0], ['rot_bytes', 5], ['rol', 3]]
        self.assertFalse(is_causal(linear_only))
        self.assertTrue(is_gf2_linear(linear_only))    # diffusion without an addition is still affine

    def test_a_diffusion_construction_reads_as_the_full_key_space(self):
        spec = dict(SPEC, name='diffused',
                    program=[['xor_key', 0], ['chain_add', 0], ['rot_bytes', 5],
                             ['add_key', 0], ['rol', 3]])
        cid = self.e.register(spec)['candidate']
        entry = [e for e in self.e.view('integrator')['catalog'] if e['id'] == cid][0]
        self.assertFalse(entry['assessment']['causal'])
        self.assertEqual(entry['assessment']['known_plaintext_work'], 65536)   # 16-bit test engine

    def test_rot_bytes_inverts_and_moves_data_both_ways(self):
        from aces.verify import transform
        data = bytes(range(24))
        cipher = transform(data, b'\x00\x01', [['rot_bytes', 5], ['xor_key', 0]])
        self.assertEqual(transform(cipher, b'\x00\x01', [['rot_bytes', 5], ['xor_key', 0]], True), data)
        self.assertNotEqual(data[:4], transform(data, b'\x00\x01', [['rot_bytes', 5]])[:4])

    def test_reaching_for_the_system_instead_of_the_literature_is_recorded(self):
        """run-008: the Adversary tried to research the project itself. The record should show it."""
        work = self.by_role(dispatch(self.e))['generator']
        deliver(self.e, work['work_id'], json.dumps(
            {'tool': 'register', 'args': {'spec': dict(SPEC, name='ACES_Prototype probe')}}))
        with self.e.connect() as db:
            rows = [json.loads(r[0]) for r in db.execute(
                "SELECT data FROM events WHERE kind='research_out_of_bounds'")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['role'], 'generator')
        self.assertIn('aces_', rows[0]['tokens'])

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



