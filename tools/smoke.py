"""End-to-end smoke: drive complete cycles through the CLI with scripted role answers.

This is the harness the orchestrator uses. Replace `Scripted.answer` with the reply from a real
session and the same loop runs the actual experiment; nothing else changes.

    python tools/smoke.py
"""
import json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aces.core import Engine  # noqa: E402

SPEC = {
    'name': 'Fold-3',
    'program': [['xor_key', 0], ['rol', 3], ['add', 11], ['xor', 90]],
    'limitations': 'Byte-wise; no diffusion across a block. The 8-bit key is exhaustible.',
    'math': 'Composition of bijections on Z/256; the inverse applies inverse ops in reverse order.',
    'assumptions': 'Key is a single byte; constants are public.',
}


def cli(*args):
    out = subprocess.run([sys.executable, '-m', 'aces.pump', *args], cwd=ROOT,
                         capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        raise SystemExit(f'pump failed: {out.stderr[-800:]}')
    return json.loads(out.stdout)


class Scripted:
    """A competent role, answering only from its projection."""

    def __init__(self):
        self.solution = None
        self.finding_made = False

    def answer(self, item, status):
        env = json.loads(item['prompt'])['environment']
        role = item['role']

        if role == 'generator':
            return {'tool': 'register', 'args': {'spec': SPEC}} if not env['catalog'] else {'idle': True}

        if role == 'integrator':
            challenge = env['challenge']
            if challenge is None:
                return {'tool': 'publish', 'args': {'candidate': env['catalog'][0]['id'], 'mode': 'open'}}
            if challenge['state'] == 'BREACHED':
                return {'tool': 'publish', 'args': {'candidate': env['catalog'][-1]['id'],
                                                    'mode': 'open', 'parent': challenge['id']}}
            return {'idle': True}

        if role == 'adversary':
            challenge = env['challenge']
            if not challenge or challenge['state'] != 'ACTIVE':
                return {'idle': True}
            if self.solution:
                plaintext, self.solution = self.solution, None
                return {'tool': 'submit', 'args': {'challenge': challenge['id'], 'plaintext': plaintext}}
            public = challenge['public']
            return {'tool': 'compute', 'args': {'program': public['spec']['program'],
                                                'known_plaintext': public['known_plaintext'],
                                                'known_ciphertext': public['known_ciphertext'],
                                                'ciphertext': public['ciphertext']}}

        if role == 'observer':
            if not self.finding_made and status['candy'] > 0:
                for event in env['events']:
                    if event['kind'] == 'breach_confirmed':
                        self.finding_made = True
                        return {'tool': 'record_finding',
                                'args': {'challenge': json.loads(event['data'])['challenge'],
                                         'finding': 'A single byte-wise key lets the known pair be '
                                                    'enumerated in 256 trials; the composition adds no '
                                                    'diffusion across the block.'}}
            return {'idle': True}

        return {'idle': True}


def main():
    db = str(Path(tempfile.mkdtemp(prefix='aces-smoke-')) / 'smoke.sqlite3')
    engine = Engine(db)
    with engine.tx() as conn:
        conn.execute("UPDATE control SET state='running'")

    driver = Scripted()
    for tick in range(1, 16):
        work = cli('--db', db, 'dispatch')
        if not work:
            print(f'tick {tick}: nothing to do')
            break
        status = cli('--db', db, 'status')

        for item in work:
            action = driver.answer(item, status)
            result = cli('--db', db, 'deliver', '--work-id', item['work_id'],
                         '--answer', json.dumps(action))
            if result.get('error'):
                print(f'tick {tick}: {item["role"]:10} ERROR {result["error"]}: {result.get("detail")}')
                continue
            print(f'tick {tick}: {item["role"]:10} {result["status"]:12} {action.get("tool", "idle")}')
            if result.get('tool') == 'compute' and result['result']['solutions']:
                driver.solution = result['result']['solutions'][0]['plaintext']

        final = cli('--db', db, 'status')
        if final['candy'] and final['findings'] and (final['challenge'] or {}).get('parent') is not None:
            print(f'\ncycle complete after {tick} ticks')
            break

    print(json.dumps(cli('--db', db, 'status'), indent=2))
    print(f'database: {db}')


if __name__ == '__main__':
    main()
