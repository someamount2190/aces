"""Benchmark ladder: does a new attack tool actually improve attack ability?

Each rung is a construction that differs from its neighbour by one property. For each we record the
strategy that worked, its evaluation count, wall time and oracle queries used. A rung that reports
"survives" is not automatically strong - the last rung is a deliberate false negative.

    python tools/bench.py [--key-bits 32]
"""
import argparse
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aces.core import Engine  # noqa: E402

BASE = {'assumptions': 'toy', 'limitations': 'toy', 'math': 'toy'}

LADDER = [
    ('linear', [['xor_key', 0]], 'gf2_linear', 'affine over GF(2)'),
    ('linear + rotation', [['xor_key', 0], ['rot_bytes', 5], ['rol', 3]], 'gf2_linear',
     'rotation is GF(2)-linear, so still affine'),
    ('causal + non-linear', [['xor_key', 0], ['add_key', 0], ['chain_add', 0]], 'sequential_recovery',
     'carries defeat linearity, causality remains'),
    ('diffusion, linear', [['xor_key', 0], ['rot_bytes', 7], ['rol', 2]], 'gf2_linear',
     'diffusion without non-linearity'),
    ('diffusion + non-linear', [['xor_key', 0], ['add_key', 0], ['chain_add', 0], ['rot_bytes', 7],
                                ['rol', 3]], None, 'both properties, no implemented attack'),
    ('diffusion = identity', [['xor_key', 0], ['add_key', 0], ['rot_bytes', 24]], None,
     'rotation by the block length is the identity: causal in effect, reported non-causal'),
]


def run(name, program, expect, key_bits):
    tmp = tempfile.TemporaryDirectory()
    try:
        engine = Engine(Path(tmp.name) / 'bench.sqlite3', key_bits=key_bits)
        engine.register(dict(BASE, name=name, program=program))
        engine.publish(1)
        started = time.time()
        result = engine.tool('adversary', 'solve', {})
        elapsed = time.time() - started
        with engine.connect() as db:
            queries = db.execute('SELECT COUNT(*) FROM oracle_queries').fetchone()[0]
        return {'name': name, 'expect': expect, 'strategy': result['strategy'],
                'evaluations': result['evaluations'], 'seconds': round(elapsed, 3),
                'queries': queries, 'note': next(r[3] for r in LADDER if r[0] == name)}
    finally:
        tmp.cleanup()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--key-bits', type=int, default=32)
    args = parser.parse_args(argv)

    rows = [run(name, program, expect, args.key_bits) for name, program, expect, _ in LADDER]

    print(f'| construction | expected | observed | evaluations | seconds | oracle queries |')
    print('|---|---|---|---|---|---|')
    correct = 0
    for row in rows:
        observed = row['strategy'] or 'survives'
        expected = row['expect'] or 'survives'
        if observed == expected:
            correct += 1
        print(f"| {row['name']} | {expected} | {observed} | {row['evaluations']} | "
              f"{row['seconds']} | {row['queries']} |")

    print()
    print(f'{correct}/{len(rows)} rungs matched expectation at {args.key_bits} bits')
    missed = [r for r in rows if (r['strategy'] or 'survives') != (r['expect'] or 'survives')]
    for row in missed:
        print(f"  UNEXPECTED {row['name']}: {row['note']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
