"""Create or resume a run database with the coordinator running.

    python tools/new_run.py runs/run-001.sqlite3 [--key-bits 32]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aces.core import Engine  # noqa: E402
from aces.verify import DEFAULT_KEY_BITS  # noqa: E402


def main(path, key_bits=DEFAULT_KEY_BITS):
    engine = Engine(path, key_bits=key_bits)
    with engine.tx() as db:
        db.execute("UPDATE control SET state='running'")
    print(f'control=running db={path} key_bits={key_bits}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', nargs='?', default='runs/run-001.sqlite3')
    parser.add_argument('--key-bits', type=int, default=DEFAULT_KEY_BITS)
    args = parser.parse_args()
    main(args.path, args.key_bits)
