"""Create or resume a run database with the coordinator running.

    python tools/new_run.py runs/run-001.sqlite3
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aces.core import Engine  # noqa: E402


def main(path):
    engine = Engine(path)
    with engine.tx() as db:
        db.execute("UPDATE control SET state='running'")
    print(f'control=running db={path}')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'runs/run-001.sqlite3')
