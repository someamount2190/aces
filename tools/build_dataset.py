"""Turn the run databases into role-specific supervised data.

Every completed dispatch is already a training triple: the role's charter is the system prompt, the
packed projection handed to the session is the user turn, and the answer the session gave is the
target. `work_items` records the answer and `dispatches` records the projection, so the join
reconstructs exactly what each session saw.

    python tools/build_dataset.py [--runs runs] [--out runs/dataset]
"""
import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aces.prompts import CHARTERS  # noqa: E402
from aces.pump import build_prompt  # noqa: E402


def rows(db):
    """Completed work items with the projection they were dispatched with."""
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("""
            SELECT w.id, w.role, w.answer, d.projection
            FROM work_items w JOIN dispatches d ON d.work_id = w.id
            WHERE w.status = 'DONE' AND w.outcome = 'tool_executed'
              AND d.projection IS NOT NULL AND w.answer IS NOT NULL AND w.answer != ''
            ORDER BY w.created
        """).fetchall()


def triples(db):
    out, turns = [], {}
    for row in rows(db):
        role = row['role']
        if role not in CHARTERS:
            continue
        try:
            view = json.loads(row['projection'])
            json.loads(row['answer'])          # the target must itself be valid JSON
        except (ValueError, TypeError):
            continue
        turns[role] = turns.get(role, 0) + 1
        out.append({'role': role, 'run': Path(db).stem,
                    'messages': [{'role': 'system', 'content': CHARTERS[role]},
                                 {'role': 'user', 'content': build_prompt(role, view, turns[role])},
                                 {'role': 'assistant', 'content': row['answer'].strip()}]})
    return out


def main(runs='runs', out='runs/dataset'):
    runs = Path(runs)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    everything, by_role = [], {}
    for db in sorted(runs.glob('run-*.sqlite3')):
        found = triples(str(db))
        everything += found
        for t in found:
            by_role.setdefault(t['role'], []).append(t)
    (out / 'all.jsonl').write_text(''.join(json.dumps(t) + '\n' for t in everything), encoding='utf-8')
    for role, items in sorted(by_role.items()):
        (out / f'{role}.jsonl').write_text(''.join(json.dumps(t) + '\n' for t in items), encoding='utf-8')
    print(f'{len(everything)} triples from {len(list(runs.glob("run-*.sqlite3")))} runs -> {out}')
    for role, items in sorted(by_role.items()):
        print(f'  {role:10s} {len(items):4d}')
    if not everything:
        print('  (nothing yet: run some cycles first)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runs', default='runs')
    parser.add_argument('--out', default='runs/dataset')
    args = parser.parse_args()
    main(args.runs, args.out)
