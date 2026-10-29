"""The dispatch pump. The coordinator never calls a model.

One tick:
    python -m aces.pump dispatch --db live.sqlite3        → work for each role that has relevant work
    ...send each prompt to that role's persistent session...
    python -m aces.pump deliver --db live.sqlite3 --work-id ID --answer '{"tool":...}'

`RoleDriver` is the seam: a subagent session today, an HTTP provider tomorrow, a script in tests.
"""
import argparse, json, sys

from .core import ROLES, Denied, Engine, packed
from .prompts import TASK


# ---- scheduling --------------------------------------------------------------------------------

def relevant(role, view, control):
    """Does this role have anything to do? Waiting is a first-class state, not a failed tick."""
    if control != 'running':
        return False
    if role == 'integrator':
        return bool(view['catalog']) and (not view['challenge'] or view['challenge']['state'] != 'ACTIVE')
    if role == 'adversary':
        return bool(view['challenge']) and view['challenge']['state'] == 'ACTIVE'
    return True


def awake(role, session, last_domain_event):
    """Generator and Observer sleep until something they did not cause has happened."""
    if role in ('generator', 'observer') and session['turns'] and session['cursor'] == last_domain_event:
        return False
    return True


def build_prompt(role, view, turn):
    body = {'role': role, 'turn': turn, 'task': TASK[role], 'environment': view,
            'respond': 'one JSON object: {"tool":"...","args":{...}} or {"idle":true}'}
    return packed(body)


# ---- commands ----------------------------------------------------------------------------------

def dispatch(engine, max_turns=50):
    control = engine.control_state()
    last = engine.last_domain_event()
    out = []
    for role in ROLES:
        view = engine.view(role)
        if not relevant(role, view, control):
            continue
        session = engine.session(role)
        if session['turns'] >= max_turns:
            continue
        if not awake(role, session, last):
            continue
        if engine.pending_work(role):
            continue
        try:
            work_id = engine.claim_work(role, last)
        except Denied:
            continue
        out.append({'work_id': work_id, 'role': role, 'turn': session['turns'] + 1,
                    'prompt': build_prompt(role, view, session['turns'] + 1)})
    return out


def deliver(engine, work_id, answer):
    item = engine.work_item(work_id)
    if item is None:
        return {'status': 'unknown_work_id', 'work_id': work_id}
    if item['status'] != 'PENDING':
        return {'status': 'already_done', 'work_id': work_id, 'role': item['role'],
                'outcome': item['outcome'], 'error': item['error_type']}
    role = item['role']
    history = json.loads(engine.session(role)['messages'])

    def fail(kind, detail):
        engine.finish_work(work_id, answer[:2000] if isinstance(answer, str) else None,
                           error_type=kind, messages=history[-20:])
        return {'status': 'error', 'work_id': work_id, 'role': role, 'error': kind, 'detail': str(detail)[:300]}

    try:
        action = json.loads(answer)
    except Exception as exc:
        return fail('SchemaViolation', exc)
    if not isinstance(action, dict):
        return fail('SchemaViolation', 'reply is not a JSON object')

    if action.get('idle'):
        engine.finish_work(work_id, answer, outcome='idle',
                           messages=(history + [{'role': 'assistant', 'content': answer},
                                                {'role': 'user', 'content': '{"idle":true}'}])[-20:])
        return {'status': 'idle', 'work_id': work_id, 'role': role}

    tool, args = action.get('tool'), action.get('args') or {}
    if tool not in engine.ALLOWED.get(role, set()):
        return fail('ToolDenied', f'{tool} not available to {role}')
    if not isinstance(args, dict):
        return fail('SchemaViolation', 'args is not an object')
    try:
        result = engine.tool(role, tool, args)
    except Denied as exc:
        return fail('ToolDenied', exc)
    except Exception as exc:
        return fail(type(exc).__name__, exc)

    engine.finish_work(work_id, answer, outcome='tool_executed',
                       messages=(history + [{'role': 'assistant', 'content': answer},
                                            {'role': 'user', 'content': packed(result)}])[-20:])
    return {'status': 'ok', 'work_id': work_id, 'role': role, 'tool': tool, 'result': result}


def status(engine):
    with engine.connect() as db:
        latest = db.execute('SELECT id,candidate,state,parent FROM challenges ORDER BY id DESC LIMIT 1').fetchone()
        return {
            'control': engine.control_state(),
            'sessions': [dict(r) for r in db.execute('SELECT role,turns,cursor FROM sessions ORDER BY role')],
            'pending': [{k: r[k] for k in ('id', 'role')} for r in engine.pending_work()],
            'candidates': db.execute('SELECT COUNT(*) FROM candidates').fetchone()[0],
            'challenge': dict(latest) if latest else None,
            'candy': db.execute('SELECT COALESCE(SUM(amount),0) FROM rewards').fetchone()[0],
            'findings': db.execute('SELECT COUNT(*) FROM findings').fetchone()[0],
            'events': db.execute('SELECT COUNT(*) FROM events').fetchone()[0],
        }


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m aces.pump', description='ACES dispatch pump')
    parser.add_argument('--db', required=True)
    sub = parser.add_subparsers(dest='command', required=True)

    d = sub.add_parser('dispatch', help='list work for roles that need it')
    d.add_argument('--max-turns', type=int, default=50)

    w = sub.add_parser('deliver', help='commit one answer')
    w.add_argument('--work-id', required=True)
    w.add_argument('--answer', required=True)

    sub.add_parser('status', help='compact state')

    r = sub.add_parser('recover', help='abandon stale dispatches')
    r.add_argument('--minutes', type=int, default=15)

    args = parser.parse_args(argv)
    engine = Engine(args.db)

    if args.command == 'dispatch':
        payload = dispatch(engine, args.max_turns)
    elif args.command == 'deliver':
        payload = deliver(engine, args.work_id, args.answer)
    elif args.command == 'status':
        payload = status(engine)
    else:
        payload = {'abandoned': engine.abandon_stale(args.minutes * 60)}

    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
