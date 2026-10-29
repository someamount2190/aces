"""Overnight autonomous cycles: local model drafts, the engine judges, the log remembers.

No human relay. Each cycle builds a fresh run, publishes a construction, and lets the fine-tuned
Adversary adapter answer the engine's dispatches. Rejected answers are kept deliberately: they are the
negative training signal the dataset has been missing.

    python tools/night_loop.py --until 05:50 --cycles 200
"""
import argparse
import json
import random
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aces.core import Engine                      # noqa: E402
from aces.prompts import CHARTERS                 # noqa: E402
from aces.pump import deliver, dispatch           # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
NIGHT = ROOT / 'runs' / 'night'

CONSTRUCTIONS = [
    {'name': 'seam_a', 'program': [['rot_bytes', 211], ['add_key', 0], ['chain_add', 0], ['rol', 3],
                                   ['xor_key', 0], ['rot_bytes', 89], ['add', 128], ['chain_xor', 0],
                                   ['add_key', 0], ['rol', 5], ['rot_bytes', 131], ['add', 46],
                                   ['chain_add', 0], ['xor_key', 0], ['rol', 7], ['rot_bytes', 59],
                                   ['add', 201], ['chain_xor', 0], ['add_key', 0], ['rol', 1]]},
    {'name': 'seam_b', 'program': [['add', 13], ['rot_bytes', 149], ['add_key', 0], ['chain_add', 0],
                                   ['rol', 2], ['xor_key', 0], ['rot_bytes', 71], ['add', 91],
                                   ['chain_xor', 0], ['add_key', 0], ['rol', 6], ['rot_bytes', 193],
                                   ['add', 37], ['chain_add', 0], ['xor_key', 0], ['rol', 4],
                                   ['rot_bytes', 53], ['add', 219], ['chain_xor', 0], ['add_key', 0],
                                   ['rol', 1], ['rot_bytes', 227], ['add', 77], ['add_key', 0]]},
    {'name': 'seam_c', 'program': [['add_key', 0], ['chain_add', 0], ['xor_key', 0], ['rot_bytes', 113],
                                   ['add', 166], ['rol', 3], ['chain_add', 0], ['xor_key', 0],
                                   ['rot_bytes', 71], ['add', 77], ['rol', 5], ['add_key', 0]]},
    {'name': 'seam_d', 'program': [['xor_key', 0], ['add_key', 0], ['rol', 2], ['chain_add', 0],
                                   ['rot_bytes', 5], ['xor', 158], ['add', 55], ['chain_add', 0],
                                   ['rot_bytes', 11], ['rol', 1], ['xor_key', 0], ['add', 93]]},
    {'name': 'seam_e', 'program': [['add', 19], ['rot_bytes', 173], ['add_key', 0], ['chain_add', 0],
                                   ['xor_key', 0], ['rol', 4], ['rot_bytes', 97], ['add', 222],
                                   ['chain_xor', 0], ['xor_key', 0], ['rol', 6], ['rot_bytes', 37],
                                   ['add_key', 0], ['chain_add', 0], ['add', 241], ['rol', 2],
                                   ['add_key', 0]]},
]

SPEC_TEXT = {
    'limitations': 'Fixed public rotations around forward-causal prefix runs; no nonce, no key '
                   'schedule. Chosen-plaintext differential probing of single-byte flips is the route.',
    'math': 'Each step is a bijection on (Z/256)^L; the modular additions carry the only GF(2) '
            'non-linearity.',
    'assumptions': 'Fixed 16-byte key reused round-robin, public program, arbitrary length L.',
}


def log(record):
    NIGHT.mkdir(parents=True, exist_ok=True)
    with (NIGHT / 'log.jsonl').open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(record) + '\n')


def pick_construction(used):
    for spec in CONSTRUCTIONS:
        if spec['name'] not in used:
            return spec
    return random.choice(CONSTRUCTIONS)


def scripted(engine, item, used):
    """Everything except the Adversary answers from a fixed policy."""
    role, view = item['role'], engine.view(item['role'])
    if role == 'generator':
        if view.get('catalog'):                    # one candidate is enough; let others act
            return json.dumps({'idle': True})
        spec = dict(pick_construction(used), **SPEC_TEXT)
        used.add(spec['name'])
        return json.dumps({'tool': 'register', 'args': {'spec': spec}})
    if role == 'integrator':
        catalog = view.get('catalog') or []
        challenge = view.get('challenge')
        if catalog and not (challenge and challenge.get('state') == 'ACTIVE'):
            return json.dumps({'tool': 'publish',
                               'args': {'candidate': catalog[0]['id'], 'mode': 'open', 'parent': None}})
        return json.dumps({'idle': True})
    if role == 'reviewer':
        actions = view.get('actions') or []
        tools = [a['tool'] for a in actions]
        first_compute = tools.index('compute') if 'compute' in tools else 99
        probed = any(t in ('oracle', 'analyse') for t in tools[:first_compute])
        open_hyp = any(h.get('status') == 'open' or h.get('reviewed') == 0
                       for h in (view.get('hypotheses') or []))
        if not probed and 'compute' in tools:
            return json.dumps({'tool': 'critique', 'args': {
                'hypothesis': (view['hypotheses'][0]['id'] if view.get('hypotheses') else 1),
                'verdict': 'flawed', 'flaw': 'enumeration_as_analysis',
                'advice': 'probe with the oracle before enumerating'}})
        return json.dumps({'tool': 'critique', 'args': {
            'hypothesis': (view['hypotheses'][0]['id'] if view.get('hypotheses') else 1),
            'verdict': 'sound', 'flaw': '',
            'advice': 'keep the probe-then-refute order'}})
    return json.dumps({'idle': True})


class Drafter:
    """The fine-tuned Adversary, or a scripted stand-in when no adapter is available."""

    def __init__(self, adapter, base):
        self.model = None
        self.tok = None
        if not adapter or not Path(adapter).exists():
            print('no adapter: using scripted adversary')
            return
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(adapter)
        base_model = AutoModelForCausalLM.from_pretrained(base, torch_dtype=torch.bfloat16)
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
        self.model = PeftModel.from_pretrained(base_model, adapter).to(device).eval()
        self.device = device
        print(f'drafter loaded on {device}')

    def __call__(self, role, prompt):
        if self.model is None:
            return json.dumps({'tool': 'analyse', 'args': {'kind': 'key_schedule'}})
        import torch
        text = self.tok.apply_chat_template(
            [{'role': 'system', 'content': CHARTERS[role]},
             {'role': 'user', 'content': prompt}],
            tokenize=False, add_generation_prompt=True)
        enc = self.tok(text, return_tensors='pt', add_special_tokens=False)
        enc['input_ids'] = enc['input_ids'][:, -2048:]
        enc['attention_mask'] = enc['attention_mask'][:, -2048:]
        enc = {k: v.to(self.device) for k, v in enc.items()}
        with torch.no_grad():
            out = self.model.generate(**enc, max_new_tokens=420, do_sample=True,
                                      temperature=0.8, top_p=0.95,
                                      pad_token_id=self.tok.eos_token_id)
        text = self.tok.decode(out[0][enc['input_ids'].shape[1]:], skip_special_tokens=True).strip()
        # Keep the first complete JSON object: a truncated tail is our fault, not the model's.
        depth, end = 0, None
        for index, char in enumerate(text):
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        return text[:end] if end else text


def one_cycle(tag, drafter, max_turns=14, budget=420):
    path = NIGHT / f'{tag}.sqlite3'
    if path.exists():
        path.unlink()
    engine = Engine(path, key_bits=128)
    with engine.tx() as db:
        db.execute("UPDATE control SET state='running'")
    used, turns, started = set(), 0, time.time()
    while turns < max_turns and time.time() - started < budget:
        items = dispatch(engine)
        if not items:
            break
        # The Adversary is the point of the exercise; everything else is scaffolding.
        order = {'adversary': 0, 'reviewer': 1, 'integrator': 2, 'generator': 3, 'observer': 4}
        items.sort(key=lambda i: order.get(i['role'], 9))
        for item in items[:2]:
            role = item['role']
            answer = drafter(role, item['prompt']) if role == 'adversary' else scripted(engine, item, used)
            try:
                result = deliver(engine, item['work_id'], answer)
            except Exception as exc:                        # noqa: BLE001
                result = {'status': 'exception', 'detail': str(exc)}
            turns += 1
            log({'at': datetime.now().isoformat(timespec='seconds'), 'run': path.stem, 'turn': turns,
                 'role': role, 'answer': answer[:400], 'result': json.dumps(result)[:400],
                 'ok': result.get('status') in ('ok', 'idle')})
            if item['role'] == 'adversary' and result.get('status') in ('ok', 'idle'):
                if not (engine.view('adversary').get('challenge')):
                    break
    return path, turns


def harvest(paths):
    from tools.build_dataset import triples
    rows = []
    for path in paths:
        rows += triples(str(path))
    if rows:
        with (NIGHT / 'dataset.jsonl').open('a', encoding='utf-8') as handle:
            for row in rows:
                handle.write(json.dumps(row) + '\n')
    return len(rows)


def main(args):
    NIGHT.mkdir(parents=True, exist_ok=True)
    now = datetime.now()
    hour, minute = (int(part) for part in args.until.split(':'))
    deadline = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if deadline <= now:                     # e.g. asked for 05:50 and it is already 06:10
        deadline += timedelta(days=1)
    print(f'running until {deadline:%H:%M}')
    drafter = Drafter(args.adapter, args.base)
    done, harvested = 0, 0
    pending = []
    while datetime.now() < deadline and done < args.cycles:
        tag = f'night-{done:03d}'
        try:
            path, turns = one_cycle(tag, drafter, args.turns, args.budget)
            pending.append(path)
            done += 1
            harvested += harvest([path])
            print(f'{tag}: {turns} turns  (cycles {done}, triples {harvested})', flush=True)
        except Exception:                                   # noqa: BLE001
            print(traceback.format_exc()[-800:], flush=True)
            log({'at': datetime.now().isoformat(timespec='seconds'), 'error': traceback.format_exc()[-800:]})
            time.sleep(5)
        if done and done % args.retrain_every == 0:
            print('retrain checkpoint reached', flush=True)
            (NIGHT / 'retrain_due').write_text(datetime.now().isoformat(), encoding='utf-8')
    print(f'finished {done} cycles, {harvested} triples')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--until', default='05:50')
    parser.add_argument('--cycles', type=int, default=400)
    parser.add_argument('--turns', type=int, default=14)
    parser.add_argument('--budget', type=int, default=420)
    parser.add_argument('--retrain-every', type=int, default=8)
    parser.add_argument('--adapter', default=r'C:\Users\Christian Correa\.aces-train\models\adversary-lora')
    parser.add_argument('--base', default='Qwen/Qwen2.5-0.5B-Instruct')
    args = parser.parse_args()
    main(args)
