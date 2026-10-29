"""Score a fine-tuned role model on protocol conformance, not on cleverness.

A small model trained on ~30 examples cannot be expected to reason about a cipher. What it can be
measured on is whether it produces something the engine would accept: valid JSON, a tool the role is
allowed to use, and the required arguments. That is the honest bar, and this script reports it.

    python tools/eval_role.py --role adversary --adapter <dir> [--base ...]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import torch  # noqa: E402
from peft import PeftModel  # noqa: E402
from transformers import AutoModelForCausalLM, AutoTokenizer  # noqa: E402

from aces.core import Engine  # noqa: E402

REQUIRED = {
    'analyse': ('kind',), 'oracle': ('plaintexts',), 'hypothesize': ('weakness', 'attack', 'predicted'),
    'resolve': ('hypothesis', 'status', 'evidence'), 'solve': (), 'compute': ('program',),
    'submit': ('challenge', 'plaintext', 'method', 'detail'), 'register': ('spec',),
    'publish': ('candidate', 'mode'), 'reject': ('candidate', 'reason', 'detail'),
    'record_finding': ('challenge', 'finding'),
    'critique': ('hypothesis', 'verdict', 'advice'), 'report_leak': ('finding',),
}


def check(role, text):
    """(valid_json, tool_allowed, args_ok, reason)"""
    try:
        obj = json.loads(text)
    except ValueError:
        return False, False, False, 'not JSON'
    if not isinstance(obj, dict):
        return False, False, False, 'not an object'
    if obj.get('idle') is True:
        return True, True, True, 'idle'
    tool = obj.get('tool')
    allowed = Engine.ALLOWED.get(role, set())
    if tool not in allowed:
        return True, False, False, f'tool {tool!r} not allowed for {role}'
    args = obj.get('args') or {}
    missing = [k for k in REQUIRED.get(tool, ()) if k not in args]
    if missing:
        return True, True, False, f'{tool} missing {missing}'
    return True, True, True, f'{tool}'


def main(args):
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    tok = AutoTokenizer.from_pretrained(args.adapter)
    base = AutoModelForCausalLM.from_pretrained(args.base, torch_dtype=torch.bfloat16)
    model = PeftModel.from_pretrained(base, args.adapter).to(device).eval()

    data = [json.loads(l) for l in Path(args.data).read_text(encoding='utf-8').splitlines() if l.strip()]
    samples = data[:args.limit]
    rows, scores = [], {'json': 0, 'tool': 0, 'args': 0}
    for example in samples:
        prompt = tok.apply_chat_template(example['messages'][:2], tokenize=False,
                                         add_generation_prompt=True)
        x = tok(prompt, return_tensors='pt', add_special_tokens=False).to(device)
        x['input_ids'] = x['input_ids'][:, -2048:]
        x['attention_mask'] = x['attention_mask'][:, -2048:]
        with torch.no_grad():
            out = model.generate(**x, max_new_tokens=args.max_new, do_sample=False,
                                 pad_token_id=tok.eos_token_id)
        text = tok.decode(out[0][x['input_ids'].shape[1]:], skip_special_tokens=True).strip()
        ok_json, ok_tool, ok_args, why = check(args.role, text)
        scores['json'] += ok_json
        scores['tool'] += ok_tool
        scores['args'] += ok_args
        rows.append({'why': why, 'generated': text[:200],
                     'expected': example['messages'][2]['content'][:200]})

    n = max(len(samples), 1)
    print(f'{args.role}: {len(samples)} samples')
    print(f'  valid JSON  {scores["json"]}/{n}')
    print(f'  tool allowed {scores["tool"]}/{n}')
    print(f'  args complete {scores["args"]}/{n}')
    for row in rows[:args.show]:
        print(f'  - {row["why"]}: {row["generated"][:120]!r}')
    if args.out:
        Path(args.out).write_text(json.dumps(rows, indent=1), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', required=True)
    parser.add_argument('--adapter', required=True)
    parser.add_argument('--base', default='Qwen/Qwen2.5-0.5B-Instruct')
    parser.add_argument('--data', default=None)
    parser.add_argument('--limit', type=int, default=8)
    parser.add_argument('--max-new', type=int, default=512)
    parser.add_argument('--show', type=int, default=8)
    parser.add_argument('--out', default=None)
    args = parser.parse_args()
    args.data = args.data or f'runs/dataset/{args.role}.jsonl'
    main(args)
