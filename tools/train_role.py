"""LoRA fine-tune one ACES role on its own recorded turns.

4 GB of VRAM is the binding constraint: the base model is frozen in bf16, only the adapters are
trained, batch is 1 with gradient accumulation, and the loss is the completion only (the charter and
payload are masked to -100). That is enough to teach a small model the *protocol* - the JSON shape,
the role's tool vocabulary, when to say idle - and nothing more. It cannot teach cryptanalysis.

    python tools/train_role.py --role adversary --base Qwen/Qwen2.5-0.5B-Instruct
"""
import argparse
import json
import math
import time
from pathlib import Path

import torch
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer


def load(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]


def encode(tok, example, seq):
    """Prompt tokens are masked; only the assistant completion carries loss.

    The prompt is long (charters run to ~2k tokens), so it is truncated from the LEFT when the pair
    does not fit. Truncating from the right would delete the completion and leave every label at
    -100, which makes the cross-entropy NaN rather than zero - a silent failure worth preventing.
    """
    messages = example['messages']
    prompt = tok.apply_chat_template(messages[:2], tokenize=False, add_generation_prompt=True)
    p = tok(prompt, add_special_tokens=False)['input_ids']
    r = tok(messages[2]['content'], add_special_tokens=False)['input_ids'] + [tok.eos_token_id]
    if len(r) >= seq - 32:            # no room left for a prompt: drop the example
        return None
    room = seq - len(r)
    p = p[-room:] if len(p) > room else p
    return p + r, [-100] * len(p) + r


def main(args):
    data = load(args.data)
    if not data:
        raise SystemExit(f'no examples in {args.data}')
    split = max(1, int(len(data) * args.holdout))
    random_state = __import__('random').Random(args.seed)
    random_state.shuffle(data)
    held, train = data[:split], data[split:]
    print(f'{len(train)} train / {len(held)} held out  (role={args.role})')

    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    bf16 = device == 'cuda' and torch.cuda.is_bf16_supported()
    dtype = torch.bfloat16 if bf16 else torch.float32
    print(f'device={device} dtype={dtype}')

    tok = AutoTokenizer.from_pretrained(args.base, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(args.base, torch_dtype=dtype, trust_remote_code=True)
    model.to(device)
    model.gradient_checkpointing_enable()
    model.config.use_cache = False

    lora = LoraConfig(r=args.rank, lora_alpha=args.rank * 2, lora_dropout=0.05, bias='none',
                      task_type='CAUSAL_LM',
                      target_modules=['q_proj', 'k_proj', 'v_proj', 'o_proj',
                                      'gate_proj', 'up_proj', 'down_proj'])
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    params = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(params, lr=args.lr)

    encoded = [e for e in (encode(tok, ex, args.seq) for ex in train) if e]
    if not encoded:
        raise SystemExit('every example was dropped: raise --seq')
    dropped = len(train) - len(encoded)
    lengths = [len(i) for i, _ in encoded]
    print(f'sequence length: mean {sum(lengths)//len(lengths)}, max {max(lengths)} (cap {args.seq})'
          + (f', {dropped} dropped' if dropped else ''))

    step = 0
    model.train()
    for epoch in range(args.epochs):
        random_state.shuffle(encoded)
        total, count = 0.0, 0
        for i, (ids, labels) in enumerate(encoded):
            x = torch.tensor([ids], device=device)
            y = torch.tensor([labels], device=device)
            out = model(input_ids=x, labels=y)
            loss = out.loss / args.accum
            loss.backward()
            total += out.loss.item()
            count += 1
            if (i + 1) % args.accum == 0 or i + 1 == len(encoded):
                torch.nn.utils.clip_grad_norm_(params, 1.0)
                opt.step()
                opt.zero_grad(set_to_none=True)
                step += 1
            if (i + 1) % 5 == 0:
                print(f'  epoch {epoch+1} step {i+1}/{len(encoded)} loss {total/max(count,1):.4f}',
                      flush=True)
        print(f'epoch {epoch+1} done: mean loss {total/max(count,1):.4f}', flush=True)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(out_dir)
    tok.save_pretrained(out_dir)
    print(f'saved adapter -> {out_dir}')

    if held:
        print('\nheld-out sample:')
        model.eval()
        ex = held[0]
        prompt = tok.apply_chat_template(ex['messages'][:2], tokenize=False, add_generation_prompt=True)
        x = tok(prompt, return_tensors='pt', add_special_tokens=False).to(device)
        with torch.no_grad():
            y = model.generate(**x, max_new_tokens=200, do_sample=False,
                               pad_token_id=tok.eos_token_id)
        got = tok.decode(y[0][x['input_ids'].shape[1]:], skip_special_tokens=True).strip()
        print('--- model ---')
        print(got[:600])
        print('--- recorded ---')
        print(ex['messages'][2]['content'][:600])
        try:
            json.loads(got)
            print('\nJSON: valid')
        except ValueError:
            print('\nJSON: INVALID')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', required=True)
    parser.add_argument('--data', default=None)
    parser.add_argument('--base', default='Qwen/Qwen2.5-0.5B-Instruct')
    parser.add_argument('--out', default=None)
    parser.add_argument('--epochs', type=int, default=6)
    parser.add_argument('--seq', type=int, default=2048)
    parser.add_argument('--lr', type=float, default=2e-4)
    parser.add_argument('--rank', type=int, default=16)
    parser.add_argument('--accum', type=int, default=4)
    parser.add_argument('--holdout', type=float, default=0.15)
    parser.add_argument('--seed', type=int, default=7)
    args = parser.parse_args()
    args.data = args.data or f'runs/dataset/{args.role}.jsonl'
    args.out = args.out or f'models/{args.role}-lora'
    main(args)
