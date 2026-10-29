# Training local role models

What these are: **small specialists that imitate each role's protocol.** They learn the JSON shape, the
tool vocabulary, and the habit of answering instead of talking. They do not learn cryptanalysis, and on a
0.5B model trained on 71 examples they cannot. Treat them as drafters whose output a subagent or the
engine still has to validate.

## What the machine can actually do

| | |
|---|---|
| GPU | RTX 2050 laptop, **4 GB VRAM** (the "15846 MB" in the brief is shared memory, not VRAM) |
| CPU / RAM | Ryzen 5 7535HS, 23.2 GB |
| Driver | 581.83, CUDA 13.0 runtime; no local toolkit needed (torch ships its own) |

Measured: a 0.5B model in bf16 occupies **950 MB**, and training with LoRA + gradient checkpointing +
sequence length 3072 peaks around **800 MB** of activations. That leaves room, but a 1.5B base would not
fit at this sequence length without QLoRA and a shorter cap. 7B is out of the question on this device.

| base | weights (bf16) | LoRA training at seq 3072 | verdict |
|---|---|---|---|
| Qwen2.5-0.5B | 0.95 GB | ~1.8 GB peak | comfortable |
| 1.5B | 3.0 GB | ~4 GB+ | would need QLoRA, seq ≤1024 |
| 7B | 14 GB | — | impossible here |

## Data

`tools/build_dataset.py` reconstructs training triples from the run databases: each completed dispatch is
already (charter → projection → answer). From runs 001–016:

| role | triples |
|---|---|
| adversary | 35 |
| generator | 17 |
| integrator | 12 |
| observer | 3 |
| reviewer | 4 |

71 total. This is the binding limitation, not the GPU. Every cycle adds roughly six.

## Method

- LoRA r=16, alpha=32, on all seven projection matrices: **8.8 M trainable of 502 M (1.75%)**.
- Base frozen in bf16; only adapters train; batch 1, grad accumulation 4.
- Loss on the **completion only** — the charter and payload are masked to `-100`.
- Prompt truncated from the **left** when the pair exceeds the cap.

That last point is a real trap: the charters run to ~2,200 tokens, so a 2048 cap truncates the prompt and
deletes the completion, leaving every label at `-100`. Cross-entropy over an all-ignored batch returns
**NaN**, not zero, so training silently produces a dead adapter. The first run did exactly that; the fix
is in `encode()` and the cap is now 3072.

## Results

Scored on protocol conformance (`tools/eval_role.py`), 10 samples per role, greedy decoding:

| role | epochs | final loss | valid JSON | tool allowed | args complete |
|---|---|---|---|---|---|
| integrator | 12 | ~0.00 | **10/10** | 9/10 | 9/10 |
| adversary | 8 | 0.25 | 9/10 | 8/10 | **3/10** |
| generator | 10 | 0.19 | 7/10 | 7/10 | 7/10 |

Training time: ~20 minutes for the adversary set, ~10 for the other two, on the laptop GPU.

### The adversary result is the interesting one

It produces valid JSON nine times out of ten, and then drops `method` and `detail` from `submit` seven
times out of ten:

```json
{"tool":"submit","args":{"challenge":1,"plaintext":"bcb1c3cd…"}}
```

That is precisely the provenance discipline the whole experiment is built on. A 0.5B model trained on 35
examples learns the *shape* of an answer and not the *constraint* that makes it admissible. It is a clean
demonstration that format imitation and rule-following are different problems.

The integrator scores best because its job is the narrowest — publish or reject, one line — and it had 12
examples to learn from.

## Honest limits

- **No reasoning is transferred.** The generator's programs are imitations of the ones in its training
  data, not designs. The adversary never attempts cryptanalysis.
- **Tiny data.** 71 examples means the integrator memorises (loss 0.002 by epoch 2); held-out behaviour is
  not measured here.
- **Held-out quality is worse than the table.** The table scores the training distribution. During training
  the generator's held-out sample was invalid JSON, and that is the more honest number for unseen input.
- **No negative examples.** The datasets contain only accepted answers, so the models never see a rejected
  one and cannot learn what the engine refuses.

## What would make them useful

1. **More cycles.** Each run adds ~6 triples; a few hundred would be the minimum for generalisation.
2. **Negative examples.** Pair refusals (`ToolDenied`, `no_derivation_trace`, `experiment_required`) with
   the answer that caused them, so the model learns the boundary rather than the shape.
3. **A drafter, not a driver.** Have the local model propose `{"tool":…}` and let the subagent or the engine
   accept/repair. The engine already refuses malformed answers, which is exactly the safety property needed.

Anything beyond that needs a GPU this laptop does not have.
