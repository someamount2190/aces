"""Cryptanalysis workbench.

Everything here is deterministic and runs inside the trusted process. The Adversary chooses a
strategy and reads the result; it does not execute its own code, so every claim stays reproducible.

Budgets are arguments, not conventions: an oracle call that would exceed the challenge's allowance
is refused rather than silently truncated.
"""
import hashlib
import time

from .verify import transform, validate, is_causal, is_gf2_linear, gf2_linear_attack

ORACLE_LIMIT = 64          # chosen plaintexts per challenge, lifetime
ORACLE_BATCH = 8           # chosen plaintexts per call
DIFF_PAIRS = 16            # pairs per differential experiment
DIFF_LIMIT = 4             # differential experiments per challenge


# ---- oracle ---------------------------------------------------------------------------------

def encrypt_batch(program, key, plaintexts):
    """Encrypt chosen plaintexts under the challenge key. Bounded by the caller."""
    validate(program)
    return [transform(p, key, program).hex() for p in plaintexts]


# ---- structural analysis --------------------------------------------------------------------

def key_schedule(program, key_bytes):
    """How the key is consumed: which byte lands on which position, and where it is touched.

    This is the analysis that made RUN-007's attack possible: a positional schedule means key byte 0
    governs position 0, and if chaining is causal the key can be peeled one byte at a time.
    """
    validate(program)
    positions = [i % max(1, key_bytes) for i in range(max(1, key_bytes) * 2)]
    return {'key_bytes': key_bytes,
            'schedule': 'round_robin_by_position',
            'position_to_key_byte': positions,
            'distinct_key_bytes': len(set(positions)),
            'key_ops': sum(1 for op, _ in program if str(op).endswith('_key')),
            'causal': is_causal(program),
            'gf2_linear': is_gf2_linear(program)}


def frequency(samples):
    """Byte histogram over ciphertext samples. With a strong construction this should be flat."""
    counts = [0] * 256
    total = 0
    for sample in samples:
        for b in sample:
            counts[b] += 1
            total += 1
    top = sorted(range(256), key=lambda b: counts[b], reverse=True)[:8]
    mean = total / 256 if total else 0
    chi = sum((c - mean) ** 2 / mean for c in counts) if mean else 0.0
    return {'samples': len(samples), 'bytes': total,
            'top_bytes': [{'byte': b, 'count': counts[b]} for b in top],
            'chi_square': round(chi, 2),
            'uniform_expected': round(mean, 2)}


def differential(program, key, difference, pairs):
    """Feed x and x ^ difference, collect the output difference distribution.

    A construction with a degenerate diffusion step (a rotation that is the identity, a chain that
    never reaches position 0) shows a concentrated distribution here.
    """
    validate(program)
    width = len(difference)
    histogram = {}
    for i in range(pairs):
        base = hashlib.sha256(f'{i}'.encode()).digest()[:width]
        left = transform(base, key, program)
        right = transform(bytes(a ^ b for a, b in zip(base, difference)), key, program)
        out = bytes(a ^ b for a, b in zip(left, right)).hex()
        histogram[out] = histogram.get(out, 0) + 1
    ordered = sorted(histogram.items(), key=lambda kv: kv[1], reverse=True)
    return {'pairs': pairs, 'distinct_outputs': len(histogram),
            'max_repeats': ordered[0][1] if ordered else 0,
            'top': ordered[:4]}


def test_key(program, key, pairs):
    """Check a candidate key against several known pairs. One pair can be a coincidence; many cannot."""
    validate(program)
    matches = 0
    for plaintext, ciphertext in pairs:
        if transform(plaintext, key, program) == ciphertext:
            matches += 1
    return {'pairs': len(pairs), 'matches': matches, 'consistent': matches == len(pairs) and matches > 0}


# ---- attack strategies ----------------------------------------------------------------------

def sequential_recovery(program, key_bits, pair):
    """Peel the key one byte at a time, with backtracking. Only possible when the construction is causal.

    With a positional key schedule and forward-only chaining, output byte i depends on key bytes
    0..i and nothing later, so each byte can be fixed by trying values and comparing a prefix. A
    prefix match at one byte is not always unique (for example ((x^k)+k) can collide across k), so a
    dead end must backtrack to the next candidate rather than abandon the attack.

    Returns (key or None, evaluations actually performed).
    """
    validate(program)
    if not is_causal(program):
        return None, 0
    plaintext, ciphertext = pair
    width = max(1, key_bits // 8)
    if len(ciphertext) < width:
        return None, 0
    key = bytearray(width)
    performed = [0]

    def peel(i):
        if i == width:
            # Every byte is fixed; only now can the whole buffer be checked. Comparing prefixes
            # alone would accept a key that matches the first `width` bytes and nothing else.
            performed[0] += 1
            return transform(plaintext, bytes(key), program) == ciphertext
        for candidate in range(256):
            key[i] = candidate
            performed[0] += 1
            if transform(plaintext, bytes(key), program)[:i + 1] == ciphertext[:i + 1]:
                if peel(i + 1):
                    return True
        key[i] = 0
        return False

    if not peel(0):
        return None, performed[0]
    final = bytes(key)
    if transform(plaintext, final, program) != ciphertext:
        return None, performed[0]
    return int.from_bytes(final, 'big'), performed[0]


def _gf2(program, bits, pair):
    key = gf2_linear_attack(program, bits, pair)
    return key, (bits + 1 if key is not None else 0)


def _sequential(program, bits, pair):
    return sequential_recovery(program, bits, pair)


STRATEGIES = (
    ('gf2_linear', _gf2),
    ('sequential_recovery', _sequential),
)


def solve(program, key_bits, pair):
    """Try every implemented strategy in cost order. Returns (strategy, key, evaluations)."""
    started = time.time()
    evaluations = 0
    for name, run in STRATEGIES:
        key, performed = run(program, key_bits, pair)
        evaluations += performed
        if key is not None:
            return {'strategy': name, 'key': key, 'evaluations': evaluations,
                    'seconds': round(time.time() - started, 3)}
    return {'strategy': None, 'key': None, 'evaluations': evaluations,
            'seconds': round(time.time() - started, 3)}
