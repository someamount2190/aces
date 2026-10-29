"""Deterministic verification. No model, no I/O, no opinion.

Everything here answers one question: does this claim hold under the rules that were fixed *before*
the claim was made? A breach is accepted by recomputation, never by assertion.
"""
import hashlib

# Bounded straight-line byte permutation language. No names, imports, loops or IO.
#
# v3 widened the key. At 16 bits a known-plaintext search was 65,536 trials; at the default 32 bits it
# is 4.29 billion, which an exhaustive enumerator cannot reach inside a turn budget. The width is a
# property of the run, not a constant of the language, so a small width can still be used to exercise
# the loop end to end.
DEFAULT_KEY_BITS = 32
COMPUTE_BUDGET = 1 << 20          # keys a single compute call will enumerate before declaring defeat
OPS = ('xor_key', 'add_key', 'xor', 'add', 'rol', 'chain_add', 'chain_xor', 'rot_bytes')
CHAIN_OPS = ('chain_add', 'chain_xor')


def validate(program):
    """Structural check. Raises ValueError; returns the program for chaining."""
    if not isinstance(program, list) or not 1 <= len(program) <= 32:
        raise ValueError('program must have 1..32 operations')
    for step in program:
        if not isinstance(step, list) or len(step) != 2 or step[0] not in OPS:
            raise ValueError('invalid operation')
        if type(step[1]) is not int or not 0 <= step[1] <= 255:
            raise ValueError('invalid operand')
    return program


def key_bytes(key, key_bits=DEFAULT_KEY_BITS):
    """Canonical key material. Bytes pass through; an integer is encoded at the run's width."""
    if isinstance(key, (bytes, bytearray)):
        if not 1 <= len(key) <= 32:
            raise ValueError('invalid key length')
        return bytes(key)
    if type(key) is not int or key < 0 or key >= (1 << key_bits):
        raise ValueError('invalid key')
    return key.to_bytes(key_bits // 8, 'big')


def transform(data, key, program, inverse=False):
    """Apply the program to the buffer. Byte-local ops act per byte; chain ops mix across bytes."""
    validate(program)
    if not isinstance(data, bytes) or len(data) > 4096:
        raise ValueError('invalid VM input')
    keys = key_bytes(key)
    buf = bytearray(data)
    steps = list(reversed(program)) if inverse else program

    for op, n in steps:
        if op == 'rot_bytes':
            if buf:
                shift = n % len(buf)
                if shift:
                    buf = buf[-shift:] + buf[:-shift] if inverse else buf[shift:] + buf[:shift]
            continue
        if op == 'chain_add':
            order = range(len(buf) - 1, 0, -1) if inverse else range(1, len(buf))
            for i in order:
                buf[i] = (buf[i] - buf[i - 1]) & 255 if inverse else (buf[i] + buf[i - 1]) & 255
            continue
        if op == 'chain_xor':
            order = range(len(buf) - 1, 0, -1) if inverse else range(1, len(buf))
            for i in order:
                buf[i] ^= buf[i - 1]
            continue
        for i in range(len(buf)):
            b = buf[i]
            v = keys[i % len(keys)] if op.endswith('_key') else n
            if op in ('xor_key', 'xor'):
                b ^= v
            elif op in ('add_key', 'add'):
                b = (b + (-v if inverse else v)) & 255
            else:
                r = n % 8
                if inverse:
                    r = (-r) % 8
                b = ((b << r) | (b >> ((8 - r) % 8))) & 255
            buf[i] = b
    return bytes(buf)


def key_sample(key_bits=DEFAULT_KEY_BITS, limit=256):
    """Keys to check invertibility against. Exhaustive when the space is small enough to afford."""
    space = 1 << key_bits
    if space <= limit:
        return [k.to_bytes(max(1, key_bits // 8), 'big') for k in range(space)]
    step = space // limit
    sample = [k.to_bytes(key_bits // 8, 'big') for k in range(0, space, step)][:limit]
    return sample + [(space - 1).to_bytes(key_bits // 8, 'big')]


def is_reversible(program, key_bits=DEFAULT_KEY_BITS, keys=None):
    """Invertibility check: exhaustive over the byte domain, sampled over the key space."""
    validate(program)
    domain = bytes(range(256))
    for key in (keys if keys is not None else key_sample(key_bits)):
        if transform(transform(domain, key, program), key, program, True) != domain:
            return False
    return True


def has_secret_term(program):
    """A challenge whose permutation ignores the key is not a cryptographic task.

    Publishing one would let a solver invert a *public* function and still collect candy, which
    inflates the reward without any cryptanalysis. Reject it at registration.
    """
    return any(op.endswith('_key') for op, _ in program)


def verify_plaintext(secret_plaintext_hex, submitted_hex):
    """Constant-time exact comparison against the committed target."""
    a = str(secret_plaintext_hex).lower()
    b = str(submitted_hex).lower()
    return len(a) == len(b) and hashlib.sha256(a.encode()).hexdigest() == hashlib.sha256(b.encode()).hexdigest()


METHODS = ('known_plaintext_key_search', 'gf2_linear', 'chosen_plaintext_search',
           'algebraic_inversion', 'distinguishing_statistic', 'implementation_defect')

# A method is "structural" when it does better than trying every key. Enumeration is labour; a
# structural method is knowledge, and only knowledge counts as a breach.
STRUCTURAL = ('gf2_linear',)


def valid_method(method):
    return method in METHODS


LINEAR_OPS = ('xor', 'xor_key', 'chain_xor', 'rol', 'rot_bytes')

# Operations that break the causal structure: one that moves data between positions in both
# directions. rot_bytes rotates the whole buffer, so byte 0 can carry information from the last byte
# — with it, the sequential one-byte-at-a-time key recovery of RUN-007 no longer applies.
#
# It is GF(2)-linear, so diffusion alone is not enough: a program built from xor and rot_bytes and no
# addition is still affine and still falls to the linear attack. A construction needs a diffusion op
# *and* a non-linear one.
DIFFUSION_OPS = ('rot_bytes',)


def is_causal(program):
    """True when output byte i depends only on input bytes 0..i.

    Every op in the current set is either position-local or a left-to-right chain, so this is true
    for every program the VM can express. The consequence is sharp: byte 0 is a per-byte function of
    plaintext byte 0 and key byte 0 alone, so one known pair yields the first key byte in 256 trials
    and each further byte follows. Total work is key_bytes * 256, not 2^(key_bits) — RUN-007's
    Generator proved this and declined to keep proposing candidates against it.
    """
    return not any(op in DIFFUSION_OPS for op, _ in program)


def _bits(data):
    out = []
    for byte in data:
        for i in range(8):
            out.append((byte >> i) & 1)
    return out


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def is_gf2_linear(program):
    """True when every step is affine over GF(2) in (key, data): xor/rol/chain_xor only.

    add, add_key and chain_add carry between bits, which breaks linearity and with it the linear
    attack. A Generator that includes one of them forces an attack other than linear algebra.
    """
    return all(op in LINEAR_OPS for op, _ in program)


def _solve_gf2(columns, target, nvars):
    """Solve sum_j k_j * columns[j] == target over GF(2). Returns the key or None."""
    bits = [_bits(c) for c in columns]
    t = _bits(target)
    rows = []
    for r in range(len(t)):
        row = 0
        for j in range(nvars):
            if bits[j][r]:
                row |= 1 << j
        if t[r]:
            row |= 1 << nvars
        rows.append(row)

    pivot_row = 0
    where = [-1] * nvars
    for col in range(nvars):
        sel = next((i for i in range(pivot_row, len(rows)) if (rows[i] >> col) & 1), None)
        if sel is None:
            continue
        rows[pivot_row], rows[sel] = rows[sel], rows[pivot_row]
        for i in range(len(rows)):
            if i != pivot_row and (rows[i] >> col) & 1:
                rows[i] ^= rows[pivot_row]
        where[col] = pivot_row
        pivot_row += 1

    mask = (1 << nvars) - 1
    for row in rows:
        if (row & mask) == 0 and ((row >> nvars) & 1):
            return None                      # inconsistent: not affine in the key
    if pivot_row < nvars:
        return None                          # underdetermined: more than one key fits
    key = 0
    for col in range(nvars):
        row = rows[where[col]]
        if (row >> nvars) & 1:
            key |= 1 << col
    return key


def gf2_linear_attack(program, key_bits, pair):
    """Recover the key from one known pair when the construction is GF(2)-affine.

    Cost is key_bits + 1 evaluations of the permutation plus Gaussian elimination: for a 32-bit key
    that is 33 permutations instead of 2^32. This is what "a method that beats enumeration" means
    concretely.
    """
    validate(program)
    if not is_gf2_linear(program):
        return None
    plaintext, ciphertext = pair
    width = max(1, key_bits // 8)
    zero = bytes(width)
    base = transform(plaintext, zero, program)
    columns = []
    for j in range(key_bits):
        key = (1 << j).to_bytes(width, 'big')
        columns.append(_xor_bytes(transform(plaintext, key, program), base))
    recovered = _solve_gf2(columns, _xor_bytes(ciphertext, base), key_bits)
    if recovered is None:
        return None
    probe = recovered.to_bytes(width, 'big')
    if transform(plaintext, probe, program) != ciphertext:
        return None
    return recovered
