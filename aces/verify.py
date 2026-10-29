"""Deterministic verification. No model, no I/O, no opinion.

Everything here answers one question: does this claim hold under the rules that were fixed *before*
the claim was made? A breach is accepted by recomputation, never by assertion.
"""
import hashlib

# Bounded straight-line byte permutation language. No names, imports, loops or IO.
#
# v2 fattened the Generator: the key is 16 bits instead of 8, and two chain operations mix across
# byte positions. Without a cross-byte operation every construction is a per-byte map, and a
# known-plaintext search costs 2^key_bits regardless of how elaborate the program looks.
KEY_BYTES = 2
KEY_BITS = KEY_BYTES * 8
KEY_SPACE = 1 << KEY_BITS
OPS = ('xor_key', 'add_key', 'xor', 'add', 'rol', 'chain_add', 'chain_xor')
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


def _key_bytes(key):
    if isinstance(key, (bytes, bytearray)):
        if not 1 <= len(key) <= 32:
            raise ValueError('invalid key length')
        return bytes(key)
    if type(key) is not int or not 0 <= key < KEY_SPACE:
        raise ValueError('invalid key')
    return key.to_bytes(KEY_BYTES, 'big')


def transform(data, key, program, inverse=False):
    """Apply the program to the buffer. Byte-local ops act per byte; chain ops mix across bytes."""
    validate(program)
    if not isinstance(data, bytes) or len(data) > 4096:
        raise ValueError('invalid VM input')
    keys = _key_bytes(key)
    buf = bytearray(data)
    steps = list(reversed(program)) if inverse else program

    for op, n in steps:
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


def key_sample(limit=512):
    """Keys to check invertibility against. Exhaustive when the space is small enough to afford."""
    if KEY_SPACE <= limit:
        return list(range(KEY_SPACE))
    step = KEY_SPACE // limit
    sample = list(range(0, KEY_SPACE, step))[:limit]
    return sample + [KEY_SPACE - 1]


def is_reversible(program, keys=None):
    """Invertibility check: exhaustive over the byte domain, sampled over the key space."""
    validate(program)
    domain = bytes(range(256))
    for key in (keys if keys is not None else key_sample()):
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


# Named attack methods the verifier can check against a derivation. A method outside this set
# cannot be verified, so it cannot ground a breach.
METHODS = ('known_plaintext_key_search', 'chosen_plaintext_search', 'algebraic_inversion',
           'distinguishing_statistic', 'implementation_defect')


def valid_method(method):
    return method in METHODS
