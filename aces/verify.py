"""Deterministic verification. No model, no I/O, no opinion.

Everything here answers one question: does this claim hold under the rules that were fixed *before*
the claim was made? A breach is accepted by recomputation, never by assertion.
"""
import hashlib

# Bounded straight-line byte permutation language. No names, imports, loops or IO.
OPS = ('xor_key', 'add_key', 'xor', 'add', 'rol')


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


def transform(data, key, program, inverse=False):
    """Apply the permutation to each byte. key is the 8-bit toy key."""
    validate(program)
    if not isinstance(data, bytes) or len(data) > 4096 or type(key) is not int or not 0 <= key <= 255:
        raise ValueError('invalid VM input')
    out = []
    for b in data:
        for op, n in (reversed(program) if inverse else program):
            v = key if op.endswith('_key') else n
            if op in ('xor_key', 'xor'):
                b ^= v
            elif op in ('add_key', 'add'):
                b = (b + (-v if inverse else v)) & 255
            else:
                r = n % 8
                if inverse:
                    r = (-r) % 8
                b = ((b << r) | (b >> ((8 - r) % 8))) & 255
        out.append(b)
    return bytes(out)


def is_reversible(program):
    """Exhaustive over the whole domain: every key, every byte. Cheap here, decisive later."""
    domain = bytes(range(256))
    for key in range(256):
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
