import hashlib
import os
from collections.abc import Callable
from functools import lru_cache
from typing import NamedTuple

_p = 2 ** 255 - 19
_q = 2 ** 252 + 27742317777372353535851937790883648493

def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()

def _sha512_mod_q(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % _q

def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)

_d = -121665 * _inv(121666) % _p
_sqrt_m1 = pow(2, (_p - 1) // 4, _p)

_IDENTITY = (0, 1, 1, 0)

def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)

def _point_mult(s: int, P):
    Q = _IDENTITY
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q

def _point_equal(P, Q) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % _p != 0:
        return False
    return (P[1] * Q[2] - Q[1] * P[2]) % _p == 0

def _recover_x(y: int, sign: int):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _sqrt_m1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x

_g_y = 4 * _inv(5) % _p
_g_x = _recover_x(_g_y, 0)
_G = (_g_x, _g_y, 1, _g_x * _g_y % _p)

_G_TABLE: list[tuple[int, int, int, int]] | None = None

def _base_table() -> list[tuple[int, int, int, int]]:
    global _G_TABLE
    if _G_TABLE is None:
        table, P = [], _G
        for _ in range(256):
            table.append(P)
            P = _point_add(P, P)
        _G_TABLE = table
    return _G_TABLE

def _base_mult(s: int):
    table = _base_table()
    if s.bit_length() > len(table):
        return _point_mult(s, _G)
    Q = _IDENTITY
    i = 0
    while s > 0:
        if s & 1:
            Q = _point_add(Q, table[i])
        s >>= 1
        i += 1
    return Q

def _point_compress(P) -> bytes:
    zinv = _inv(P[2])
    x = P[0] * zinv % _p
    y = P[1] * zinv % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")

def _point_decompress(data: bytes):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)

def _secret_expand(seed: bytes):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]

@lru_cache(maxsize=4)
def pure_secret_to_public(seed: bytes) -> bytes:
    a, _ = _secret_expand(seed)
    return _point_compress(_base_mult(a))

def pure_sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _secret_expand(seed)
    public = pure_secret_to_public(seed)
    r = _sha512_mod_q(prefix + message)
    R = _point_compress(_base_mult(r))
    h = _sha512_mod_q(R + public + message)
    s = (r + h * a) % _q
    return R + int.to_bytes(s, 32, "little")

def pure_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public)
    if A is None:
        return False
    R_bytes = signature[:32]
    R = _point_decompress(R_bytes)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _q:
        return False
    h = _sha512_mod_q(R_bytes + public + message)
    return _point_equal(_base_mult(s), _point_add(R, _point_mult(h, A)))


class Backend(NamedTuple):
    name: str
    sign: Callable[[bytes, bytes], bytes]
    verify: Callable[[bytes, bytes, bytes], bool]
    secret_to_public: Callable[[bytes], bytes]

PURE_BACKEND = Backend("python", pure_sign, pure_verify, pure_secret_to_public)

def _cryptography_backend() -> Backend:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    def sign(seed: bytes, message: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)

    def verify(public: bytes, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True

    def secret_to_public(seed: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)

    return Backend("cryptography", sign, verify, secret_to_public)

def _pynacl_backend() -> Backend:
    import nacl.exceptions
    import nacl.signing

    def sign(seed: bytes, message: bytes) -> bytes:
        return bytes(nacl.signing.SigningKey(seed).sign(message).signature)

    def verify(public: bytes, message: bytes, signature: bytes) -> bool:
        try:
            nacl.signing.VerifyKey(public).verify(message, signature)
        except (nacl.exceptions.BadSignatureError, nacl.exceptions.TypeError,
                ValueError):
            return False
        return True

    def secret_to_public(seed: bytes) -> bytes:
        return bytes(nacl.signing.SigningKey(seed).verify_key)

    return Backend("pynacl", sign, verify, secret_to_public)

_BACKEND_BUILDERS = {
    "python": lambda: PURE_BACKEND,
    "cryptography": _cryptography_backend,
    "pynacl": _pynacl_backend,
}
_AUTO_ORDER = ("cryptography", "pynacl", "python")

def select_backend(name: str | None = None) -> Backend:
    if name:
        if name not in _BACKEND_BUILDERS:
            raise ValueError(
                f"unknown Ed25519 backend '{name}': "
                f"expected one of {', '.join(_BACKEND_BUILDERS)}")
        return _BACKEND_BUILDERS[name]()
    for candidate in _AUTO_ORDER:
        try:
            return _BACKEND_BUILDERS[candidate]()
        except ImportError:
            continue
    return PURE_BACKEND

_active: Backend | None = None

def _backend() -> Backend:
    global _active
    if _active is None:
        _active = select_backend(os.environ.get("DECISION_AUDIT_ED25519_BACKEND") or None)
    return _active

def use_backend(name: str | None = None) -> Backend:
    global _active
    _active = select_backend(name)
    return _active

def active_backend() -> str:
    return _backend().name

def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    return _backend().sign(seed, message)

def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    return _backend().verify(public, message, signature)

def secret_to_public(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    return _backend().secret_to_public(seed)
