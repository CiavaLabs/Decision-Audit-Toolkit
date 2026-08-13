import contextlib
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from . import ed25519


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _require_path(path: Path | None, what: str) -> Path:
    if path is None:
        raise RuntimeError(f"no {what} path configured for a stored-key signer")
    return path

def _write_key_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    try:
        handle = os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)
        raise
    with handle as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    with contextlib.suppress(OSError):
        os.chmod(path, mode)

class HmacSigner:
    scheme = "hmac"

    def __init__(self, key_path: str | None = None):
        self.key_path = Path(key_path) if key_path else None
        self._key: bytes | None = None if self.key_path else secrets.token_bytes(32)

    def can_verify(self) -> bool:
        return self._key is not None or (self.key_path is not None and self.key_path.exists())

    @property
    def key(self) -> bytes:
        if self._key is None:
            self._key = self._load_or_create_key()
        return self._key

    def _load_or_create_key(self) -> bytes:
        path = _require_path(self.key_path, "HMAC key")
        if path.exists():
            data = path.read_bytes()
            if len(data) != 32:
                raise ValueError("Stored HMAC key must be 32 bytes")
            return data
        key = secrets.token_bytes(32)
        _write_key_file(path, key)
        return key

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self.key, message, hashlib.sha256).digest()

    def verify(self, message: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(message), signature)

class Ed25519Signer:
    scheme = "ed25519"

    def __init__(self, key_path: str | None = None, public_key_path: str | None = None):
        self.key_path = Path(key_path) if key_path else None
        self.public_key_path = Path(public_key_path) if public_key_path else None
        self._seed: bytes | None = None
        self._public: bytes | None = None
        if not self.key_path:
            self._seed = secrets.token_bytes(32)
            self._public = ed25519.secret_to_public(self._seed)

    def can_verify(self) -> bool:
        if self._public is not None:
            return True
        if self.public_key_path and self.public_key_path.exists():
            return True
        return self.key_path is not None and self.key_path.exists()

    @property
    def public_key(self) -> bytes:
        if self._public is None:
            if self.public_key_path and self.public_key_path.exists():
                self._public = self._read_key(self.public_key_path)
            else:
                self._public = ed25519.secret_to_public(self._load_or_create_seed())
        return self._public

    def _load_or_create_seed(self) -> bytes:
        if self._seed is None:
            path = _require_path(self.key_path, "Ed25519 seed")
            if path.exists():
                self._seed = self._read_key(path)
            elif self.public_key_path and self.public_key_path.exists():
                raise ValueError(
                    "public key present but private seed missing: cannot sign "
                    f"(expected seed at {path})")
            else:
                self._seed = secrets.token_bytes(32)
                _write_key_file(path, self._seed)
                if self.public_key_path:
                    _write_key_file(self.public_key_path,
                                    ed25519.secret_to_public(self._seed), mode=0o644)
        return self._seed

    @staticmethod
    def _read_key(path: Path) -> bytes:
        data = path.read_bytes()
        if len(data) != 32:
            raise ValueError(f"Stored Ed25519 key at {path} must be 32 bytes")
        return data

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(self._load_or_create_seed(), message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return ed25519.verify(self.public_key, message, signature)

def make_signer(scheme: str, key_path: str | None = None,
                public_key_path: str | None = None):
    if scheme == "hmac":
        return HmacSigner(key_path)
    if scheme == "ed25519":
        return Ed25519Signer(key_path, public_key_path)
    raise ValueError(f"unknown signature scheme '{scheme}'")
