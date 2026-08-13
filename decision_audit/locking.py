import os
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

try:
    import fcntl as _fcntl
except ImportError:
    _fcntl = None  # type: ignore[assignment]

try:
    import msvcrt as _msvcrt
except ImportError:
    _msvcrt = None  # type: ignore[assignment]

fcntl: ModuleType | None = _fcntl
msvcrt: ModuleType | None = _msvcrt

LOCK_SUFFIX = ".lock"

def lock_path_for(storage_path: str | Path) -> Path:
    path = Path(storage_path)
    return path.with_name(path.name + LOCK_SUFFIX)

@contextmanager
def file_lock(storage_path: str | Path | None):
    if storage_path is None:
        yield
        return
    path = lock_path_for(storage_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        _acquire(fd)
        try:
            yield
        finally:
            _release(fd)
    finally:
        os.close(fd)

def _acquire(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX)
    elif msvcrt is not None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)

def _release(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
    elif msvcrt is not None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
