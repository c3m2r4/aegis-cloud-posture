"""Cross-process serialization for explicit discovery and assessment runs."""
from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from typing import Self


class ScanAlreadyRunning(RuntimeError):
    """Another AEGIS process is collecting against this database."""


class ScanLock:
    """An advisory OS lock held on a mode-0600 sidecar file.

    The lock is released automatically when its owning process exits. The file
    itself is intentionally retained so another process never races its inode.
    """

    def __init__(self, database: Path):
        resolved = database.expanduser().resolve()
        self.path = resolved.with_name(resolved.name + ".scan.lock")
        self._fd: int | None = None

    def acquire(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise RuntimeError("Could not create the local scan lock") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise RuntimeError("The local scan lock is not a regular file")
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    if exc.errno in {errno.EACCES, errno.EDEADLK, errno.EAGAIN}:
                        raise ScanAlreadyRunning("Another AEGIS collection is already running") from None
                    raise
            else:
                import fcntl
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    if exc.errno in {errno.EACCES, errno.EAGAIN}:
                        raise ScanAlreadyRunning("Another AEGIS collection is already running") from None
                    raise
            self._fd = fd
            return self
        except Exception:
            os.close(fd)
            raise

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> Self:
        return self if self._fd is not None else self.acquire()

    def __exit__(self, *_exc: object) -> None:
        self.release()


def acquire_scan_lock(database: Path) -> ScanLock:
    """Acquire the configured database's lock without waiting."""
    return ScanLock(database).acquire()
