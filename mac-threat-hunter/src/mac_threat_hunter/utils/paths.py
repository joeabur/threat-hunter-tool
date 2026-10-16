"""Path-safety and bounded file-reading helpers.

Evidence is untrusted. Every file read is size-bounded and refuses to follow
symlinks that leave the evidence directory.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath

from .errors import InputError, PathSafetyError


def resolve_within(base: Path, relative: str) -> Path:
    """Resolve ``relative`` under ``base``; reject traversal, absolute paths and symlinks."""
    if not relative or "\x00" in relative:
        raise PathSafetyError(f"invalid path: {relative!r}")
    if os.path.isabs(relative) or PurePosixPath(relative).is_absolute() or ":" in relative[:2]:
        raise PathSafetyError(f"absolute paths are not allowed in evidence: {relative!r}")
    parts = PurePosixPath(relative.replace("\\", "/")).parts
    if ".." in parts:
        raise PathSafetyError(f"path traversal is not allowed: {relative!r}")
    base_resolved = base.resolve()
    candidate = base_resolved.joinpath(*parts)
    # Reject symlinks anywhere along the relative path, not only the final component.
    current = base_resolved
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise PathSafetyError(f"symlinks are not followed inside evidence: {relative!r}")
    try:
        candidate.resolve().relative_to(base_resolved)
    except ValueError as exc:
        raise PathSafetyError(f"path escapes the evidence directory: {relative!r}") from exc
    return candidate


def read_bytes_bounded(path: Path, max_bytes: int) -> bytes:
    """Read a regular file, refusing symlinks, non-regular files and oversize files."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise PathSafetyError(f"refusing to follow symlink: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise InputError(f"not a regular file: {path}")
    if st.st_size > max_bytes:
        raise InputError(f"{path} is {st.st_size} bytes, over the {max_bytes} byte limit")
    try:
        with open(path, "rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(data) > max_bytes:
        raise InputError(f"{path} grew beyond the {max_bytes} byte limit while reading")
    return data


def read_text_bounded(path: Path, max_bytes: int) -> str:
    return read_bytes_bounded(path, max_bytes).decode("utf-8", errors="replace")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, max_bytes: int) -> str | None:
    """Hash a regular file without following symlinks; ``None`` if unreadable or too large."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


def ensure_output_dir(path: Path) -> Path:
    """Create an output directory, refusing to write through a symlink."""
    if path.is_symlink():
        raise PathSafetyError(f"output directory must not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True)
    return path


def normalize_posix(path: str) -> str:
    """Collapse ``.``/``..``/duplicate slashes in a macOS path string without touching disk."""
    import posixpath

    return posixpath.normpath(path) if path else path
