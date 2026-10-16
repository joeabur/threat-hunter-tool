"""Safe subprocess execution and file access helpers.

Nothing here executes discovered content. Subprocess calls use argv lists (never a shell),
a fixed PATH, a timeout and an output limit.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Files this tool refuses to read, even if a user lists them in a config file.
SENSITIVE_BASENAMES = {"shadow", "gshadow", "shadow-", "gshadow-", "master.passwd", "secrets"}
SENSITIVE_PATTERNS = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pem", ".key", ".p12", ".pfx")


class UnsafePathError(ValueError):
    """Raised for path traversal, symlink escapes or sensitive-file requests."""


@dataclass
class CommandResult:
    argv: list[str]
    ok: bool
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False
    error: str = ""


Runner = Callable[[Sequence[str], int, int], CommandResult]


def run_command(argv: Sequence[str], timeout: int = 15, max_output: int = 8 * 1024 * 1024) -> CommandResult:
    """Run ``argv`` without a shell. Never raises; failures are reported in the result."""
    args = list(argv)
    if not args:
        return CommandResult(args, False, None, "", "", error="empty command")
    exe = shutil.which(args[0], path=SAFE_PATH)
    if exe is None:
        return CommandResult(args, False, None, "", "", error=f"{args[0]}: not found")
    env = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
    try:
        proc = subprocess.Popen(
            [exe, *args[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except OSError as exc:
        return CommandResult(args, False, None, "", "", error=str(exc))
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return CommandResult(args, False, None, "", "", timed_out=True, error=f"timed out after {timeout}s")
    truncated = len(out) > max_output
    text = out[:max_output].decode("utf-8", errors="replace")
    return CommandResult(
        args,
        proc.returncode == 0,
        proc.returncode,
        text,
        err[:4096].decode("utf-8", errors="replace"),
        truncated=truncated,
        error="" if proc.returncode == 0 else f"exit status {proc.returncode}",
    )


def is_sensitive_path(path: str) -> bool:
    base = posixpath.basename(path).lower()
    if base in SENSITIVE_BASENAMES:
        return True
    return any(base.startswith(p) or base.endswith(p) for p in SENSITIVE_PATTERNS)


def safe_join(base: Path, relative: str) -> Path:
    """Join ``relative`` under ``base``; reject traversal and symlinks that leave ``base``."""
    if "\x00" in relative:
        raise UnsafePathError("NUL byte in path")
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise UnsafePathError(f"path escapes base directory: {relative!r}")
    base_resolved = base.resolve()
    candidate = (base_resolved / rel).resolve()
    if candidate != base_resolved and base_resolved not in candidate.parents:
        raise UnsafePathError(f"path resolves outside base directory: {relative!r}")
    return candidate


def read_regular_file(path: Path, max_bytes: int) -> bytes:
    """Read at most ``max_bytes`` from a regular, non-symlink file."""
    if path.is_symlink():
        raise UnsafePathError(f"refusing to follow symlink: {path}")
    if not path.is_file():
        raise UnsafePathError(f"not a regular file: {path}")
    if path.stat().st_size > max_bytes:
        raise UnsafePathError(f"file exceeds size limit ({max_bytes} bytes): {path}")
    return path.read_bytes()


def read_text_head(path: Path, max_bytes: int) -> str:
    """Read up to ``max_bytes`` of a file as text (follows no symlinks)."""
    if path.is_symlink() or not path.is_file():
        raise UnsafePathError(f"not a regular file: {path}")
    with path.open("rb") as fh:
        return fh.read(max_bytes).decode("utf-8", errors="replace")


def read_text_tail(path: Path, max_bytes: int) -> tuple[str, bool]:
    """Return the last ``max_bytes`` of a file and whether the head was cut off."""
    if path.is_symlink() or not path.is_file():
        raise UnsafePathError(f"not a regular file: {path}")
    size = path.stat().st_size
    with path.open("rb") as fh:
        cut = size > max_bytes
        if cut:
            fh.seek(size - max_bytes)
        data = fh.read(max_bytes)
    text = data.decode("utf-8", errors="replace")
    if cut and "\n" in text:
        text = text.split("\n", 1)[1]  # drop the partial first line
    return text, cut


def sha256_file(path: Path, max_bytes: int = 64 * 1024 * 1024) -> str | None:
    """SHA-256 of a regular file, or None if unreadable / over the size limit."""
    try:
        h = hashlib.sha256()
        total = 0
        with path.open("rb") as fh:
            while chunk := fh.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    return None
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_output_dir(path: str | Path) -> Path:
    """Validate a user-supplied output directory and return it (not created)."""
    p = Path(path)
    if "\x00" in str(path):
        raise UnsafePathError("NUL byte in output path")
    if p.is_symlink():
        raise UnsafePathError(f"refusing to write through a symlink: {p}")
    if p.exists() and not p.is_dir():
        raise UnsafePathError(f"output path exists and is not a directory: {p}")
    return p


def atomic_write_text(path: Path, text: str) -> None:
    if path.is_symlink():
        raise UnsafePathError(f"refusing to write through a symlink: {path}")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(text.encode("utf-8"))  # bytes: no newline translation, so hashes match on Windows
    os.replace(tmp, path)
