"""Bounded, shell-free subprocess execution.

Collectors only ever run fixed argv lists (never ``shell=True``) with a timeout
and an output cap. Discovered binaries are never executed.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import threading
from dataclasses import dataclass


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None


def _drain(stream: object, limit: int, sink: list[bytes], flag: dict[str, bool]) -> None:
    total = 0
    read = getattr(stream, "read", None)
    if read is None:
        return
    while True:
        chunk = read(65536)
        if not chunk:
            return
        remaining = limit - total
        if remaining <= 0:
            flag["truncated"] = True
            continue  # keep draining so the child does not block, but discard
        sink.append(chunk[:remaining])
        total += min(len(chunk), remaining)
        if len(chunk) > remaining:
            flag["truncated"] = True


def run_command(
    argv: list[str],
    *,
    timeout: float = 15.0,
    max_output_bytes: int = 4 * 1024 * 1024,
) -> CommandResult:
    """Run ``argv`` without a shell, with a timeout and output cap. Never raises."""
    if not argv or not all(isinstance(a, str) for a in argv):
        return CommandResult(list(argv), None, "", "", error="invalid argv")
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"}
    if os.name == "nt":  # pragma: no cover - live collection is macOS-only
        env = dict(os.environ)
    try:
        proc = subprocess.Popen(  # noqa: S603  # nosec B603
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            close_fds=True,
        )
    except FileNotFoundError:
        return CommandResult(argv, None, "", "", error="command not found")
    except PermissionError:
        return CommandResult(argv, None, "", "", error="permission denied")
    except OSError as exc:
        return CommandResult(argv, None, "", "", error=f"cannot start: {exc.strerror or exc}")

    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    out_flag = {"truncated": False}
    err_flag = {"truncated": False}
    threads = [
        threading.Thread(target=_drain, args=(proc.stdout, max_output_bytes, out_chunks, out_flag)),
        threading.Thread(target=_drain, args=(proc.stderr, 64 * 1024, err_chunks, err_flag)),
    ]
    for t in threads:
        t.daemon = True
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()  # our own child only; this tool never signals other processes
        proc.wait()
    for t in threads:
        t.join(timeout=2)
    return CommandResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=b"".join(out_chunks).decode("utf-8", errors="replace"),
        stderr=b"".join(err_chunks).decode("utf-8", errors="replace"),
        timed_out=timed_out,
        truncated=out_flag["truncated"],
    )
