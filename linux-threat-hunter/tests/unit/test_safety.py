import os
import sys
from pathlib import Path

import pytest

from linux_threat_hunter.utils.redact import Redactor
from linux_threat_hunter.utils.safe import (
    UnsafePathError,
    is_sensitive_path,
    read_regular_file,
    read_text_tail,
    run_command,
    safe_join,
    sha256_file,
    validate_output_dir,
)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX utilities")
def test_subprocess_timeout_is_enforced() -> None:
    res = run_command(["sleep", "5"], timeout=1)
    assert res.timed_out and not res.ok and "timed out" in res.error


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX utilities")
def test_subprocess_output_limit_and_failure() -> None:
    res = run_command(["seq", "1", "100000"], timeout=10, max_output=100)
    assert res.truncated and len(res.stdout) == 100
    bad = run_command(["false"])
    assert not bad.ok and bad.returncode == 1


def test_subprocess_missing_command_and_no_shell() -> None:
    res = run_command(["definitely-not-a-command-xyz"])
    assert not res.ok and "not found" in res.error
    assert run_command([]).error == "empty command"
    # shell metacharacters are plain arguments, never interpreted
    if sys.platform != "win32":
        res = run_command(["echo", "a; echo injected"])
        assert res.stdout.strip() == "a; echo injected"


def test_safe_join_blocks_traversal(tmp_path: Path) -> None:
    for bad in ("../x", "a/../../x", "/etc/passwd", "a\x00b"):
        with pytest.raises(UnsafePathError):
            safe_join(tmp_path, bad)
    assert safe_join(tmp_path, "a/b.txt") == (tmp_path / "a/b.txt").resolve()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_symlink_escape_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    base = tmp_path / "base"
    base.mkdir()
    (base / "link").symlink_to(outside)
    with pytest.raises(UnsafePathError):
        safe_join(base, "link")
    with pytest.raises(UnsafePathError):
        read_regular_file(base / "link", 1000)
    with pytest.raises(UnsafePathError):
        read_text_tail(base / "link", 10)


def test_read_regular_file_limits(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_bytes(b"x" * 100)
    with pytest.raises(UnsafePathError):
        read_regular_file(f, 10)
    with pytest.raises(UnsafePathError):
        read_regular_file(tmp_path, 10)  # directory
    assert sha256_file(f, max_bytes=10) is None  # over limit: skipped
    assert sha256_file(tmp_path / "missing") is None


def test_read_text_tail_drops_partial_line(tmp_path: Path) -> None:
    f = tmp_path / "log"
    f.write_text("aaaa\nbbbb\ncccc\n")
    text, cut = read_text_tail(f, 8)
    assert cut and text == "cccc\n"


def test_sensitive_paths() -> None:
    for p in ("/etc/shadow", "/home/a/.ssh/id_rsa", "/etc/ssl/private/x.pem", "/etc/gshadow"):
        assert is_sensitive_path(p)
    assert not is_sensitive_path("/etc/passwd")


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_output_dir_validation(tmp_path: Path) -> None:
    f = tmp_path / "file"
    f.write_text("x")
    with pytest.raises(UnsafePathError):
        validate_output_dir(f)
    link = tmp_path / "link"
    os.symlink(tmp_path, link)
    with pytest.raises(UnsafePathError):
        validate_output_dir(link)
    assert validate_output_dir(tmp_path / "new") == tmp_path / "new"


def test_redaction_patterns() -> None:
    r = Redactor()
    assert r.text("tool --password hunter2 --x") == "tool --password [REDACTED] --x"
    assert r.text("run token=abc123 next") == "run token=[REDACTED] next"
    assert r.text("curl -H 'Authorization: Bearer abcdef' u") == "curl -H 'Authorization: Bearer [REDACTED]' u"
    assert "pw" not in r.text("mysql://user:pw@host/db")
    assert "AKIAABCDEFGHIJKLMNOP" not in r.text("key AKIAABCDEFGHIJKLMNOP")
    # ordinary log text is untouched
    assert r.text("Failed password for root from 1.2.3.4") == "Failed password for root from 1.2.3.4"
    assert r.obj({"a": ["secret=x"], "n": 3}) == {"a": ["secret=[REDACTED]"], "n": 3}
