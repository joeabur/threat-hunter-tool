from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from mac_threat_hunter.utils.errors import InputError, PathSafetyError
from mac_threat_hunter.utils.paths import (
    ensure_output_dir,
    read_bytes_bounded,
    resolve_within,
    sha256_file,
)
from mac_threat_hunter.utils.proc import run_command
from mac_threat_hunter.utils.redact import Redactor
from mac_threat_hunter.utils.regexsafe import UnsafePatternError, compile_safe, safe_search
from mac_threat_hunter.utils.timeutil import parse_timestamp, to_iso


class TestTime:
    def test_iso_z_and_offset_normalised_to_utc(self) -> None:
        a = parse_timestamp("2026-03-10T14:30:00Z")
        b = parse_timestamp("2026-03-10T09:30:00-05:00")
        assert a.utc == b.utc == datetime(2026, 3, 10, 14, 30, tzinfo=UTC)
        assert b.zone == "explicit:-05:00"
        assert b.original == "2026-03-10T09:30:00-05:00"

    def test_unified_log_format(self) -> None:
        p = parse_timestamp("2026-03-10 14:10:00.123456+0000")
        assert p.utc == datetime(2026, 3, 10, 14, 10, 0, 123456, tzinfo=UTC)
        assert p.zone == "explicit:+00:00"

    def test_ps_lstart_uses_assumed_offset(self) -> None:
        off = timezone(timedelta(hours=2))
        p = parse_timestamp("Tue Mar 10 16:30:00 2026", assume_offset=off, assume_label="local")
        assert p.utc == datetime(2026, 3, 10, 14, 30, tzinfo=UTC)
        assert p.zone == "local:+02:00"

    def test_naive_defaults_to_utc_and_is_labelled(self) -> None:
        p = parse_timestamp("2026-03-10T14:30:00")
        assert p.utc == datetime(2026, 3, 10, 14, 30, tzinfo=UTC)
        assert p.zone == "assumed-utc"

    @pytest.mark.parametrize(
        "bad", ["not a date", "2026-13-45T99:00:00Z", "", None, "Tue Foo 99 99:99:99 2026"]
    )
    def test_unparseable_returns_none_but_keeps_original(self, bad: object) -> None:
        p = parse_timestamp(bad)
        assert p.utc is None

    def test_epoch_seconds_and_millis(self) -> None:
        assert parse_timestamp(1773153000).utc == parse_timestamp(1773153000000).utc
        assert to_iso(None) is None


class TestRegexSafety:
    @pytest.mark.parametrize(
        "pattern",
        [
            r"(a+)+$",
            r"(.*)*x",
            r"(?:[a-z]+\s?)+",
            r"(\w)\1",
            r"(?=x)y",
            r"a{1,5000}",
            "a" * 400,
            "",
        ],
    )
    def test_rejects_unsafe_patterns(self, pattern: str) -> None:
        with pytest.raises(UnsafePatternError):
            compile_safe(pattern)

    def test_accepts_simple_bounded_patterns(self) -> None:
        assert safe_search(r"(?:curl|wget)\s[^|]{0,200}\|\s*sh\b", "curl http://x | sh")

    def test_input_is_truncated_before_matching(self) -> None:
        text = "a" * 5000 + "needle"
        assert not safe_search("needle", text, max_input=4096)
        assert safe_search("needle", text, max_input=6000)

    def test_pathological_input_is_fast_for_accepted_pattern(self) -> None:
        import time

        start = time.monotonic()
        safe_search(r"(?:ba|z)?sh\b.{0,100}x", "sh " * 2000)
        assert time.monotonic() - start < 1.0


class TestRedaction:
    def test_default_patterns(self) -> None:
        r = Redactor()
        out = r.redact(
            "run --password=hunter2 --token abc123 Authorization: Bearer abcdefgh12345 AKIAABCDEFGHIJKLMNOP"
        )
        assert "hunter2" not in out and "abc123" not in out and "abcdefgh12345" not in out
        assert "AKIA" not in out

    def test_url_credentials(self) -> None:
        assert "s3cret" not in Redactor().redact("curl https://user:s3cret@host.example.test/x")

    def test_redact_obj_recurses(self) -> None:
        out = Redactor().redact_obj({"a": ["password=x1"], "b": {"c": "token=y2"}, "n": 3})
        assert "x1" not in str(out) and "y2" not in str(out) and out["n"] == 3

    def test_extra_patterns(self) -> None:
        assert Redactor([r"(secret-)\d+"]).redact("secret-1234") == "secret-[REDACTED]"


class TestPaths:
    def test_resolve_within_ok(self, tmp_path: Path) -> None:
        (tmp_path / "a.json").write_text("{}")
        assert resolve_within(tmp_path, "a.json").name == "a.json"

    @pytest.mark.parametrize("rel", ["../x", "a/../../x", "/etc/passwd", "", "a\x00b", "..\\x"])
    def test_traversal_and_absolute_rejected(self, tmp_path: Path, rel: str) -> None:
        with pytest.raises(PathSafetyError):
            resolve_within(tmp_path, rel)

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
    def test_symlink_rejected(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        inside = tmp_path / "ev"
        inside.mkdir()
        (inside / "link.json").symlink_to(outside)
        with pytest.raises(PathSafetyError):
            resolve_within(inside, "link.json")
        with pytest.raises(PathSafetyError):
            read_bytes_bounded(inside / "link.json", 1000)
        assert sha256_file(inside / "link.json", 1000) is None

    def test_size_limit(self, tmp_path: Path) -> None:
        f = tmp_path / "big"
        f.write_bytes(b"x" * 100)
        with pytest.raises(InputError):
            read_bytes_bounded(f, 50)
        assert sha256_file(f, 50) is None
        assert sha256_file(f, 100) is not None

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(InputError):
            read_bytes_bounded(tmp_path / "nope", 10)

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
    def test_output_dir_symlink_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(PathSafetyError):
            ensure_output_dir(link)


class TestSubprocess:
    def test_runs_without_shell(self) -> None:
        res = run_command([sys.executable, "-c", "print('a;b $HOME')"])
        assert res.ok and res.stdout.strip() == "a;b $HOME"

    def test_timeout_kills_child(self) -> None:
        res = run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
        assert res.timed_out and not res.ok

    def test_output_cap(self) -> None:
        res = run_command([sys.executable, "-c", "print('x' * 200000)"], max_output_bytes=1000)
        assert res.truncated and len(res.stdout) == 1000

    def test_missing_command_is_error_not_exception(self) -> None:
        res = run_command(["/nonexistent/definitely-not-here"])
        assert res.error and not res.ok

    def test_invalid_argv(self) -> None:
        assert run_command([]).error == "invalid argv"

    def test_environment_is_sanitised(self) -> None:
        if os.name == "nt":
            pytest.skip("POSIX environment check")
        os.environ["MTH_SECRET_TEST"] = "leak"
        res = run_command(
            [sys.executable, "-c", "import os; print(os.environ.get('MTH_SECRET_TEST'))"]
        )
        assert res.stdout.strip() == "None"
