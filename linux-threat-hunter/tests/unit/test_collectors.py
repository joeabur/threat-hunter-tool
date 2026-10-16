"""Collectors run against a fake filesystem/procfs and mocked utilities."""

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from linux_threat_hunter.collectors import COLLECTORS, CollectContext, collect, plan
from linux_threat_hunter.collectors.auth import collect_auth
from linux_threat_hunter.collectors.files import collect_files
from linux_threat_hunter.collectors.host import collect_host
from linux_threat_hunter.collectors.network import collect_network
from linux_threat_hunter.collectors.persistence import collect_persistence
from linux_threat_hunter.collectors.process import collect_processes, parse_stat
from linux_threat_hunter.evidence import load_evidence
from linux_threat_hunter.utils.safe import CommandResult

NOW = datetime(2025, 10, 14, 9, 0, tzinfo=UTC)


def fake_runner(outputs: dict[str, CommandResult]) -> Any:
    def runner(argv: Any, timeout: int, max_output: int) -> CommandResult:
        return outputs.get(argv[0], CommandResult(list(argv), False, None, "", "", error=f"{argv[0]}: not found"))

    return runner


def ok(stdout: str, argv: str = "x") -> CommandResult:
    return CommandResult([argv], True, 0, stdout, "")


@pytest.fixture()
def fs(tmp_path: Path, config: dict[str, Any]) -> CollectContext:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
    (root / "etc/os-release").write_text("ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=Ubuntu\n")
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "stat").write_text("cpu 1 2 3\nbtime 1760000000\n")
    return CollectContext(config=config, fs_root=root, proc_root=proc, now=NOW, runner=fake_runner({}))


def add_proc(
    ctx: CollectContext, pid: int, name: str, ppid: int, uid: int = 1000, exe: Path | None = None, cmdline: str = ""
) -> None:
    d = ctx.proc_root / str(pid)
    d.mkdir()
    fields = ["S", str(ppid)] + ["0"] * 17 + ["1234"]  # starttime is field index 19 after the name
    (d / "stat").write_text(f"{pid} ({name}) " + " ".join(fields) + "\n")
    (d / "status").write_text(f"Name:\t{name}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    (d / "cmdline").write_bytes(cmdline.replace(" ", "\x00").encode())
    if exe is not None:
        os.symlink(exe, d / "exe")


def test_parse_stat_handles_odd_names() -> None:
    s = parse_stat("42 (weird (name) x) S 7 " + " ".join(["0"] * 17) + " 99\n")
    assert s and s["name"] == "weird (name) x" and s["ppid"] == 7 and s["starttime_ticks"] == 99
    assert parse_stat("garbage") is None and parse_stat("1 (a) S") is None


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_process_collector_handles_missing_inaccessible_and_redacts(fs: CollectContext, tmp_path: Path) -> None:
    binary = tmp_path / "bin_a"
    binary.write_bytes(b"binary-a")
    add_proc(fs, 100, "a", 1, uid=1000, exe=binary, cmdline="a --password hunter2 --x")
    add_proc(fs, 101, "noexe", 1, uid=0)  # exe unreadable (e.g. other user's process)
    (fs.proc_root / "102").mkdir()  # vanished mid-collection: no stat file
    (fs.proc_root / "notapid").mkdir()
    res = collect_processes(fs)
    procs = {p["pid"]: p for p in res.outputs["processes.json"]}
    assert set(procs) == {100, 101}
    assert procs[100]["user"] == "alice" and procs[100]["exe"] == str(binary) and len(procs[100]["sha256"]) == 64
    assert "hunter2" not in procs[100]["cmdline"] and "[REDACTED]" in procs[100]["cmdline"]
    assert procs[101]["exe"] is None and "sha256" not in procs[101]
    assert res.counts["vanished"] == 1 and res.counts["inaccessible_attributes"] >= 1
    assert procs[100]["start_time"].startswith("2025-")


def test_process_collector_without_proc(fs: CollectContext) -> None:
    fs.proc_root = fs.proc_root / "missing"
    res = collect_processes(fs)
    assert res.status == "failed" and res.errors


def test_network_collector_ok_and_unavailable(fs: CollectContext) -> None:
    fs.runner = fake_runner({"ss": ok('tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n')})
    res = collect_network(fs)
    assert res.status in {"ok", "partial"} and res.counts["listening"] == 1
    fs.runner = fake_runner({})
    res = collect_network(fs)
    assert res.status == "failed" and "iproute2" in " ".join(res.notes)


def test_persistence_collector(fs: CollectContext) -> None:
    root = fs.fs_root
    (root / "etc/systemd/system").mkdir(parents=True)
    (root / "etc/systemd/system/a.service").write_text("[Service]\nExecStart=/tmp/evil --token abc123\n")
    (root / "etc/systemd/system/a.service.d").mkdir()
    (root / "etc/systemd/system/a.service.d/override.conf").write_text("[Service]\nExecStart=/bin/true\n")
    (root / "etc/systemd/system/b.timer").write_text("[Timer]\nOnCalendar=daily\n")
    if sys.platform != "win32":
        (root / "etc/systemd/system/masked.service").symlink_to("/dev/null")
    (root / "etc/cron.d").mkdir()
    (root / "etc/cron.d/job").write_text("* * * * * root /nonexistent/x\n")
    (root / "etc/crontab").write_text("17 * * * * root true\n")
    (root / "home/alice/.ssh").mkdir(parents=True)
    (root / "home/alice/.bashrc").write_text("alias a=b\n")
    (root / "home/alice/.ssh/authorized_keys").write_text("ssh-ed25519 AAAASECRETKEYMATERIAL a@b\n")
    (root / "home/alice/.ssh/id_rsa").write_text("-----BEGIN PRIVATE KEY-----")
    res = collect_persistence(fs)
    arts = {a["path"]: a for a in res.outputs["persistence.json"]}
    assert (
        "/etc/systemd/system/a.service" in arts and arts["/etc/systemd/system/a.service"]["kind"] == "systemd_service"
    )
    assert "abc123" not in arts["/etc/systemd/system/a.service"]["content"]  # redacted
    assert arts["/etc/systemd/system/a.service"]["referenced_paths_exist"] == {"/tmp/evil": False}
    assert arts["/etc/systemd/system/a.service.d/override.conf"]["kind"] == "systemd_dropin"
    assert arts["/etc/systemd/system/b.timer"]["kind"] == "systemd_timer"
    assert "/etc/systemd/system/masked.service" not in arts  # symlinks are not followed
    ak = arts["/home/alice/.ssh/authorized_keys"]
    assert "content" not in ak and ak["key_count"] == 1 and len(ak["sha256"]) == 64
    assert not any("id_rsa" in p for p in arts)
    assert "SECRETKEYMATERIAL" not in json.dumps(res.outputs)
    assert arts["/etc/cron.d/job"]["has_user_field"] is True


def test_persistence_modules_only_in_full_profile(fs: CollectContext) -> None:
    (fs.proc_root / "modules").write_text("nf_tables 100 3 - Live 0x0\n")
    assert not [a for a in collect_persistence(fs).outputs["persistence.json"] if a["kind"] == "kernel_module"]
    fs.profile = "full"
    mods = [a for a in collect_persistence(fs).outputs["persistence.json"] if a["kind"] == "kernel_module"]
    assert mods and mods[0]["name"] == "nf_tables"


def test_files_collector_never_reads_sensitive_files(fs: CollectContext) -> None:
    root = fs.fs_root
    (root / "etc/shadow").write_text("root:$6$hash:::\n")
    (root / "etc/sudoers").write_text("root ALL=(ALL) ALL\n")
    (root / "tmp").mkdir()
    (root / "tmp/dropper").write_bytes(b"\x7fELF....")
    os.chmod(root / "tmp/dropper", 0o755)
    (root / "tmp/data.txt").write_text("not executable")
    fs.config["collection"]["file_integrity_paths"] = ["/etc/shadow", "/etc/sudoers", "/etc/missing"]
    res = collect_files(fs)
    paths = {r["path"] for r in res.outputs["files.json"]}
    assert (
        "/etc/shadow" not in paths
        and "/etc/sudoers" in paths
        and "/tmp/dropper" in paths
        and "/tmp/data.txt" not in paths
    )
    assert any("sensitive" in n for n in res.notes) and "root:$6$hash" not in json.dumps(res.outputs)
    dropper = next(r for r in res.outputs["files.json"] if r["path"] == "/tmp/dropper")
    assert dropper["file_type"] == "elf" and dropper["is_executable"]


def test_auth_collector_files_journal_and_failure(fs: CollectContext) -> None:
    res = collect_auth(fs)
    assert res.status == "failed" and "no readable auth log" in res.errors[0]
    log = fs.fs_root / "var/log"
    log.mkdir(parents=True)
    (log / "auth.log").write_text(
        "Oct 14 03:11:09 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2 password=hunter2\n"
    )
    res = collect_auth(fs)
    assert res.status == "ok" and "hunter2" not in res.outputs["auth.log"]
    (log / "auth.log").unlink()
    (log / "secure").write_text("x\n")  # distro difference: /var/log/secure
    assert "source: /var/log/secure" in collect_auth(fs).notes[0]
    (log / "secure").unlink()
    fs.runner = fake_runner({"journalctl": ok("Oct 14 03:11:09 h sshd[1]: x\n")})
    assert "journalctl" in collect_auth(fs).notes[0]


def test_auth_log_tail_is_bounded(fs: CollectContext) -> None:
    log = fs.fs_root / "var/log"
    log.mkdir(parents=True)
    (log / "auth.log").write_text("line\n" * 100000)
    fs.config["collection"]["auth_log_max_bytes"] = 1000
    res = collect_auth(fs)
    assert len(res.outputs["auth.log"]) <= 1000 and "tail only" in " ".join(res.notes)


def test_host_collector_partial_when_tools_missing(fs: CollectContext) -> None:
    res = collect_host(fs)
    host = res.outputs["host.json"]
    assert host["distribution"]["id"] == "ubuntu" and host["hostname"] and res.status == "partial"
    assert host["interfaces"] is None  # not claimed when unavailable


def test_orchestration_isolates_failures_and_refuses_overwrite(
    fs: CollectContext, tmp_path: Path, monkeypatch: Any
) -> None:
    import linux_threat_hunter.collectors as c

    def boom(ctx: CollectContext) -> Any:
        raise RuntimeError("kaboom")

    specs = list(c.COLLECTORS)
    monkeypatch.setattr(
        c,
        "COLLECTORS",
        [
            type(specs[0])(s.name, s.description, s.sources, s.access_note, boom if s.name == "network" else s.fn)
            for s in specs
        ],
    )
    out = tmp_path / "out"
    manifest, results = collect(fs, out)
    st = {r.name: r.status for r in results}
    assert st["network"] == "failed" and st["process"] in {"ok", "partial"}
    assert (out / "manifest.json").exists() and json.loads((out / "manifest.json").read_text())["files"]
    with pytest.raises(FileExistsError):
        collect(fs, out)
    collect(fs, out, force=True)
    ev = load_evidence(out, fs.config)
    assert ev.manifest["collectors"] and not any("does not match" in w for w in ev.warnings)


def test_dry_run_plan_touches_nothing(fs: CollectContext, tmp_path: Path) -> None:
    rows = plan(fs)
    assert [r["collector"] for r in rows] == [c.name for c in COLLECTORS]
    assert all(r["access"] for r in rows)
    assert not (tmp_path / "out").exists()
