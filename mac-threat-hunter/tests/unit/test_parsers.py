from __future__ import annotations

from datetime import UTC, datetime

from mac_threat_hunter.parsers.common import NormalizeContext, mode_flags
from mac_threat_hunter.parsers.files import normalize_files
from mac_threat_hunter.parsers.logs import parse_log_text
from mac_threat_hunter.parsers.network import normalize_network
from mac_threat_hunter.parsers.persistence import normalize_persistence
from mac_threat_hunter.parsers.process import derive_script_path, normalize_processes
from mac_threat_hunter.utils.redact import Redactor

COLLECTED = datetime(2026, 3, 10, 14, 30, tzinfo=UTC)
INTERP = ["sh", "bash", "zsh", "python3", "osascript", "node"]


def ctx() -> NormalizeContext:
    return NormalizeContext(Redactor(), INTERP, COLLECTED)


class TestProcesses:
    def test_ancestry_and_parent_fields(self) -> None:
        raw = [
            {"pid": 1, "ppid": 0, "name": "launchd", "path": "/sbin/launchd"},
            {"pid": 10, "ppid": 1, "name": "Word", "path": "/Applications/Word"},
            {"pid": 11, "ppid": 10, "name": "sh", "path": "/bin/sh", "cmdline": "sh -c id"},
        ]
        recs = normalize_processes(raw, "p.json", ctx())
        assert recs[2].data["parent_name"] == "Word"
        assert recs[2].data["ancestors"] == ["Word", "launchd"]
        assert recs[0].data.get("parent_name") is None

    def test_missing_parent_is_absent_not_guessed(self) -> None:
        recs = normalize_processes([{"pid": 5, "ppid": 999, "name": "x"}], "p.json", ctx())
        assert "parent_name" not in recs[0].data

    def test_ppid_cycle_terminates(self) -> None:
        raw = [{"pid": 1, "ppid": 2, "name": "a"}, {"pid": 2, "ppid": 1, "name": "b"}]
        recs = normalize_processes(raw, "p.json", ctx())
        assert len(recs[0].data["ancestors"]) <= 2

    def test_cmdline_redacted(self) -> None:
        recs = normalize_processes(
            [{"pid": 1, "name": "x", "cmdline": "x --password=abc"}], "p.json", ctx()
        )
        assert "abc" not in recs[0].data["cmdline"]
        assert "abc" not in recs[0].data["search_text"]

    def test_script_path_derivation(self) -> None:
        c = ctx()
        assert (
            derive_script_path("python3", "python3 -u /tmp/x.py arg", c)["script_path"]
            == "/tmp/x.py"
        )
        assert derive_script_path("bash", "bash -c 'curl x | sh'", c) == {"inline_script": True}
        assert derive_script_path("osascript", "osascript -e 'beep'", c) == {"inline_script": True}
        assert derive_script_path("curl", "curl http://x", c) == {}
        assert derive_script_path(
            "python3", 'python3 "unterminated', c
        )  # malformed quoting tolerated

    def test_non_dict_records_ignored(self) -> None:
        assert normalize_processes(["junk", 5, None], "p.json", ctx()) == []  # type: ignore[list-item]

    def test_start_time_parsed(self) -> None:
        recs = normalize_processes(
            [{"pid": 1, "name": "x", "start_time": "2026-03-10T10:00:00Z"}], "p", ctx()
        )
        assert recs[0].observed_at == datetime(2026, 3, 10, 10, 0, tzinfo=UTC)


class TestNetwork:
    def test_listener_flags_and_ip_normalisation(self) -> None:
        raw = [
            {
                "state": "listen",
                "local_address": "*",
                "local_port": 80,
                "pid": 1,
                "process_name": "x",
            },
            {"state": "LISTEN", "local_address": "127.0.0.1", "local_port": 631},
            {"state": "ESTABLISHED", "remote_address": "[2001:0DB8::1]", "remote_port": 443},
        ]
        recs = normalize_network(raw, "n.json", ctx())
        assert recs[0].data["is_listener"] and recs[0].data["local_is_wildcard"]
        assert recs[1].data["local_is_loopback"]
        assert recs[2].data["remote_address"] == "2001:db8::1"

    def test_hostname_remote_kept_as_host(self) -> None:
        recs = normalize_network(
            [{"state": "ESTABLISHED", "remote_address": "Host.Example.TEST."}], "n", ctx()
        )
        assert recs[0].data["remote_host"] == "host.example.test"
        assert "remote_address" not in recs[0].data

    def test_pid_join_marks_association(self) -> None:
        raw = [{"state": "ESTABLISHED", "pid": 7, "process_name": "a"}]
        recs = normalize_network(raw, "n", ctx(), {7: {"path": "/tmp/a", "sha256": "ab" * 32}})
        assert recs[0].data["process_path"] == "/tmp/a"
        assert (
            recs[0].data["process_association"] == "lsof"
            or recs[0].data["process_association"] == "joined-by-pid"
        )

    def test_missing_pid_reports_unavailable(self) -> None:
        recs = normalize_network([{"state": "ESTABLISHED"}], "n", ctx())
        assert recs[0].data["process_association"] == "unavailable"


class TestPersistenceAndFiles:
    def test_permission_flags(self) -> None:
        assert mode_flags("0666")["world_writable"] is True
        assert (
            mode_flags("0664")["group_writable"] is True
            and mode_flags("0664")["world_writable"] is False
        )
        assert mode_flags("4755")["setuid"] is True
        assert mode_flags("zzz") == {} and mode_flags(None) == {}

    def test_search_text_and_redaction(self) -> None:
        raw = [{"path": "/x.plist", "kind": "launch_agent", "program_arguments": ["/bin/sh", "-c", "run --token=abc"],
                "lines_of_interest": ["export SECRET_TOKEN=abc"]}]  # fmt: skip
        d = normalize_persistence(raw, "p.json", ctx())[0].data
        assert "abc" not in d["search_text"] and "abc" not in str(d["program_arguments"])

    def test_file_age_days(self) -> None:
        d = normalize_files(
            [{"path": "/tmp/x", "mtime": "2026-03-07T14:30:00Z", "mode": "0755"}], "f", ctx()
        )[0].data
        assert d["age_days"] == 3.0


class TestLogs:
    NDJSON = (
        '{"timestamp":"2026-03-10 14:10:00.123456+0000","processImagePath":"/usr/sbin/sshd","processID":8,'
        '"eventMessage":"Failed password for invalid user admin from 192.0.2.50 port 5 ssh2"}\n'
        '{"timestamp":"2026-03-10 14:10:05.000000+0000","processImagePath":"/usr/bin/sudo",'
        '"eventMessage":"alice : 1 incorrect password attempt ; TTY=ttys001"}\n'
        '{"timestamp":"2026-03-10 14:10:06.000000+0000","processImagePath":"/usr/sbin/sshd",'
        '"eventMessage":"Accepted publickey for bob from 192.0.2.9 port 22 ssh2"}\n'
    )

    def test_ndjson_auth_extraction(self) -> None:
        res = parse_log_text(self.NDJSON, "l", ctx(), 100)
        a, b, c = (r.data for r in res.records)
        assert (
            a["auth_result"] == "failed"
            and a["src_ip"] == "192.0.2.50"
            and a["auth_user"] == "admin"
        )
        assert b["auth_result"] == "failed" and b["auth_user"] == "alice" and b["process"] == "sudo"
        assert c["auth_result"] == "accepted"
        assert res.records[0].observed_at == datetime(2026, 3, 10, 14, 10, 0, 123456, tzinfo=UTC)
        assert res.records[0].time_original.startswith("2026-03-10 14:10:00")

    def test_malformed_lines_counted_not_fatal(self) -> None:
        res = parse_log_text(self.NDJSON + "garbage\n{broken json\n[]\n", "l", ctx(), 100)
        assert len(res.records) == 3 and res.malformed_lines == 3

    def test_json_array_export(self) -> None:
        res = parse_log_text(
            '[{"timestamp":"2026-03-10T10:00:00Z","eventMessage":"hello","processImagePath":"/a/b"}, 5]',
            "l",
            ctx(),
            10,
        )
        assert len(res.records) == 1 and res.malformed_lines == 1

    def test_syslog_style_line(self) -> None:
        line = "2026-03-10 14:10:00.000000+0000  host sshd[12]: Failed password for root from 192.0.2.1 port 1 ssh2\n"
        res = parse_log_text(line, "l", ctx(), 10)
        assert res.records[0].data["src_ip"] == "192.0.2.1" and res.records[0].data["pid"] == 12

    def test_record_cap(self) -> None:
        res = parse_log_text(self.NDJSON * 10, "l", ctx(), 5)
        assert len(res.records) == 5

    def test_redaction_of_messages(self) -> None:
        res = parse_log_text(
            '{"timestamp":"2026-03-10T10:00:00Z","eventMessage":"login password=hunter2"}\n',
            "l",
            ctx(),
            5,
        )
        assert "hunter2" not in res.records[0].data["message"]

    def test_empty_and_binary_input(self) -> None:
        assert parse_log_text("", "l", ctx(), 5).records == []
        assert parse_log_text("\x00\x01\x02\n", "l", ctx(), 5).malformed_lines == 1
