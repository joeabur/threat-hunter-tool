from __future__ import annotations

import json
from pathlib import Path

import pytest

from mac_threat_hunter.config import Config
from mac_threat_hunter.ioc.loader import load_iocs, normalize_value, parse_iocs
from mac_threat_hunter.ioc.matcher import match_ioc_rule
from mac_threat_hunter.models import EvidenceRef, Record, Rule
from mac_threat_hunter.rules_engine.evaluator import EvalContext, build_lists
from mac_threat_hunter.utils.errors import InputError, ValidationError
from mac_threat_hunter.utils.redact import Redactor

SHA = "ab" * 32


def iocs(*items: dict) -> object:
    return parse_iocs({"schema_version": 1, "indicators": list(items)}, max_indicators=1000)


class TestNormalisation:
    @pytest.mark.parametrize(
        ("t", "raw", "expected"),
        [
            ("sha256", SHA.upper(), SHA),
            ("ip", " 198.51.100.023 ".replace("023", "23"), "198.51.100.23"),
            ("ip", "[2001:DB8::1]", "2001:db8::1"),
            ("domain", "C2.Example.TEST.", "c2.example.test"),
            ("path", "/private//tmp/./x", "/private/tmp/x"),
            ("process_name", " .updater ", ".updater"),
        ],
    )
    def test_normalises(self, t: str, raw: str, expected: str) -> None:
        assert normalize_value(t, raw) == expected

    @pytest.mark.parametrize(
        ("t", "raw"),
        [
            ("sha256", "abc"),
            ("sha256", "g" * 64),
            ("ip", "999.1.1.1"),
            ("ip", "example.test"),
            ("domain", "localhost"),
            ("domain", "-bad-.example.test"),
            ("domain", "1.2.3.4"),
            ("domain", "*.example.test"),
            ("path", "relative/path"),
            ("path", "/tmp/../etc"),
            ("path", "/tmp/*"),
            ("process_name", "/bin/sh"),
            ("process_name", ""),
            ("process_name", "a*"),
        ],
    )
    def test_rejects_invalid_and_wildcards(self, t: str, raw: str) -> None:
        with pytest.raises(ValueError):
            normalize_value(t, raw)


class TestParsing:
    def test_bundled_example_is_valid_and_synthetic(self, repo_root: Path) -> None:
        s = load_iocs(repo_root / "examples" / "iocs.json")
        assert s.synthetic and s.count() == 7 and s.counts_by_type()["sha256"] == 2

    def test_errors_are_aggregated(self) -> None:
        with pytest.raises(ValidationError) as exc:
            iocs(
                {"type": "ip", "value": "nope"},
                {"type": "wat", "value": "x"},
                {"type": "sha256", "value": SHA, "severity": "huge"},
            )
        assert len(exc.value.problems) == 3

    def test_duplicates_collapse(self) -> None:
        s = iocs({"type": "sha256", "value": SHA}, {"type": "sha256", "value": SHA.upper()})
        assert s.count() == 1  # type: ignore[attr-defined]

    def test_yaml_file(self, tmp_path: Path) -> None:
        f = tmp_path / "i.yaml"
        f.write_text("indicators:\n  - {type: ip, value: 192.0.2.1}\n")
        assert load_iocs(f).count() == 1

    def test_bad_files(self, tmp_path: Path) -> None:
        (tmp_path / "a.json").write_text("{not json")
        with pytest.raises(InputError):
            load_iocs(tmp_path / "a.json")
        (tmp_path / "b.json").write_text(json.dumps({"indicators": "x"}))
        with pytest.raises(ValidationError):
            load_iocs(tmp_path / "b.json")
        with pytest.raises(InputError):
            load_iocs(tmp_path / "missing.json")

    def test_indicator_limit(self) -> None:
        with pytest.raises(ValidationError):
            parse_iocs({"indicators": [{"type": "ip", "value": "192.0.2.1"}] * 3}, max_indicators=2)

    def test_flag_validation(self) -> None:
        with pytest.raises(ValidationError):
            iocs({"type": "ip", "value": "192.0.2.1", "include_subdomains": True})
        with pytest.raises(ValidationError):
            iocs({"type": "sha256", "value": SHA, "case_insensitive": True})


def rule(matches: list[dict], source: str = "network") -> Rule:
    return Rule(id="MTH-TEST-009", name="t", version=1, type="ioc", sources=[source], description="d",
                rationale="r", severity="high", confidence="medium", category="ioc_match", ioc={"matches": matches})  # fmt: skip


def rec(source: str, **data: object) -> Record:
    return Record(source, dict(data), EvidenceRef("x.json", 0))


def run(r: Rule, s: object, records: list[Record], cfg: Config):  # type: ignore[no-untyped-def]
    ctx = EvalContext(cfg, Redactor(), "h", build_lists(cfg))
    return match_ioc_rule(r, {r.sources[0]: records}, s, ctx)  # type: ignore[arg-type]


class TestMatching:
    def test_exact_ip_and_domain(self, cfg: Config) -> None:
        s = iocs(
            {"type": "ip", "value": "198.51.100.23"}, {"type": "domain", "value": "c2.example.test"}
        )
        r = rule(
            [
                {"type": "ip", "fields": ["remote_address"]},
                {"type": "domain", "fields": ["remote_host"]},
            ]
        )
        f, _ = run(r, s, [rec("network", remote_address="198.51.100.23"), rec("network", remote_host="c2.example.test"),
                          rec("network", remote_address="198.51.100.230"), rec("network", remote_host="notc2.example.test")], cfg)  # fmt: skip
        assert len(f) == 2
        assert f[0].ioc["match_mode"] == "exact" and "not confirmation" in f[0].ioc["note"]

    def test_subdomain_matching_is_explicit(self, cfg: Config) -> None:
        r = rule([{"type": "domain", "fields": ["remote_host"]}])
        strict = iocs({"type": "domain", "value": "bad.example.test"})
        loose = iocs({"type": "domain", "value": "bad.example.test", "include_subdomains": True})
        records = [rec("network", remote_host="x.bad.example.test")]
        assert run(r, strict, records, cfg)[0] == []
        found = run(r, loose, records, cfg)[0]
        assert len(found) == 1 and "subdomain" in found[0].ioc["match_mode"]

    def test_process_name_case_sensitive_by_default(self, cfg: Config) -> None:
        r = rule([{"type": "process_name", "fields": ["name"]}], "process")
        s = iocs({"type": "process_name", "value": "Evil"})
        assert run(r, s, [rec("process", name="evil")], cfg)[0] == []
        assert len(run(r, s, [rec("process", name="Evil")], cfg)[0]) == 1
        ci = iocs({"type": "process_name", "value": "Evil", "case_insensitive": True})
        assert len(run(r, ci, [rec("process", name="eVIL")], cfg)[0]) == 1

    def test_hash_and_path_normalisation(self, cfg: Config) -> None:
        r = rule(
            [{"type": "sha256", "fields": ["sha256"]}, {"type": "path", "fields": ["path"]}], "file"
        )
        s = iocs({"type": "sha256", "value": SHA}, {"type": "path", "value": "/private/tmp/x"})
        f, _ = run(r, s, [rec("file", sha256=SHA.upper(), path="/private//tmp/x")], cfg)
        assert len(f) == 1 and len(f[0].ioc["all_matches"]) == 2  # one finding per artifact

    def test_text_token_matching_is_exact_per_token(self, cfg: Config) -> None:
        r = rule(
            [
                {"type": "ip", "fields": ["search_text"], "text": True},
                {"type": "domain", "fields": ["search_text"], "text": True},
            ],
            "log",
        )
        s = iocs(
            {"type": "ip", "value": "198.51.100.23"}, {"type": "domain", "value": "c2.example.test"}
        )
        hit = rec("log", search_text="curl http://c2.example.test/x and 198.51.100.23")
        near = rec(
            "log",
            search_text="curl http://c2.example.test.evil.test/x 198.51.100.230 1198.51.100.23",
        )
        f, _ = run(r, s, [hit, near], cfg)
        assert len(f) == 1 and len(f[0].ioc["all_matches"]) == 2

    def test_missing_field_is_not_a_match(self, cfg: Config) -> None:
        r = rule([{"type": "ip", "fields": ["remote_address"]}])
        assert (
            run(r, iocs({"type": "ip", "value": "192.0.2.1"}), [rec("network", other=1)], cfg)[0]
            == []
        )

    def test_finding_carries_indicator_severity_and_source_artifact(self, cfg: Config) -> None:
        r = rule([{"type": "ip", "fields": ["remote_address"]}])
        s = iocs(
            {
                "type": "ip",
                "value": "192.0.2.1",
                "severity": "critical",
                "description": "d",
                "references": ["https://x.test"],
            }
        )
        f = run(r, s, [rec("network", remote_address="192.0.2.1")], cfg)[0][0]
        assert f.severity == "critical" and f.ioc["value"] == "192.0.2.1"
        assert f.evidence_ref == "x.json#0" and f.category == "ioc_match"
