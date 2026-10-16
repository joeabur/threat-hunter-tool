from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from helpers import make_evidence
from mac_threat_hunter.baseline.compare import compare_observations, compare_to_baseline
from mac_threat_hunter.baseline.model import (
    canonical_hash,
    create_baseline,
    load_baseline,
    observations_from_evidence,
    validate_baseline_dict,
)
from mac_threat_hunter.config import Config
from mac_threat_hunter.evidence.loader import load_evidence
from mac_threat_hunter.utils.errors import InputError, PathSafetyError, ValidationError


class TestEvidenceLoading:
    def test_loads_synthetic_with_valid_hashes(self, synthetic: Path, cfg: Config) -> None:
        ev = load_evidence(synthetic, cfg)
        assert (
            ev.synthetic
            and not ev.integrity_failures
            and ev.hostname == "synthetic-mac.example.test"
        )
        assert ev.total_records() == 53 and ev.malformed_log_lines == 1

    def test_hash_mismatch_flagged_not_hidden(
        self, synthetic: Path, tmp_path: Path, cfg: Config
    ) -> None:
        dst = tmp_path / "ev"
        shutil.copytree(synthetic, dst)
        with (dst / "processes.json").open("a") as fh:
            fh.write("\n")
        ev = load_evidence(dst, cfg)
        assert ev.integrity_failures == ["processes.json"]
        assert any("does not match manifest" in w for w in ev.warnings)

    def test_no_manifest_warns(self, synthetic: Path, tmp_path: Path, cfg: Config) -> None:
        dst = tmp_path / "ev"
        shutil.copytree(synthetic, dst)
        (dst / "manifest.json").unlink()
        ev = load_evidence(dst, cfg)
        assert any("No manifest" in w for w in ev.warnings) and ev.total_records() > 0

    def test_manifest_traversal_is_contained(self, tmp_path: Path, cfg: Config) -> None:
        ev_dir = make_evidence(tmp_path / "ev", processes=[{"pid": 1, "name": "a"}])
        outside = tmp_path / "secret.json"
        outside.write_text('{"records":[{"pid":9,"name":"leak"}]}')
        manifest = json.loads((ev_dir / "manifest.json").read_text())
        manifest["files"].append(
            {"name": "../secret.json", "source": "process", "sha256": "0" * 64}
        )
        (ev_dir / "manifest.json").write_text(json.dumps(manifest))
        ev = load_evidence(ev_dir, cfg)
        assert all(r.data.get("name") != "leak" for r in ev.records["process"])
        assert any("secret.json" in w and "skipped" in w for w in ev.warnings)

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
    def test_symlinked_evidence_file_not_followed(self, tmp_path: Path, cfg: Config) -> None:
        ev_dir = make_evidence(tmp_path / "ev", processes=[{"pid": 1, "name": "a"}])
        target = tmp_path / "other.json"
        target.write_text('{"records":[{"pid":9,"name":"leak"}]}')
        (ev_dir / "processes.json").unlink()
        (ev_dir / "processes.json").symlink_to(target)
        ev = load_evidence(ev_dir, cfg)
        assert ev.records["process"] == [] and any("symlink" in w for w in ev.warnings)

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
    def test_symlinked_evidence_directory_refused(
        self, synthetic: Path, tmp_path: Path, cfg: Config
    ) -> None:
        link = tmp_path / "link"
        link.symlink_to(synthetic)
        with pytest.raises(PathSafetyError):
            load_evidence(link, cfg)

    def test_missing_directory_and_empty_directory(self, tmp_path: Path, cfg: Config) -> None:
        with pytest.raises(InputError):
            load_evidence(tmp_path / "nope", cfg)
        (tmp_path / "empty").mkdir()
        with pytest.raises(InputError):
            load_evidence(tmp_path / "empty", cfg)

    def test_malformed_json_file_is_skipped_with_warning(self, tmp_path: Path, cfg: Config) -> None:
        ev_dir = make_evidence(
            tmp_path / "ev", processes=[{"pid": 1, "name": "a"}], network=[{"state": "LISTEN"}]
        )
        (ev_dir / "network.json").write_text("{not json")
        ev = load_evidence(ev_dir, cfg)
        assert len(ev.records["process"]) == 1 and ev.records["network"] == []
        assert any("network.json" in w for w in ev.warnings)

    def test_malformed_manifest(self, tmp_path: Path, cfg: Config) -> None:
        ev_dir = make_evidence(tmp_path / "ev", processes=[{"pid": 1, "name": "a"}])
        (ev_dir / "manifest.json").write_text('{"files": "nope"}')
        with pytest.raises(InputError):
            load_evidence(ev_dir, cfg)

    def test_oversize_file_skipped(self, tmp_path: Path, cfg: Config) -> None:
        ev_dir = make_evidence(tmp_path / "ev", processes=[{"pid": 1, "name": "a" * 3000}])
        small = Config(**{**cfg.__dict__, "limits": {**cfg.limits, "max_evidence_file_mb": 1}})
        (ev_dir / "processes.json").write_text(
            '{"records":[' + '{"pid":1,"name":"a"},' * 100000 + '{"pid":2}]}'
        )
        ev = load_evidence(ev_dir, small)
        assert ev.records["process"] == [] and any("limit" in w for w in ev.warnings)

    def test_record_cap_reported(self, tmp_path: Path, cfg: Config) -> None:
        ev_dir = make_evidence(
            tmp_path / "ev", processes=[{"pid": i, "name": "a"} for i in range(50)]
        )
        capped = Config(**{**cfg.__dict__, "limits": {**cfg.limits, "max_records_per_source": 10}})
        ev = load_evidence(ev_dir, capped)
        assert len(ev.records["process"]) == 10 and "process" in ev.truncated_sources


class TestBaseline:
    def test_create_validate_roundtrip(self, clean: Path, tmp_path: Path, cfg: Config) -> None:
        ev = load_evidence(clean, cfg)
        bl = create_baseline(ev)
        path = tmp_path / "b.json"
        path.write_text(json.dumps(bl.to_dict()))
        loaded = load_baseline(path)
        assert loaded.observations == bl.observations
        assert any("compromise" in w for w in json.loads(path.read_text())["warnings"])

    def test_tampering_breaks_integrity(self, clean: Path, tmp_path: Path, cfg: Config) -> None:
        doc = create_baseline(load_evidence(clean, cfg)).to_dict()
        doc["observations"]["files"]["/etc/hosts"]["sha256"] = "f" * 64
        problems = validate_baseline_dict(doc)
        assert any("integrity hash mismatch" in p for p in problems)
        path = tmp_path / "b.json"
        path.write_text(json.dumps(doc))
        with pytest.raises(ValidationError):
            load_baseline(path)

    @pytest.mark.parametrize("mutate", [lambda d: d.pop("kind"), lambda d: d.update(schema_version=9),
                                        lambda d: d.update(observations=[]), lambda d: d.pop("integrity")])  # fmt: skip
    def test_schema_violations(self, clean: Path, cfg: Config, mutate) -> None:  # type: ignore[no-untyped-def]
        doc = create_baseline(load_evidence(clean, cfg)).to_dict()
        mutate(doc)
        assert validate_baseline_dict(doc)

    def test_invalid_json_baseline(self, tmp_path: Path) -> None:
        (tmp_path / "b.json").write_text("{")
        with pytest.raises(InputError):
            load_baseline(tmp_path / "b.json")

    def test_compare_added_removed_modified(self) -> None:
        before = {"persistence": {"/a": {"sha256": "1"}, "/b": {"sha256": "1"}}, "files": {}}
        after = {"persistence": {"/a": {"sha256": "2"}, "/c": {"sha256": "1"}}, "files": {}}
        by = {c.key: c for c in compare_observations(before, after)}
        assert by["/a"].change == "modified" and by["/a"].changed_attributes == ["sha256"]
        assert by["/b"].change == "removed" and by["/c"].change == "added"

    def test_synthetic_vs_clean_baseline_differences(
        self, synthetic: Path, repo_root: Path, cfg: Config
    ) -> None:
        ev = load_evidence(synthetic, cfg)
        changes = compare_to_baseline(
            load_baseline(repo_root / "examples/baselines/clean-baseline.json"), ev
        )
        keyed = {(c.category, c.key): c.change for c in changes}
        assert keyed[("persistence", "/Users/alice/.zshrc")] == "modified"
        assert keyed[("files", "/etc/hosts")] == "modified"
        assert (
            keyed[("persistence", "/Users/alice/Library/LaunchAgents/com.example.updater.plist")]
            == "added"
        )
        assert keyed[("listeners", "tcp/8000/python3")] == "added"
        assert keyed[("config", "security_gatekeeper")] == "modified"
        assert (
            "persistence",
            "/Library/LaunchDaemons/com.vendor.legit.plist",
        ) not in keyed  # unchanged

    def test_uncovered_categories_are_not_reported_as_removed(
        self, repo_root: Path, tmp_path: Path, cfg: Config
    ) -> None:
        only_procs = make_evidence(tmp_path / "ev", processes=[{"pid": 1, "name": "a"}])
        ev = load_evidence(only_procs, cfg)
        changes = compare_to_baseline(
            load_baseline(repo_root / "examples/baselines/clean-baseline.json"), ev
        )
        assert changes == []

    def test_listener_key_and_config_extraction(self, synthetic: Path, cfg: Config) -> None:
        obs = observations_from_evidence(load_evidence(synthetic, cfg))
        assert "tcp/8000/python3" in obs["listeners"]
        assert obs["config"]["security_sip"] == {"value": "enabled"}

    def test_canonical_hash_is_order_independent(self) -> None:
        assert canonical_hash({"a": 1, "b": 2}) == canonical_hash({"b": 2, "a": 1})
