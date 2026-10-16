import json
import sys
from pathlib import Path
from typing import Any

import pytest

from linux_threat_hunter.evidence import load_evidence, write_evidence
from linux_threat_hunter.evidence.store import EvidenceError


def test_missing_directory(config: dict[str, Any], tmp_path: Path) -> None:
    with pytest.raises(EvidenceError):
        load_evidence(tmp_path / "nope", config)


def test_empty_directory_degrades_gracefully(config: dict[str, Any], tmp_path: Path) -> None:
    ev = load_evidence(tmp_path, config)
    assert ev.available == set() and ev.total_records == 0
    assert any("manifest.json missing" in w for w in ev.warnings)


def test_malformed_inputs_become_warnings(config: dict[str, Any], tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text("{not json")
    (tmp_path / "processes.json").write_text('{"not": "a list"}')
    (tmp_path / "network.json").write_text('[1, 2, {"proto": "tcp"}]')
    (tmp_path / "files.json").write_bytes(b"\xff\xfe\x00garbage")
    (tmp_path / "auth.log").write_bytes(
        b"\xff\xfe binary \x00 junk\nOct 14 03:11:09 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2\n"
    )
    ev = load_evidence(tmp_path, config)
    joined = "\n".join(ev.warnings)
    assert "processes.json" in joined and "files.json" in joined and "manifest.json" in joined
    assert "process" not in ev.available and "file" not in ev.available
    assert len(ev.of("network")) == 1  # non-object entries skipped
    assert len(ev.of("auth")) == 1


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_symlinked_evidence_is_refused(config: dict[str, Any], tmp_path: Path) -> None:
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps([{"pid": 1, "name": "leak"}]))
    d = tmp_path / "ev"
    d.mkdir()
    (d / "processes.json").symlink_to(secret)
    ev = load_evidence(d, config)
    assert "process" not in ev.available and any("symlink" in w for w in ev.warnings)


def test_size_and_record_limits(config: dict[str, Any], tmp_path: Path) -> None:
    import copy

    cfg = copy.deepcopy(config)
    cfg["limits"]["max_records_per_source"] = 5
    (tmp_path / "processes.json").write_text(json.dumps([{"pid": i, "name": "x"} for i in range(50)]))
    ev = load_evidence(tmp_path, cfg)
    assert len(ev.of("process")) == 5 and any("truncated" in w for w in ev.warnings)
    cfg["limits"]["max_evidence_file_bytes"] = 10
    ev2 = load_evidence(tmp_path, cfg)
    assert "process" not in ev2.available and any("size limit" in w for w in ev2.warnings)


def test_hash_mismatch_is_reported(config: dict[str, Any], tmp_path: Path) -> None:
    write_evidence(
        tmp_path / "e", {"collected_at": "2025-10-14T09:00:00Z"}, {"processes.json": [{"pid": 1, "name": "a"}]}
    )
    assert not load_evidence(tmp_path / "e", config).warnings
    (tmp_path / "e" / "processes.json").write_bytes(b'[{"pid": 1, "name": "tampered"}]')
    assert any("does not match manifest" in w for w in load_evidence(tmp_path / "e", config).warnings)


def test_process_parent_enrichment_and_naive_event_time(config: dict[str, Any], tmp_path: Path) -> None:
    (tmp_path / "processes.json").write_text(
        json.dumps([{"pid": 1, "ppid": 0, "name": "init", "exe": "/sbin/init"}, {"pid": 2, "ppid": 1, "name": "sh"}])
    )
    (tmp_path / "events.json").write_text(json.dumps([{"timestamp": "2025-10-14T03:00:00", "command": "x"}]))
    ev = load_evidence(tmp_path, config)
    assert ev.of("process")[1].data["parent_name"] == "init"
    assert ev.of("event")[0].timestamp is None  # zone unknown: not guessed
