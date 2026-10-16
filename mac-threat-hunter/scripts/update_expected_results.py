#!/usr/bin/env python3
"""Regenerate examples/expected-results/expected-rule-hits.json from the synthetic demo.

Review the diff by hand: this file is the contract the tests and walkthrough rely on.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mac_threat_hunter.baseline.model import load_baseline  # noqa: E402
from mac_threat_hunter.config import default_rules_dir, load_config  # noqa: E402
from mac_threat_hunter.detections.runner import run_hunt  # noqa: E402
from mac_threat_hunter.evidence.loader import load_evidence  # noqa: E402
from mac_threat_hunter.ioc.loader import load_iocs  # noqa: E402
from mac_threat_hunter.rules_engine.loader import load_rules  # noqa: E402


def main() -> None:
    cfg = load_config()
    rules = load_rules([default_rules_dir()], cfg)
    ev = load_evidence(ROOT / "examples" / "synthetic-evidence", cfg)
    hunt = run_hunt(
        ev, rules, cfg,
        iocs=load_iocs(ROOT / "examples" / "iocs.json"),
        baseline=load_baseline(ROOT / "examples" / "baselines" / "clean-baseline.json"),
    )  # fmt: skip
    counts = Counter(f.rule_id for f in hunt.findings)
    doc = {
        "description": "Findings per rule when hunting examples/synthetic-evidence with "
        "examples/iocs.json and examples/baselines/clean-baseline.json",
        "total_findings": len(hunt.findings),
        "rule_hits": dict(sorted(counts.items())),
        "rules_with_no_hits_expected": sorted(r.id for r in rules.rules if r.id not in counts),
    }
    out = ROOT / "examples" / "expected-results" / "expected-rule-hits.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
