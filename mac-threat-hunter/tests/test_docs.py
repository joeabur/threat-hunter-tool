"""Documentation consistency: generated docs, internal links and documented CLI commands."""

from __future__ import annotations

import re
import runpy
import shlex
from pathlib import Path

import pytest

from mac_threat_hunter.cli import build_parser

ROOT = Path(__file__).resolve().parents[1]
DOCS = sorted([*ROOT.glob("*.md"), *(ROOT / "docs").glob("*.md")])
REQUIRED = [
    "README.md", "docs/getting-started.md", "docs/walkthrough.md", "docs/user-guide.md",
    "docs/rule-authoring.md", "docs/configuration.md", "docs/troubleshooting.md",
    "docs/security-and-limitations.md", "docs/architecture.md", "docs/detection-coverage.md",
    "docs/examples.md", "LICENSE", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md",
    "CHANGELOG.md", ".gitignore", ".pre-commit-config.yaml",
]  # fmt: skip


def test_required_files_exist() -> None:
    assert [p for p in REQUIRED if not (ROOT / p).is_file()] == []


def test_coverage_doc_is_current() -> None:
    generated = runpy.run_path(str(ROOT / "scripts" / "gen_coverage.py"))["main"]()
    assert (ROOT / "docs" / "detection-coverage.md").read_text(encoding="utf-8") == generated


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_internal_links_resolve(doc: Path) -> None:
    text = doc.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        path = target.split("#", 1)[0]
        assert (doc.parent / path).exists(), f"{doc.name}: broken link {target}"


def test_documented_commands_parse() -> None:
    parser = build_parser()
    seen = 0
    for doc in DOCS:
        text = doc.read_text(encoding="utf-8")
        for block in re.findall(r"```bash\n(.*?)```", text, re.S):
            joined = re.sub(r"\\\n\s*", " ", block)
            for line in joined.splitlines():
                line = line.split(" | ")[0].split(" #")[0].split("; ")[0].strip()
                if not line.startswith("python -m mac_threat_hunter ") or "[" in line:
                    continue
                argv = shlex.split(line)[3:]
                argv = [a for a in argv if a not in (">", "2>&1")]
                try:
                    parser.parse_args(argv)
                except SystemExit as exc:  # argparse exits on error
                    pytest.fail(f"{doc.name}: cannot parse `{line}` ({exc.code})")
                seen += 1
    assert seen >= 10
