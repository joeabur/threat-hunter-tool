"""Documentation must match the implementation: links resolve and documented commands parse."""

import re
import shlex
from pathlib import Path

import pytest

from conftest import ROOT
from linux_threat_hunter.cli import build_parser

DOCS = sorted((ROOT / "docs").glob("*.md")) + [ROOT / "README.md"]
REQUIRED_DOCS = [
    "getting-started",
    "walkthrough",
    "user-guide",
    "rule-authoring",
    "configuration",
    "troubleshooting",
    "security-and-limitations",
    "architecture",
    "detection-coverage",
    "examples",
]


def test_required_docs_exist_and_readme_links_all() -> None:
    readme = (ROOT / "README.md").read_text()
    for name in REQUIRED_DOCS:
        assert (ROOT / "docs" / f"{name}.md").is_file(), name
        assert f"docs/{name}.md" in readme, f"README does not link docs/{name}.md"
    for f in ("LICENSE", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md", "CHANGELOG.md"):
        assert (ROOT / f).is_file(), f


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_relative_links_resolve(doc: Path) -> None:
    for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", doc.read_text()):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        assert (doc.parent / target).resolve().exists(), f"{doc.name}: broken link {target}"


def documented_commands() -> list[tuple[str, str]]:
    cmds = []
    for doc in DOCS:
        text = doc.read_text()
        for block in re.findall(r"```(?:bash|sh|console)?\n(.*?)```", text, flags=re.S):
            joined = block.replace("\\\n", " ")
            for line in joined.splitlines():
                line = line.strip().removeprefix("$ ").strip()
                if (
                    line.startswith("python -m linux_threat_hunter")
                    and "<" not in line
                    and "#" not in line.split("linux_threat_hunter", 1)[1][:1]
                ):
                    cmds.append((doc.name, line))
    return cmds


def test_documented_commands_exist_and_parse() -> None:
    cmds = documented_commands()
    assert len(cmds) >= 25
    parser = build_parser()
    for doc, line in cmds:
        argv = shlex.split(line.split(" #")[0])[3:]
        try:
            parser.parse_args(argv)
        except SystemExit as exc:  # argparse error
            raise AssertionError(f"{doc}: documented command does not parse: {line}") from exc


def test_documented_example_paths_exist() -> None:
    for doc in DOCS:
        for path in re.findall(r"(?:examples|configs|rules|scripts)/[\w./-]+\.(?:json|ya?ml|sh|log)", doc.read_text()):
            assert (ROOT / path).exists(), f"{doc.name}: references missing file {path}"
