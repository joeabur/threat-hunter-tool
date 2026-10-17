# threat-hunter-tool

Open-source, read-only threat hunting tools for Linux, macOS and Windows.

Each tool collects point-in-time telemetry from an authorized host (or analyses exported evidence), runs transparent detection rules mapped to MITRE ATT&CK, and writes evidence-backed reports. None of them remediate anything or execute what they discover. Findings are leads to validate, not verdicts.

| Tool | Language | Folder | Start here |
|---|---|---|---|
| Linux Threat Hunter | Python 3.11+ | [`linux-threat-hunter/`](linux-threat-hunter/) | [Getting started](linux-threat-hunter/docs/getting-started.md) |
| macOS Threat Hunter | Python 3.11+ | [`mac-threat-hunter/`](mac-threat-hunter/) | [Getting started](mac-threat-hunter/docs/getting-started.md) |
| Windows Threat Hunter | PowerShell 5.1 / 7 | [`windows-threat-hunter/`](windows-threat-hunter/) | [Getting started](windows-threat-hunter/docs/getting-started.md) |

Every tool ships synthetic fixtures, tests, a walkthrough and its own CI workflow under `.github/workflows/`. Use them only on systems you are authorized to examine. See each tool's `SECURITY.md` for reporting vulnerabilities.
