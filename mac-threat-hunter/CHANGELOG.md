# Changelog

All notable changes are documented here. Format follows Keep a Changelog; versioning follows SemVer.

## [0.1.0] - Unreleased

### Added
- Read-only macOS collectors: system, processes, network, persistence, files, unified log.
- Evidence manager with SHA-256 manifest, traversal/symlink protection and resource caps.
- Declarative YAML rules engine (36 rules), bounded regex, thresholds, allowlists, suppressions.
- IOC engine (exact matching by default) and baseline create/compare/update with integrity hash.
- MITRE ATT&CK mapping with justifications; Markdown, JSON and CSV reports with redaction.
- CLI: `info`, `doctor`, `rules list|validate`, `collect`, `hunt`, `baseline`, `report`.
- Synthetic evidence, demo script, walkthrough, documentation set and CI workflows.
