# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - Unreleased

### Added
- Read-only Linux collectors: host, process, network (`ss`), persistence (systemd, cron, shell startup, SSH metadata, rc, optional modules), authentication logs, selected files.
- Declarative rule engine (match, threshold, sequence, baseline, IOC, correlation) with schema validation and resource limits.
- 33 detection rules across process, persistence, authentication, network, file integrity and correlation.
- IOC matching (SHA-256, process names, file paths, IPs, domains), baseline create/validate/compare/update, ATT&CK registry.
- JSON, CSV and Markdown reports with redaction and injection hardening.
- CLI: `info`, `doctor`, `rules`, `collect`, `hunt`, `show`, `trace`, `report`, `baseline`.
- Synthetic evidence, demo script, walkthrough with five exercises, documentation and CI workflows.
