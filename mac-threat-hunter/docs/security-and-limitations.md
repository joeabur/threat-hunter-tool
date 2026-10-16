# Security model and limitations

## What this tool is

A read-only, explainable hunting aid for macOS endpoints you own or are explicitly authorised to
examine. It collects a bounded set of metadata, applies declarative rules, and reports **leads**.

## What this tool is not

- **Not an EDR or antivirus.** It does not block, quarantine, remediate or monitor continuously.
- **Not a complete detector.** It does not detect all macOS malware. Its coverage is the rules in
  [detection-coverage.md](detection-coverage.md) and nothing else.
- **Not proof either way.** A finding is not a verdict; no findings is not a clean bill of health.
- **Not a forensic acquisition tool.** Evidence is live-system metadata, not a disk image.
- **Live collectors are lightly tested.** They were developed
  against recorded command output and mocks; the macOS CI job exercises them on GitHub's runners.
  Output formats of `lsof`, `log`, `codesign` and `spctl` vary between macOS versions.

## Safety guarantees (and how they are enforced)

| Guarantee | Mechanism |
| --- | --- |
| Read-only | Collectors only read; subprocesses are a fixed allowlist of commands run without a shell, with timeout and output cap (`utils/proc.py`) |
| No privilege escalation | Never calls `sudo`; unreadable items become recorded privilege notes |
| Never executes discovered files | Files are hashed/stat'ed/parsed as data; `codesign -dv` inspects but does not run |
| Path safety | Evidence loader rejects traversal and symlinks; manifest hashes are verified |
| Bounded regex | Length, repetition and construct limits; input truncated before matching |
| Bounded resources | Caps on file size, records, findings, rules, IOCs and subprocess output |
| Redaction | Secrets, tokens, passwords and home paths scrubbed on collection and again on report output |
| Safe reports | CSV formula-injection guard; Markdown escaping |
| No network | Nothing is uploaded; there are no network calls at runtime |

## Privacy

Process command lines, file paths, usernames and log messages can be sensitive. Redaction is
best-effort pattern matching; **review output before sharing**. Evidence directories and reports
are git-ignored by default. Store them with the same care as the host's own data.

## Known limitations

- Rootkits, kernel or firmware implants, and anything that hides from user-space tools are not seen.
- Without Full Disk Access some protected locations are unreadable; this tool does not request it.
- A sleeping attacker whose artifacts match no rule, or who mimics allowlisted names, will not be flagged.
- Baselines record what was observed, not what is safe; a compromised host's baseline encodes the compromise.
- Allowlisting by name or team ID can be abused; keep allowlists narrow and reviewed.
- Timestamps without a zone are treated as local time and labelled as assumed.
- Heuristics produce false positives; each rule documents its known ones.

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md).
