# Security and limitations

## Purpose and non-goals

Linux Threat Hunter helps authorized analysts look for suspicious activity. It is **not** an EDR, antivirus, or remediation tool. By design it never kills processes, disables accounts, modifies services, deletes files, changes firewall rules, installs software, or invokes `sudo`.

## Threat model

| Asset | Threat | Mitigation |
|---|---|---|
| The analyst's machine | malicious evidence (crafted logs, YAML, JSON, filenames) | no code from data is evaluated; YAML uses `safe_load`; rule/IOC/config files are size-limited and schema-validated; regexes bounded; evidence files must be regular files (symlinks refused); records and lines capped |
| The monitored host | collection side effects | read-only reads; no execution of discovered binaries, unit commands, cron commands or scripts; subprocesses use argv lists (never a shell), a fixed `PATH`, a timeout and an output limit; the only external programs are `ss`, `ip`, `who`, `journalctl` |
| Sensitive data | leakage through evidence or reports | command lines, unit/cron/startup content and logs are redacted by configurable patterns at collection and again in every report; private keys, `shadow`/`gshadow` and similar files are never read (also enforced if a config lists them); `authorized_keys` is hashed, never stored; no network transmission of any kind |
| Report consumers | injection via report content | CSV cells starting with `= + - @` are prefixed; Markdown text is escaped; evidence JSON is fenced and fence-breaking text neutralised |
| Output integrity | overwriting or redirecting writes | output directories that are symlinks or files are refused; evidence/baselines are not replaced without an explicit flag; manifests carry per-file SHA-256 values and mismatches are reported |

## Privileges

Everything runs as the invoking user. Collection is more complete with extra read access (for example root-owned logs, other users' `/proc/<pid>/exe`, `/etc/sudoers`), but the tool never requests it. `collect --dry-run` and `doctor` show what each collector needs. Grant access through your organization's approved process and run the tool under that account.

## Privacy and evidence handling

Evidence directories, baselines, results and reports can contain usernames, hostnames, IP addresses, command lines and log lines, even after redaction (redaction is best-effort and pattern-based). Keep them private, restrict permissions, do not upload them to third-party services, and follow your organization's retention policy. The repository ignores evidence, results, reports and baselines in `.gitignore`; do not commit real ones.

## What findings mean

- A finding is a **lead**. Severity and confidence are separate; neither proves compromise.
- Kinds: *observation* (recorded fact), *heuristic*, *ioc_match*, *correlation*. Reports keep them distinct.
- Common explanations (administrators, package updates, scanners, automation, service accounts) are listed per finding.
- An IOC match shows equality with an indicator, not guilt. Indicator lists can be stale or over-broad.
- ATT&CK mappings are relations, not confirmations. Techniques not listed are not implied absent.

## Blind spots and limitations

- **Snapshots.** Processes, sockets and file state are captured at one moment; short-lived activity is missed. PID reuse across time is not handled.
- **Visibility.** Without privileges many attributes are unreadable; containers see only their namespace; hidden processes (rootkits), kernel-level activity and in-memory-only payloads are out of scope.
- **Logs.** Only a bounded tail of one auth log (or a bounded journald query) is read; rotated/compressed logs, remote logs and `auditd` are not. Log content can be forged by an attacker with sufficient access, and log gaps cannot be distinguished from absence of events.
- **Timestamps.** Syslog timestamps lack year and zone; they are interpreted using the manifest. Wrong manifest data gives wrong times. Snapshot-based findings carry collection time only (`timestamp_basis: collection`).
- **Baselines.** They preserve malicious state, go stale, and the integrity hash does not stop a determined editor.
- **Coverage.** A small, documented set of rules (see [detection coverage](detection-coverage.md)). Absence of findings is not assurance.
- **Regex safety.** Length and structure checks reduce but cannot eliminate pathological patterns; input is truncated before matching.
- **Platforms.** Live collection is Linux-only and verified on Ubuntu 24.04; other distributions are expected to work but are not verified. Non-Linux hosts can analyze evidence only.

## Safe usage checklist

1. Have written authorization for the host.
2. Run `collect --dry-run`, then collect as the account you are authorized to use.
3. Store evidence with restricted permissions on an appropriate system.
4. Hunt with IOCs and a baseline made from trusted data when possible.
5. Validate each finding (rule out the listed false positives) before escalating.
6. Never treat "no findings" as "clean".
7. Take any containment action through your incident-response process, outside this tool.
