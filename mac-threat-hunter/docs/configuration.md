# Configuration

`configs/default.yaml` is always loaded; `--config FILE` overlays it (mappings merge, lists
replace). Unknown keys are rejected with exit code 4. Allowlists live in `configs/allowlists.yaml`
(`--allowlists` to replace).

| Key | Default | Meaning |
|---|---|---|
| `limits.max_evidence_file_mb` | 64 | Larger evidence files are skipped with a warning |
| `limits.max_records_per_source` | 200000 | Extra records ignored and reported |
| `limits.max_findings_per_rule` | 200 | Extra findings dropped and flagged `capped` |
| `limits.max_regex_input_chars` | 4096 | Text truncated before regex matching |
| `limits.max_rules` / `max_rule_file_kb` | 500 / 128 | Rule loading bounds |
| `limits.max_ioc_indicators` | 100000 | IOC file bound |
| `limits.max_log_output_mb` | 64 | Cap on `log show` output |
| `limits.subprocess_timeout_seconds` | 20 | Timeout per native command |
| `collection.profiles` | see file | Collector lists per profile |
| `collection.include_cmdline` | true | `false` omits command lines entirely |
| `collection.hash_max_mb` | 64 | Files above this are not hashed |
| `collection.hash_skip_prefixes` | sealed system paths | Not hashed or code-sign checked |
| `collection.codesign_max_lookups` | 150 | `codesign -dv` calls per collection |
| `collection.persistence_dirs` | LaunchAgents/Daemons, StartupItems | `system` and `per_user` (relative to each home) |
| `collection.shell_startup_files` | zsh/bash/profile files | `system` and `per_user` |
| `collection.login_hook_plist` | `/var/root/Library/Preferences/com.apple.loginwindow.plist` | Usually needs root |
| `collection.watch_directories` | `/private/tmp`, `/Users/Shared`, `~/Downloads`, ... | Shallow scan for executables; `~/` expands per home |
| `collection.config_files` / `config_dirs` | sudoers, hosts, sshd_config, ... | Metadata and hashes only |
| `collection.logs.default_window` / `max_window` | 1h / 7d | Unified-log window |
| `collection.logs.default_predicate` | auth/shell related processes | Must pass predicate validation |
| `redaction.enabled` | true | Disabling it is not recommended |
| `redaction.extra_patterns` | [] | Extra regexes; group 1 (if any) is kept |
| `redaction.replacement` | `[REDACTED]` | Replacement text |
| `writable_locations` | `/tmp`, `/Users/Shared`, `/Users/*/Downloads`, ... | Globs used by rules via `$setting:writable_locations` |
| `rule_overrides` | {} | Per rule: `enabled`, `severity`, `confidence`, `threshold.count/window_seconds` |
| `suppressions` | [] | See below |

Redaction runs at collection time, again when evidence is parsed, in findings, and again when
reports are written. Default patterns cover `password/token/secret/api key/authorization`
assignments and flags, bearer tokens, URL credentials, AWS-style access key IDs and PEM private
key headers. Redaction is pattern-based and best-effort: review evidence before sharing it.

## Suppressions

```yaml
suppressions:
  - rule_id: MTH-NET-001
    reason: "Approved developer web server on this lab host"   # required, >= 8 characters
    match: { process_name: python3 }                            # exact values on finding artifact/evidence fields
    expires: "2027-01-01"                                       # optional; expired entries are ignored with a warning
```

Suppressed findings stay in `results.json` and the report (marked suppressed with the reason).

## Allowlists (`configs/allowlists.yaml`)

Named lists referenced from rules as `$allowlist:<name>`: `trusted_exec_prefixes`,
`writable_location_exceptions`, `persistence_label_prefixes`, `shell_interpreters`,
`script_interpreters`, `expected_listener_processes`, `office_and_browser_parents`,
`security_config_paths`, `system_launch_dirs`. A permissive allowlist hides real findings: review
them for your fleet.
