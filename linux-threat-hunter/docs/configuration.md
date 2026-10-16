# Configuration

Defaults are built in and mirrored in `configs/default.yaml` (a test keeps them identical). Pass overrides with `--config my.yaml`; only the keys you set change. Unknown top-level keys are an error (exit 2).

```bash
python -m linux_threat_hunter hunt --input ./evidence --config my.yaml --allowlists configs/allowlists.yaml
```

## Top-level keys

| Key | Default | Meaning |
|---|---|---|
| `config_version` | `1` | schema version |
| `limits` | see below | resource limits for inputs, rules and subprocesses |
| `redaction` | patterns + `[REDACTED]` | regexes whose matches are replaced in collected data and all output |
| `collection` | see below | what the collectors look at |
| `variables` | see below | lists referenced by rules as `$name` |
| `disabled_rules` | `[]` | rule IDs to skip |
| `rule_overrides` | `{}` | per-rule `severity`, `confidence`, `params`, `enabled` |
| `allowlists` | `{}` | conditions that suppress known-good records (`'*'` or a rule ID) |

## `limits`

| Option | Default | Meaning |
|---|---|---|
| `max_evidence_file_bytes` | 52428800 | largest evidence file that will be read |
| `max_records_per_source` | 200000 | records/lines read per source (rest ignored with a warning) |
| `max_line_length` | 4096 | auth log line truncation |
| `max_findings_per_rule` | 500 | findings kept per rule (the cap is reported) |
| `max_rule_file_bytes` | 262144 | largest rule, config, IOC or allowlist file |
| `max_regex_length` | 256 | longest regex a rule/config may contain (max 1024) |
| `max_regex_input_chars` | 4096 | characters of a field a regex sees |
| `max_condition_depth` | 6 | nesting of `all/any/not` |
| `max_list_values` | 1000 | list size in conditions |
| `subprocess_timeout_seconds` | 15 | timeout for `ss`, `ip`, `who`, `journalctl` |
| `subprocess_max_output_bytes` | 8388608 | output kept from a subprocess |
| `max_hash_file_bytes` | 67108864 | files larger than this are not hashed |

All limits must be positive integers.

## `collection`

| Option | Default | Meaning |
|---|---|---|
| `process_hashing` | `true` | SHA-256 of process executables (read via `/proc/<pid>/exe`) |
| `auth_log_paths` | `/var/log/auth.log`, `/var/log/secure` | first readable file wins; else journald |
| `auth_log_max_bytes` | 5242880 | only the tail of the log is read |
| `journal_since`, `journal_max_lines` | `7 days ago`, 20000 | bounded journald fallback |
| `systemd_dirs` | `/etc/systemd/system`, `/etc/systemd/user`, `/run/systemd/system`, `/usr/local/lib/systemd/system` | plus each user's `~/.config/systemd/user` |
| `systemd_vendor_dirs_full` | `/usr/lib/systemd/system`, `/lib/systemd/system` | added by `--profile full` |
| `cron_files`, `cron_dirs` | `/etc/crontab`; `/etc/cron.d`, `cron.hourly|daily|weekly|monthly`, `/var/spool/cron[/crontabs]` | cron locations |
| `shell_startup_files`, `shell_startup_dirs`, `user_shell_files` | `/etc/profile`, `/etc/bash.bashrc`, `/etc/zsh/zshrc`; `/etc/profile.d`; `.bashrc`, `.profile`, `.bash_profile`, `.zshrc`, `.bash_logout` | shell startup |
| `ssh_config_files`, `ssh_config_dirs` | `/etc/ssh/sshd_config`; `/etc/ssh/sshd_config.d` | SSH daemon config (private keys are never read; `authorized_keys` is hashed only) |
| `rc_files` | `/etc/rc.local`, `/etc/ld.so.preload` | startup-related files |
| `file_integrity_paths` | `/etc/passwd`, `/etc/group`, `/etc/sudoers`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/ssh/sshd_config`, `/etc/ld.so.preload`, `/etc/crontab`, selected `/etc/pam.d/*` | hashed with owner/mode. Sensitive files (`shadow`, private keys, ...) are refused even if listed |
| `executable_scan_dirs`, `executable_scan_max_entries` | `/tmp`, `/var/tmp`, `/dev/shm`; 500 | executables looked for (depth 2) |
| `max_users` | 200 | home directories inspected |
| `max_unit_bytes`, `content_excerpt_bytes` | 65536, 16384 | content stored per artifact |

## `variables`

| Variable | Default | Used by |
|---|---|---|
| `writable_dirs` | `/tmp`, `/var/tmp`, `/dev/shm`, `/home/*/.cache` | writable-location rules |
| `suspicious_command_patterns` | 4 bounded regexes (download piped to shell, `/dev/tcp/ip/port`, base64 decode piped to shell, `nc -e`) | command-pattern rules |
| `sudo_suspicious_patterns` | root shell / `su` / edits of sudoers, shadow, passwd | `LTH-AUTH-004` |
| `shell_names`, `server_process_names` | common shells; nginx, apache2, httpd, php-fpm, mysqld, postgres, redis-server | `LTH-PROC-003` |
| `security_config_dirs` | `/etc` | file permission/ownership rules |

## `rule_overrides`

```yaml
rule_overrides:
  LTH-AUTH-001:
    severity: high          # optional
    confidence: medium      # optional
    params:
      count: 10
      window_seconds: 600
  LTH-NET-002:
    enabled: false
```

Allowed keys are `severity`, `confidence`, `params`, `enabled`; anything else is rejected.

## `allowlists`

```yaml
allowlists:
  '*':                      # every rule
    - {field: user, op: equals, value: backup-svc}
  LTH-PROC-001:
    - {field: exe, op: startswith, value: /tmp/.mount_}   # AppImage mounts, ticket SEC-123
```

Entries use the [condition grammar](rule-authoring.md) and are validated at start-up. Suppressed records are counted per rule in the report (`suppressed`). Always record why an entry exists.

## `redaction`

`patterns` replace matches; if a pattern has a capture group 1, the group is kept and the rest replaced (so `--password hunter2` becomes `--password [REDACTED]`). Defaults cover `--password/--token/--secret/--api-key`, `key=value` pairs, `Authorization: Bearer ...`, credentials in URLs, and AWS access key IDs. Redaction is best-effort pattern matching; review outputs before sharing.

## Environment

`LTH_RULES_DIR`: directory of rules to use when `--rules-dir` is not given.
