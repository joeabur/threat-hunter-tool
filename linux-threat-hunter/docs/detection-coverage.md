# Detection coverage

All shipped rules, generated from `rules/` and kept in sync by a test that fails if a rule ID is missing here. Run `python -m linux_threat_hunter rules list --format markdown` for the live list.

## How to read this

- **Severity** is the potential impact if the finding is real; **confidence** is how much weight the rule's condition deserves on its own. They are separate.
- **Kind** (`observation`, `heuristic`, `ioc_match`, `correlation`) is shown in every finding. An *observation* is a recorded fact (for example a file differs from the baseline); whether it matters needs analyst validation.
- **ATT&CK**: a *detection* is the evidence a rule looks for. A *technique* is a general adversary behavior. A mapping says the rule's behavior is **related** to the technique; it does not prove use of the technique. Rules without a justified mapping say `none`. Coverage is partial and not-observed techniques are not implied absent. Official pages follow `https://attack.mitre.org/techniques/T1053/003/`.

## Rules

| Rule | Name | Type | Evidence source | Severity / confidence | ATT&CK | Expected false positives |
|---|---|---|---|---|---|---|
| `LTH-AUTH-001` | Repeated failed SSH authentication | threshold | auth.log / secure / journald | medium / medium | T1110 | (1) Vulnerability scanners and authorized penetration tests. (2) Automation with an expired password or key. |
| `LTH-AUTH-002` | Successful SSH login after repeated failures | sequence | auth.log / secure / journald | high / medium | T1110 | (1) A legitimate user mistyping a password several times before succeeding. (2) Penetration tests and red-team exercises. |
| `LTH-AUTH-003` | New privileged account activity compared with baseline | baseline | baseline: privileged_users | medium / low | none | (1) Newly onboarded administrators. (2) Service accounts with sudo rules that run infrequently (and so were absent when the baseline was built). |
| `LTH-AUTH-004` | Suspicious sudo command pattern | match | auth.log / secure / journald | low / low | T1548.003 | (1) Routine administration (sudo -i, sudo su -, visudo). (2) Configuration-management tools editing account files. |
| `LTH-AUTH-005` | Authentication from an analyst-supplied suspicious IP | ioc | auth.log / secure / journald | medium / medium | none | (1) The indicator list may be stale, over-broad or contain shared infrastructure (CDNs, scanners). (2) Security tooling or an analyst may legitimately handle the indicator (sandboxes, threat-intel lookups). |
| `LTH-COR-001` | Failed-login burst followed by successful login (same source) | correlation | other findings | high / medium | none | (1) Same causes as the linked rules: mistyped passwords, scanners, automation. |
| `LTH-COR-002` | New persistence artifact whose content matches an IOC | correlation | other findings | critical / medium | none | (1) A stale or over-broad IOC list combined with a legitimate new service. |
| `LTH-COR-003` | Suspicious process linked to unusual network endpoint | correlation | other findings | high / medium | none | (1) Development tools running from scratch directories that also open sockets. |
| `LTH-FILE-001` | Security-relevant file changed compared with baseline | baseline | baseline: files | medium / medium | none | (1) Package updates, configuration management runs and administrator edits. (2) /etc/resolv.conf and /etc/hosts are rewritten by network managers and containers. |
| `LTH-FILE-002` | Executable file in a watched writable directory | match | selected files (files.json) | medium / low | none | (1) Installer, build and test tooling that unpack helpers to /tmp. (2) Language runtimes caching compiled objects. |
| `LTH-FILE-003` | World-writable security-relevant file | match | selected files (files.json) | high / high | none | (1) Rare, misconfigured lab or container images. |
| `LTH-FILE-004` | Unexpected owner on a security-relevant file | match | selected files (files.json) | high / medium | none | (1) Files deliberately delegated to a service account by an administrator. (2) Container or chroot images where UID mapping makes names differ. |
| `LTH-FILE-005` | File matches an analyst-supplied IOC | ioc | selected files (files.json) | high / medium | none | (1) The indicator list may be stale, over-broad or contain shared infrastructure (CDNs, scanners). (2) Security tooling or an analyst may legitimately handle the indicator (sandboxes, threat-intel lookups). |
| `LTH-NET-001` | Connection to an analyst-supplied suspicious endpoint | ioc | `ss -tunap` (network.json) | high / medium | none | (1) The indicator list may be stale, over-broad or contain shared infrastructure (CDNs, scanners). (2) Security tooling or an analyst may legitimately handle the indicator (sandboxes, threat-intel lookups). |
| `LTH-NET-002` | New listening service compared with baseline | baseline | baseline: listeners | medium / medium | none | (1) New legitimate services, development servers, containers publishing ports. (2) Ephemeral UDP listeners. |
| `LTH-NET-003` | Network endpoint owned by a process in a writable location | match | `ss -tunap` (network.json) | medium / medium | none | (1) Developer servers started from scratch directories. (2) Installers/updaters downloading from a temp location. |
| `LTH-PERS-001` | New or modified systemd service compared with baseline | baseline | baseline: persistence | medium / medium | T1543.002 | (1) Package installs and upgrades that add or change units. (2) Configuration management and legitimate administrator changes. |
| `LTH-PERS-002` | Persistence references a missing executable | match | systemd/cron/shell/SSH files (persistence.json) | low / medium | none | (1) Software removed without cleaning its units or cron entries. (2) Executables on not-yet-mounted filesystems. |
| `LTH-PERS-003` | Service command references a writable path | match | systemd/cron/shell/SSH files (persistence.json) | high / medium | T1543.002 | (1) Services deliberately using a private temp directory for scratch files (check whether it is the executable or only an argument). (2) Development or CI services. |
| `LTH-PERS-004` | New or modified cron entry compared with baseline | baseline | baseline: persistence | medium / medium | T1053.003 | (1) Package-provided cron jobs (logrotate, certbot) added or updated. (2) Administrator-scheduled maintenance. |
| `LTH-PERS-005` | Shell startup file changed compared with baseline | baseline | baseline: persistence | medium / medium | T1546.004 | (1) Users customizing prompts, aliases and PATH. (2) Version managers (nvm, pyenv) editing startup files. |
| `LTH-PERS-006` | Persistence artifact matches an analyst-supplied IOC | ioc | systemd/cron/shell/SSH files (persistence.json) | high / medium | none | (1) The indicator list may be stale, over-broad or contain shared infrastructure (CDNs, scanners). (2) Security tooling or an analyst may legitimately handle the indicator (sandboxes, threat-intel lookups). |
| `LTH-PERS-007` | Download-and-execute pattern in persistence commands | match | systemd/cron/shell/SSH files (persistence.json) | high / medium | T1059.004 | (1) Auto-update jobs that deliberately fetch scripts from a trusted internal source. (2) Documented bootstrap scripts. |
| `LTH-PERS-008` | New or modified systemd timer compared with baseline | baseline | baseline: persistence | medium / medium | T1053.006 | (1) Package updates (apt-daily, fstrim) and administrator scheduling. |
| `LTH-PERS-009` | Cron job command references a writable path | match | systemd/cron/shell/SSH files (persistence.json) | high / medium | T1053.003 | (1) Jobs that only write logs or temp output to /tmp (check whether the executable itself is there). |
| `LTH-PERS-010` | SSH authorized_keys changed compared with baseline | baseline | baseline: persistence | medium / medium | T1098.004 | (1) Users or automation rotating keys. (2) New administrators onboarded. |
| `LTH-PERS-011` | ld.so.preload added or changed | baseline | baseline: persistence | high / medium | T1574.006 | (1) Legitimate instrumentation or security products that preload libraries. |
| `LTH-PROC-001` | Process executing from a writable location | match | `/proc` snapshot (processes.json) | medium / medium | none | (1) Package managers, language runtimes, CI jobs and installers that unpack and run helpers from /tmp. (2) Developer workstations running locally built binaries from scratch directories. |
| `LTH-PROC-002` | Process matches an analyst-supplied IOC | ioc | `/proc` snapshot (processes.json) | high / medium | none | (1) The indicator list may be stale, over-broad or contain shared infrastructure (CDNs, scanners). (2) Security tooling or an analyst may legitimately handle the indicator (sandboxes, threat-intel lookups). |
| `LTH-PROC-003` | Shell spawned by a network-facing service | match | `/proc` snapshot (processes.json) | medium / medium | T1059.004 | (1) Applications that shell out by design (PHP system(), cron-like helpers, database admin scripts, backup hooks). (2) Legitimate maintenance run through a service's exec features. |
| `LTH-PROC-004` | Running executable changed since baseline | baseline | baseline: executables | medium / medium | none | (1) Package or kernel updates replacing binaries. (2) Self-updating software. |
| `LTH-PROC-005` | Suspicious command pattern in process command line | match | `/proc` snapshot (processes.json) | medium / low | T1059.004 | (1) Installers documented as 'curl ... | sh' (package bootstrap scripts). (2) Administrators testing connectivity with bash /dev/tcp or nc. |
| `LTH-PROC-006` | Suspicious command pattern in imported events | match | imported events (events.json) | medium / low | T1059.004 | (1) Documented installer one-liners. (2) Authorized testing. |

Each rule file also holds the full rationale, investigation steps, limitations and references; `show` prints them for any finding.

## ATT&CK techniques used

| Technique | Official title | Rules |
|---|---|---|
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Scheduled Task/Job: Cron | LTH-PERS-004, LTH-PERS-009 |
| [T1053.006](https://attack.mitre.org/techniques/T1053/006/) | Scheduled Task/Job: Systemd Timers | LTH-PERS-008 |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | LTH-PERS-007, LTH-PROC-003, LTH-PROC-005, LTH-PROC-006 |
| [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | Account Manipulation: SSH Authorized Keys | LTH-PERS-010 |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | LTH-AUTH-001, LTH-AUTH-002 |
| [T1543.002](https://attack.mitre.org/techniques/T1543/002/) | Create or Modify System Process: Systemd Service | LTH-PERS-001, LTH-PERS-003 |
| [T1546.004](https://attack.mitre.org/techniques/T1546/004/) | Event Triggered Execution: Unix Shell Configuration Modification | LTH-PERS-005 |
| [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | LTH-AUTH-004 |
| [T1574.006](https://attack.mitre.org/techniques/T1574/006/) | Hijack Execution Flow: Dynamic Linker Hijacking | LTH-PERS-011 |

Registry entries without a rule (T1110.001, T1078, T1021.004) are reserved for future rules and are not claimed as coverage.

## Correlation windows and limits

| Rule | Links | Joined on | Window |
|---|---|---|---|
| `LTH-COR-001` | LTH-AUTH-001 with LTH-AUTH-002 | `ip` | 1800 |
| `LTH-COR-002` | LTH-PERS-001, LTH-PERS-004 with LTH-PERS-006 | `path` | none (identifier only) |
| `LTH-COR-003` | LTH-PROC-001, LTH-PROC-002, LTH-PROC-003, LTH-PROC-005 with LTH-NET-001, LTH-NET-003 | `pid` | none (identifier only) |

Only findings sharing the identifier are linked. When both findings carry event timestamps and a window is set, the gap must be within it; `LTH-COR-001` additionally requires event timestamps on both sides. Findings that come from snapshots (processes, sockets, files) have only a collection time, so `LTH-COR-003` relies on the pid being valid within one collection run. PID reuse across time is not handled.

## Known gaps

These are not detected (or only weakly) and must not be assumed covered:

- Kernel-level or rootkit activity, fileless/in-memory execution, container escape, eBPF programs.
- Persistence outside the collected locations (for example `at` jobs, udev rules, PAM modules, `/etc/init.d` content analysis, user systemd units of users not under `/home` or `/root`).
- Credential access beyond SSH password failures (no Kerberos/LDAP/PAM-other analysis), and key-based brute force.
- Network behavior beyond socket state: no packet, DNS or flow analysis. Domain IOCs only match when the evidence records a hostname.
- Rotated or compressed logs, remote/centralized logs, auditd records.
- Process ancestry beyond one parent level, and anything requiring telemetry that was not collected.
- Kernel modules are collected in the `full` profile and compared in baselines, but no rule alerts on them yet.
- Time-of-check effects: everything is a snapshot at collection time.

Rules whose data is missing are reported as **skipped** with a reason, never as clean.
