# Rule authoring

Rules are declarative YAML (or JSON) files under `rules/`. They are validated against a schema before every run. **Rules cannot contain executable code**: no Python, no shell, no templating beyond `{field}` substitution, and regular expressions are bounded.

## Anatomy

```yaml
id: LTH-PROC-001                  # LTH-<AREA>-<NNN>, unique
name: Process executing from a writable location
version: 1.0.0                    # semantic version of the rule
type: match                       # match | threshold | sequence | baseline | ioc | correlation
data_source: process              # process | persistence | auth | network | file | event | baseline | findings
severity: medium                  # informational | low | medium | high | critical  (impact if real)
confidence: medium                # low | medium | high  (weight of the condition alone)
classification: heuristic         # observation | heuristic | ioc_match | correlation
description: What the rule looks for.
rationale: Why that is worth an analyst's time.
conditions:                       # type-specific, see below
  all:
    - {field: exe, op: path_under, value: $writable_dirs}
    - not: {field: kernel_thread, op: equals, value: true}
allowlist: []                     # optional conditions that suppress known-good records
params: {}                        # thresholds etc. (overridable in config)
finding:
  title: "Process {name} (pid {pid}) is executing from {exe}"
  explanation: "Process {name} runs {exe}, which is under a writable directory."
  artifact: "pid {pid} {exe}"     # optional
attack:                           # optional; only where justified
  - {tactic: execution, technique: T1059.004}
false_positives: [ ... ]          # required, non-empty
investigation_steps: [ ... ]      # required, non-empty
limitations: [ ... ]              # optional: missing context shown in every finding
references: [ "https://..." ]     # optional, https only
```

`{field}` placeholders accept dotted names (`{fields.ExecStart}`); a missing field renders as `unknown`. Nothing else is interpolated.

## Conditions

A condition is a leaf `{field, op, value}` or a composite `all` / `any` / `not`.

| Operator | Meaning |
|---|---|
| `equals`, `not_equals` | scalar comparison |
| `in`, `not_in` | membership in a list |
| `contains` | substring (string field) or element (list field) |
| `contains_any` | any listed substring/element |
| `startswith`, `endswith` | string prefix/suffix |
| `regex`, `regex_any` | bounded regular expression(s), searched in the first 4096 characters |
| `gt`, `gte`, `lt`, `lte` | numeric comparison |
| `exists` | `true`/`false`: field presence |
| `path_under`, `not_path_under` | path is under any listed directory (normalized; `*` globs allowed, `/home/*/.cache`) |
| `text_references_path_under` | any absolute-path token in the text is under a listed directory |

**Missing fields never match** (except `exists: false`), so an unknown value is never treated as "missing" or "bad". For example `exec_exists: false` only matches when the collector recorded that the file did not exist.

**Variables.** `value: $name` references `variables.<name>` in the [configuration](configuration.md) (for example `$writable_dirs`, `$suspicious_command_patterns`). Users tune detections there without editing rules.

## Rule types

**match**: evaluate `conditions` per record; one finding per matching record.

**threshold**: records matching `conditions` are grouped by `group_by` and counted in a sliding window. `params: {count, window_seconds}`. One finding per burst (consecutive events within the window). Records without a usable timestamp are not counted (noted in the rule status).

```yaml
type: threshold
data_source: auth
conditions: {field: event, op: equals, value: ssh_failed}
group_by: [src_ip]
params: {count: 5, window_seconds: 300}
```

**sequence**: within each `group_by` group, a `then` event preceded by at least `count` `first` events within `window_seconds`.

```yaml
type: sequence
sequence:
  first: {field: event, op: equals, value: ssh_failed}
  then:  {field: event, op: equals, value: ssh_accepted}
group_by: [src_ip]
params: {count: 5, window_seconds: 900}
```

**baseline**: a change reported by the baseline comparison. `categories` (`persistence`, `files`, `executables`, `listeners`, `privileged_users`), `changes` (`added`, `removed`, `modified`) and an optional `where` condition evaluated on the change record (`kind`, `path`, `key`, `changed_fields`, current attributes). Skipped if no baseline was supplied or the category is not comparable.

```yaml
type: baseline
data_source: baseline
baseline:
  categories: [persistence]
  changes: [added, modified]
  where: {field: kind, op: equals, value: shell_startup}
```

**ioc**: records from `data_source` are matched against the IOC file for the listed `indicator_types` (`sha256`, `process_name`, `file_path`, `ip`, `domain`). Optional `group_by` collapses repeated identical matches into one finding with an `occurrences` count. Skipped without `--iocs`. See the matched fields per source in `ioc/matcher.py`.

**correlation**: link findings from other rules.

```yaml
type: correlation
data_source: findings
correlate:
  a: [LTH-PERS-001, LTH-PERS-004]
  b: [LTH-PERS-006]
  join_on: path              # pid | path | exec_path | ip | user | sha256
  require_event_time: false  # true: both findings must carry event timestamps
params: {window_seconds: 1800}   # optional; applies when both findings have event timestamps
```

Findings are linked **only** if they share the join identifier and satisfy the timing conditions. One correlation finding is produced per join value and lists every linked finding.

## Record fields by data source

| Source | Fields (main ones) |
|---|---|
| `process` | `pid`, `ppid`, `name`, `user`, `exe`, `cmdline`, `sha256`, `start_time`, `state`, `kernel_thread`, `parent_name`, `parent_exe` |
| `persistence` | `kind` (`systemd_service`, `systemd_timer`, `systemd_dropin`, `cron_file`, `cron_job`, `cron_script`, `shell_startup`, `ssh_config`, `ssh_authorized_keys`, `ld_preload`, `rc_script`, `kernel_module`), `path`, `owner`, `mode`, `mtime`, `sha256`, `content`, `commands`, `commands_text`, `exec_path`, `exec_exists`, `fields.*`; cron jobs add `schedule`, `cron_user`, `command`, `line_no` |
| `auth` | `event` (`ssh_failed`, `ssh_invalid_user`, `ssh_accepted`, `sudo_command`, `sudo_auth_failure`), `user`, `src_ip`, `port`, `method`, `command`, `target_user`, `timestamp`, `raw`, `line_no` |
| `network` | `proto`, `state`, `local_addr`, `local_port`, `remote_addr`, `remote_port`, `listening`, `pid`, `process`, `process_exe` |
| `file` | `path`, `owner`, `mode`, `world_writable`, `setuid`, `is_executable`, `sha256`, `source_dir`, `file_type` |
| `event` | `timestamp`, `user`, `command`, `source`, optional `src_ip`, `sha256` |

## Validation and resource limits

```bash
python -m linux_threat_hunter rules validate --rules-dir ./my-rules
```

Rejected: unknown keys or operators, malformed IDs or versions, invalid or non-registry ATT&CK IDs, a tactic that does not belong to the technique, non-https references, nested conditions deeper than `limits.max_condition_depth`, lists longer than `limits.max_list_values`, regexes longer than `limits.max_regex_length`, regexes with nested quantifiers (`(a+)+`) or backreferences, and rule files larger than `limits.max_rule_file_bytes`. At run time regex input is truncated to `limits.max_regex_input_chars` and findings per rule are capped by `limits.max_findings_per_rule`. A heuristic filter cannot prove a regex is safe; keep patterns simple and anchored.

## Writing good rules (false-positive guidance)

1. State the **rationale** and list **expected false positives** realistically (administrators, package managers, scanners, automation, service accounts, NAT).
2. Choose severity (impact if real) and confidence (weight of the condition) **separately**. Wide net, low confidence is fine; high severity does not make a weak signal high-confidence.
3. Prefer `observation` for facts and `heuristic` for judgments. Never write explanation text that asserts compromise.
4. Use thresholds and windows, document them, and make them overridable (`params`).
5. Map to ATT&CK only when the rule's behavior supports it. Leaving `attack` empty is correct for generic signals.
6. List missing context in `limitations` (what the rule cannot see).
7. Add tests: one true positive, and at least one near-miss that must **not** fire.
