# Rule authoring

Rules are YAML (or JSON) files, one rule per file, under a directory passed with `--rules` (or
`rules/`). They are validated before any hunt; an invalid rule stops the hunt (exit 4). Rules are
purely declarative: unknown keys (including anything resembling `script`, `exec`, `python`) are
rejected, YAML is loaded with `safe_load`, and nothing in a rule is ever evaluated as code.
`schemas/rule.schema.json` describes the structure for editors; the loader also checks semantics
(known allowlist names, regex safety, ATT&CK catalogue membership).

## Pattern rule

```yaml
id: MTH-EXEC-001                 # MTH-<LETTERS>-<3 digits>, unique
name: Process executing from a user-writable location
version: 1                       # bump when behaviour changes
type: pattern                    # pattern (default) | ioc | baseline
source: process                  # or a list: system, process, persistence, network, file, log
description: ...
rationale: ...                   # why this is worth a look
severity: medium                 # informational|low|medium|high|critical
confidence: medium               # low|medium|high
title: "Process running from writable location: {name}"   # {field} placeholders only
requires: [path]                 # records lacking these are skipped and counted, never guessed
context_fields: [sha256]         # optional fields reported under "missing context" when absent
conditions:
  all:  [ {field: path, op: path_under, value: "$setting:writable_locations"} ]
  any:  [ ... ]
  none: [ {field: path, op: path_under, value: "$allowlist:writable_location_exceptions"} ]
threshold:                       # optional: N matching records for one group within a window
  count: 5
  window_seconds: 300
  group_by: src_ip
evidence_fields: [pid, name, path, cmdline]
attack:
  techniques: [T1059]
  justification: "At least 20 characters explaining why the rule's behaviour IS this technique."
false_positives: [ ... ]         # required, non-empty
investigation: [ ... ]           # required, non-empty
references: [ ... ]
```

Groups `all`, `any`, `none` may nest (depth 3, 60 conditions maximum). A condition is
`{field, op, value}` where `field` is a lowercase dotted name in the normalised record.

### Operators

`equals`, `not_equals`, `iequals`, `in`, `not_in`, `startswith`, `endswith`, `contains`,
`icontains`, `startswith_any`, `endswith_any`, `contains_any`, `regex`, `iregex`, `exists`
(true/false), `gt`, `gte`, `lt`, `lte`, `path_under` (boundary-aware, normalises `..`, glob
entries allowed), `glob`.

**Missing fields never match** (including `not_equals`/`not_in`): use `exists: false` to assert
absence. This is deliberate so that missing telemetry cannot create findings.

### List references

`value: "$allowlist:<name>"` or `"$setting:writable_locations"` for list operators.
Unknown names fail validation.

### Regexes

Bounded: at most 300 characters, repetition counts up to 200, no nested quantifiers (`(a+)+`), no
backreferences or lookarounds. Input is truncated to `limits.max_regex_input_chars`. This is a
defence against catastrophic backtracking, not a guarantee; keep patterns simple and anchored.

### Thresholds

Matching records are grouped by `group_by`; a finding is emitted for a group when `count` records
fall inside any `window_seconds` window (inclusive). Records without a timestamp or group value are
skipped and counted. Tune with `rule_overrides` rather than editing the rule. Document the common
causes of the pattern (scanners, automation, typos) in `false_positives`.

## IOC rule

```yaml
type: ioc
source: network
ioc:
  matches:
    - {type: ip,     fields: [remote_address]}
    - {type: domain, fields: [remote_host]}
    - {type: ip, fields: [search_text], text: true}   # exact IP tokens inside free text
```

Types: `sha256`, `process_name`, `path`, `ip`, `domain`. One finding is produced per record
listing every indicator that hit it.

## Baseline rule

```yaml
type: baseline
source: file
baseline: {category: files, change: added, filters: {all: [{field: is_executable, op: equals, value: true}]}}
```

Categories: `persistence`, `files`, `listeners`, `config`; changes: `added`, `removed`, `modified`.

## Normalised fields (selection)

| Source | Fields |
|---|---|
| process | `pid`, `ppid`, `user`, `name`, `path`, `cmdline`, `search_text`, `sha256`, `codesign_status`, `parent_name`, `parent_path`, `ancestors`, `script_path`, `inline_script` |
| persistence | `kind`, `path`, `label`, `owner`, `mode`, `world_writable`, `group_writable`, `program_path`, `program_exists`, `program_sha256`, `program_arguments`, `run_at_load`, `keep_alive`, `lines_of_interest`, `search_text` |
| network | `proto`, `state`, `is_listener`, `local_address`, `local_port`, `local_is_loopback`, `remote_address`, `remote_host`, `remote_port`, `pid`, `process_name`, `process_path`, `process_association` |
| file | `path`, `kind`, `owner`, `mode`, `size`, `sha256`, `is_executable`, `is_macho`, `age_days`, `world_writable` |
| log | `process`, `process_path`, `pid`, `message`, `search_text`, `subsystem`, `auth_result`, `auth_user`, `src_ip` |
| system | `security_sip`, `security_gatekeeper`, `security_filevault`, `security_firewall`, `os_version`, `os_build`, `hostname` |

## Safe rule design

1. Describe observable behaviour, not a conclusion ("script run from /tmp", not "malware").
2. Prefer exact fields and anchored patterns; add `none` allowlist exclusions.
3. Use `requires` for any field the claim depends on.
4. Map ATT&CK only when the behaviour *is* the technique, and write the justification.
5. Write realistic false positives and next steps; a rule without them will not load.
6. Add a positive and a false-positive test; see `tests/integration/test_detections.py`.

Validate: `python -m mac_threat_hunter rules validate path/to/rules`. After adding a rule, run
`python scripts/gen_coverage.py` and, if the demo output changes,
`python scripts/update_expected_results.py` and review the diff.
