# Architecture

```text
 macOS host                       evidence dir (read-only input)              outputs
 ┌──────────┐  collectors   ┌──────────────────────────┐  hunt   ┌──────────────────────────┐
 │ ps, lsof │──────────────▶│ manifest.json (hashes)   │────────▶│ results.json             │
 │ plists,  │  bounded,     │ processes/network/...json │         │ report.md / .json / .csv │
 │ log show │  no shell     │ unified_log.ndjson        │         └──────────────────────────┘
 └──────────┘               └──────────────────────────┘
```

Collection and analysis are decoupled: you can collect on a Mac and hunt anywhere.

## Packages (`src/mac_threat_hunter/`)

| Package | Role |
| --- | --- |
| `cli.py` | argparse commands; maps `HunterError` subclasses to exit codes |
| `collectors/` | Read-only macOS collectors (`system`, `processes`, `network`, `persistence`, `files`, `logs`) behind a common `Collector` base with per-collector failure isolation |
| `utils/` | `proc` (bounded subprocess), `paths` (traversal/symlink checks), `redact`, `regexsafe`, `timeutil`, `errors` |
| `evidence/` | Manifest writing/verification and the loader (hash check, size/record caps) |
| `parsers/` | Normalise each source into `Record(source, data, ref, observed_at, ...)` |
| `rules_engine/` | YAML rule loading, JSON-schema validation, condition operators, evaluator (thresholds, `requires`, allowlists) |
| `ioc/` | IOC loading and exact/opt-in matching |
| `baseline/` | Baseline model, canonical hashing, comparison |
| `detections/runner.py` | `run_hunt()` orchestrates rules, IOCs and baselines into findings; stable IDs; suppressions |
| `attack/` | Curated MITRE ATT&CK catalogue with justifications |
| `reporting/` | Markdown/JSON/CSV rendering with redaction re-applied |

## Data flow for `hunt`

1. `load_evidence` verifies `manifest.json` hashes, applies caps, parses each file into records.
2. `load_ruleset` loads rules, validates against `schemas/rule.schema.json`, compiles bounded regexes.
3. `run_hunt` evaluates each rule against its source's records; rules lacking required data
   (IOC file, baseline, telemetry) are *skipped and reported*.
4. Findings carry class (`heuristic`, `ioc_match`, `baseline_change`), separate severity and
   confidence, ATT&CK mapping, evidence reference, explanation, false positives and next steps.
5. `reporting` writes results with redaction applied.

## Design decisions

- **Declarative rules** so analysts can read and review detections without reading Python.
- **Missing field never matches**, even for negated operators, to avoid false positives on absent data.
- **Severity ≠ confidence** so a strong behaviour with weak context is expressed honestly.
- **Per-collector degradation**: one failing collector never aborts the run; failures are reported.
- **Single dependency (PyYAML)** to keep the supply chain small.
- **Honest ATT&CK**: only techniques with a written justification are mapped.
