# Troubleshooting

Run `python -m mac_threat_hunter doctor` first; it checks Python, PyYAML, the platform, the
configuration, the allowlists and the rules.

| Symptom | Cause | Fix |
| --- | --- | --- |
| `No module named mac_threat_hunter` | Virtualenv not active or package not installed | `source .venv/bin/activate && python -m pip install -e ".[dev]"` |
| `requires Python >= 3.11` at install | Old interpreter | Use `python3.11` or newer to create the venv |
| `collect` says `unsupported` / exits without data | Live collection runs on macOS only | Use the synthetic evidence, or run on a Mac |
| `Evidence directory not found` (exit 3) | Wrong `--input` path | Point at the folder that contains `manifest.json` |
| `SHA-256 does not match manifest` warning | A file changed after collection | Treat results as unreliable; re-collect. For synthetic demo copies only, `scripts/refresh_manifest.py` |
| `no telemetry` (exit 5) | Evidence contains no usable records | Check `collector_status` in `manifest.json` for failures |
| Many rules "skipped" | They need `--iocs` or `--baseline` | Supply them; skipped rules are listed, never silently dropped |
| `rules validate` fails (exit 4) | Rule breaks the schema or regex limits | Read the message (file, rule id, field); see [rule-authoring.md](rule-authoring.md) |
| Regex rejected | Pattern over 300 chars, nested quantifier, backreference, lookaround | Simplify; these limits prevent catastrophic backtracking |
| `baseline create` refuses | File exists | Add `--force` only if you mean to replace it |
| Baseline integrity error | File edited by hand or corrupted | Re-create it; the hash detects accidents, not tampering |
| Empty process/socket lists on macOS | Unprivileged user cannot see other users' items | Expected; recorded as a privilege note, not an error. The tool never uses sudo |
| `log show` is slow or empty | Wide time window, or logs not readable | Narrow `--last`, use `--logarchive` or `--log-file` |
| `codesign` fields missing | Lookup cap reached or binary unreadable | Raise `codesign_max_lookups` in the config |
| Output truncated | A resource limit was hit | Limits and truncation are reported in the results; raise them in `configs/default.yaml` copy |
| Unexpected zero findings | Absence of findings is not a clean bill of health | Check which sources were analysed in the report |

## Exit codes

`0` ok, `1` a finding met `--fail-on`, `2` usage error, `3` bad input, `4` validation error,
`5` no telemetry.

## Still stuck

Open an issue with the output of `doctor`, the command line, and (redacted) error text. Do not
attach real evidence; see [SECURITY.md](../SECURITY.md).
