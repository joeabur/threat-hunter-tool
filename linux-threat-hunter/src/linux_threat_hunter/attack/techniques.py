"""Technique IDs, official titles and tactics (MITRE ATT&CK Enterprise, Linux relevant).

This is a deliberately small registry: only techniques that a shipped rule maps to.
A rule's ATT&CK mapping states which technique its behavior is *related to*; it does not
prove that the technique was used, and the absence of a mapping does not mean absence of
the behavior.
"""

from __future__ import annotations

import re

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# id -> (official title, tactics)
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", ("execution",)),
    "T1053.003": ("Scheduled Task/Job: Cron", ("execution", "persistence", "privilege-escalation")),
    "T1053.006": (
        "Scheduled Task/Job: Systemd Timers",
        ("execution", "persistence", "privilege-escalation"),
    ),
    "T1543.002": (
        "Create or Modify System Process: Systemd Service",
        ("persistence", "privilege-escalation"),
    ),
    "T1546.004": (
        "Event Triggered Execution: Unix Shell Configuration Modification",
        ("privilege-escalation", "persistence"),
    ),
    "T1098.004": (
        "Account Manipulation: SSH Authorized Keys",
        ("persistence", "privilege-escalation"),
    ),
    "T1110": ("Brute Force", ("credential-access",)),
    "T1110.001": ("Brute Force: Password Guessing", ("credential-access",)),
    "T1078": (
        "Valid Accounts",
        ("defense-evasion", "persistence", "privilege-escalation", "initial-access"),
    ),
    "T1548.003": (
        "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        ("privilege-escalation", "defense-evasion"),
    ),
    "T1021.004": ("Remote Services: SSH", ("lateral-movement",)),
    "T1105": ("Ingress Tool Transfer", ("command-and-control",)),
    "T1574.006": (
        "Hijack Execution Flow: Dynamic Linker Hijacking",
        ("persistence", "privilege-escalation", "defense-evasion"),
    ),
}


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def validate_mapping(tactic: str, technique: str) -> list[str]:
    errors: list[str] = []
    if not TECHNIQUE_ID_RE.match(technique):
        return [f"invalid technique ID format: {technique!r}"]
    entry = TECHNIQUES.get(technique)
    if entry is None:
        return [f"technique {technique} is not in the registry (see attack/techniques.py)"]
    if tactic not in entry[1]:
        errors.append(f"tactic {tactic!r} is not a tactic of {technique} (valid: {', '.join(entry[1])})")
    return errors


def attack_entry(tactic: str, technique: str) -> dict[str, str]:
    title = TECHNIQUES[technique][0]
    return {
        "tactic": tactic,
        "technique": technique,
        "title": title,
        "url": technique_url(technique),
    }
