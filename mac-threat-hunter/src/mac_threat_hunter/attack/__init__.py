"""MITRE ATT&CK technique catalogue limited to techniques referenced by shipped rules."""

from __future__ import annotations

import re

from ..models import AttackMapping

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Tactic ID -> official tactic name (Enterprise matrix).
TACTICS: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0011": "Command and Control",
}

# Technique ID -> (official title, tactic IDs). Titles use ATT&CK's "Parent: Sub" form for
# sub-techniques. This is a curated subset, not the whole matrix: a rule may only map to
# techniques listed here, and every mapping must be justified by the rule's behaviour.
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1059": ("Command and Scripting Interpreter", ("TA0002",)),
    "T1059.002": ("Command and Scripting Interpreter: AppleScript", ("TA0002",)),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", ("TA0002",)),
    "T1204": ("User Execution", ("TA0002",)),
    "T1543.001": ("Create or Modify System Process: Launch Agent", ("TA0003", "TA0004")),
    "T1543.004": ("Create or Modify System Process: Launch Daemon", ("TA0003", "TA0004")),
    "T1037.002": ("Boot or Logon Initialization Scripts: Login Hook", ("TA0003", "TA0004")),
    "T1546.004": (
        "Event Triggered Execution: Unix Shell Configuration Modification",
        ("TA0003", "TA0004"),
    ),
    "T1553.001": ("Subvert Trust Controls: Gatekeeper Bypass", ("TA0005",)),
    "T1105": ("Ingress Tool Transfer", ("TA0011",)),
    "T1027": ("Obfuscated Files or Information", ("TA0005",)),
    "T1140": ("Deobfuscate/Decode Files or Information", ("TA0005",)),
    "T1071": ("Application Layer Protocol", ("TA0011",)),
    "T1110": ("Brute Force", ("TA0006",)),
    "T1110.001": ("Brute Force: Password Guessing", ("TA0006",)),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ("TA0004", "TA0005")),
    "T1548.004": (
        "Abuse Elevation Control Mechanism: Elevated Execution with Prompt",
        ("TA0004", "TA0005"),
    ),
    "T1222.002": (
        "File and Directory Permissions Modification: Linux and Mac File and Directory "
        "Permissions Modification",
        ("TA0005",),
    ),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ("TA0005",)),
    "T1036": ("Masquerading", ("TA0005",)),
}


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def is_valid_id_format(technique_id: str) -> bool:
    return bool(TECHNIQUE_ID_RE.match(technique_id))


def resolve(technique_id: str) -> AttackMapping | None:
    entry = TECHNIQUES.get(technique_id)
    if entry is None:
        return None
    name, tactic_ids = entry
    return AttackMapping(
        technique_id=technique_id,
        name=name,
        tactics=[f"{t} {TACTICS[t]}" for t in tactic_ids],
        url=technique_url(technique_id),
    )
