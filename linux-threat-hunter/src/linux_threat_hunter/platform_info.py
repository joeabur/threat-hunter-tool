"""Platform / distribution detection (testable: all paths are injectable)."""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Any

SUPPORTED_ID_LIKE = {"debian", "ubuntu", "fedora", "rhel", "centos"}


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def detect_distribution(root: Path = Path("/")) -> dict[str, Any]:
    for rel in ("etc/os-release", "usr/lib/os-release"):
        p = root / rel
        try:
            info = parse_os_release(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        ids = {info.get("ID", "")} | set(info.get("ID_LIKE", "").split())
        return {
            "id": info.get("ID", "unknown"),
            "version_id": info.get("VERSION_ID", ""),
            "pretty_name": info.get("PRETTY_NAME", info.get("NAME", "unknown")),
            "id_like": info.get("ID_LIKE", ""),
            "documented_support": bool(ids & SUPPORTED_ID_LIKE),
            "source": str(p),
        }
    return {
        "id": "unknown",
        "version_id": "",
        "pretty_name": "unknown",
        "id_like": "",
        "documented_support": False,
        "source": "",
    }


def detect_init_system(root: Path = Path("/")) -> str:
    try:
        comm = (root / "proc/1/comm").read_text(encoding="utf-8").strip()
        if comm:
            return "systemd" if comm == "systemd" else comm
    except OSError:
        pass
    if (root / "run/systemd/system").is_dir():
        return "systemd"
    return "unknown"


def normalize_arch(machine: str) -> str:
    m = machine.lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(m, m)


def platform_summary(root: Path = Path("/")) -> dict[str, Any]:
    arch = normalize_arch(platform.machine())
    return {
        "system": platform.system(),
        "is_linux": platform.system() == "Linux",
        "architecture": arch,
        "architecture_supported": arch in {"x86_64", "aarch64"},
        "python": platform.python_version(),
        "distribution": detect_distribution(root) if platform.system() == "Linux" else None,
        "init_system": detect_init_system(root) if platform.system() == "Linux" else "n/a",
        "is_root": hasattr(os, "geteuid") and os.geteuid() == 0,
    }
