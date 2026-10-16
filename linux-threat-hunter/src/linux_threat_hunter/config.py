"""Configuration defaults, loading and validation."""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import yaml

from linux_threat_hunter.utils.redact import DEFAULT_REDACTION_PATTERNS
from linux_threat_hunter.utils.safe import read_regular_file

SUSPICIOUS_COMMAND_PATTERNS = [
    r"(curl|wget)\s[^|;&]{0,200}\|\s*(sudo\s+)?(ba|da|z)?sh\b",
    r"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+",
    r"base64\s+(-d|--decode)[^|;]{0,100}\|\s*(ba|da)?sh\b",
    r"\bnc(at)?\s[^;|&]{0,80}\s-e\s",
]

SUDO_SUSPICIOUS_PATTERNS = [
    r"^(/usr)?/bin/(ba|da|z)?sh(\s|$)",
    r"^(/usr)?/bin/su(\s|$)",
    r"/etc/(sudoers|shadow|passwd)\b",
]

DEFAULT_CONFIG: dict[str, Any] = {
    "config_version": 1,
    "limits": {
        "max_evidence_file_bytes": 52428800,
        "max_records_per_source": 200000,
        "max_line_length": 4096,
        "max_findings_per_rule": 500,
        "max_rule_file_bytes": 262144,
        "max_regex_length": 256,
        "max_regex_input_chars": 4096,
        "max_condition_depth": 6,
        "max_list_values": 1000,
        "subprocess_timeout_seconds": 15,
        "subprocess_max_output_bytes": 8388608,
        "max_hash_file_bytes": 67108864,
    },
    "redaction": {"patterns": DEFAULT_REDACTION_PATTERNS, "replacement": "[REDACTED]"},
    "collection": {
        "process_hashing": True,
        "auth_log_paths": ["/var/log/auth.log", "/var/log/secure"],
        "auth_log_max_bytes": 5242880,
        "journal_since": "7 days ago",
        "journal_max_lines": 20000,
        "systemd_dirs": [
            "/etc/systemd/system",
            "/etc/systemd/user",
            "/run/systemd/system",
            "/usr/local/lib/systemd/system",
        ],
        "systemd_vendor_dirs_full": ["/usr/lib/systemd/system", "/lib/systemd/system"],
        "cron_files": ["/etc/crontab"],
        "cron_dirs": [
            "/etc/cron.d",
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron/crontabs",
            "/var/spool/cron",
        ],
        "shell_startup_files": ["/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"],
        "shell_startup_dirs": ["/etc/profile.d"],
        "user_shell_files": [".bashrc", ".profile", ".bash_profile", ".zshrc", ".bash_logout"],
        "ssh_config_files": ["/etc/ssh/sshd_config"],
        "ssh_config_dirs": ["/etc/ssh/sshd_config.d"],
        "rc_files": ["/etc/rc.local", "/etc/ld.so.preload"],
        "file_integrity_paths": [
            "/etc/passwd",
            "/etc/group",
            "/etc/sudoers",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/ssh/sshd_config",
            "/etc/ld.so.preload",
            "/etc/crontab",
            "/etc/pam.d/sshd",
            "/etc/pam.d/sudo",
            "/etc/pam.d/common-auth",
        ],
        "executable_scan_dirs": ["/tmp", "/var/tmp", "/dev/shm"],
        "executable_scan_max_entries": 500,
        "max_users": 200,
        "max_unit_bytes": 65536,
        "content_excerpt_bytes": 16384,
    },
    "variables": {
        "writable_dirs": ["/tmp", "/var/tmp", "/dev/shm", "/home/*/.cache"],
        "suspicious_command_patterns": SUSPICIOUS_COMMAND_PATTERNS,
        "sudo_suspicious_patterns": SUDO_SUSPICIOUS_PATTERNS,
        "shell_names": ["sh", "bash", "dash", "zsh", "ksh", "ash"],
        "server_process_names": [
            "nginx",
            "apache2",
            "httpd",
            "php-fpm",
            "php-fpm8.3",
            "mysqld",
            "postgres",
            "redis-server",
        ],
        "security_config_dirs": ["/etc"],
    },
    "disabled_rules": [],
    "rule_overrides": {},
    "allowlists": {},
}


class ConfigError(ValueError):
    """Raised when a configuration file is invalid."""


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, val in over.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict) and key not in ("rule_overrides", "allowlists"):
            out[key] = _merge(out[key], val)
        else:
            out[key] = copy.deepcopy(val)
    return out


def _load_yaml(path: Path, limit: int) -> dict[str, Any]:
    try:
        raw = read_regular_file(path, limit)
        data = yaml.safe_load(raw.decode("utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


def validate_config(cfg: dict[str, Any]) -> None:
    unknown = set(cfg) - set(DEFAULT_CONFIG)
    if unknown:
        raise ConfigError(f"unknown configuration keys: {sorted(unknown)}")
    for key in ("limits", "collection", "variables", "redaction"):
        if not isinstance(cfg.get(key), dict):
            raise ConfigError(f"'{key}' must be a mapping")
    for name, default in DEFAULT_CONFIG["limits"].items():
        val = cfg["limits"].get(name)
        if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
            raise ConfigError(f"limits.{name} must be a positive integer (default {default})")
    if cfg["limits"]["max_regex_length"] > 1024:
        raise ConfigError("limits.max_regex_length may not exceed 1024")
    for p in cfg["redaction"].get("patterns", []):
        try:
            re.compile(p)
        except re.error as exc:
            raise ConfigError(f"invalid redaction pattern {p!r}: {exc}") from exc
    for name in ("disabled_rules",):
        if not isinstance(cfg[name], list):
            raise ConfigError(f"'{name}' must be a list")
    if not isinstance(cfg["rule_overrides"], dict) or not isinstance(cfg["allowlists"], dict):
        raise ConfigError("'rule_overrides' and 'allowlists' must be mappings")
    for rid, ov in cfg["rule_overrides"].items():
        if not isinstance(ov, dict) or set(ov) - {"severity", "confidence", "params", "enabled"}:
            raise ConfigError(f"rule_overrides.{rid}: allowed keys are severity, confidence, params, enabled")


def load_config(path: str | Path | None = None, allowlists: str | Path | None = None) -> dict[str, Any]:
    """Defaults, then an optional config file, then an optional allowlists file."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    limit = cfg["limits"]["max_rule_file_bytes"]
    if path is not None:
        cfg = _merge(cfg, _load_yaml(Path(path), limit))
    if allowlists is not None:
        extra = _load_yaml(Path(allowlists), limit)
        unknown = set(extra) - {"allowlists"}
        if unknown:
            raise ConfigError(f"allowlists file may only contain 'allowlists' (found {sorted(unknown)})")
        cfg = _merge(cfg, extra)
    validate_config(cfg)
    return cfg
