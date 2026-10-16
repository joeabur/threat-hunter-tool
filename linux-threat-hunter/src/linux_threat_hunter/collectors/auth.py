"""Authentication logs: auth.log / secure (bounded tail) with a journald fallback."""

from __future__ import annotations

from linux_threat_hunter.collectors.base import CollectContext, CollectorResult
from linux_threat_hunter.utils.safe import UnsafePathError, read_text_tail


def collect_auth(ctx: CollectContext) -> CollectorResult:
    res = CollectorResult("auth", "ok")
    cfg = ctx.config["collection"]
    for path in cfg["auth_log_paths"]:
        real = ctx.host_path(path)
        if not real.exists():
            continue
        try:
            text, cut = read_text_tail(real, cfg["auth_log_max_bytes"])
        except (OSError, UnsafePathError) as exc:
            res.errors.append(f"{path}: {exc}")
            res.notes.append(
                f"{path} is not readable as this user; run as a user in the 'adm' group "
                "or with elevated access if appropriate (never done automatically)"
            )
            continue
        text = ctx.redactor.text(text)
        res.outputs["auth.log"] = text
        res.counts = {"bytes": len(text), "lines": text.count("\n")}
        res.notes.append(f"source: {path}" + (" (tail only: older entries not collected)" if cut else ""))
        res.notes.append("rotated logs (auth.log.1, *.gz) are not collected")
        if res.errors:
            res.status = "partial"
        return res
    # journald fallback (bounded)
    out = ctx.run(
        [
            "journalctl",
            "--no-pager",
            "-q",
            "-o",
            "short-iso",
            "--since",
            cfg["journal_since"],
            "-n",
            str(cfg["journal_max_lines"]),
            "SYSLOG_IDENTIFIER=sshd",
            "+",
            "SYSLOG_IDENTIFIER=sudo",
        ]
    )
    if out.ok and out.stdout.strip():
        res.outputs["auth.log"] = ctx.redactor.text(out.stdout)
        res.counts = {"lines": out.stdout.count("\n")}
        res.notes.append("source: journalctl (sshd + sudo identifiers, bounded)")
        return res
    res.status = "failed"
    res.errors.append(f"no readable auth log: files missing/unreadable and journalctl: {out.error or 'empty'}")
    return res
