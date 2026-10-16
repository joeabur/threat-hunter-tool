from __future__ import annotations

import socket

from ..models import CollectorResult
from ..utils.timeutil import local_offset_string, to_iso
from . import parsing
from .base import CollectContext, Collector

_COMMANDS = {
    "sw_vers": ["/usr/bin/sw_vers"],
    "arch": ["/usr/bin/uname", "-m"],
    "boottime": ["/usr/sbin/sysctl", "-n", "kern.boottime"],
    "who": ["/usr/bin/who"],
    "sip": ["/usr/bin/csrutil", "status"],
    "gatekeeper": ["/usr/sbin/spctl", "--status"],
    "filevault": ["/usr/bin/fdesetup", "status"],
    "firewall": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
    "ifconfig": ["/sbin/ifconfig", "-a"],
    "routes": ["/usr/sbin/netstat", "-rn", "-f", "inet"],
}


class SystemCollector(Collector):
    name = "system"
    description = "macOS version, architecture, uptime, sessions, protections, interfaces, routes"
    privilege_note = (
        "No elevated access needed; fdesetup status may report limited detail without admin."
    )

    def planned(self, ctx: CollectContext) -> list[str]:
        return [" ".join(c) for c in _COMMANDS.values()]

    def collect(self, ctx: CollectContext, result: CollectorResult) -> None:
        outputs: dict[str, str] = {}
        for key, argv in _COMMANDS.items():
            res = ctx.run(argv)
            if res.ok:
                outputs[key] = res.stdout + (res.stderr if key == "firewall" else "")
            else:
                reason = "timed out" if res.timed_out else (res.error or f"exit {res.returncode}")
                # csrutil/spctl report state on stdout even with non-zero exit on some versions
                if res.stdout and key in {"sip", "gatekeeper", "firewall", "filevault"}:
                    outputs[key] = res.stdout
                else:
                    result.errors.append(f"{' '.join(argv)}: {reason}")
        osinfo = parsing.parse_sw_vers(outputs.get("sw_vers", ""))
        try:
            hostname = socket.gethostname()
        except OSError:
            hostname = ""
        boot = parsing.parse_boottime(outputs.get("boottime", ""))
        uptime = None
        if boot:
            from ..utils.timeutil import parse_timestamp

            parsed = parse_timestamp(boot).utc
            if parsed:
                uptime = int((ctx.now - parsed).total_seconds())
        record = {
            "hostname": hostname,
            "os": {
                "product_name": osinfo["product_name"],
                "version": osinfo["version"],
                "build": osinfo["build"],
            },
            "arch": outputs.get("arch", "").strip(),
            "boot_time": boot,
            "uptime_seconds": uptime,
            "local_utc_offset": local_offset_string(),
            "collected_at": to_iso(ctx.now),
            "sessions": parsing.parse_who(outputs.get("who", "")),
            "security": {
                "sip": parsing.parse_csrutil(outputs.get("sip", "")),
                "gatekeeper": parsing.parse_spctl(outputs.get("gatekeeper", "")),
                "filevault": parsing.parse_fdesetup(outputs.get("filevault", "")),
                "firewall": parsing.parse_firewall(outputs.get("firewall", "")),
            },
            "interfaces": parsing.parse_ifconfig(outputs.get("ifconfig", "")),
            "routes": parsing.parse_netstat_routes(outputs.get("routes", "")),
        }
        result.records.append(record)
        if not osinfo["version"]:
            result.errors.append("macOS version could not be determined")
