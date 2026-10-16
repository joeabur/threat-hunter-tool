from __future__ import annotations

from typing import Any

from ..utils.paths import sha256_file
from . import parsing
from .base import CollectContext


class FileEnricher:
    """Hash and code-sign lookups with caching and per-run limits. Never executes files."""

    def __init__(self, ctx: CollectContext) -> None:
        self.ctx = ctx
        self.hash_limit = int(ctx.config.collection.get("hash_max_mb", 64)) * 1024 * 1024
        self.skip = tuple(ctx.config.collection.get("hash_skip_prefixes", []))
        self.codesign_budget = int(ctx.config.collection.get("codesign_max_lookups", 150))
        self._hash: dict[str, str | None] = {}
        self._sign: dict[str, dict[str, Any] | None] = {}
        self.notes: list[str] = []

    def is_system_path(self, path: str) -> bool:
        return path.startswith(self.skip)

    def sha256(self, path: str) -> str | None:
        if not path.startswith("/") or "\x00" in path or self.is_system_path(path):
            return None
        if path not in self._hash:
            self._hash[path] = sha256_file(self.ctx.real_path(path), self.hash_limit)
        return self._hash[path]

    def codesign(self, path: str) -> dict[str, Any] | None:
        if not path.startswith("/") or "\x00" in path or self.is_system_path(path):
            return None
        if path in self._sign:
            return self._sign[path]
        if self.codesign_budget <= 0:
            if "codesign lookup limit reached" not in self.notes:
                self.notes.append(
                    "codesign lookup limit reached; remaining files have no signing data"
                )
            self._sign[path] = None
            return None
        self.codesign_budget -= 1
        res = self.ctx.run(["/usr/bin/codesign", "-dv", "--verbose=2", path], max_bytes=64 * 1024)
        if res.error or res.timed_out:
            self._sign[path] = None
        else:
            self._sign[path] = parsing.parse_codesign(res.stderr or res.stdout)
        return self._sign[path]
