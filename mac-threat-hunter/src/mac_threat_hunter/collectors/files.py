from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from ..models import CollectorResult
from ..utils.paths import sha256_file
from .base import CollectContext, Collector, file_meta

_MACHO_MAGIC = {
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}  # fmt: skip


def _head(path: Path, n: int = 4) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return b""
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return b""
        return os.read(fd, n)
    except OSError:
        return b""
    finally:
        os.close(fd)


class FileCollector(Collector):
    name = "files"
    description = (
        "Executables in watched directories and metadata/hashes of security-relevant config files"
    )
    privilege_note = (
        "Other users' Downloads and root-only files cannot be read without elevated access."
    )

    def planned(self, ctx: CollectContext) -> list[str]:
        cfg = ctx.config.collection
        return (
            [f"scan (non-recursive) {d}" for d in cfg["watch_directories"]]
            + [f"stat+hash {f}" for f in cfg["config_files"]]
            + [f"stat+hash files in {d}" for d in cfg["config_dirs"]]
        )

    def collect(self, ctx: CollectContext, result: CollectorResult) -> None:
        cfg = ctx.config.collection
        hash_limit = int(cfg.get("hash_max_mb", 64)) * 1024 * 1024
        per_dir = int(cfg.get("watch_max_files_per_dir", 500))
        for spec in cfg["watch_directories"]:
            for display_dir in ctx.expand_home(spec):
                self._scan_dir(ctx, result, display_dir, per_dir, hash_limit)
        for display in cfg["config_files"]:
            rec = self._config_file(ctx, display, hash_limit)
            if rec:
                result.records.append(rec)
        for d in cfg["config_dirs"]:
            real = ctx.real_path(d)
            try:
                names = sorted(os.listdir(real))[:per_dir]
            except FileNotFoundError:
                continue
            except PermissionError:
                result.errors.append(f"permission denied reading {d}")
                continue
            except OSError as exc:
                result.errors.append(f"cannot read {d}: {exc.strerror or exc}")
                continue
            for name in names:
                rec = self._config_file(ctx, f"{d}/{name}", hash_limit)
                if rec:
                    result.records.append(rec)

    def _scan_dir(self, ctx: CollectContext, result: CollectorResult, display_dir: str,
                  per_dir: int, hash_limit: int) -> None:  # fmt: skip
        real_dir = ctx.real_path(display_dir)
        try:
            entries = sorted(os.scandir(real_dir), key=lambda e: e.name)
        except FileNotFoundError:
            return
        except PermissionError:
            result.errors.append(f"permission denied reading {display_dir}")
            return
        except OSError as exc:
            result.errors.append(f"cannot read {display_dir}: {exc.strerror or exc}")
            return
        count = 0
        for entry in entries:
            try:
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            path = Path(entry.path)
            head = _head(path)
            st = entry.stat(follow_symlinks=False)
            exec_bit = bool(st.st_mode & 0o111)
            macho = head in _MACHO_MAGIC
            shebang = head[:2] == b"#!"
            if not (exec_bit or macho or shebang):
                continue
            count += 1
            if count > per_dir:
                result.notes.append(
                    f"{display_dir}: more than {per_dir} executables; remainder not recorded"
                )
                break
            meta = file_meta(path, f"{display_dir.rstrip('/')}/{entry.name}") or {}
            rec: dict[str, Any] = {
                **meta, "kind": "watched_file", "is_executable": True,
                "has_exec_bit": exec_bit, "is_macho": macho, "has_shebang": shebang,
            }  # fmt: skip
            digest = sha256_file(path, hash_limit)
            if digest:
                rec["sha256"] = digest
            result.records.append(rec)

    def _config_file(
        self, ctx: CollectContext, display: str, hash_limit: int
    ) -> dict[str, Any] | None:
        real = ctx.real_path(display)
        meta = file_meta(real, display)
        if meta is None or meta.get("is_symlink"):
            return None
        if not stat.S_ISREG(os.lstat(real).st_mode):
            return None
        rec: dict[str, Any] = {**meta, "kind": "config_file", "is_executable": False}
        digest = sha256_file(real, hash_limit)
        if digest:
            rec["sha256"] = digest
        return rec
