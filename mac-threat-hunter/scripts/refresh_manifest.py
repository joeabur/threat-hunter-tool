#!/usr/bin/env python3
"""Re-hash a SYNTHETIC evidence directory after you edited its files on purpose.

The tool refuses to trust evidence whose files no longer match manifest.json. When you edit a
copy of the synthetic evidence for a walkthrough exercise, run this to record the new hashes.
It refuses to touch evidence that is not marked synthetic, so it cannot be used to make
tampered real evidence look intact.

    python scripts/refresh_manifest.py path/to/edited-synthetic-evidence
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    directory = Path(argv[1])
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file() or directory.is_symlink():
        print(f"error: {directory} has no manifest.json", file=sys.stderr)
        return 3
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("synthetic") is not True:
        print("error: refusing to re-hash evidence that is not marked synthetic", file=sys.stderr)
        return 2
    for entry in manifest["files"]:
        name = entry["name"]
        if "/" in name or "\\" in name or name.startswith("."):
            print(f"error: unexpected file name {name!r}", file=sys.stderr)
            return 3
        path = directory / name
        if path.is_symlink() or not path.is_file():
            print(f"error: {name} missing or a symlink", file=sys.stderr)
            return 3
        data = path.read_bytes()
        entry["sha256"] = hashlib.sha256(data).hexdigest()
        entry["size"] = len(data)
    manifest["modified_after_collection"] = True
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"re-hashed {len(manifest['files'])} files in {directory}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
