#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import sys


path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
blocks: list[list[str]] = []
current: list[str] = []
for line in lines:
    if not line or line.startswith("#"):
        continue
    if line[:1].isspace():
        if not current:
            raise SystemExit(f"orphan continuation: {line}")
        current.append(line)
    else:
        if current:
            blocks.append(current)
        current = [line]
if current:
    blocks.append(current)
if not blocks:
    raise SystemExit("empty requirements lock")

seen: set[str] = set()
for block in blocks:
    header = block[0]
    match = re.fullmatch(
        r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9._+-]*)"
        r"(?:\s*;\s*[^\\]+)?\s*\\?",
        header,
    )
    if not match:
        raise SystemExit(f"requirement is not exactly pinned: {header}")
    name = match.group(1).lower().replace("_", "-")
    if name in seen:
        raise SystemExit(f"duplicate requirement: {name}")
    seen.add(name)
    joined = "\n".join(block)
    if not re.search(r"--hash=sha256:[0-9a-f]{64}(?:\s|$)", joined):
        raise SystemExit(f"requirement lacks a SHA-256 hash: {name}")
    if any(token in joined.lower() for token in ("git+", "latest", "http://", "https://")):
        raise SystemExit(f"mutable or direct dependency in lock: {name}")

required = {
    "cloverlabs-camoufox",
    "browserforge",
    "playwright",
    "greenlet",
    "lxml",
    "numpy",
    "orjson",
}
missing = required - seen
if missing:
    raise SystemExit(f"missing locked dependencies: {sorted(missing)}")
content = path.read_text(encoding="utf-8")
if "cloverlabs-camoufox==0.6.0" not in content:
    raise SystemExit("wrong Camoufox package pin")
if "9f7d26eb4e4f494bcd0f8bf043d5932cba11f7bd82c2795d595f5ff602a87744" not in content:
    raise SystemExit("Camoufox wheel hash missing")
print(f"Validated {len(blocks)} hash-pinned requirements.")
