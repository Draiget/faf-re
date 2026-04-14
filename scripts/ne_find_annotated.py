#!/usr/bin/env python3
"""Find needs_evidence tokens whose address IS already referenced in src/sdk.

These are drift-audit false positives: the address appears in source, but the
audit didn't find it because of regex or path quirks. They can be safely
re-marked as recovered.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "sdk"
PROG = ROOT / "decomp" / "recovery" / "recovered_progress.json"

ADDR_RE = re.compile(r"0x([0-9A-Fa-f]{8})\b")
FUN_REF_RE = re.compile(r"FUN_([0-9A-Fa-f]{8})\b")
FUN_RE = re.compile(r"^FUN_([0-9A-Fa-f]+)$")

annotated = set()
for p in SRC.rglob("*"):
    if not p.is_file() or p.suffix.lower() not in {".h", ".hpp", ".cpp", ".cc", ".c"}:
        continue
    try:
        t = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    for m in ADDR_RE.finditer(t):
        annotated.add(int(m.group(1), 16))
    for m in FUN_REF_RE.finditer(t):
        annotated.add(int(m.group(1), 16))

with open(PROG, encoding="utf-8") as f:
    data = json.load(f)
rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]

found = []
for tok, info in rec.items():
    if not isinstance(info, dict) or info.get("status") != "needs_evidence":
        continue
    m = FUN_RE.match(tok)
    if not m:
        continue
    if int(m.group(1), 16) in annotated:
        found.append(tok)

print(f"needs_evidence tokens already referenced in src/sdk: {len(found)}")
out = ROOT / "scripts" / "ne_already_annotated.txt"
out.write_text("\n".join(found) + "\n", encoding="utf-8")
print(f"wrote {out}")
