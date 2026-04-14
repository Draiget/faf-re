#!/usr/bin/env python3
"""Show needs_evidence tokens grouped by source file — with per-token details."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROG = ROOT / "decomp" / "recovery" / "recovered_progress.json"

target = sys.argv[1] if len(sys.argv) > 1 else None

with open(PROG, encoding="utf-8") as f:
    data = json.load(f)
ns = data["namespaces"]["fa_full_2026_03_26"]
rec = ns["recovered"]

matches = []
for tok, info in rec.items():
    if not isinstance(info, dict):
        continue
    if info.get("status") != "needs_evidence":
        continue
    sps = info.get("source_paths") or []
    if not sps:
        continue
    norm = str(sps[0]).replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    if target and target not in norm:
        continue
    matches.append((tok, norm, info))

print(f"found {len(matches)} tokens")
for tok, norm, info in matches:
    print(f"  {tok}  {norm}  note={info.get('note','')[:60]}")
