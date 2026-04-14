#!/usr/bin/env python3
"""Analyze needs_evidence entries in recovered_progress.json."""
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROG = ROOT / "decomp" / "recovery" / "recovered_progress.json"
SRC = ROOT / "src" / "sdk"

with open(PROG, encoding="utf-8") as f:
    data = json.load(f)

ns = data["namespaces"]["fa_full_2026_03_26"]
rec = ns["recovered"]
ne = [(k, v) for k, v in rec.items() if isinstance(v, dict) and v.get("status") == "needs_evidence"]
print(f"needs_evidence total: {len(ne)}")

by_src = Counter()
no_src = []
missing_src = []
existing_src = defaultdict(list)

for tok, info in ne:
    sps = info.get("source_paths") or []
    if not sps:
        no_src.append(tok)
        by_src["(no-source)"] += 1
        continue
    norm = str(sps[0]).replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    if norm.startswith("src/") or norm.startswith("dependencies/"):
        p = ROOT / norm
    else:
        p = SRC / norm
    by_src[norm] += 1
    if p.exists():
        existing_src[norm].append(tok)
    else:
        missing_src.append((tok, norm))

print(f"\nneeds_evidence with no source path: {len(no_src)}")
print(f"needs_evidence pointing to missing file: {len(missing_src)}")
print(f"needs_evidence pointing to existing file: {sum(len(v) for v in existing_src.values())}")
print(f"unique source paths: {len(by_src)}")

print("\nTop missing src files:")
miss_by = Counter(m for _, m in missing_src)
for p, c in miss_by.most_common(20):
    print(f"  {c:4d}  {p}")

print("\nTop existing src files:")
for p, toks in sorted(existing_src.items(), key=lambda x: -len(x[1]))[:20]:
    print(f"  {len(toks):4d}  {p}")

# For existing files, check if the address is already referenced anywhere in src/sdk
ADDR_RE = re.compile(r"0x([0-9A-Fa-f]{8})\b")
FUN_REF_RE = re.compile(r"FUN_([0-9A-Fa-f]{8})\b")

annotated = set()
for path in SRC.rglob("*"):
    if not path.is_file() or path.suffix.lower() not in {".h", ".hpp", ".cpp", ".cc", ".c"}:
        continue
    try:
        txt = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    for m in ADDR_RE.finditer(txt):
        annotated.add(int(m.group(1), 16))
    for m in FUN_REF_RE.finditer(txt):
        annotated.add(int(m.group(1), 16))

print(f"\ntotal annotated addresses in src/sdk: {len(annotated)}")

already_in_src = 0
for tok, info in ne:
    m = re.match(r"FUN_([0-9A-Fa-f]+)$", tok)
    if m and int(m.group(1), 16) in annotated:
        already_in_src += 1

print(f"needs_evidence tokens whose address IS already in src/sdk: {already_in_src}")
print(f"needs_evidence tokens truly missing from src/sdk: {len(ne) - already_in_src}")
