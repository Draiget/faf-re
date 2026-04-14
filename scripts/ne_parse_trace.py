#!/usr/bin/env python3
"""Trace what parse_ida_name rejects."""
import sys, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from ne_name_recover import parse_ida_name

PROG = ROOT / "decomp" / "recovery" / "recovered_progress.json"
DISASM = ROOT / "decomp" / "recovery" / "disasm" / "fa_full_2026_03_26"
NAME_RE = re.compile(r"^# Function (.+)$", re.MULTILINE)

with open(PROG, encoding="utf-8") as f:
    data = json.load(f)
rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]
ne = [t for t, v in rec.items() if isinstance(v, dict) and v.get("status") == "needs_evidence"]

fails = []
passes = []
for tok in ne:
    md = DISASM / f"{tok}.md"
    if not md.exists():
        continue
    txt = md.read_text(encoding="utf-8", errors="replace")
    m = NAME_RE.search(txt)
    if not m:
        continue
    raw = m.group(1).strip()
    p = parse_ida_name(raw)
    if p is None:
        fails.append((tok, raw))
    else:
        passes.append((tok, raw, p))

print(f"parse fails: {len(fails)}  passes: {len(passes)}")
print("\n-- first 30 passes --")
for tok, raw, (cls, method, dem) in passes[:30]:
    print(f"  {tok}  cls={cls} method={method}  raw={raw[:80]}")
