#!/usr/bin/env python3
"""Find tiny thunk/nullsub tokens in remaining needs_evidence.

Pattern: sub_* name, <= 10 insns, body is trivial (retn, jmp, or single call).
"""
from __future__ import annotations
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROG = ROOT / "decomp" / "recovery" / "recovered_progress.json"
DISASM = ROOT / "decomp" / "recovery" / "disasm" / "fa_full_2026_03_26"

INSTR_RE = re.compile(r"^- instructions: `(\d+)`", re.MULTILINE)
CALLERS_RE = re.compile(r"^- callers: `(\d+)`", re.MULTILINE)
NAME_RE = re.compile(r"^# Function (.+)$", re.MULTILINE)

with open(PROG, encoding="utf-8") as f:
    data = json.load(f)
rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]
ne = [t for t, v in rec.items() if isinstance(v, dict) and v.get("status") == "needs_evidence"]

thunks = []
for tok in ne:
    md = DISASM / f"{tok}.md"
    if not md.exists():
        continue
    txt = md.read_text(encoding="utf-8", errors="replace")
    instr_m = INSTR_RE.search(txt)
    name_m = NAME_RE.search(txt)
    if not instr_m or not name_m:
        continue
    instr = int(instr_m.group(1))
    name = name_m.group(1).strip()
    if instr > 10:
        continue
    if not re.match(r"^sub_[0-9A-Fa-f]+$", name):
        continue
    thunks.append((tok, instr))

print(f"tiny sub_* thunks: {len(thunks)}")
for tok, i in thunks[:30]:
    print(f"  {tok}  insn={i}")
out = ROOT / "scripts" / "ne_thunks.txt"
out.write_text("\n".join(t for t, _ in thunks) + "\n", encoding="utf-8")
