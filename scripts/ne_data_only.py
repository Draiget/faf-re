#!/usr/bin/env python3
"""Find needs_evidence tokens that are data-only referenced (vtable/typeinfo
callbacks). These are functions registered via data pointers — reflection
callbacks, virtual thunks, etc. They may already be subsumed by an
already-recovered registration call in source.

For each token with callers==0 AND xrefs_code==0 AND xrefs_data>0, check if:
  - The token name contains a recognizable reflection pattern (RRef_*,
    New*, Delete*, Copy*, Ctr*, Move*, Dtr*, etc.)
  - The body is tiny forwarder (<= 20 insns)
"""
from __future__ import annotations
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROG = ROOT / "decomp" / "recovery" / "recovered_progress.json"
DISASM = ROOT / "decomp" / "recovery" / "disasm" / "fa_full_2026_03_26"

INSTR_RE = re.compile(r"^- instructions: `(\d+)`", re.MULTILINE)
CALLERS_RE = re.compile(r"^- callers: `(\d+)`", re.MULTILINE)
XREFS_RE = re.compile(r"^- incoming_xrefs: `(\d+)`", re.MULTILINE)
XREFS_CODE_RE = re.compile(r"^- incoming_xrefs_code: `(\d+)`", re.MULTILINE)
XREFS_DATA_RE = re.compile(r"^- incoming_xrefs_data: `(\d+)`", re.MULTILINE)
NAME_RE = re.compile(r"^# Function (.+)$", re.MULTILINE)


with open(PROG, encoding="utf-8") as f:
    data = json.load(f)
rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]
ne_toks = [t for t, v in rec.items() if isinstance(v, dict) and v.get("status") == "needs_evidence"]

data_only = []
for tok in ne_toks:
    md = DISASM / f"{tok}.md"
    if not md.exists():
        continue
    try:
        txt = md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    def g(r):
        m = r.search(txt)
        return int(m.group(1)) if m else -1
    callers = g(CALLERS_RE)
    xrefs_code = g(XREFS_CODE_RE)
    xrefs_data = g(XREFS_DATA_RE)
    instr = g(INSTR_RE)
    if callers == 0 and xrefs_code == 0 and xrefs_data > 0:
        m = NAME_RE.search(txt)
        name = m.group(1).strip() if m else "?"
        data_only.append((tok, name, instr, xrefs_data))

print(f"data-only referenced: {len(data_only)}")
for tok, name, instr, xd in data_only[:20]:
    print(f"  {tok}  insn={instr:3d}  xrefs_data={xd}  {name[:100]}")

# Group by name patterns
patterns = defaultdict(list)
for tok, name, instr, xd in data_only:
    if "RRef_" in name:
        patterns["reflection_rref"].append(tok)
    elif re.search(r"\b(New|Ctr|Delete|Copy|Dtr|Move)\w*Ref\b", name):
        patterns["reflection_callback"].append(tok)
    elif "__vftable" in name or "vtable" in name or "vftable" in name:
        patterns["vtable"].append(tok)
    elif re.match(r"^sub_", name):
        patterns["sub_unnamed"].append(tok)
    else:
        patterns["other"].append(tok)

print("\nBy pattern:")
for k, toks in sorted(patterns.items(), key=lambda x: -len(x[1])):
    print(f"  {k}: {len(toks)}")

out = {k: v for k, v in patterns.items()}
(ROOT / "scripts" / "ne_data_only.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
