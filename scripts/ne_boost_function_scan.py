#!/usr/bin/env python3
"""Mark compiler-generated boost::function / typeid callback stubs as skip.

Pattern: data-only referenced, sub_* anonymous name, <= 20 insns, body has
signature shape of a boost::function functor manager call or typeid dispatch.
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
XREFS_CODE_RE = re.compile(r"^- incoming_xrefs_code: `(\d+)`", re.MULTILINE)
XREFS_DATA_RE = re.compile(r"^- incoming_xrefs_data: `(\d+)`", re.MULTILINE)
NAME_RE = re.compile(r"^# Function (.+)$", re.MULTILINE)

with open(PROG, encoding="utf-8") as f:
    data = json.load(f)
rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]
ne_toks = [t for t, v in rec.items() if isinstance(v, dict) and v.get("status") == "needs_evidence"]

boost_fn = []
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
    if callers != 0 or xrefs_code != 0 or xrefs_data <= 0:
        continue
    if instr > 20:
        continue
    nm = NAME_RE.search(txt)
    name = nm.group(1).strip() if nm else ""
    # Must be sub_* (unknown name)
    if not re.match(r"^sub_[0-9A-Fa-f]+$", name):
        continue
    # Body shape check: look for boost functor-manager shape or typeid RTTI check
    patterns = [
        r"\(\*\*v1\)\(v1, 1\)",       # functor manager cleanup
        r"\(\*\*v1\)\(v1, 0\)",       # functor manager clone
        r"type_info::operator==",      # typeid dispatch
        r"return this \+ \d+;",        # offset-return from type check
        r"\(\*\*\*\*.*\)\(.*, 1\)",
        r"RTTI Type Descriptor",
    ]
    body = txt
    if not any(re.search(p, body) for p in patterns):
        continue
    boost_fn.append(tok)

print(f"boost::function / typeid callback candidates: {len(boost_fn)}")
out_path = ROOT / "scripts" / "ne_boost_fn_tokens.txt"
out_path.write_text("\n".join(boost_fn) + "\n", encoding="utf-8")
