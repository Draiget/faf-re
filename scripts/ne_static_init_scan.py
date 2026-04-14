#!/usr/bin/env python3
"""Mark static-initializer glue functions as skip.

Pattern: data-only referenced (callers==0, xrefs_code==0, xrefs_data>0) AND
body matches `... atexit(...) ...` — compiler-generated _xc_a table entry.
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

with open(PROG, encoding="utf-8") as f:
    data = json.load(f)
rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]
ne_toks = [t for t, v in rec.items() if isinstance(v, dict) and v.get("status") == "needs_evidence"]

static_init = []
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
    # Check body for atexit pattern
    cfile = DISASM / f"{tok}.c"
    body = ""
    if cfile.exists():
        body = cfile.read_text(encoding="utf-8", errors="replace")
    else:
        body = txt  # md includes decompiled code
    if "atexit" not in body:
        continue
    if instr > 30:
        continue
    static_init.append(tok)

print(f"static-init candidates: {len(static_init)}")
out_path = ROOT / "scripts" / "ne_static_init_tokens.txt"
out_path.write_text("\n".join(static_init) + "\n", encoding="utf-8")
print(f"wrote {out_path}")
