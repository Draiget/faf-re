#!/usr/bin/env python3
"""Bucket remaining needs_evidence by function-name patterns."""
from __future__ import annotations
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROG = ROOT / "decomp" / "recovery" / "recovered_progress.json"
DISASM = ROOT / "decomp" / "recovery" / "disasm" / "fa_full_2026_03_26"
NAME_RE = re.compile(r"^# Function (.+)$", re.MULTILINE)

with open(PROG, encoding="utf-8") as f:
    data = json.load(f)
rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]
ne_toks = [t for t, v in rec.items() if isinstance(v, dict) and v.get("status") == "needs_evidence"]

buckets = defaultdict(list)
for tok in ne_toks:
    md = DISASM / f"{tok}.md"
    if not md.exists():
        buckets["(no_meta)"].append(tok)
        continue
    try:
        txt = md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        buckets["(read_err)"].append(tok)
        continue
    m = NAME_RE.search(txt)
    if not m:
        buckets["(no_name)"].append(tok)
        continue
    name = m.group(1).strip()
    if "scalar deleting destructor" in name or "`vector deleting destructor'" in name:
        buckets["scalar_deleting_dtor"].append((tok, name))
    elif name.startswith("??_G") or name.startswith("??_E"):
        buckets["compiler_dtor_thunk"].append((tok, name))
    elif re.search(r"::\~\w+$|~\w+@@", name):
        buckets["destructor"].append((tok, name))
    elif re.search(r"^gpg::gal::", name):
        buckets["gpg_gal"].append((tok, name))
    elif re.search(r"^gpg::", name):
        buckets["gpg"].append((tok, name))
    elif re.search(r"^Moho::", name):
        buckets["moho"].append((tok, name))
    elif re.match(r"^sub_[0-9A-Fa-f]+$", name):
        buckets["sub_generic"].append((tok, name))
    elif re.match(r"^\?", name):
        buckets["msvc_mangled"].append((tok, name))
    else:
        buckets["other"].append((tok, name))

for k, v in sorted(buckets.items(), key=lambda x: -len(x[1])):
    print(f"{k}: {len(v)}")
    for item in v[:3]:
        if isinstance(item, tuple):
            print(f"    {item[0]}  {item[1]}")
        else:
            print(f"    {item}")

out = {}
for k, v in buckets.items():
    out[k] = [x[0] if isinstance(x, tuple) else x for x in v]
(ROOT / "scripts" / "ne_name_buckets.json").write_text(
    json.dumps(out, indent=2), encoding="utf-8"
)
