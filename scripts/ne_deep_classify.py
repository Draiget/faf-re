#!/usr/bin/env python3
"""Deep classify remaining needs_evidence tokens.

For each token:
  - Read meta md to get instructions/callers/xrefs/callees
  - Read decompiled C body to look for STL patterns, thunk patterns, etc.
  - Walk callers: if all callers are already in skip/external_dependency/recovered,
    this function is either subsumed or should be recovered with the caller.

Buckets:
  - orphan: callers=0, xrefs=0
  - tiny_nullsub: <=3 insns (retn, nop)
  - stl_helper: body matches std::vector/map/set/string helper patterns
  - callers_all_skipped: every caller is already in skip/external_dependency
  - callers_all_recovered: every caller is already recovered (investigate inline)
  - needs_real_work: rest
"""
from __future__ import annotations
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROG = ROOT / "decomp" / "recovery" / "recovered_progress.json"
DISASM = ROOT / "decomp" / "recovery" / "disasm" / "fa_full_2026_03_26"

INSTR_RE = re.compile(r"^- instructions: `(\d+)`", re.MULTILINE)
CALLERS_RE = re.compile(r"^- callers: `(\d+)`", re.MULTILINE)
CALLEES_RE = re.compile(r"^- callees: `(\d+)`", re.MULTILINE)
XREFS_RE = re.compile(r"^- incoming_xrefs: `(\d+)`", re.MULTILINE)
CALLERS_SECTION_RE = re.compile(r"## Callers\n(.*?)\n## ", re.DOTALL)
FUN_REF_IN_LIST_RE = re.compile(
    r"`?(FUN_[0-9A-Fa-f]+|sub_[0-9A-Fa-f]+|0x[0-9A-Fa-f]{6,16})`?"
)

# STL body signatures (MSVC8 Dinkumware) — stricter to avoid false positives
STL_SIGNATURES = [
    r"\b0xAAAAAA9u?\b",            # map/set max_size
    r"\b0xFFFFFFFu\b",             # vector<16B>::max_size()
    r"std::_Tree_nod",
    r"_Tree_nod",
    r"_Myres\b",                   # string internal
    r"_Bxty\b",
    r"_Isnil",
    r"std::runtime_error",
    r"std::length_error",
    r"std::out_of_range",
]
STL_RE = re.compile("|".join(STL_SIGNATURES))

# Engine-specific symbol hints (if present, NOT a plain STL helper)
ENGINE_SIGNATURES = [
    r"Moho::",
    r"gpg::",
    r"SimArmy",
    r"CAi",
    r"CSim",
    r"CWld",
    r"IEntity",
    r"::`vftable",
    r"\.mName",
    r"\.mObj",
    r"vftable",
]
ENGINE_RE = re.compile("|".join(ENGINE_SIGNATURES))

THUNK_PATTERNS = [
    r"^\s*jmp\s",
    r"^\s*ret[nq]?\s*$",
]


def load_prog():
    with open(PROG, encoding="utf-8") as f:
        return json.load(f)


def parse_meta(tok: str) -> dict | None:
    md = DISASM / f"{tok}.md"
    if not md.exists():
        return None
    try:
        txt = md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    def g(r, default=-1):
        m = r.search(txt)
        return int(m.group(1)) if m else default
    instr = g(INSTR_RE)
    callers = g(CALLERS_RE)
    callees = g(CALLEES_RE)
    xrefs = g(XREFS_RE)
    callers_list = []
    sec = CALLERS_SECTION_RE.search(txt)
    if sec:
        for ln in sec.group(1).splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("<none>"):
                continue
            for m in FUN_REF_IN_LIST_RE.finditer(ln):
                name = m.group(1)
                if name.startswith("sub_"):
                    name = "FUN_" + name[4:].upper().rjust(8, "0")
                elif name.startswith("0x"):
                    name = "FUN_" + name[2:].upper().rjust(8, "0")
                callers_list.append(name)
    c_file = DISASM / f"{tok}.c"
    body = ""
    if c_file.exists():
        try:
            body = c_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    return {
        "instr": instr,
        "callers": callers,
        "callees": callees,
        "xrefs": xrefs,
        "callers_list": callers_list,
        "stl_hit": bool(STL_RE.search(body)) and not bool(ENGINE_RE.search(body)),
        "engine_hit": bool(ENGINE_RE.search(body)),
        "body_len": len(body),
    }


def main():
    data = load_prog()
    rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]

    def status_of(tok):
        info = rec.get(tok)
        if isinstance(info, dict):
            return info.get("status", "?")
        return None

    ne_toks = [
        t for t, v in rec.items()
        if isinstance(v, dict) and v.get("status") == "needs_evidence"
    ]
    print(f"needs_evidence: {len(ne_toks)}")

    buckets = defaultdict(list)
    no_meta = []
    for tok in ne_toks:
        m = parse_meta(tok)
        if not m:
            no_meta.append(tok)
            continue
        if m["instr"] <= 3 and m["callers"] == 0:
            buckets["tiny_nullsub"].append(tok)
        elif m["instr"] <= 5 and m["callers"] <= 1 and m["callees"] == 0:
            buckets["tiny_leaf"].append(tok)
        elif m["callers"] == 0 and m["xrefs"] == 0:
            buckets["orphan"].append(tok)
        elif m["stl_hit"]:
            buckets["stl_helper"].append(tok)
        else:
            # Caller status analysis
            if m["callers_list"]:
                caller_statuses = [status_of(c) for c in m["callers_list"]]
                non_null = [s for s in caller_statuses if s]
                if non_null and all(s == "skip" for s in non_null):
                    buckets["callers_all_skipped"].append(tok)
                elif non_null and all(
                    s in ("skip", "external_dependency") for s in non_null
                ):
                    buckets["callers_all_skip_or_ext"].append(tok)
                else:
                    buckets["needs_real_work"].append(tok)
            else:
                buckets["no_caller_list"].append(tok)

    print(f"no_meta: {len(no_meta)}")
    for b, toks in sorted(buckets.items(), key=lambda x: -len(x[1])):
        print(f"{b}: {len(toks)}")

    out = {k: v for k, v in buckets.items()}
    out["no_meta"] = no_meta
    out_path = ROOT / "scripts" / "ne_deep_classification.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
