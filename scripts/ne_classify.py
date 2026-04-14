#!/usr/bin/env python3
"""Classify needs_evidence entries: orphan-trivial vs real-needs-work.

Orphan-trivial = 0 callers, 0 incoming xrefs, <= 12 instructions. These are
compiler template-instantiation artifacts (tiny setters/comparators) emitted
into the binary but never called.

Real-needs-work = has callers OR larger body, i.e. functions that still need
actual behavior recovery.
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
XREFS_RE = re.compile(r"^- incoming_xrefs: `(\d+)`", re.MULTILINE)
XREFS_CODE_RE = re.compile(r"^- incoming_xrefs_code: `(\d+)`", re.MULTILINE)

ORPHAN_MAX_INSTR = 12  # legacy knob, not used in simplified rule


def classify_token(tok: str) -> dict:
    md = DISASM / f"{tok}.md"
    if not md.exists():
        return {"kind": "no-meta"}
    try:
        txt = md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"kind": "read-error"}
    instr = int(INSTR_RE.search(txt).group(1)) if INSTR_RE.search(txt) else -1
    callers = int(CALLERS_RE.search(txt).group(1)) if CALLERS_RE.search(txt) else -1
    xrefs = int(XREFS_RE.search(txt).group(1)) if XREFS_RE.search(txt) else -1
    xrefs_code = int(XREFS_CODE_RE.search(txt).group(1)) if XREFS_CODE_RE.search(txt) else -1
    # Orphan = dead in binary: no callers AND no incoming xrefs.
    is_orphan = callers == 0 and xrefs == 0 and instr > 0
    return {
        "kind": "orphan-trivial" if is_orphan else "needs-work",
        "instructions": instr,
        "callers": callers,
        "xrefs": xrefs,
        "xrefs_code": xrefs_code,
    }


def main() -> None:
    with open(PROG, encoding="utf-8") as f:
        data = json.load(f)
    ns = data["namespaces"]["fa_full_2026_03_26"]
    rec = ns["recovered"]
    ne = [(k, v) for k, v in rec.items() if isinstance(v, dict) and v.get("status") == "needs_evidence"]

    kinds = Counter()
    orphan_by_src: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    work_by_src: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    orphan_no_src: list[tuple[str, dict]] = []
    work_no_src: list[tuple[str, dict]] = []

    for tok, info in ne:
        clas = classify_token(tok)
        kinds[clas["kind"]] += 1
        sps = info.get("source_paths") or []
        src = None
        if sps:
            src = str(sps[0]).replace("\\", "/")
            if src.startswith("./"):
                src = src[2:]
        if clas["kind"] == "orphan-trivial":
            if src:
                orphan_by_src[src].append((tok, clas))
            else:
                orphan_no_src.append((tok, clas))
        else:
            if src:
                work_by_src[src].append((tok, clas))
            else:
                work_no_src.append((tok, clas))

    print("Classification:")
    for k, c in kinds.most_common():
        print(f"  {k}: {c}")

    print(f"\norphan-trivial with source: {sum(len(v) for v in orphan_by_src.values())}")
    print(f"orphan-trivial no source:   {len(orphan_no_src)}")
    print(f"needs-work with source:     {sum(len(v) for v in work_by_src.values())}")
    print(f"needs-work no source:       {len(work_no_src)}")

    print("\nTop orphan-trivial sources:")
    for src, toks in sorted(orphan_by_src.items(), key=lambda x: -len(x[1]))[:15]:
        print(f"  {len(toks):4d}  {src}")

    print("\nTop needs-work sources:")
    for src, toks in sorted(work_by_src.items(), key=lambda x: -len(x[1]))[:15]:
        print(f"  {len(toks):4d}  {src}")

    # Dump summary JSON
    out = {
        "orphan_trivial_with_src": {
            src: [tok for tok, _ in toks] for src, toks in orphan_by_src.items()
        },
        "orphan_trivial_no_src": [tok for tok, _ in orphan_no_src],
        "needs_work_with_src": {
            src: [tok for tok, _ in toks] for src, toks in work_by_src.items()
        },
        "needs_work_no_src": [tok for tok, _ in work_no_src],
    }
    out_path = ROOT / "scripts" / "ne_classification.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
