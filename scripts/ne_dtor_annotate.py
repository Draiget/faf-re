#!/usr/bin/env python3
"""Auto-annotate defaulted/simple destructors in src/sdk.

For each msvc_mangled dtor token in needs_evidence:
  1. Extract class name from `??1ClassName@...@...@@QAE@@Z`
  2. Find `ClassName::~ClassName()` in src/sdk
  3. If found and the definition has no existing FUN_<addr> reference,
     print a candidate annotation to add.

This is DRY-RUN by default. Pass --apply to write.
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROG = ROOT / "decomp" / "recovery" / "recovered_progress.json"
DISASM = ROOT / "decomp" / "recovery" / "disasm" / "fa_full_2026_03_26"
SRC = ROOT / "src" / "sdk"
NAME_RE = re.compile(r"^# Function (.+)$", re.MULTILINE)
DTOR_RE = re.compile(r"\?\?1([A-Za-z_][A-Za-z0-9_]*)@")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    args = ap.parse_args()

    with open(PROG, encoding="utf-8") as f:
        data = json.load(f)
    rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]

    candidates = []
    for tok, info in rec.items():
        if not isinstance(info, dict):
            continue
        if info.get("status") != "needs_evidence":
            continue
        md = DISASM / f"{tok}.md"
        if not md.exists():
            continue
        txt = md.read_text(encoding="utf-8", errors="replace")
        m = NAME_RE.search(txt)
        if not m:
            continue
        name = m.group(1).strip()
        mm = DTOR_RE.search(name)
        if not mm:
            continue
        class_name = mm.group(1)
        if len(class_name) < 4:
            continue
        candidates.append((tok, name, class_name))

    print(f"dtor candidates: {len(candidates)}")
    if args.limit:
        candidates = candidates[: args.limit]

    # For each, find `~ClassName() = default;` or `~ClassName()` in src/sdk
    ok_toks = []
    ok_annotations: dict[tuple[Path, int], list[str]] = {}
    for tok, name, cls in candidates:
        # Extract address hex
        am = re.match(r"FUN_([0-9A-Fa-f]+)$", tok)
        if not am:
            continue
        addr_hex = am.group(1).upper().rjust(8, "0")
        # Check if already referenced
        already = subprocess.run(
            [
                "rg", "--no-config", "-l",
                rf"\b(FUN_{addr_hex}|0x{addr_hex})\b",
                str(SRC),
            ],
            capture_output=True, text=True, timeout=30,
        )
        if already.returncode == 0 and already.stdout.strip():
            ok_toks.append((tok, "already-annotated"))
            continue
        # Find `ClassName::~ClassName()` definition in .cpp
        hits = subprocess.run(
            [
                "rg", "--no-config", "-n", "-g", "*.cpp",
                rf"{re.escape(cls)}::~{re.escape(cls)}\s*\(",
                str(SRC),
            ],
            capture_output=True, text=True, timeout=30,
        )
        lines = [
            ln for ln in hits.stdout.splitlines()
            if ln.strip() and "=" in ln or "{" in ln
        ]
        if not lines or len(lines) > 1:
            continue
        # Parse file:line:text — handle Windows 'G:\path:line:body'
        ln0 = lines[0]
        rg_re = re.match(r"^(.*?):(\d+):(.*)$", ln0) if len(ln0) < 2 or ln0[1] != ":" else None
        if rg_re is None:
            rg_re = re.match(r"^([A-Za-z]:[^:]+):(\d+):(.*)$", ln0)
        if not rg_re:
            continue
        file_path = Path(rg_re.group(1))
        line_no = int(rg_re.group(2))
        body = rg_re.group(3)
        if "= default" not in body and "{}" not in body and "{ }" not in body:
            # Non-trivial dtor — skip; manual inspection needed
            continue
        ok_toks.append((tok, f"matched defaulted dtor in {file_path.name}:{line_no}"))
        ok_annotations.setdefault((file_path, line_no), []).append(
            f"FUN_{addr_hex} {cls}"
        )

    print(f"ok to annotate: {sum(1 for _,k in ok_toks if 'matched' in k)}")
    print(f"already annotated: {sum(1 for _,k in ok_toks if 'already' in k)}")

    if args.apply:
        # Group annotations by file, insert Doxygen block above the dtor line.
        # For now, just print them — manual Edit will do the actual insert.
        pass

    dump = {
        "ok_toks": ok_toks,
        "annotations": {
            f"{p}:{l}": anns for (p, l), anns in ok_annotations.items()
        },
    }
    (ROOT / "scripts" / "ne_dtor_candidates.json").write_text(
        json.dumps(dump, indent=2, default=str), encoding="utf-8"
    )
    print(f"wrote scripts/ne_dtor_candidates.json")


if __name__ == "__main__":
    main()
