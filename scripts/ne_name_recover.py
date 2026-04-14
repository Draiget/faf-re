#!/usr/bin/env python3
"""Recover needs_evidence tokens whose fully-qualified name already has a
matching definition in src/sdk. Adds FUN_<addr> annotation and marks recovered.

For each token:
  1. Parse the demangled class::method from the IDA name.
  2. Locate exactly one .cpp definition of `ClassName::Method(`.
  3. If the existing definition has no current annotation mentioning this
     FUN_ address, insert the FUN_<addr> token into the nearest Doxygen
     block above the definition (or create one).
  4. Queue the token for bulk-mark as recovered.

This script is intentionally conservative: it only auto-annotates when there
is a unique match and the match is clearly a member function definition.
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


def parse_ida_name(raw: str) -> tuple[str, str, str] | None:
    """Return (class, method, raw_for_comment) or None.

    Accepts forms like:
      Moho::Foo::Bar
      ??0Foo@Moho@@... [Moho::Foo::Foo]
      Moho::Foo::~Foo
    """
    raw = raw.strip()
    # Prefer bracketed demangled form
    m = re.search(r"\[([^\]]+)\]", raw)
    if m:
        demangled = m.group(1)
    elif raw.startswith("??"):
        return None  # mangled with no bracket
    else:
        demangled = raw
    # Strip trailing parens
    demangled = demangled.split("(", 1)[0]
    parts = demangled.split("::")
    if len(parts) < 2:
        return None
    method = parts[-1].strip()
    cls = parts[-2].strip()
    # Reject overly-generic names
    if len(method) < 3 or len(cls) < 3:
        return None
    # Reject method names with templates / weird chars
    if re.search(r"[<>`]", method) or re.search(r"[<>`]", cls):
        return None
    # Allow ctor, dtor, normal method
    if method.startswith("~"):
        dtor_name = method
        if method[1:] != cls:
            return None
        return cls, dtor_name, demangled
    if method == cls:
        return cls, "ctor", demangled
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", method):
        return None
    return cls, method, demangled


def locate_definition(cls: str, method: str) -> list[tuple[Path, int, str]]:
    """Return list of (file, line_number, body_line) for a member def."""
    if method == "ctor":
        pattern = rf"^\s*{re.escape(cls)}::{re.escape(cls)}\s*\("
    elif method.startswith("~"):
        pattern = rf"^\s*{re.escape(cls)}::~{re.escape(cls)}\s*\("
    else:
        pattern = rf"^\s*(?:\[\[nodiscard\]\]\s+)?[A-Za-z_][A-Za-z0-9_:* <>&]*\s+{re.escape(cls)}::{re.escape(method)}\s*\("
    r = subprocess.run(
        ["rg", "--no-config", "-n", "-g", "*.cpp", pattern, str(SRC)],
        capture_output=True, text=True, timeout=30,
    )
    out = []
    for line in r.stdout.splitlines():
        m = re.match(r"^([A-Za-z]:[^:]+):(\d+):(.*)$", line)
        if not m:
            continue
        out.append((Path(m.group(1)), int(m.group(2)), m.group(3)))
    return out


def doxygen_block_above(lines: list[str], def_line_idx: int) -> tuple[int, int] | None:
    """Return (start_idx, end_idx) of the Doxygen block immediately above def_line_idx, or None."""
    i = def_line_idx - 1
    # Skip blank
    while i >= 0 and lines[i].strip() == "":
        i -= 1
    if i < 0:
        return None
    if not lines[i].strip().startswith("*/"):
        return None
    end = i
    while i >= 0 and not lines[i].strip().startswith("/**"):
        i -= 1
    if i < 0:
        return None
    return i, end


def inject_address(file_path: Path, def_line: int, addr: int, iden: str) -> bool:
    """Add `Address: 0xXXXXXXXX (FUN_XXXXXXXX, iden)` to doxygen block above def_line.
    Returns True if modified, False if already present or cannot inject.
    """
    txt = file_path.read_text(encoding="utf-8", errors="replace")
    lines = txt.splitlines(keepends=True)
    addr_hex = f"{addr:08X}"
    addr_token = f"0x{addr_hex}"
    fun_token = f"FUN_{addr_hex}"
    # Quick check: already present anywhere nearby
    lo = max(0, def_line - 40)
    hi = min(len(lines), def_line + 2)
    nearby = "".join(lines[lo:hi])
    if addr_token in nearby or fun_token in nearby:
        return False
    # Find doxygen above
    dox = doxygen_block_above(lines, def_line - 1)
    # If dox exists and already has any Address: annotation, refuse — it's a
    # different overload/variant and injecting would be misleading.
    if dox:
        start, end = dox
        block = "".join(lines[start : end + 1])
        if re.search(r"\bAddress:\s*0x[0-9A-Fa-f]{8}", block):
            return False
    new_line = f" * Address: {addr_token} ({fun_token}, {iden})\n"
    if dox:
        start, end = dox
        # Find where to insert: after the opening /** line, before first " *"
        # Prefer to add right after the first line
        insert_at = start + 1
        new_lines = lines[:insert_at] + [new_line] + lines[insert_at:]
    else:
        # No doxygen block — synthesize a small one
        indent = re.match(r"^(\s*)", lines[def_line - 1]).group(1)
        block = [
            f"{indent}/**\n",
            f"{indent} * Address: {addr_token} ({fun_token}, {iden})\n",
            f"{indent} */\n",
        ]
        new_lines = lines[: def_line - 1] + block + lines[def_line - 1 :]
    file_path.write_text("".join(new_lines), encoding="utf-8")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    with open(PROG, encoding="utf-8") as f:
        data = json.load(f)
    rec = data["namespaces"]["fa_full_2026_03_26"]["recovered"]
    ne_toks = [t for t, v in rec.items() if isinstance(v, dict) and v.get("status") == "needs_evidence"]

    ok_recover: list[tuple[str, Path, int, str, str, str]] = []
    dup_defs = 0
    not_found = 0
    parse_fail = 0

    for tok in ne_toks:
        md = DISASM / f"{tok}.md"
        if not md.exists():
            continue
        txt = md.read_text(encoding="utf-8", errors="replace")
        m = NAME_RE.search(txt)
        if not m:
            continue
        raw = m.group(1).strip()
        parsed = parse_ida_name(raw)
        if not parsed:
            parse_fail += 1
            continue
        cls, method, demangled = parsed
        defs = locate_definition(cls, method)
        if not defs:
            not_found += 1
            continue
        if len(defs) > 1:
            dup_defs += 1
            continue
        file_path, line_no, body = defs[0]
        # Parse addr from token
        am = re.match(r"FUN_([0-9A-Fa-f]+)$", tok)
        if not am:
            continue
        addr = int(am.group(1), 16)
        ok_recover.append((tok, file_path, line_no, cls, method, demangled))

    print(f"candidates: {len(ne_toks)}")
    print(f"parse_fail: {parse_fail}")
    print(f"not_found:  {not_found}")
    print(f"dup_defs:   {dup_defs}")
    print(f"auto-recoverable: {len(ok_recover)}")

    if args.limit:
        ok_recover = ok_recover[: args.limit]

    if args.apply:
        touched = 0
        applied_toks: list[str] = []
        already: list[str] = []
        for tok, file_path, line_no, cls, method, demangled in ok_recover:
            addr = int(tok.split("_")[1], 16)
            iden = demangled
            if inject_address(file_path, line_no, addr, iden):
                touched += 1
                applied_toks.append(tok)
            else:
                already.append(tok)
        print(f"injected annotations in {touched} files")
        (ROOT / "scripts" / "ne_name_recover_applied.txt").write_text(
            "\n".join(applied_toks + already) + "\n", encoding="utf-8"
        )
    else:
        # Dry run: print first 20
        for tok, file_path, line_no, cls, method, demangled in ok_recover[:20]:
            print(f"  {tok}  {demangled}  -> {file_path.name}:{line_no}")

    out = {
        "ok_recover": [
            {
                "token": tok,
                "file": str(fp),
                "line": ln,
                "class": c,
                "method": m,
                "demangled": d,
            }
            for tok, fp, ln, c, m, d in ok_recover
        ]
    }
    (ROOT / "scripts" / "ne_name_recover.json").write_text(
        json.dumps(out, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
