"""Cross-check each recovered function's C++ identifier against the mangled
symbol the shipped binary carries for that address.

Why this exists
---------------
`Entity::RevertCollisionShape` (0x0067AE70) and `Entity::SetCollisionShapeNone`
(0x0067AE00) spent months with their names on each other's bodies. Every gate we
had passed: both bodies were faithful transcriptions, both carried `Address:`
blocks, the callgraph agreed, `faidx verify` was clean. The only artifact that
disagreed was the binary's own export label - and nothing read it. The visible
result was a crash: `airunit.lua` calls `RevertCollisionShape()` when a plane
lands, our body deleted the collision primitive instead of rebuilding it, and the
next motion beat dereferenced it unguarded at 0x0067AA57.

This makes that disagreement mechanical.

What it trusts
--------------
Only a real MSVC mangled export (`?Foo@Bar@Moho@@QAE...`) counts. A bare IDA
label is somebody's guess and has already been observed attached to the wrong
body - `Moho::STransportPickUpInfo::AddUnit` at 0x005E4480 labels a function
whose disassembly unambiguously *removes* (scan, `memmove_s` the tail down,
decrement end). Mangled names come from the image; labels do not.

What a hit means
----------------
Not every mismatch is a bug. The naming contract in CLAUDE.md deliberately
prefers intent names, and a prefix difference (`SheetLock` vs `Lock`) is
cosmetic. The two shapes worth reading carefully are:

  * the SWAPS section - our name for address A is the binary's name for
    address B. That is the collision-shape bug exactly.
  * opposite verbs - Add/Remove, Enable/Disable, Lock/Unlock, Read/Write,
    Serialize/Deserialize, Show/Hide, Attach/Detach.

Usage
-----
    python scripts/namecheck.py [--all] [--namespace fa_full_2026_03_26]

`--all` prints every mismatch instead of the ranked head.
"""

import argparse
import io
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "src", "sdk")

ADDR_RE = re.compile(r"Address:\s*0x([0-9A-Fa-f]{8})")
DEF_RE = re.compile(
    r"^\s*(?:\[\[nodiscard\]\]\s*)?(?:template\s*<[^>]*>\s*)?"
    r"(?:[A-Za-z_][\w:<>,\*&\s]*?\s+)?"
    r"(?:([A-Za-z_]\w*)::)?([~A-Za-z_]\w*)\s*\("
)
PLACEHOLDER_RE = re.compile(r"^(sub_|FUN_|loc_|unknown_libname|nullsub|j_)")

OPPOSITE_VERBS = (
    "Add", "Remove", "Enable", "Disable", "Show", "Hide", "Start", "Stop",
    "Lock", "Unlock", "Push", "Pop", "Attach", "Detach", "Insert", "Erase",
    "Open", "Close", "Acquire", "Release", "Serialize", "Deserialize",
    "Read", "Write", "Revert", "Apply",
)


def read_binary_symbol(asm_dir, addr_hex):
    path = os.path.join(asm_dir, "FUN_%s.asm" % addr_hex.upper())
    if not os.path.exists(path):
        return None
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
            for _ in range(8):
                line = handle.readline()
                if not line:
                    return None
                if line.startswith("function_name:"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def method_of(symbol):
    """The trailing identifier of a mangled export, or None if not authoritative."""
    if not symbol or not symbol.startswith("?") or "@@" not in symbol:
        return None
    bracketed = re.search(r"\[([^\]]+)\]", symbol)
    if not bracketed:
        return None
    full = bracketed.group(1).strip().split("(")[0].strip()
    if PLACEHOLDER_RE.match(full):
        return None
    parts = [part for part in full.split("::") if part]
    return parts[-1] if parts else None


def anchors_in(path):
    """Every (address, our identifier, line) the file annotates."""
    found = []
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().split("\n")
    except OSError:
        return found

    for index, line in enumerate(lines):
        match = ADDR_RE.search(line)
        if not match:
            continue
        # The definition is the first non-comment line after the Doxygen block.
        for offset in range(index + 1, min(index + 40, len(lines))):
            candidate = lines[offset]
            stripped = candidate.strip()
            if not stripped or stripped.startswith(("*", "//", "/*")):
                continue
            definition = DEF_RE.match(candidate)
            if definition:
                found.append((match.group(1).upper(), definition.group(2), offset + 1))
            break
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", default="fa_full_2026_03_26")
    parser.add_argument("--all", action="store_true", help="print every mismatch")
    args = parser.parse_args()

    asm_dir = os.path.join(REPO, "decomp", "recovery", "disasm", args.namespace)
    if not os.path.isdir(asm_dir):
        sys.stderr.write("no such namespace dir: %s\n" % asm_dir)
        return 2

    mismatches = []
    anchor_count = 0
    authoritative = 0

    for dirpath, _dirs, files in os.walk(SRC):
        for name in files:
            if not name.endswith((".cpp", ".h")):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, REPO).replace("\\", "/")
            for addr, ours, line in anchors_in(path):
                anchor_count += 1
                theirs = method_of(read_binary_symbol(asm_dir, addr))
                if not theirs:
                    continue
                authoritative += 1
                if theirs == ours:
                    continue
                if ours.startswith("~") or theirs.startswith("~"):
                    continue
                if "operator" in ours or "operator" in theirs:
                    continue
                mismatches.append((addr, ours, theirs, rel, line))

    by_binary_name = set(entry[2] for entry in mismatches)
    swaps = [m for m in mismatches if m[1] in by_binary_name]
    verbs = [
        m for m in mismatches
        if m not in swaps and any(v in m[1] or v in m[2] for v in OPPOSITE_VERBS)
    ]
    rest = [m for m in mismatches if m not in swaps and m not in verbs]

    def dump(title, rows, limit=None):
        print("== %s (%d) ==" % (title, len(rows)))
        for addr, ours, theirs, rel, line in sorted(rows)[: (limit or len(rows))]:
            print("0x%s  ours=%-38s binary=%-38s %s:%d" % (addr, ours, theirs, rel, line))
        print("")

    print("anchors scanned              : %d" % anchor_count)
    print("checked against a mangled export: %d" % authoritative)
    print("name mismatches              : %d" % len(mismatches))
    print("")
    dump("SWAPS - our name is another address's binary name", swaps)
    dump("OPPOSITE VERBS - read these", verbs, None if args.all else 60)
    dump("other", rest, None if args.all else 40)

    return 1 if swaps else 0


if __name__ == "__main__":
    sys.exit(main())
