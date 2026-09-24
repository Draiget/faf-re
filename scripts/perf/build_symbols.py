"""Build the lookup tables the sampling profiler needs, from the repo's own indexes.

Writes into <out_dir> (default: %TEMP%/faf_perf):
  symmap.json     sorted [start_ea, end_ea, token, anchor_symbol, anchor_location] per IDA function
  symnames.json   same order: [token, best_name, location] (anchor symbol, else a meaningful IDA name)
  callsites.txt   every `call` line of the disassembly export (exact return addresses for stack walks)

usage: python scripts/perf/build_symbols.py [out_dir]
"""
import json
import os
import pathlib
import sqlite3
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
NAMESPACE = REPO / "decomp" / "recovery" / "disasm" / "fa_full_2026_03_26"
CALLGRAPH = NAMESPACE / "_callgraph_index.sqlite"
SOURCE_INDEX = REPO / "decomp" / "recovery" / "_source_index.sqlite"


def main():
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.environ.get("TEMP", "."), "faf_perf"))
    out.mkdir(parents=True, exist_ok=True)

    cg = sqlite3.connect(str(CALLGRAPH))
    funcs = cg.execute("select token, start_ea, end_ea, function_name, demangled_name, has_meaningful_name "
                       "from functions").fetchall()

    anchors = {}
    si = sqlite3.connect(str(SOURCE_INDEX))
    for ea, symbol, label, path, line, kind in si.execute("select ea, symbol, label, file, line, kind from anchors"):
        name = symbol or label
        if not name:
            continue
        current = anchors.get(ea)
        if current is None or (kind == "definition" and current[2] != "definition"):
            anchors[ea] = (name, "%s:%s" % (path, line), kind)

    rows = []
    for token, start, end, fname, dname, meaningful in funcs:
        anchor = anchors.get(start)
        ida_name = (dname or fname) if meaningful else None
        rows.append((start, end, token, anchor[0] if anchor else None, anchor[1] if anchor else None, ida_name))
    rows.sort()
    json.dump([[s, e, t, a, loc] for s, e, t, a, loc, _ in rows], open(out / "symmap.json", "w"))
    json.dump([[t, a or ida or t, loc or ""] for s, e, t, a, loc, ida in rows], open(out / "symnames.json", "w"))

    # Every call instruction of the export; the sampler turns them into exact return addresses.
    with open(out / "callsites.txt", "w") as sink:
        subprocess.run(["rg", "-N", "--no-filename", "-g", "FUN_*.asm", r"^0x[0-9A-Fa-f]{8}: [0-9A-F ]+\s+call\s",
                        str(NAMESPACE)], stdout=sink, check=False)
    print("functions: %d, named: %d, out: %s" % (len(rows), sum(1 for r in rows if r[3] or r[5]), out))


if __name__ == "__main__":
    main()
