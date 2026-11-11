#!/usr/bin/env python3
"""Inspect a .fmap (Extended / Full3D) file.

    python tools/mapformat/mapinfo.py file.fmap [--dump] [--validate] [--lenient]

Default: header + chunk table (container level checks only: framing, CRCs, inflate, simHash).
--validate: the whole reader (features, every chunk decoded strictly, cross-chunk rules); warnings are printed.
--dump:     the canonical text dump (implies --validate).
--lenient:  with --validate, render / metadata / derived chunk errors become warnings.
Exit code 0 = valid, 1 = invalid (the reason is printed to stderr), 2 = usage / unreadable file.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mapfmt import chunks as C                                      # noqa: E402
from mapfmt.container import read_container                         # noqa: E402
from mapfmt.dump import dump_text                                   # noqa: E402
from mapfmt.errors import MapFormatError                            # noqa: E402
from mapfmt.features import names                                   # noqa: E402
from mapfmt.loadmap import load_map                                 # noqa: E402

FORMAT_NAME = {3: "Extended", 4: "Full3D"}
CLASS_NAME = {"S": "sim", "R": "render", "M": "meta", "D": "derived"}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file")
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--lenient", action="store_true")
    a = ap.parse_args(argv)
    try:
        with open(a.file, "rb") as f:
            data = f.read()
    except OSError as e:
        print("cannot read %s: %s" % (a.file, e), file=sys.stderr)
        return 2
    try:
        if a.validate or a.dump:
            lm = load_map(data, a.lenient)
            c = lm.container
        else:
            lm = None
            c = read_container(data)
        if a.dump:
            sys.stdout.write(dump_text(data, a.lenient))
            return 0
        print("format     %s (container %d)" % (FORMAT_NAME[c.container], c.container))
        print("revision   %d" % c.revision)
        print("required   0x%016x  %s" % (c.required, " ".join(names(c.required)) or "-"))
        print("optional   0x%016x  %s" % (c.optional, " ".join(names(c.optional)) or "-"))
        print("mapGuid    %s" % c.guid.hex())
        print("simHash    %s" % c.sim_hash.hex())
        print("fileSize   %d, %d chunks" % (c.file_size, len(c.entries)))
        print("%-4s %4s %3s %-6s %-8s %9s %9s  %s" % ("id", "inst", "ver", "flags", "class", "stored", "raw", "status"))
        for e in c.entries:
            cd = C.CHUNKS.get(e.id)
            cls = CLASS_NAME[cd.cls] if cd else ("sim" if e.sim else "derived" if e.derived else "?")
            fl = ("R" if e.required else "-") + ("S" if e.sim else "-") + ("D" if e.derived else "-") + ("z" if e.deflated else "-")
            key = (e.id, e.instance)
            status = "known" if cd else "unknown"
            if lm is not None:
                status = "skipped" if key in lm.skipped else "dropped" if key in lm.dropped else "ok"
            print("%-4s %4d %3d %-6s %-8s %9d %9d  %s" % (e.id, e.instance, e.version, fl, cls, e.stored_size, e.raw_size, status))
        if lm is not None:
            print("derived features: required %s, optional %s" % (" ".join(names(lm.derived_required)) or "-",
                                                                  " ".join(names(lm.derived_optional)) or "-"))
            for w in lm.warnings:
                print("warning: " + w)
            print("valid")
        return 0
    except MapFormatError as e:
        print("INVALID %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
