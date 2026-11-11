"""Canonical text dump of a whole file (CONTAINER.md section 8).

    file.container = 3
    file.revision = 1
    file.flags = 0x00000000
    file.required = 0x0000000000000003
    file.optional = 0x00000000000001fa
    file.mapGuid = <32 hex>
    file.simHash = <64 hex>
    chunk GRID inst=0 ver=1 flags=0x0003 raw=29
    GRID.cellsX = 64
    ...
    chunk ZZZO inst=0 skipped          (unknown optional chunk, or a version newer than this reader knows)

Chunks in directory order, fields in spec order, `\n` line endings, ASCII. `flags` of a chunk line is the stored
directory flags (so it includes the DEFLATE bit), `raw` the declared raw size. The file lines beyond the three of the
spec example (flags, optional, mapGuid, simHash) are part of this reference's contract.
"""
import os

from . import chunks as C
from .loadmap import load_map


def dump_text(src, lenient=False):
    if isinstance(src, (str, os.PathLike)):
        with open(src, "rb") as f:
            src = f.read()
    lm = load_map(bytes(src), lenient)
    c = lm.container
    out = [
        "file.container = %d" % c.container,
        "file.revision = %d" % c.revision,
        "file.flags = 0x%08x" % c.flags,
        "file.required = 0x%016x" % c.required,
        "file.optional = 0x%016x" % c.optional,
        "file.mapGuid = %s" % c.guid.hex(),
        "file.simHash = %s" % c.sim_hash.hex(),
    ]
    for e in c.entries:
        key = (e.id, e.instance)
        if key in lm.skipped:
            out.append("chunk %s inst=%d skipped" % key)
            continue
        if key in lm.dropped:
            out.append("chunk %s inst=%d dropped" % key)
            continue
        out.append("chunk %s inst=%d ver=%d flags=0x%04x raw=%d" % (e.id, e.instance, e.version, e.flags, e.raw_size))
        out.extend(C.dump_chunk(e.id, lm.chunks[key], lm.ctx))
    return "\n".join(out) + "\n"
