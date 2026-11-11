"""All chunk codecs under one roof.

For every chunk id of EXTENDED.md / FULL3D.md this module exposes
    encode_<id>(dict, ctx=None) -> bytes
    decode_<id>(bytes, ctx=None) -> dict          (strict: payload consumed exactly)
    dump_<id>(dict, ctx=None)    -> list of canonical dump lines
e.g. `encode_grid`, `decode_hght`, `dump_scat`. `ctx` is the file context a few chunks need for sizes:
{'cellsX': .., 'cellsZ': .., 'worldCells': ..} (see `context_from`). The generic forms take the id:
`encode_chunk('GRID', d)`.
"""
from . import chunks_render, chunks_sim, chunks_world3d    # noqa: F401  (importing registers the chunks)
from .chunkdef import CHUNKS, decode_chunk, dump_chunk, encode_chunk    # noqa: F401
from .errors import ChunkError
from .schema import Reader, Scope


def _make(cid):
    def enc(d, ctx=None):
        return encode_chunk(cid, d, ctx)

    def dec(raw, ctx=None):
        return decode_chunk(cid, raw, ctx)

    def dmp(d, ctx=None):
        return dump_chunk(cid, d, ctx)

    enc.__name__, dec.__name__, dmp.__name__ = "encode_" + cid.lower(), "decode_" + cid.lower(), "dump_" + cid.lower()
    return enc, dec, dmp


for _cid in CHUNKS:
    globals()["encode_" + _cid.lower()], globals()["decode_" + _cid.lower()], globals()["dump_" + _cid.lower()] = _make(_cid)

EXTENDED_IDS = [i for i, c in CHUNKS.items() if c.container_min == 3]
FULL3D_ONLY_IDS = [i for i, c in CHUNKS.items() if c.container_min == 4]
EXTENDED_REQUIRED = [i for i, c in CHUNKS.items() if c.extended_required]    # META GRID HGHT PLAY GPLY WBOD
SIM_IDS = [i for i, c in CHUNKS.items() if c.cls == "S"]


def context_from(decoded):
    """Build the decode context from already decoded chunks (dict id -> dict, instance 0)."""
    ctx = {}
    g = decoded.get("GRID")
    if g:
        ctx["cellsX"], ctx["cellsZ"] = g["cellsX"], g["cellsZ"]
    w = decoded.get("WRLD")
    if w:
        ctx["worldCells"] = w["cellsX"] * w["cellsY"] * w["cellsZ"]
    return ctx


# ------------------------------------------------------------------ native mesh body (MSHB format 1)

def encode_native_mesh(d):
    w = []
    try:
        chunks_world3d.NATIVE_MESH.enc(w, d, Scope({}, None, {}))
    except ChunkError as e:
        raise ChunkError(e.detail, chunk="MSHB native mesh", code=e.code)
    return b"".join(w)


def decode_native_mesh(raw):
    r = Reader(raw)
    try:
        d = chunks_world3d.NATIVE_MESH.dec(r, Scope({}, None, {}))
    except ChunkError as e:
        raise ChunkError(e.detail, chunk="MSHB native mesh", code=e.code)
    if r.remaining:
        raise ChunkError("%d unread trailing bytes" % r.remaining, chunk="MSHB native mesh")
    return d
