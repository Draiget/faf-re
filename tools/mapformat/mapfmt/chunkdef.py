"""Chunk registry and the generic codec entry points.

`chunk(...)` registers a chunk id with its class (S sim, R render, M metadata, D derived), version, layout and the
container that may hold it (3 = Extended and Full3D, 4 = Full3D only). `encode_chunk` / `decode_chunk` /
`dump_chunk` are the generic functions; `chunks.py` exposes them per id as `encode_grid`, `decode_grid`, ...
"""
from .container import F_DERIVED, F_REQUIRED, F_SIM
from .errors import ChunkError
from .schema import Reader, Scope, Struct

CHUNKS = {}                     # id -> ChunkDef (registration order = spec order)
CLASS_FLAGS = {"S": F_SIM, "R": 0, "M": 0, "D": F_DERIVED}


class ChunkDef(object):
    def __init__(self, id, cls, schema, version=1, extended_required=False, container_min=3, instanced=False,
                 raw_max=None, what=""):
        self.id, self.cls, self.schema, self.version = id, cls, schema, version
        self.extended_required = extended_required
        self.container_min = container_min
        self.instanced = instanced      # instance may be non-zero
        self.raw_max = raw_max
        self.what = what

    def default_flags(self, required=None):
        """Directory flags for a chunk of this class. Sim chunks are REQUIRED unless told otherwise (a broken sim
        chunk must refuse the map); everything else is optional."""
        if required is None:
            required = self.cls == "S"
        return CLASS_FLAGS[self.cls] | (F_REQUIRED if required else 0)


def chunk(id, cls, fields, check=None, **kw):
    assert id not in CHUNKS and len(id) == 4
    CHUNKS[id] = ChunkDef(id, cls, Struct(list(fields), check), **kw)
    return CHUNKS[id]


def _check_finite(obj, path=""):
    """EXTENDED.md appendix A: all floats in sim chunks are finite."""
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            raise ChunkError("non-finite float%s" % (" in " + path if path else ""))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _check_finite(v, k if not path else path + "." + str(k))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _check_finite(v, path)


def encode_chunk(id, d, ctx=None):
    cd = CHUNKS[id]
    if cd.cls == "S":
        try:
            _check_finite(d)
        except ChunkError as e:
            raise ChunkError(e.detail, chunk=id, code=e.code)
    w = []
    try:
        cd.schema.enc(w, d, Scope({}, None, ctx or {}))
    except ChunkError as e:
        raise ChunkError(e.detail, chunk=id, code=e.code)
    out = b"".join(w)
    if cd.raw_max is not None and len(out) > cd.raw_max:
        raise ChunkError("payload of %d bytes exceeds %d" % (len(out), cd.raw_max), chunk=id)
    return out


def decode_chunk(id, raw, ctx=None):
    cd = CHUNKS[id]
    if cd.raw_max is not None and len(raw) > cd.raw_max:
        raise ChunkError("payload of %d bytes exceeds %d" % (len(raw), cd.raw_max), chunk=id)
    r = Reader(raw)
    try:
        d = cd.schema.dec(r, Scope({}, None, ctx or {}))
    except ChunkError as e:
        raise ChunkError(e.detail, chunk=id, code=e.code)
    if r.remaining:
        raise ChunkError("%d unread trailing bytes (chunks are consumed exactly)" % r.remaining, chunk=id)
    if cd.cls == "S":
        try:
            _check_finite(d)
        except ChunkError as e:
            raise ChunkError(e.detail, chunk=id, code=e.code)
    return d


def dump_chunk(id, d, ctx=None):
    out = []
    try:
        CHUNKS[id].schema.dump(out, id, d, Scope({}, None, ctx or {}))
    except ChunkError as e:
        raise ChunkError(e.detail, chunk=id, code=e.code)
    return out
