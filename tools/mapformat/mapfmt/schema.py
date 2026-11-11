"""A tiny declarative layer for chunk payloads.

Every chunk of EXTENDED.md / FULL3D.md is described once as a `Struct` of typed fields. One generic walker then gives
the strict decoder (payload consumed exactly, counts limited, never more elements than the remaining bytes can hold),
the encoder and the canonical text dump, so the three can never disagree about a layout.

Values: struct -> dict, array -> list, vec -> list of numbers, bytes/planes/bitmasks -> bytes.
Fixed point (fx8/fx10/fx16/fx32) values are kept as the raw integers, floats as Python floats that are exactly
binary32 values (encode rounds, decode never produces anything else).

Dump (CONTAINER.md section 8): `PREFIX.field = value`; arrays `PREFIX.name.count = n` + `PREFIX.name[i]...`;
vectors inline `[a, b]`; floats as `f32:xxxxxxxx` bit patterns; strings JSON-escaped (ASCII); blobs and bitmasks
`bytes[n] sha256:<hex>`; planes `plane[COLSxROWS] sha256:<hex>` of the decoded little-endian samples.
"""
import hashlib
import json
import struct

from . import predict
from .errors import ChunkError


class Scope(object):
    """Evaluation context for `when`, dimension and count callbacks: the struct being processed, its parent, the
    file-level context (cellsX, cellsZ, worldCells, ...)."""
    __slots__ = ("cur", "parent", "ctx")

    def __init__(self, cur, parent, ctx):
        self.cur = cur
        self.parent = parent
        self.ctx = ctx

    def need(self, key):
        v = self.ctx.get(key) if self.ctx else None
        if v is None:
            raise ChunkError("needs %s from the file context (decode GRID first)" % key)
        return v


class Reader(object):
    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0

    @property
    def remaining(self):
        return len(self.data) - self.pos

    def take(self, n):
        if n < 0 or n > self.remaining:
            raise ChunkError("payload ends %d bytes short (need %d at offset %d of %d)" %
                             (n - self.remaining, n, self.pos, len(self.data)))
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def unpack(self, fmt, size):
        return struct.unpack(fmt, self.take(size))[0]


class Ty(object):
    minsize = 0

    def enc(self, w, v, s):
        raise NotImplementedError

    def dec(self, r, s):
        raise NotImplementedError

    def dump(self, out, prefix, v, s):
        raise NotImplementedError


def f32_bits(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]


def f32_round(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


def _pack_f32(x):
    try:
        return struct.pack("<f", x)
    except (OverflowError, struct.error):
        raise ChunkError("value %r does not fit binary32" % (x,))


class Prim(Ty):
    FMT = {"u8": ("<B", 1), "u16": ("<H", 2), "u32": ("<I", 4), "u64": ("<Q", 8), "i8": ("<b", 1), "i16": ("<h", 2),
           "i32": ("<i", 4), "i64": ("<q", 8), "f32": ("<f", 4), "f64": ("<d", 8)}

    def __init__(self, kind, lo=None, hi=None, mask=None, eq=None):
        self.kind = kind
        self.fmt, self.size = Prim.FMT[kind]
        self.minsize = self.size
        self.lo, self.hi, self.mask, self.eq = lo, hi, mask, eq

    def __call__(self, lo=None, hi=None, mask=None, eq=None):
        """Restricted copy: value range lo..hi, `mask` = the only bits allowed to be set, `eq` = exact value."""
        return Prim(self.kind, lo, hi, mask, eq)

    @property
    def is_float(self):
        return self.kind[0] == "f"

    def _check(self, v):
        if self.eq is not None and v != self.eq:
            raise ChunkError("value %r, expected exactly %r" % (v, self.eq))
        if self.lo is not None and v < self.lo or self.hi is not None and v > self.hi:
            raise ChunkError("value %r outside %r..%r" % (v, self.lo, self.hi))
        if self.mask is not None and not self.is_float and (v & ~self.mask):
            raise ChunkError("value 0x%x sets reserved bits (allowed mask 0x%x)" % (v, self.mask))

    def enc(self, w, v, s):
        if self.is_float:
            if not isinstance(v, (int, float)):
                raise ChunkError("expected a number, got %r" % (v,))
        elif not isinstance(v, int):
            raise ChunkError("expected an integer, got %r" % (v,))
        self._check(v)
        try:
            w.append(struct.pack(self.fmt, v))
        except (struct.error, OverflowError):
            raise ChunkError("value %r does not fit %s" % (v, self.kind))

    def dec(self, r, s):
        v = r.unpack(self.fmt, self.size)
        self._check(v)
        return v

    def text(self, v):
        if self.kind == "f32":
            return "f32:%08x" % f32_bits(v)
        if self.kind == "f64":
            return "f64:%016x" % struct.unpack("<Q", struct.pack("<d", v))[0]
        return str(v)

    def dump(self, out, prefix, v, s):
        out.append("%s = %s" % (prefix, self.text(v)))


u8, u16, u32, u64 = Prim("u8"), Prim("u16"), Prim("u32"), Prim("u64")
i8, i16, i32, i64 = Prim("i8"), Prim("i16"), Prim("i32"), Prim("i64")
f32, f64 = Prim("f32"), Prim("f64")
fx32 = fx10 = fx16 = i32     # fixed point is kept (and dumped) as the raw integer


def enum8(n):
    """u8 with values 0..n-1; an unknown value refuses the chunk."""
    return u8(0, n - 1)


class Vec(Ty):
    """Fixed-size vector of primitives, dumped inline."""

    def __init__(self, n, elem):
        self.n, self.elem = n, elem
        self.minsize = n * elem.size

    def enc(self, w, v, s):
        if len(v) != self.n:
            raise ChunkError("vector needs %d components, got %d" % (self.n, len(v)))
        for x in v:
            self.elem.enc(w, x, s)

    def dec(self, r, s):
        return [self.elem.dec(r, s) for _ in range(self.n)]

    def dump(self, out, prefix, v, s):
        out.append("%s = [%s]" % (prefix, ", ".join(self.elem.text(x) for x in v)))


vec2, vec3, vec4, quat, color3 = Vec(2, f32), Vec(3, f32), Vec(4, f32), Vec(4, f32), Vec(3, f32)
fxvec2 = Vec(2, i32)
fx10vec3 = Vec(3, i32)
srgb8 = Vec(3, u8)


def sha_line(n, data):
    return "bytes[%d] sha256:%s" % (n, hashlib.sha256(data).hexdigest())


class Str(Ty):
    """u16 length + UTF-8, at most 4096 bytes."""
    minsize = 2

    def check(self, st):
        pass

    def enc(self, w, v, s):
        if not isinstance(v, str):
            raise ChunkError("expected a string, got %r" % (v,))
        b = v.encode("utf-8")
        if len(b) > 4096:
            raise ChunkError("string of %d bytes exceeds 4096" % len(b))
        self.check(v)
        w.append(struct.pack("<H", len(b)) + b)

    def dec(self, r, s):
        n = r.unpack("<H", 2)
        if n > 4096:
            raise ChunkError("string length %d exceeds 4096" % n)
        b = r.take(n)
        try:
            st = b.decode("utf-8")
        except UnicodeDecodeError:
            raise ChunkError("string is not valid UTF-8")
        self.check(st)
        return st

    def dump(self, out, prefix, v, s):
        out.append("%s = %s" % (prefix, json.dumps(v, ensure_ascii=True)))


class Path(Str):
    """`path` = str, lower case VFS path starting with '/'. The empty string means "none / neutral"."""

    def check(self, st):
        # "lower case" = no ASCII A-Z (the VFS is case insensitive for ASCII only); the C++ reader applies the same rule
        if st and (not st.startswith("/") or any("A" <= c <= "Z" for c in st)):
            raise ChunkError("path %r is not a lower case VFS path starting with '/'" % st)


STR, PATH = Str(), Path()


class Bytes(Ty):
    """Fixed number of raw bytes (keys, hashes), dumped as a blob."""

    def __init__(self, n):
        self.n = n
        self.minsize = n

    def enc(self, w, v, s):
        if len(v) != self.n:
            raise ChunkError("expected %d bytes, got %d" % (self.n, len(v)))
        w.append(bytes(v))

    def dec(self, r, s):
        return r.take(self.n)

    def dump(self, out, prefix, v, s):
        out.append("%s = %s" % (prefix, sha_line(len(v), v)))


class RawBytes(Ty):
    """Bytes whose length follows from other fields (`nbytes(scope)`), no stored count."""

    def __init__(self, nbytes):
        self.nbytes = nbytes

    def enc(self, w, v, s):
        if len(v) != self.nbytes(s):
            raise ChunkError("data is %d bytes, expected %d" % (len(v), self.nbytes(s)))
        w.append(bytes(v))

    def dec(self, r, s):
        return r.take(self.nbytes(s))

    def dump(self, out, prefix, v, s):
        out.append("%s = %s" % (prefix, sha_line(len(v), v)))


class Blob(Ty):
    """`<count_name>` (u32, or u64 with width=8) followed by that many bytes. The dict holds the bytes under the
    field name; the dump prints `<count_name>` and the bytes as two lines."""
    minsize = 4

    def __init__(self, count_name="byteCount", width=4, max_size=None):
        self.count_name, self.width, self.max_size = count_name, width, max_size
        self.minsize = width

    def enc(self, w, v, s):
        if self.max_size is not None and len(v) > self.max_size:
            raise ChunkError("%s of %d bytes exceeds %d" % (self.count_name, len(v), self.max_size))
        w.append(struct.pack("<I" if self.width == 4 else "<Q", len(v)) + bytes(v))

    def dec(self, r, s):
        n = r.unpack("<I" if self.width == 4 else "<Q", self.width)
        if self.max_size is not None and n > self.max_size:
            raise ChunkError("%s %d exceeds %d" % (self.count_name, n, self.max_size))
        return r.take(n)

    def dump(self, out, prefix, v, s):
        base = prefix[:prefix.rfind(".") + 1]
        out.append("%s%s = %d" % (base, self.count_name, len(v)))
        out.append("%s = %s" % (prefix, sha_line(len(v), v)))


class BitMask(Ty):
    """bitmask(W,H): rows of ceil(W/8) bytes, LSB first, row 0 = z 0. Padding bits are not inspected."""

    def __init__(self, dims):
        self.dims = dims

    def nbytes(self, s):
        cols, rows = self.dims(s)
        return rows * ((cols + 7) // 8)

    def enc(self, w, v, s):
        if len(v) != self.nbytes(s):
            raise ChunkError("bitmask is %d bytes, expected %d" % (len(v), self.nbytes(s)))
        w.append(bytes(v))

    def dec(self, r, s):
        return r.take(self.nbytes(s))

    def dump(self, out, prefix, v, s):
        out.append("%s = %s" % (prefix, sha_line(len(v), v)))


class Plane(Ty):
    """Predictor-coded plane. `dims(scope) -> (cols, rows)`. With `pred_field=None` the stored layout is
    `u8 predictor` + data and the value is {'predictor': p, 'data': decoded bytes}; with `pred_field='name'` the
    predictor is a sibling field (HGHT, HDET) and the value is just the decoded little-endian bytes."""

    def __init__(self, elem_bytes, dims, channels=1, pred_field=None):
        self.elem_bytes, self.dims, self.channels, self.pred_field = elem_bytes, dims, channels, pred_field
        self.minsize = 0 if pred_field else 1

    def _eb(self, s):
        return self.elem_bytes(s) if callable(self.elem_bytes) else self.elem_bytes

    def _geom(self, s):
        cols, rows = self.dims(s)
        if cols < 0 or rows < 0 or cols * rows > (1 << 30):
            raise ChunkError("plane of %dx%d is out of range" % (cols, rows))
        return cols, rows, self._eb(s)

    def enc(self, w, v, s):
        cols, rows, eb = self._geom(s)
        if self.pred_field:
            p, data = s.cur[self.pred_field], v
        else:
            p, data = v["predictor"], v["data"]
            w.append(struct.pack("<B", p))
        w.append(predict.encode_plane(data, rows, cols, self.channels, eb, p))

    def dec(self, r, s):
        cols, rows, eb = self._geom(s)
        if self.pred_field:
            p = s.cur[self.pred_field]
        else:
            p = r.take(1)[0]
        n = cols * rows * self.channels * eb
        if n > r.remaining:
            raise ChunkError("plane needs %d bytes but only %d remain" % (n, r.remaining))
        data = predict.decode_plane(r.take(n), rows, cols, self.channels, eb, p)
        return data if self.pred_field else {"predictor": p, "data": data}

    def dump(self, out, prefix, v, s):
        cols, rows, _ = self._geom(s)
        data = v if self.pred_field else v["data"]
        out.append("%s = plane[%dx%d] sha256:%s" % (prefix, cols, rows, hashlib.sha256(data).hexdigest()))


def plane(data, predictor=0):
    """Value of an inline-predictor plane."""
    return {"predictor": predictor, "data": bytes(data)}


class Array(Ty):
    """`u32 count` + elements, count within lo..hi (hi is the limit stated by the spec) and never larger than the
    remaining bytes can hold. `expect(scope)` pins the count to another field (CIDX, SPLT)."""
    minsize = 4

    def __init__(self, elem, lo=0, hi=1 << 32, expect=None):
        self.elem, self.lo, self.hi, self.expect = elem, lo, hi, expect

    def enc(self, w, v, s):
        n = len(v)
        self._count(n, s)
        w.append(struct.pack("<I", n))
        for x in v:
            self.elem.enc(w, x, s)

    def _count(self, n, s):
        if n < self.lo or n > self.hi:
            raise ChunkError("count %d outside %d..%d" % (n, self.lo, self.hi))
        if self.expect is not None and n != self.expect(s):
            raise ChunkError("count %d, expected %d" % (n, self.expect(s)))

    def dec(self, r, s):
        n = r.unpack("<I", 4)
        self._count(n, s)
        if n * max(self.elem.minsize, 1) > r.remaining:
            raise ChunkError("count %d cannot fit in the remaining %d bytes" % (n, r.remaining))
        return [self.elem.dec(r, s) for _ in range(n)]

    def dump(self, out, prefix, v, s):
        out.append("%s.count = %d" % (prefix, len(v)))
        for i, x in enumerate(v):
            self.elem.dump(out, "%s[%d]" % (prefix, i), x, s)


class Rep(Ty):
    """A repeated element whose count is another field (no stored count). Dumped like an array."""

    def __init__(self, elem, count):
        self.elem, self.count = elem, count

    def enc(self, w, v, s):
        if len(v) != self.count(s):
            raise ChunkError("%d elements, expected %d" % (len(v), self.count(s)))
        for x in v:
            self.elem.enc(w, x, s)

    def dec(self, r, s):
        n = self.count(s)
        if n * max(self.elem.minsize, 1) > r.remaining:
            raise ChunkError("count %d cannot fit in the remaining %d bytes" % (n, r.remaining))
        return [self.elem.dec(r, s) for _ in range(n)]

    def dump(self, out, prefix, v, s):
        out.append("%s.count = %d" % (prefix, len(v)))
        for i, x in enumerate(v):
            self.elem.dump(out, "%s[%d]" % (prefix, i), x, s)


class F(object):
    """A struct field. `when(scope)` makes it conditional. `note` marks a field name the spec does not give
    (the text is the spec phrase it stands for); those are listed in DUMP_NAMES.md."""
    __slots__ = ("name", "ty", "when", "note")

    def __init__(self, name, ty, when=None, note=None):
        self.name, self.ty, self.when, self.note = name, ty, when, note


class Struct(Ty):
    def __init__(self, fields, check=None):
        self.fields = fields
        self.check = check
        self.minsize = sum(f.ty.minsize for f in fields if f.when is None)

    def enc(self, w, v, s):
        if not isinstance(v, dict):
            raise ChunkError("expected a dict, got %r" % (v,))
        sc = Scope(v, s, s.ctx if s else None)
        names = set()
        for f in self.fields:
            if f.when is not None and not f.when(sc):
                continue
            names.add(f.name)
            if f.name not in v:
                raise ChunkError("field %s is missing" % f.name)
            try:
                f.ty.enc(w, v[f.name], sc)
            except ChunkError as e:
                raise ChunkError("%s: %s" % (f.name, e.detail), code=e.code)
        extra = set(v) - names
        if extra:
            raise ChunkError("unexpected fields %s" % sorted(extra))
        if self.check:
            self.check(v, sc)

    def dec(self, r, s):
        d = {}
        sc = Scope(d, s, s.ctx if s else None)
        for f in self.fields:
            if f.when is not None and not f.when(sc):
                continue
            try:
                d[f.name] = f.ty.dec(r, sc)
            except ChunkError as e:
                raise ChunkError("%s: %s" % (f.name, e.detail), code=e.code)
        if self.check:
            self.check(d, sc)
        return d

    def dump(self, out, prefix, v, s):
        sc = Scope(v, s, s.ctx if s else None)
        for f in self.fields:
            if f.when is not None and not f.when(sc):
                continue
            f.ty.dump(out, "%s.%s" % (prefix, f.name), v[f.name], sc)


def struct_(*fields, **kw):
    return Struct(list(fields), kw.get("check"))
