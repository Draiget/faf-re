"""Container framing for containers 3 and 4 (CONTAINER.md): writer, validating reader, simHash.

Reader check order (CONTAINER.md section 6): header magic / container / size / CRC, directory bounds + CRC,
per-chunk range + overlap, then per chunk CRC of the stored bytes and inflate to the declared rawSize.

Decisions where the spec is silent (listed in the final report of the reference implementation):
  * a file shorter than fileSize is TRUNCATED, a longer one FILE_SIZE_MISMATCH;
  * the directory must end exactly at the end of the file (dirOffset + 48*dirCount == fileSize, "the directory is at
    the end"), so nothing can hide behind it;
  * reserved header / directory fields are written as 0 and *not* checked by the reader (forward compatibility);
    unknown entry flag bits are refused (they could mean an unknown codec);
  * the reader recomputes simHash and refuses a file whose header lies.
"""
import hashlib
import struct
import zlib

from .errors import MapFormatError

MAGIC = 0x1A70614D
HEADER_SIZE = 128
ENTRY_SIZE = 48
REVISION = 1

F_REQUIRED = 1
F_SIM = 2
F_DERIVED = 4
F_DEFLATE = 8
KNOWN_ENTRY_FLAGS = F_REQUIRED | F_SIM | F_DERIVED | F_DEFLATE
HF_SIGNATURE = 1

HEADER_FMT = "<IIHHIQQIIQQ16s32s16sII"   # 4+4+2+2+4+8+8+4+4+8+8+16+32+16+4+4 = 128
ENTRY_FMT = "<4sHHIIQQQQ"                # 48
assert struct.calcsize(HEADER_FMT) == HEADER_SIZE and struct.calcsize(ENTRY_FMT) == ENTRY_SIZE


class Limits(object):
    """Reader hard caps (CONTAINER.md section 6)."""

    def __init__(self, file_size=4 << 30, dir_entries=4096, chunk_raw=1 << 30, total_raw=3 << 30, ratio=1032):
        self.file_size = file_size
        self.dir_entries = dir_entries
        self.chunk_raw = chunk_raw
        self.total_raw = total_raw
        self.ratio = ratio


class Entry(object):
    """One directory entry. `stored` / `raw` are filled by the reader (raw only once CRC and inflate passed)."""

    def __init__(self, id, version=1, flags=0, instance=0, crc32=0, offset=0, stored_size=0, raw_size=0, reserved=0):
        self.id = id
        self.version = version
        self.flags = flags
        self.instance = instance
        self.crc32 = crc32
        self.offset = offset
        self.stored_size = stored_size
        self.raw_size = raw_size
        self.reserved = reserved
        self.stored = None
        self.raw = None
        self.error = None            # set in lenient mode when CRC / inflate failed

    @property
    def key(self):
        return (self.id.encode("ascii"), self.instance)

    @property
    def required(self):
        return bool(self.flags & F_REQUIRED)

    @property
    def sim(self):
        return bool(self.flags & F_SIM)

    @property
    def derived(self):
        return bool(self.flags & F_DERIVED)

    @property
    def deflated(self):
        return bool(self.flags & F_DEFLATE)

    def pack(self):
        return struct.pack(ENTRY_FMT, self.id.encode("ascii"), self.version, self.flags, self.instance, self.crc32,
                           self.offset, self.stored_size, self.raw_size, self.reserved)


class Container(object):
    def __init__(self):
        self.container = 0
        self.revision = 0
        self.flags = 0
        self.file_size = 0
        self.dir_offset = 0
        self.dir_count = 0
        self.dir_crc = 0
        self.required = 0
        self.optional = 0
        self.guid = b""
        self.sim_hash = b""
        self.entries = []

    def find(self, id, instance=0):
        for e in self.entries:
            if e.id == id and e.instance == instance:
                return e
        return None


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def deflate_raw(data, level=9):
    """Raw DEFLATE (RFC 1951), no zlib/gzip wrapper. Deterministic for a given zlib build."""
    c = zlib.compressobj(level, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def inflate_raw(data, raw_size):
    """Inflate exactly `raw_size` bytes; a stream that is longer, shorter, unfinished or has trailing bytes fails."""
    d = zlib.decompressobj(-15)
    try:
        out = d.decompress(data, raw_size + 1)
        if len(out) <= raw_size and not d.eof:
            out += d.flush()
    except zlib.error as e:
        raise MapFormatError("INFLATE_FAILED", "deflate stream is corrupt (%s)" % e)
    if len(out) != raw_size or not d.eof or d.unused_data or d.unconsumed_tail:
        raise MapFormatError("INFLATE_FAILED", "inflated %d bytes, directory declares %d (eof=%s)" %
                             (len(out), raw_size, d.eof))
    return out


def sim_hash(entries):
    """SHA-256 over the SIM entries in directory order: id(4) | version u16 | instance u32 | rawSize u64 | raw bytes."""
    h = hashlib.sha256()
    for e in entries:
        if e.flags & F_SIM:
            h.update(e.id.encode("ascii"))
            h.update(struct.pack("<HIQ", e.version, e.instance, e.raw_size))
            h.update(e.raw)
    return h.digest()


# ------------------------------------------------------------------------------------------------------ writer

class ChunkSpec(object):
    """A chunk to be written. `flags` are the REQUIRED / SIM / DERIVED bits; DEFLATE comes from `compress`."""

    def __init__(self, id, payload, instance=0, version=1, flags=0, compress=False):
        self.id = id
        self.payload = bytes(payload)
        self.instance = instance
        self.version = version
        self.flags = flags & ~F_DEFLATE
        self.compress = compress


def write_container(chunks, container=3, revision=REVISION, required=0, optional=0, guid=b"\0" * 16,
                    limits=None, header_flags=None):
    """Lay out header, 16-byte aligned chunk data and the directory (sorted bytewise by (id, instance)).

    Returns the file bytes. The writer refuses what the reader would refuse (ratio, duplicate ids, sizes)."""
    limits = limits or Limits()
    if container not in (3, 4):
        raise MapFormatError("UNSUPPORTED_CONTAINER", "writer handles containers 3 and 4, not %r" % container)
    if len(guid) != 16:
        raise MapFormatError("BAD_HEADER", "mapGuid must be 16 bytes")
    specs = sorted(chunks, key=lambda c: (c.id.encode("ascii"), c.instance))
    for a, b in zip(specs, specs[1:]):
        if (a.id, a.instance) == (b.id, b.instance):
            raise MapFormatError("BAD_DIRECTORY", "duplicate chunk %s instance %d" % (a.id, a.instance))
    if len(specs) > limits.dir_entries:
        raise MapFormatError("LIMIT", "too many chunks (%d)" % len(specs))
    body = bytearray()
    entries = []
    pos = HEADER_SIZE
    for c in specs:
        if len(c.id) != 4 or not all(0x20 <= ord(ch) < 0x7F for ch in c.id):
            raise MapFormatError("BAD_ENTRY", "chunk id %r is not four printable ASCII characters" % c.id)
        if c.flags & F_SIM and c.flags & F_DERIVED:
            raise MapFormatError("BAD_ENTRY", "chunk %s: SIM and DERIVED are exclusive" % c.id)
        stored = deflate_raw(c.payload) if c.compress else c.payload
        e = Entry(c.id, c.version, c.flags | (F_DEFLATE if c.compress else 0), c.instance, crc32(stored), pos,
                  len(stored), len(c.payload))
        if c.compress and len(c.payload) > len(stored) * limits.ratio:
            raise MapFormatError("INFLATE_RATIO", "chunk %s would exceed the 1:%d ratio" % (c.id, limits.ratio))
        e.stored = stored
        e.raw = c.payload
        entries.append(e)
        body += stored
        pad = (-len(stored)) % 16
        body += b"\0" * pad
        pos += len(stored) + pad
    dir_offset = pos
    dir_bytes = b"".join(e.pack() for e in entries)
    file_size = dir_offset + len(dir_bytes)
    if header_flags is None:
        header_flags = HF_SIGNATURE if any(e.id == "SIGN" for e in entries) else 0
    head = struct.pack("<IIHHIQQIIQQ16s32s16sI", MAGIC, container, revision, HEADER_SIZE, header_flags, file_size,
                       dir_offset, len(entries), crc32(dir_bytes), required, optional, guid, sim_hash(entries),
                       b"\0" * 16, 0)
    assert len(head) == HEADER_SIZE - 4
    head += struct.pack("<I", crc32(head))
    return head + bytes(body) + dir_bytes


# ------------------------------------------------------------------------------------------------------ reader

def parse_header(data):
    """Magic, container, size and CRC checks; returns a Container without entries."""
    if len(data) < 4 or struct.unpack_from("<I", data, 0)[0] != MAGIC:
        raise MapFormatError("BAD_MAGIC", "not a map file (magic is not 0x1A70614D)")
    if len(data) < 8:
        raise MapFormatError("TRUNCATED", "file is shorter than 8 bytes")
    cont = struct.unpack_from("<I", data, 4)[0]
    if cont not in (3, 4):
        raise MapFormatError("UNSUPPORTED_CONTAINER", "container version %d is not 3 (Extended) or 4 (Full3D)" % cont)
    if len(data) < HEADER_SIZE:
        raise MapFormatError("TRUNCATED", "file is shorter than the 128 byte header")
    (_m, _c, rev, hsize, flags, fsize, doff, dcount, dcrc, req, opt, guid, shash, _r, _r2,
     hcrc) = struct.unpack_from(HEADER_FMT, data, 0)
    if hsize != HEADER_SIZE:
        raise MapFormatError("BAD_HEADER", "headerSize is %d, expected 128" % hsize)
    if crc32(data[:HEADER_SIZE - 4]) != hcrc:
        raise MapFormatError("BAD_HEADER_CRC", "header CRC mismatch")
    c = Container()
    c.container, c.revision, c.flags, c.file_size, c.dir_offset, c.dir_count = cont, rev, flags, fsize, doff, dcount
    c.dir_crc, c.required, c.optional, c.guid, c.sim_hash = dcrc, req, opt, guid, shash
    return c


def read_container(data, limits=None, lenient=False):
    """Parse and validate. In lenient mode a chunk whose CRC / inflate fails gets `entry.error` set (and no raw)
    instead of raising, so tools can still list the file; header and directory errors always raise."""
    limits = limits or Limits()
    c = parse_header(data)
    if c.file_size > limits.file_size:
        raise MapFormatError("LIMIT", "file size %d exceeds the limit" % c.file_size)
    if len(data) < c.file_size:
        raise MapFormatError("TRUNCATED", "file has %d bytes, header declares %d" % (len(data), c.file_size))
    if len(data) > c.file_size:
        raise MapFormatError("FILE_SIZE_MISMATCH", "file has %d bytes, header declares %d" % (len(data), c.file_size))
    if c.dir_count > limits.dir_entries:
        raise MapFormatError("LIMIT", "directory has %d entries (max %d)" % (c.dir_count, limits.dir_entries))
    dir_len = c.dir_count * ENTRY_SIZE
    if c.dir_offset < HEADER_SIZE or c.dir_offset + dir_len != c.file_size:
        raise MapFormatError("BAD_DIRECTORY", "directory [%d, %d) is not the end of the %d byte file" %
                             (c.dir_offset, c.dir_offset + dir_len, c.file_size))
    dir_bytes = data[c.dir_offset:c.dir_offset + dir_len]
    if crc32(dir_bytes) != c.dir_crc:
        raise MapFormatError("BAD_DIR_CRC", "directory CRC mismatch")

    total_raw = 0
    prev_key = None
    for i in range(c.dir_count):
        idb, ver, flags, inst, crc, off, ssz, rsz, res = struct.unpack_from(ENTRY_FMT, dir_bytes, i * ENTRY_SIZE)
        if not all(0x20 <= b < 0x7F for b in idb):
            raise MapFormatError("BAD_ENTRY", "entry %d: id is not four printable ASCII characters" % i)
        e = Entry(idb.decode("ascii"), ver, flags, inst, crc, off, ssz, rsz, res)
        if flags & ~KNOWN_ENTRY_FLAGS:
            raise MapFormatError("BAD_ENTRY", "%s: unknown flag bits 0x%04x" % (e.id, flags & ~KNOWN_ENTRY_FLAGS))
        if flags & F_SIM and flags & F_DERIVED:
            raise MapFormatError("BAD_ENTRY", "%s: SIM and DERIVED are exclusive" % e.id)
        if prev_key is not None and e.key <= prev_key:
            raise MapFormatError("BAD_DIRECTORY", "%s inst=%d: entries are not strictly sorted by (id, instance)" % (e.id, inst))
        prev_key = e.key
        c.entries.append(e)

    # per-chunk range, alignment, overlap
    for e in c.entries:
        if e.offset % 16:
            raise MapFormatError("CHUNK_RANGE", "%s inst=%d: offset %d is not 16-byte aligned" % (e.id, e.instance, e.offset))
        if e.offset < HEADER_SIZE or e.offset + e.stored_size > c.dir_offset:
            raise MapFormatError("CHUNK_RANGE", "%s inst=%d: range [%d, %d) is outside [128, %d)" %
                                 (e.id, e.instance, e.offset, e.offset + e.stored_size, c.dir_offset))
    by_off = sorted(c.entries, key=lambda e: (e.offset, e.stored_size))
    for a, b in zip(by_off, by_off[1:]):
        if a.stored_size and b.stored_size and a.offset + a.stored_size > b.offset:
            raise MapFormatError("CHUNK_OVERLAP", "%s and %s overlap" % (a.id, b.id))
    for e in c.entries:
        if e.raw_size > limits.chunk_raw:
            raise MapFormatError("LIMIT", "%s inst=%d: raw size %d exceeds the limit" % (e.id, e.instance, e.raw_size))
        if e.deflated:
            if e.raw_size > e.stored_size * limits.ratio:
                raise MapFormatError("INFLATE_RATIO", "%s inst=%d: raw %d from stored %d exceeds 1:%d" %
                                     (e.id, e.instance, e.raw_size, e.stored_size, limits.ratio))
        elif e.raw_size != e.stored_size:
            raise MapFormatError("BAD_ENTRY", "%s inst=%d: not compressed but rawSize != storedSize" % (e.id, e.instance))
        total_raw += e.raw_size
        if total_raw > limits.total_raw:
            raise MapFormatError("LIMIT", "sum of raw chunk sizes exceeds the limit")

    # per chunk: CRC of the stored bytes, then inflate
    for e in c.entries:
        e.stored = data[e.offset:e.offset + e.stored_size]
        try:
            if crc32(e.stored) != e.crc32:
                raise MapFormatError("BAD_CHUNK_CRC", "%s inst=%d: CRC mismatch" % (e.id, e.instance))
            e.raw = inflate_raw(e.stored, e.raw_size) if e.deflated else e.stored
        except MapFormatError as err:
            if not lenient:
                raise
            e.error = err
    if all(e.error is None for e in c.entries):
        if sim_hash(c.entries) != c.sim_hash:
            raise MapFormatError("BAD_SIM_HASH", "header simHash does not match the SIM chunks")
    return c
