#!/usr/bin/env python3
"""Tests of the Python reference implementation (tools/mapformat/). Plain asserts:

    python tests/mapformat/test_reference.py [name-filter]      exit 0 = all pass

The goldens in tests/mapformat/golden/ are the contract with the C++ reader; this file proves the reference itself:
every chunk round-trips, predictors invert, every negative file fails with the intended error and no other, the
goldens regenerate byte for byte, the dumps match the stored .dump.txt, simHash behaves as specified.
"""
import hashlib
import os
import struct
import subprocess
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
TOOLS = os.path.join(ROOT, "tools", "mapformat")
GOLDEN = os.path.join(HERE, "golden")
sys.path.insert(0, TOOLS)

import gen_dump_names                                         # noqa: E402
import golden_content as G                                    # noqa: E402
import golden_world3d as G3                                   # noqa: E402
import make_golden                                            # noqa: E402
from mapfmt import chunks as C                                # noqa: E402
from mapfmt import container as K                             # noqa: E402
from mapfmt import predict, scatter                           # noqa: E402
from mapfmt.builder import MapBuilder                         # noqa: E402
from mapfmt.dump import dump_text                             # noqa: E402
from mapfmt.errors import ChunkError, MapFormatError         # noqa: E402
from mapfmt.features import derive_features                   # noqa: E402
from mapfmt.loadmap import load_map                           # noqa: E402

VALID = ["extended_min", "extended_full", "full3d_full", "extended_classic_equiv", "unknown_optional_chunk"]


def golden(name):
    with open(os.path.join(GOLDEN, name), "rb") as f:
        return f.read()


def expect(code, fn, *a, **kw):
    """fn must raise MapFormatError with exactly this code."""
    try:
        fn(*a, **kw)
    except MapFormatError as e:
        assert e.code == code, "expected %s, got %s" % (code, e)
        return e
    raise AssertionError("expected %s, nothing was raised" % code)


# ------------------------------------------------------------------------------------------------ predictors

def test_predictor_known_answers():
    assert predict.encode_plane(bytes([10, 20, 30]), 1, 3, 1, 1, 1) == bytes([10, 10, 10])
    assert predict.encode_plane(bytes([1, 2, 4, 6]), 2, 2, 1, 1, 2) == bytes([1, 2, 3, 4])
    # Paeth on [[1,2],[3,5]], worked by hand in the module docstring's terms
    assert predict.encode_plane(bytes([1, 2, 3, 5]), 2, 2, 1, 1, 3) == bytes([1, 1, 2, 2])
    # modulo arithmetic: 0 - 255 = 1 (mod 256), u16 wraps at 65536
    assert predict.encode_plane(bytes([255, 0]), 1, 2, 1, 1, 1) == bytes([255, 1])
    assert predict.encode_plane(struct.pack("<2H", 65535, 0), 1, 2, 1, 2, 1) == struct.pack("<2H", 65535, 1)
    # interleaved: left neighbour is `channels` elements back
    assert predict.encode_plane(bytes([1, 10, 3, 14]), 1, 2, 2, 1, 1) == bytes([1, 10, 2, 4])


def test_predictor_roundtrip():
    rng = G.Rng(5)
    for eb in (1, 2, 4):
        for ch in (1, 2, 4):
            for rows, cols in ((1, 1), (1, 7), (5, 1), (6, 9)):
                data = rng.bytes(rows * cols * ch * eb)
                for p in range(4):
                    enc = predict.encode_plane(data, rows, cols, ch, eb, p)
                    assert predict.decode_plane(enc, rows, cols, ch, eb, p) == data
    expect_chunk_error(lambda: predict.decode_plane(b"\0\0", 1, 2, 1, 1, 4))
    expect_chunk_error(lambda: predict.decode_plane(b"\0", 1, 2, 1, 1, 0))


def expect_chunk_error(fn):
    try:
        fn()
    except ChunkError:
        return
    raise AssertionError("expected ChunkError")


# ------------------------------------------------------------------------------------------------ chunks

def golden_entries(name):
    """(entry, raw, ctx) for every chunk of a golden file."""
    lm = load_map(golden(name))
    return lm, [(e, e.raw) for e in lm.container.entries if (e.id, e.instance) in lm.chunks]


def test_every_chunk_id_is_in_a_golden():
    ids_ext = set(e.id for e in load_map(golden("extended_full.fmap")).container.entries)
    ids_3d = set(e.id for e in load_map(golden("full3d_full.fmap")).container.entries)
    assert set(C.EXTENDED_IDS) <= ids_ext, sorted(set(C.EXTENDED_IDS) - ids_ext)
    assert set(C.CHUNKS) <= ids_3d, sorted(set(C.CHUNKS) - ids_3d)
    assert len(C.CHUNKS) == 55 and len(C.FULL3D_ONLY_IDS) == 15
    # multiple instances where the spec allows them
    ents = [(e.id, e.instance) for e in load_map(golden("extended_full.fmap")).container.entries]
    for cid, n in (("WFLW", 2), ("SCDM", 2), ("DRVD", 3), ("ASST", 2)):
        assert sum(1 for i, _ in ents if i == cid) == n, cid
    comp = [e.deflated for e in load_map(golden("extended_full.fmap")).container.entries]
    assert any(comp) and not all(comp), "compressed and uncompressed chunks must be mixed"


def test_chunk_roundtrip_bytes():
    """decode then encode reproduces the stored bytes of every chunk of every valid golden."""
    n = 0
    for name in VALID:
        lm, entries = golden_entries(name + ".fmap")
        for e, raw in entries:
            d = lm.chunks[(e.id, e.instance)]
            assert C.encode_chunk(e.id, d, lm.ctx) == raw, (name, e.id, e.instance)
            fn = getattr(C, "encode_" + e.id.lower())
            assert fn(d, lm.ctx) == raw
            assert getattr(C, "decode_" + e.id.lower())(raw, lm.ctx) == d
            n += 1
    assert n > 100


def test_chunk_roundtrip_dicts():
    """The dicts the goldens are built from survive encode -> decode unchanged (floats are exact binary32)."""
    ext, _ = G.extended_full()
    sets = [G.extended_min(), ext, G.classic_equiv(), G3.world3d_chunks()]
    ctx = {"cellsX": G.W, "cellsZ": G.H, "worldCells": 4}
    for chunks in sets:
        for cid, inst, d, _ in chunks:
            c = dict(ctx)
            if chunks is sets[2]:
                c = {"cellsX": 64, "cellsZ": 64}
            raw = C.encode_chunk(cid, d, c)
            assert C.decode_chunk(cid, raw, c) == d, (cid, inst)


def test_native_mesh_roundtrip():
    for raw in (G3.native_quad(), G3.native_tri()):
        d = C.decode_native_mesh(raw)
        assert C.encode_native_mesh(d) == raw
    expect_chunk_error(lambda: C.decode_native_mesh(G3.native_quad() + b"\0"))
    expect_chunk_error(lambda: C.decode_native_mesh(G3.native_quad()[:-1]))


def test_chunks_are_strict():
    """Trailing bytes and truncation make a chunk invalid; garbage never raises anything but ChunkError."""
    lm, entries = golden_entries("full3d_full.fmap")
    rng = G.Rng(99)
    for e, raw in entries:
        expect_chunk_error(lambda: C.decode_chunk(e.id, raw + b"\0", lm.ctx))
        expect_chunk_error(lambda: C.decode_chunk(e.id, raw[:-1], lm.ctx))
        for _ in range(12):                    # bit flips: either still decodes or fails cleanly
            b = bytearray(raw)
            for _ in range(1 + rng.below(3)):
                b[rng.below(len(b))] ^= 1 << rng.below(8)
            try:
                C.decode_chunk(e.id, bytes(b), lm.ctx)
            except ChunkError:
                pass


def test_count_lies_are_refused_without_allocating():
    # META with tag count 0xFFFFFFFF in a tiny payload
    d = G.extended_min()[0][2]
    raw = C.encode_chunk("META", d)
    # find the tags array: it is the 6th string-ish field; simply craft: name "", locs 0, 4 empty strs, tags=huge
    bogus = struct.pack("<H", 0) + struct.pack("<I", 0) + struct.pack("<4H", 0, 0, 0, 0) + struct.pack("<I", 0xFFFFFFFF)
    expect_chunk_error(lambda: C.decode_chunk("META", bogus))
    # a limit stated by the spec: 65 tags
    d2 = dict(d)
    d2["tags"] = ["t"] * 65
    expect_chunk_error(lambda: C.encode_chunk("META", d2))
    # plane larger than the payload
    expect_chunk_error(lambda: C.decode_chunk("HGHT", struct.pack("<fbBH", 0.0, -7, 0, 0), {"cellsX": 60000, "cellsZ": 60000}))
    assert len(raw) > 0


def test_enum_and_reserved_values_refused():
    g = G.extended_min()[1][2]
    bad = dict(g)
    bad["reserved"] = 1
    expect_chunk_error(lambda: C.encode_chunk("GRID", bad))
    bad = dict(g)
    bad["cellSize"] = 2.0
    expect_chunk_error(lambda: C.encode_chunk("GRID", bad))
    p = G.extended_min()[3][2]
    bad = dict(p)
    bad["borderMode"] = 3
    expect_chunk_error(lambda: C.encode_chunk("PLAY", bad, {"cellsX": 64, "cellsZ": 48}))


def test_dump_values():
    """Spot checks of the dump rules."""
    out = C.dump_chunk("GRID", G.extended_min()[1][2])
    assert out[0] == "GRID.cellsX = 64" and out[2] == "GRID.cellSize = f32:3f800000"
    assert C.dump_chunk("PLAY", G.extended_min()[3][2], {"cellsX": 64, "cellsZ": 48})[-1] == "PLAY.polygon.count = 0"
    meta = G.meta("x\"é\n")
    assert 'META.name = "x\\"\\u00e9\\n"' in C.dump_chunk("META", meta)
    wb = C.dump_chunk("WBOD", G.extended_min()[5][2], {"cellsX": 64, "cellsZ": 48})
    assert "WBOD.bodies[0].level = f32:42be0000" in wb
    full, _ = G.extended_full()
    lite = [c for c in full if c[0] == "LITE"][0][2]
    assert "LITE.sunColor = [f32:3f800000, f32:3f75c28f, f32:3f666666]" in C.dump_chunk("LITE", lite)
    sign = [c for c in full if c[0] == "SIGN"][0][2]
    assert C.dump_chunk("SIGN", sign)[1].startswith("SIGN.publicKey = bytes[32] sha256:")


# ------------------------------------------------------------------------------------------------ container

def test_container_fuzz():
    """Bit flips and truncations anywhere in a file are refused cleanly: only MapFormatError, never another exception."""
    rng = G.Rng(2026)
    for name in ("extended_min.fmap", "extended_full.fmap", "full3d_full.fmap"):
        data = golden(name)
        for i in range(400):
            b = bytearray(data)
            for _ in range(1 + rng.below(2)):
                b[rng.below(len(b))] ^= 1 << rng.below(8)
            try:
                load_map(bytes(b))
            except MapFormatError:
                pass
        for n in (0, 1, 7, 8, 100, 127, 128, 129, len(data) // 2, len(data) - 49, len(data) - 48, len(data) - 1):
            try:
                load_map(data[:n])
                raise AssertionError("a truncated file was accepted")
            except MapFormatError:
                pass


def test_container_basics():
    data = golden("extended_full.fmap")
    c = K.read_container(data)
    assert c.find("GRID").raw_size == 29                      # GRID v1 is 29 bytes
    assert struct.unpack_from("<IIHH", data, 0) == (0x1A70614D, 3, 1, 128)
    assert c.file_size == len(data) and c.dir_offset + 48 * c.dir_count == len(data)
    keys = [e.key for e in c.entries]
    assert keys == sorted(keys) and len(set(keys)) == len(keys)
    assert all(e.offset % 16 == 0 for e in c.entries)
    assert c.flags & 1 == 1                       # SIGN present
    assert K.crc32(data[:124]) == struct.unpack_from("<I", data, 124)[0]
    assert load_map(golden("full3d_full.fmap")).container.container == 4
    # round trip through the writer from the entries' raw bytes reproduces the file for uncompressed data
    specs = [K.ChunkSpec(e.id, e.raw, e.instance, e.version, e.flags, e.deflated) for e in c.entries]
    again = K.write_container(specs, 3, c.revision, c.required, c.optional, c.guid)
    assert again == data


def test_writer_refuses_bad_input():
    expect("BAD_DIRECTORY", K.write_container, [K.ChunkSpec("AAAA", b"1"), K.ChunkSpec("AAAA", b"2")])
    expect("BAD_ENTRY", K.write_container, [K.ChunkSpec("AAA", b"1")])
    expect("BAD_ENTRY", K.write_container, [K.ChunkSpec("AAAA", b"1", flags=K.F_SIM | K.F_DERIVED)])
    expect("UNSUPPORTED_CONTAINER", K.write_container, [], 2)
    expect("INFLATE_RATIO", K.write_container, [K.ChunkSpec("AAAA", b"\0" * 400000, compress=True)],
           limits=K.Limits(ratio=100))


def test_deflate_is_raw():
    raw = bytes(range(256)) * 40
    z = K.deflate_raw(raw)
    assert z[:2] != b"\x78\x9c" and K.inflate_raw(z, len(raw)) == raw
    expect("INFLATE_FAILED", K.inflate_raw, z, len(raw) + 1)
    expect("INFLATE_FAILED", K.inflate_raw, z, len(raw) - 1)
    expect("INFLATE_FAILED", K.inflate_raw, z + b"x", len(raw))
    expect("INFLATE_FAILED", K.inflate_raw, z[:-3], len(raw))


NEGATIVE = {
    # file: (code raised by read_container, or None when the container is fine and load_map must raise `file_code`)
    "bad_magic.fmap": ("BAD_MAGIC", None),
    "bad_container_5.fmap": ("UNSUPPORTED_CONTAINER", None),
    "bad_header_crc.fmap": ("BAD_HEADER_CRC", None),
    "truncated.fmap": ("TRUNCATED", None),
    "bad_dir_crc.fmap": ("BAD_DIR_CRC", None),
    "bad_chunk_crc.fmap": ("BAD_CHUNK_CRC", None),
    "chunk_out_of_range.fmap": ("CHUNK_RANGE", None),
    "unknown_required_chunk.fmap": (None, "UNKNOWN_REQUIRED_CHUNK"),
    "unsupported_required_feature.fmap": (None, "UNSUPPORTED_FEATURE"),
    "inflate_bomb.fmap": ("INFLATE_RATIO", None),
    "gpl_bad_surface_id.fmap": (None, "CROSS_CHUNK"),
}


def test_negative_files():
    for name, (container_code, file_code) in sorted(NEGATIVE.items()):
        data = golden(name)
        if container_code:
            expect(container_code, K.read_container, data)
            expect(container_code, load_map, data)
        else:
            K.read_container(data)                 # the container itself is valid
            expect(file_code, load_map, data)
    e = expect("UNSUPPORTED_FEATURE", load_map, golden("unsupported_required_feature.fmap"))
    assert "EXTENDED_FEATURES" in e.message
    e = expect("CROSS_CHUNK", load_map, golden("gpl_bad_surface_id.fmap"))
    assert "surface id 5" in e.message
    # no negative file is accepted by mapinfo --validate, every valid one is
    for name in NEGATIVE:
        assert subprocess.call([sys.executable, os.path.join(TOOLS, "mapinfo.py"), os.path.join(GOLDEN, name), "--validate"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 1, name


def test_unknown_optional_chunk_is_skipped():
    lm = load_map(golden("unknown_optional_chunk.fmap"))
    assert ("ZZZO", 0) in lm.skipped and ("ZZZO", 0) not in lm.chunks
    assert "chunk ZZZO inst=0 skipped" in dump_text(golden("unknown_optional_chunk.fmap")).split("\n")
    base = load_map(golden("extended_min.fmap"))
    assert lm.container.sim_hash == base.container.sim_hash       # not a sim chunk: the hash is unchanged


def test_directory_rules():
    mn = golden("extended_min.fmap")

    def patched(fn):
        return make_golden.patch_dir(mn, fn)

    def misalign(ents):
        make_golden.entry(ents, "META")[5] += 8
    expect("CHUNK_RANGE", K.read_container, patched(misalign))

    def overlap(ents):
        make_golden.entry(ents, "META")[5] = make_golden.entry(ents, "HGHT")[5]
    expect("CHUNK_OVERLAP", K.read_container, patched(overlap))

    def dup(ents):
        make_golden.entry(ents, "META")[0] = b"GRID"
    expect("BAD_DIRECTORY", K.read_container, patched(dup))

    def unsorted(ents):
        ents[0], ents[1] = ents[1], ents[0]
    expect("BAD_DIRECTORY", K.read_container, patched(unsorted))

    def flag(ents):
        make_golden.entry(ents, "META")[2] |= 0x10
    expect("BAD_ENTRY", K.read_container, patched(flag))

    def both(ents):
        make_golden.entry(ents, "GRID")[2] |= K.F_DERIVED
    expect("BAD_ENTRY", K.read_container, patched(both))

    def rawsize(ents):
        make_golden.entry(ents, "META")[7] += 1
    expect("BAD_ENTRY", K.read_container, patched(rawsize))

    def toolarge(ents):
        make_golden.entry(ents, "HGHT")[7] = make_golden.entry(ents, "HGHT")[6] * 2000
    expect("INFLATE_RATIO", K.read_container, patched(toolarge))
    expect("LIMIT", K.read_container, patched(toolarge), K.Limits(chunk_raw=1 << 20, ratio=1 << 40))
    expect("BAD_SIM_HASH", K.read_container, make_golden.patch_header_crc(mn[:40] + b"\xff" * 8 + mn[48:72] + b"\0" * 32 + mn[104:]))
    expect("LIMIT", K.read_container, mn, K.Limits(dir_entries=2))
    # a file longer than the header says
    expect("FILE_SIZE_MISMATCH", K.read_container, mn + b"\0")
    expect("TRUNCATED", K.read_container, mn[:100])
    expect("BAD_MAGIC", K.read_container, b"")


def test_class_flags_and_instances():
    mn = golden("extended_min.fmap")

    # META flagged SIM (hash and CRCs consistent): the directory disagrees with the chunk class
    c = K.read_container(mn)
    specs = [K.ChunkSpec(e.id, e.raw, e.instance, e.version, e.flags | (K.F_SIM if e.id == "META" else 0), e.deflated)
             for e in c.entries]
    expect("BAD_CHUNK", load_map, K.write_container(specs, 3, c.revision, c.required, c.optional, c.guid))
    # and a header that lies about simHash is refused by the container reader
    expect("BAD_SIM_HASH", K.read_container, make_golden.patch_header_crc(mn[:72] + b"" + mn[73:]))
    b = MapBuilder(3)
    for cid, inst, d, comp in G.extended_min():
        b.add(cid, d, inst, comp)
    b.add("META", G.meta("second"), instance=1)           # META is a singleton
    expect("BAD_CHUNK", load_map, b.build())


def test_container3_never_sees_container4_chunks():
    b = MapBuilder(3)
    for cid, inst, d, comp in G.extended_min():
        b.add(cid, d, inst, comp)
    b.add_raw("WRLD", b"\0" * 10, flags=0)
    lm = load_map(b.build())
    assert ("WRLD", 0) in lm.skipped
    b.add_raw("SLYR", b"\0" * 4, instance=0, flags=K.F_SIM | K.F_REQUIRED)
    expect("UNKNOWN_REQUIRED_CHUNK", load_map, b.build())


def test_lenient_mode():
    data = golden("extended_full.fmap")
    c = K.read_container(data)
    d = bytearray(data)
    off = c.find("LITE").offset
    d[off + 1] ^= 0xFF                                   # render chunk: corrupt bytes
    expect("BAD_CHUNK_CRC", load_map, bytes(d))
    lm = load_map(bytes(d), lenient=True)
    assert ("LITE", 0) in lm.dropped and any("LITE" in w for w in lm.warnings)
    assert "chunk LITE inst=0 dropped" in dump_text(bytes(d), lenient=True)
    d = bytearray(data)
    d[c.find("GRID").offset + 2] ^= 0xFF                 # sim chunk: lenient does not help
    expect("BAD_CHUNK_CRC", load_map, bytes(d), True)


def test_missing_and_bad_chunks():
    ch = [c for c in G.extended_min() if c[0] != "WBOD"]
    expect("MISSING_CHUNK", load_map, make_golden.make("m", ch)[0])
    ch = [c for c in G.extended_min() if c[0] != "META"]
    assert "META is missing" in load_map(make_golden.make("m", ch)[0]).warnings
    # a sim bit in the content that requiredFeatures does not announce is refused
    mn = make_golden.make("m", G.extended_min())[1]
    full, _ = G.extended_full()
    b = MapBuilder(3)
    for cid, inst, d, comp in G.extended_min():
        b.add(cid, d, inst, comp)
    data = b.build()
    req, opt = derive_features(b.decoded())
    assert req == 1 and opt == 0 and mn is not None and full
    data = K.write_container([K.ChunkSpec(e.id, e.raw, e.instance, e.version, e.flags, e.deflated) for e in K.read_container(data).entries],
                             3, required=0)
    expect("CROSS_CHUNK", load_map, data)
    # GRID elevation range must bound the heights
    bad = G.extended_min()
    bad[1] = (bad[1][0], 0, dict(bad[1][2], maxElevation=100.0), False)
    expect("CROSS_CHUNK", load_map, make_golden.make("m", bad)[0])


# ------------------------------------------------------------------------------------------------ simHash

def _rebuild(data, change=None, recompress=None, drop=()):
    c = K.read_container(data)
    specs = []
    for e in c.entries:
        if e.id in drop:
            continue
        raw = change(e) if change else e.raw
        raw = raw if raw is not None else e.raw
        comp = e.deflated if recompress is None else recompress
        specs.append(K.ChunkSpec(e.id, raw, e.instance, e.version, e.flags, comp))
    return K.write_container(specs, c.container, c.revision, c.required, c.optional, c.guid)


def test_sim_hash():
    data = golden("extended_full.fmap")
    base = K.read_container(data).sim_hash
    assert base == bytes.fromhex(golden("extended_full.simhash").decode().strip())
    # recompression (and not compressing at all) keeps it
    assert K.read_container(_rebuild(data, recompress=False)).sim_hash == base
    assert K.read_container(_rebuild(data, recompress=True)).sim_hash == base
    # metadata, render and derived changes keep it
    def other(e):
        if e.id == "META":
            return C.encode_chunk("META", dict(G.meta("Renamed map", nlocs=2), author="someone else"))
        if e.id == "LITE":
            d = C.decode_chunk("LITE", e.raw)
            d["sunIntensity"] = 2.0
            return C.encode_chunk("LITE", d)
        if e.id == "DRVD":
            return e.raw
        return None
    assert K.read_container(_rebuild(data, other)).sim_hash == base
    assert K.read_container(_rebuild(data, drop=("SPLT", "DRVD", "MINI"))).sim_hash == base
    # one sim byte changes it
    def sim_byte(e):
        if e.id == "PLAY":
            b = bytearray(e.raw)
            b[0] ^= 1
            return bytes(b)
    assert K.read_container(_rebuild(data, sim_byte)).sim_hash != base
    # the hash follows the definition literally
    c = K.read_container(data)
    h = hashlib.sha256()
    for e in c.entries:
        if e.sim:
            h.update(e.id.encode() + struct.pack("<HIQ", e.version, e.instance, e.raw_size) + e.raw)
    assert h.digest() == base
    # the instance number is part of the hash input, and a sim chunk of an unknown id counts
    assert len(set(K.read_container(golden(n + ".fmap")).sim_hash for n in VALID)) == 4     # unknown_optional == min


# ------------------------------------------------------------------------------------------------ goldens

def test_goldens_regenerate_byte_identical():
    files = make_golden.build_all()
    again = make_golden.build_all()
    assert files == again
    for name, data in files.items():
        assert golden(name) == data, name
    on_disk = set(os.listdir(GOLDEN))
    assert set(files) <= on_disk
    assert "README.md" in on_disk
    for n in ("README.md",):
        assert len(golden(n)) > 100


def test_dumps_and_hashes_match_files():
    for name in VALID:
        data = golden(name + ".fmap")
        text = dump_text(data)
        assert text.encode("ascii") == golden(name + ".dump.txt"), name
        assert text.endswith("\n") and "\r" not in text
        assert load_map(data).container.sim_hash.hex() + "\n" == golden(name + ".simhash").decode()
        assert dump_text(os.path.join(GOLDEN, name + ".fmap")) == text      # path input
    d = dump_text(golden("extended_min.fmap")).split("\n")
    assert d[0:3] == ["file.container = 3", "file.revision = 1", "file.flags = 0x00000000"]
    assert [l for l in d if l.startswith("chunk ")][0] == "chunk GPLY inst=0 ver=1 flags=0x0003 raw=3102"


def test_golden_features():
    exp = {"extended_min": (1, 0), "extended_classic_equiv": (1 << 7 | 1 << 8, 0),
           "extended_full": ((1 << 0) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9),
                             (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19))}
    for name, (req, opt) in exp.items():
        c = K.read_container(golden(name + ".fmap"))
        assert (c.required, c.optional) == (req, opt), (name, hex(c.required), hex(c.optional))
    c = K.read_container(golden("full3d_full.fmap"))
    # WORLD_CELLS, COLLISION, NAV3D, LARGE_COORDS, VOLUMES_SIM required (bit 36 lightmaps is optional)
    assert c.required >> 32 == 0b101111 and c.optional >> 32 == 0b10000
    # classic equivalent: square, one global body, step -7, dense SPLT
    lm = load_map(golden("extended_classic_equiv.fmap"))
    g = lm.chunks[("GRID", 0)]
    assert g["cellsX"] == g["cellsZ"] == 64 and lm.chunks[("HGHT", 0)]["stepLog2"] == -7
    assert len(lm.chunks[("WBOD", 0)]["bodies"]) == 1 and lm.chunks[("SPLT", 0)]["mode"] == 1
    assert lm.chunks[("SPLT", 0)]["layers"] == 2


def test_golden_heights_use_the_spec_formula():
    lm = load_map(golden("extended_full.fmap"))
    h = lm.chunks[("HGHT", 0)]
    vals = struct.unpack("<%dH" % (len(h["samples"]) // 2), h["samples"])
    assert len(vals) == 65 * 49
    from mapfmt.loadmap import height_value
    assert height_value(256, -4.0, -8) == -3.0 and height_value(0, 0.0, -7) == 0.0 and height_value(128, 0.0, -7) == 1.0
    g = lm.chunks[("GRID", 0)]
    assert g["minElevation"] == height_value(min(vals), h["minHeight"], h["stepLog2"])


# ------------------------------------------------------------------------------------------------ scatter

def test_pcg32_and_hash_known_answers():
    r = scatter.PCG32(42, 54)
    assert [r.next() for _ in range(6)] == [0xa15c02b7, 0x7b47f409, 0xba1d3330, 0x83d2f293, 0xbfa4784b, 0xcbed606e]
    assert scatter.splitmix64(0) == 0xE220A8397B1DCDAF
    assert scatter.splitmix64(0x9E3779B97F4A7C15) == 0x6E789E6AA1B965F4
    # negative block coordinates are two's complement, different blocks give different seeds
    seeds = set(scatter.hash64(7, 0, bx, bz) for bx in range(-2, 3) for bz in range(-2, 3))
    assert len(seeds) == 25
    assert scatter.unit(0xFFFFFFFF) == (2 ** 24 - 1) / 2.0 ** 24 and scatter.unit(255) == 0.0
    assert scatter.r32(0.1) == 0.10000000149011612


def test_scatter_expected_file():
    text = golden("scatter_expected.txt").decode()
    kv = dict(l.split(" = ", 1) for l in text.strip().split("\n"))
    lm = load_map(golden("extended_full.fmap"))
    layer = lm.chunks[("SCAT", 0)]["layers"][0]
    inst = scatter.generate_layer(layer, 0, 64, 48, scatter.FlatSampler(10.0, 1.0))
    count, digest = scatter.summary(inst)
    assert int(kv["count"]) == count and kv["sha256"] == digest and count > 0
    assert len(scatter.pack_records(inst)) == 28 * count
    assert all(0.0 <= i["x"] < 64.0 and 0.0 <= i["z"] < 48.0 and i["y"] == 10.0 for i in inst)
    assert all(i["yawDeg"] >= 0.0 and 0 <= i["variant"] < 2 for i in inst)


def test_scatter_rejection_keeps_the_stream():
    """A rejected candidate still consumes its six numbers, so removing part of the world removes exactly those
    instances and changes nothing else."""
    lm = load_map(golden("extended_full.fmap"))
    layer = lm.chunks[("SCAT", 0)]["layers"][0]
    base = scatter.generate_layer(layer, 0, 64, 48, scatter.FlatSampler(10.0))

    class Holes(scatter.FlatSampler):
        def hole(self, x, z):
            return x < 20.0

    holed = scatter.generate_layer(layer, 0, 64, 48, Holes(10.0))
    assert holed == [i for i in base if i["x"] >= 20.0] and 0 < len(holed) < len(base)
    # a different layer index or seed gives a different picture
    assert scatter.generate_layer(layer, 1, 64, 48, scatter.FlatSampler(10.0)) != base
    # the density map scales the per-block candidate count
    layer2 = dict(layer, densityMap=0)
    half_map = scatter.generate_layer(layer2, 0, 64, 48, scatter.FlatSampler(10.0, 0.5))
    assert 0 < len(half_map) < len(base)
    # the sampler's altitude / slope / material / surface tests
    class Steep(scatter.FlatSampler):
        def slope_deg(self, x, z):
            return 60.0
    assert scatter.generate_layer(layer, 0, 64, 48, Steep(10.0)) == []
    lay3 = dict(layer, allowedMaterials=[1])
    assert scatter.generate_layer(lay3, 0, 64, 48, scatter.FlatSampler(10.0)) == []
    lay4 = dict(layer, forbiddenSurfaces=[0])
    assert scatter.generate_layer(lay4, 0, 64, 48, scatter.FlatSampler(10.0)) == []
    lay5 = dict(layer, minAltitude=11.0)
    assert scatter.generate_layer(lay5, 0, 64, 48, scatter.FlatSampler(10.0)) == []


def test_scatter_variant_pick():
    v = [{"weight": 0.0}, {"weight": 1.0}, {"weight": 3.0}, {"weight": 0.0}]
    assert scatter.pick_variant(v, 0.0) == 1 and scatter.pick_variant(v, 0.24) == 1
    assert scatter.pick_variant(v, 0.25) == 2 and scatter.pick_variant(v, 0.999999) == 2


# ------------------------------------------------------------------------------------------------ tools

def test_dump_names_file_is_current():
    # Line endings are not content: a checkout with autocrlf has CRLF.
    text = open(gen_dump_names.PATH, encoding="utf-8", newline="").read().replace("\r\n", "\n")
    assert gen_dump_names.render() == text


def test_mapinfo_cli():
    base = [sys.executable, os.path.join(TOOLS, "mapinfo.py")]
    for name in VALID:
        p = subprocess.run(base + [os.path.join(GOLDEN, name + ".fmap"), "--validate"], capture_output=True, text=True)
        assert p.returncode == 0, (name, p.stderr)
        assert "valid" in p.stdout.splitlines()[-1] and "simHash" in p.stdout
        p = subprocess.run(base + [os.path.join(GOLDEN, name + ".fmap"), "--dump"], capture_output=True, text=True)
        assert p.returncode == 0 and p.stdout.replace("\r\n", "\n") == golden(name + ".dump.txt").decode()
    p = subprocess.run(base + [os.path.join(GOLDEN, "bad_chunk_crc.fmap")], capture_output=True, text=True)
    assert p.returncode == 1 and "BAD_CHUNK_CRC" in p.stderr
    p = subprocess.run(base + [os.path.join(GOLDEN, "gpl_bad_surface_id.fmap")], capture_output=True, text=True)
    assert p.returncode == 0                      # the container is fine, only --validate sees the cross-chunk rule
    assert subprocess.run(base + [os.path.join(GOLDEN, "nonexistent.fmap")], capture_output=True).returncode == 2


def main():
    filt = sys.argv[1] if len(sys.argv) > 1 else ""
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f) and filt in n]
    # keep file order (definition order) for readable output
    tests.sort(key=lambda t: t[1].__code__.co_firstlineno)
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print("ok    " + name)
        except Exception:
            failed += 1
            print("FAIL  " + name)
            traceback.print_exc()
    print("ALL PASS (%d tests)" % len(tests) if not failed else "%d of %d FAILED" % (failed, len(tests)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
