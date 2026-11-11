"""Extended (container 3): metadata chunks and sim chunks (EXTENDED.md). Field names are the backticked names of the
spec; a field name the spec does not give carries a `note` (the spec phrase it stands for) and is listed in
DUMP_NAMES.md.

Semantic checks that need only the chunk itself (ranges, sortedness, index validity) run in every decode *and* encode.
Checks against the grid (`ctx` has cellsX / cellsZ) run when the context is known.
"""
import struct

from .chunkdef import chunk
from .errors import ChunkError
from .schema import (F, Array, BitMask, Blob, Bytes, Plane, Struct, PATH, STR, enum8, f32, fxvec2, i8, i16, i32,
                     quat, u8, u16, u32, u64, vec2, vec3)

MiB = 1 << 20


def kind_in(*vals):
    return lambda s: s.cur["kind"] in vals


def field_in(name, *vals):
    return lambda s: s.cur[name] in vals


def bit_set(name, b):
    return lambda s: bool(s.cur[name] & b)


def grid_dims(s):
    return s.need("cellsX"), s.need("cellsZ")


def has_grid(s):
    return bool(s.ctx) and s.ctx.get("cellsX") is not None


def cross(msg):
    """A rule the spec lists under "cross-chunk checks (refuse)"."""
    return ChunkError(msg, code="CROSS_CHUNK")


def unique(items, key, what):
    seen = set()
    for it in items:
        k = key(it)
        if k in seen:
            raise ChunkError("duplicate %s %r" % (what, k))
        seen.add(k)


# --------------------------------------------------------------------------------------------- shared structures

def _shape_check(d, s):
    if d["kind"] == 0 and (d["x1"] < d["x0"] or d["z1"] < d["z0"]):
        raise ChunkError("rect corners are not ordered")
    if d["kind"] == 2 and d["r"] < 0:
        raise ChunkError("circle radius is negative")


SHAPE = Struct([
    F("kind", enum8(3)),
    F("x0", f32, kind_in(0)), F("z0", f32, kind_in(0)), F("x1", f32, kind_in(0)), F("z1", f32, kind_in(0)),
    F("points", Array(vec2, 3, 1024), kind_in(1), note="polygon `array<vec2>`"),
    F("cx", f32, kind_in(2)), F("cz", f32, kind_in(2)), F("r", f32, kind_in(2)),
], _shape_check)

POSE = Struct([F("pos", vec3), F("yawDeg", f32), F("pitchDeg", f32), F("fovDeg", f32)])


# --------------------------------------------------------------------------------------------- metadata chunks

def _meta_check(d, s):
    if d["minPlayers"] > d["maxPlayers"]:
        raise ChunkError("minPlayers %d > maxPlayers %d" % (d["minPlayers"], d["maxPlayers"]))


chunk("META", "M", [
    F("name", STR),
    F("locs", Array(Struct([F("lang", STR), F("name", STR), F("description", STR)]), 0, 64), note="`array<loc>`"),
    F("author", STR), F("version", STR), F("license", STR), F("website", STR),
    F("tags", Array(STR, 0, 64)),
    F("mapType", enum8(4)), F("minPlayers", u8), F("maxPlayers", u8),
    F("reqs", Array(Struct([F("kind", STR), F("id", STR), F("minVersion", STR)]), 0, 64), note="`array<req>`"),
    F("createdUtc", u64), F("modifiedUtc", u64), F("toolName", STR), F("toolVersion", STR),
], _meta_check, extended_required=True, raw_max=MiB, what="identity, localisation, requirements")


def _prev_check(d, s):
    if not (1 <= d["width"] <= 2048 and 1 <= d["height"] <= 2048):
        raise ChunkError("preview size %dx%d outside 1..2048" % (d["width"], d["height"]))


chunk("PREV", "M", [
    F("kind", enum8(2)), F("width", u32), F("height", u32),
    F("data", Blob("byteCount"), note="the bytes after `byteCount`"),
], _prev_check, what="lobby preview image")

chunk("GENR", "M", [
    F("generator", STR), F("generatorVersion", STR), F("seed", u64),
    F("json", Blob("jsonLen", max_size=256 * 1024), note="the UTF-8 JSON after `jsonLen`"),
    F("notes", Array(Struct([F("key", STR), F("value", STR)]), 0, 256), note="`array<{str key, str value}>` notes"),
], what="generator recipe")

chunk("SIGN", "M", [
    F("algo", u8(eq=1)), F("publicKey", Bytes(32)), F("signature", Bytes(64)), F("keyName", STR),
], what="signature")

_BANNED_EXT = (".lua", ".bp", ".scd", ".xsb", ".xwb", ".exe", ".dll")


def _asset_check(d, s):
    name = d["name"]
    parts = name.split("/")
    if (not name or name.startswith("/") or "\\" in name or ":" in name or ".." in parts or "." in parts or "" in parts
            or any(ord(c) < 0x20 for c in name) or name.lower().endswith(_BANNED_EXT)):
        raise ChunkError("asset name %r is not a relative data path below the embedded root" % name)


chunk("ASST", "M", [
    F("assets", Array(Struct([
        F("name", STR), F("kind", enum8(6)), F("data", Blob("size", width=8, max_size=1 << 30)),
    ], _asset_check), 0, 65535), note="`array<asset>`"),
], instanced=True, what="embedded asset bundle")


# --------------------------------------------------------------------------------------------- sim chunks

def _grid_check(d, s):
    for k in ("cellsX", "cellsZ"):
        if not 1 <= d[k] <= 65536:
            raise ChunkError("%s %d outside 1..65536" % (k, d[k]))
    if (d["cellsX"] + 1) * (d["cellsZ"] + 1) > (1 << 30):
        raise ChunkError("total sample count exceeds 2^30")
    if d["minElevation"] > d["maxElevation"]:
        raise ChunkError("minElevation > maxElevation")


chunk("GRID", "S", [
    F("cellsX", u32), F("cellsZ", u32), F("cellSize", f32(eq=1.0)), F("originX", f32(eq=0.0)), F("originZ", f32(eq=0.0)),
    F("minElevation", f32), F("maxElevation", f32), F("reserved", u8(eq=0)),
], _grid_check, extended_required=True, what="dimensions, cell size")

chunk("HGHT", "S", [
    F("minHeight", f32), F("stepLog2", i8(-16, 0)), F("predictor", u8(0, 3)), F("tileSize", u16(eq=0)),
    F("samples", Plane(2, lambda s: (s.need("cellsX") + 1, s.need("cellsZ") + 1), pred_field="predictor"),
      note="the `u16` samples"),
], extended_required=True, what="heightfield")


def _play_check(d, s):
    if d["x1"] <= d["x0"] or d["z1"] <= d["z0"]:
        raise ChunkError("playable rectangle is empty")
    if has_grid(s) and not (0 <= d["x0"] and 0 <= d["z0"] and d["x1"] <= s.ctx["cellsX"] and d["z1"] <= s.ctx["cellsZ"]):
        raise cross("playable rectangle is outside the grid")
    poly = d["polygon"]
    if poly and not 3 <= len(poly) <= 1024:
        raise ChunkError("polygon needs 0 or 3..1024 points, has %d" % len(poly))
    for x, z in poly:
        if not (d["x0"] * 256 <= x <= d["x1"] * 256 and d["z0"] * 256 <= z <= d["z1"] * 256):
            raise ChunkError("polygon point (%d, %d) lies outside the rectangle" % (x, z))


chunk("PLAY", "S", [
    F("x0", i32), F("z0", i32), F("x1", i32), F("z1", i32), F("borderMode", enum8(3)),
    F("polygon", Array(fxvec2, 0, 1024), note="`array<fxvec2>`"),
], _play_check, extended_required=True, what="playable area")


def _mask_check(d, s):
    if d["kind"] not in (1, 8):
        raise ChunkError("mask kind %d is not 1 (bitmask) or 8 (u8 plane)" % d["kind"])


def _gply_check(d, s):
    unique(d["surfaces"], lambda x: x["id"], "surface id")
    unique(d["masks"], lambda x: x["name"], "mask name")
    ids = set(x["id"] for x in d["surfaces"])
    data = d["ids"]["data"]
    present = set(data) if d["idWidth"] == 1 else set(struct.unpack("<%dH" % (len(data) // 2), data))
    missing = sorted(present - ids)
    if missing:
        raise cross("surface id %d is not in the surface table" % missing[0])


chunk("GPLY", "S", [
    F("legacyTerrainIds", u8(0, 1)),
    F("surfaces", Array(Struct([
        F("id", u16), F("name", STR), F("flags", u32(mask=0xF)), F("speedMul", u16), F("effectsKey", STR),
    ]), 0, 1024), note="`array<surface>`"),
    F("idWidth", u8(1, 2)),
    F("ids", Plane(lambda s: s.cur["idWidth"], grid_dims), note="surface ids plane"),
    F("masks", Array(Struct([
        F("name", STR), F("kind", u8),
        F("data", BitMask(grid_dims), field_in("kind", 1)),
        F("data", Plane(1, grid_dims), field_in("kind", 8)),
    ], _mask_check), 0, 64), note="`array<mask>`"),
], _gply_check, extended_required=True, what="surface ids, named gameplay masks")


def _poly_in_grid(poly, s):
    if has_grid(s):
        mx, mz = s.ctx["cellsX"] * 256, s.ctx["cellsZ"] * 256
        for x, z in poly:
            if not (0 <= x <= mx and 0 <= z <= mz):
                raise cross("polygon point (%d, %d) lies outside the grid" % (x, z))


def _body_check(d, s):
    if d["extentKind"] == 2:
        _poly_in_grid(d["polygon"], s)


def _wbod_check(d, s):
    unique(d["bodies"], lambda b: b["id"], "water body id")


chunk("WBOD", "S", [
    F("bodies", Array(Struct([
        F("id", u16), F("name", STR), F("kind", enum8(3)), F("level", f32), F("extentKind", enum8(3)),
        F("mask", BitMask(grid_dims), field_in("extentKind", 1), note="bitmask extent"),
        F("polygon", Array(fxvec2, 3, 4096), field_in("extentKind", 2), note="polygon extent `array<fxvec2>`"),
    ], _body_check), 1, 256), note="`array<body>`"),
], _wbod_check, extended_required=True, what="water bodies (level, extent)")


def _deck_check(d, s):
    if d["x1"] < d["x0"] or d["z1"] < d["z0"]:
        raise ChunkError("deck %r: rectangle corners are not ordered" % d["name"])
    if has_grid(s) and not (0 <= d["x0"] and 0 <= d["z0"] and d["x1"] < s.ctx["cellsX"] and d["z1"] < s.ctx["cellsZ"]):
        raise cross("deck %r lies outside the grid" % d["name"])
    if d["clearanceBelow"] < 0:
        raise ChunkError("clearanceBelow is negative")


def _levl_check(d, s):
    unique(d["decks"], lambda x: x["id"], "deck id")
    ids = set(x["id"] for x in d["decks"])
    for deck in d["decks"]:
        for p in deck["portals"]:
            if p["targetDeck"] != 0xFFFF and p["targetDeck"] not in ids:
                raise ChunkError("portal of deck %d targets unknown deck %d" % (deck["id"], p["targetDeck"]))


chunk("LEVL", "S", [
    F("decks", Array(Struct([
        F("id", u16), F("name", STR), F("x0", i32), F("z0", i32), F("x1", i32), F("z1", i32), F("mode", enum8(3)),
        F("h0", f32), F("h1", f32), F("axis", enum8(2)),
        F("patch", Plane(2, lambda s: (s.cur["x1"] - s.cur["x0"] + 1, s.cur["z1"] - s.cur["z0"] + 1)),
          field_in("mode", 2), note="patch mode `plane<u16>`"),
        F("clearanceBelow", f32), F("flags", u32(mask=0xF)),
        F("portals", Array(Struct([F("a", fxvec2), F("b", fxvec2), F("targetDeck", u16)]), 0, 64)),
    ], _deck_check), 0, 1024), note="`array<deck>`"),
], _levl_check, what="decks / second walkable level")


def _marker_check(d, s):
    unique(d["props"], lambda p: p["key"], "marker property")


def _mrkr_check(d, s):
    n = len(d["markers"])
    for i, m in enumerate(d["markers"]):
        for l in m["links"]:
            if l >= n:
                raise cross("marker %d links to index %d, only %d markers" % (i, l, n))


chunk("MRKR", "S", [
    F("markers", Array(Struct([
        F("type", enum8(18)), F("name", STR), F("pos", vec3), F("yawDeg", f32), F("army", i16(-1)), F("flags", u32(eq=0)),
        F("props", Array(Struct([
            F("key", STR), F("vtype", enum8(4)),
            F("value", STR, field_in("vtype", 0)), F("value", i32, field_in("vtype", 1)),
            F("value", f32, field_in("vtype", 2)), F("value", u8(0, 1), field_in("vtype", 3)),
        ]), 0, 32), note="`array<prop>`"),
        F("links", Array(u32, 0, 64)),
    ], _marker_check), 0, 65536), note="`array<marker>`"),
], _mrkr_check, what="typed markers")

def _area_check(d, s):
    for a in d["areas"]:
        if a["flags"] & 1 and a["yMin"] > a["yMax"]:
            raise ChunkError("area %r: yMin above yMax" % a["name"])


chunk("AREA", "S", [
    F("areas", Array(Struct([
        F("name", STR), F("shape", SHAPE), F("flags", u8(mask=1)),
        F("yMin", f32, bit_set("flags", 1)), F("yMax", f32, bit_set("flags", 1)),
        F("tags", Array(STR, 0, 16)),
    ]), 0, 4096), note="`array<area>`"),
], _area_check, what="named areas")


def _prop_check(d, s):
    if "" in d["blueprints"]:
        raise ChunkError("a blueprint path is empty")
    n = len(d["blueprints"])
    for i, p in enumerate(d["props"]):
        if p["blueprintIndex"] >= n:
            raise cross("prop %d uses blueprint index %d, only %d blueprints" % (i, p["blueprintIndex"], n))


chunk("PROP", "S", [
    F("blueprints", Array(PATH, 0, 65535)),
    F("props", Array(Struct([
        F("blueprintIndex", u32), F("pos", vec3), F("rot", quat), F("scale", vec3), F("flags", u32(eq=0)),
    ]), 0, 1000000), note="`array<prop>`"),
], _prop_check, what="props with collision (sim entities)")


def _hint_check(d, s):
    ids = set(r["id"] for r in d["regions"])
    if len(ids) != len(d["regions"]):
        raise ChunkError("duplicate region id")
    for r in d["regions"]:
        for n in r["neighbors"]:
            if n not in ids:
                raise ChunkError("region %d has unknown neighbor %d" % (r["id"], n))
    for c in d["chokes"]:
        if c["regionA"] not in ids or c["regionB"] not in ids:
            raise ChunkError("choke refers to an unknown region")


chunk("HINT", "S", [
    F("regions", Array(Struct([
        F("id", u32), F("name", STR), F("kind", enum8(6)), F("area", f32), F("centroid", vec2),
        F("neighbors", Array(u32, 0, 64)),
    ]), 0, 4096), note="`array<region>`"),
    F("chokes", Array(Struct([
        F("pos", vec2), F("width", f32), F("regionA", u32), F("regionB", u32), F("layerMask", u8(mask=0xF)),
    ]), 0, 4096), note="`array<choke>`"),
    F("candidates", Array(Struct([
        F("pos", vec2), F("layer", u8), F("score", f32), F("markerIds", Array(u32, 0, 32)),
    ]), 0, 4096), note="`array<candidate>`"),
], _hint_check, what="strategic hints for AI and scripts")
