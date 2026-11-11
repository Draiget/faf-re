"""Full3D (container 4): the chunks of FULL3D.md. See chunks_sim.py for conventions."""
from .chunkdef import chunk
from .chunks_sim import field_in, has_grid, unique
from .errors import ChunkError
from .schema import (F, Array, BitMask, Blob, Plane, RawBytes, Rep, Struct, PATH, STR, Vec, color3, enum8, f32, f64,
                     fx10, fx10vec3, fx16, fxvec2, i16, i32, quat, u8, u16, u32, vec2, vec3)

# ------------------------------------------------------------------------------------------------ sub-structures

MESHREF = Struct([F("bundle", u16), F("index", u16)])
def _shape3d_check(d, s):
    k = d["kind"]
    if k == 0 and any(h < 0 for h in d["halfExtents"]):
        raise ChunkError("negative box half extent")
    if k in (1, 4) and d["radius"] < 0:
        raise ChunkError("negative radius")
    if k == 3 and d["yMin"] > d["yMax"]:
        raise ChunkError("yMin above yMax")


SHAPE3D = Struct([
    F("kind", enum8(5)),
    F("center", fx10vec3, lambda s: s.cur["kind"] in (0, 1)),
    F("halfExtents", fx10vec3, field_in("kind", 0)),
    F("rot", Vec(4, i16), field_in("kind", 0), note="box `i16[4] rot` (snorm quaternion)"),
    F("vertices", Array(fx10vec3, 4, 256), field_in("kind", 2), note="convex hull `array<fx10vec3>`"),
    F("polygon", Array(fxvec2, 3, 1024), field_in("kind", 3), note="extruded polygon `array<fxvec2>`"),
    F("yMin", fx10, field_in("kind", 3)), F("yMax", fx10, field_in("kind", 3)),
    F("a", fx10vec3, field_in("kind", 4)), F("b", fx10vec3, field_in("kind", 4)),
    F("radius", fx10, lambda s: s.cur["kind"] in (1, 4)),
], _shape3d_check)


def _world_cells(s):
    return s.need("worldCells")


# ------------------------------------------------------------------------------------------------ WRLD, CIDX


def _wrld_check(d, s):
    if min(d["cellsX"], d["cellsY"], d["cellsZ"]) < 1 or d["cellsX"] * d["cellsY"] * d["cellsZ"] > (1 << 22):
        raise ChunkError("cell counts must be >= 1 with a product <= 2^22")
    if not 32.0 <= d["cellSize"] <= 4096.0:
        raise ChunkError("cellSize outside 32..4096")
    if any(a > b for a, b in zip(d["boundsMin"], d["boundsMax"])):
        raise ChunkError("boundsMin exceeds boundsMax")
    if not d["unitsPerMeter"] > 0.0:
        raise ChunkError("unitsPerMeter must be positive")
    far = any(d[k] != 0.0 for k in ("originX", "originY", "originZ")) or any(abs(v) > (1 << 20) for v in d["boundsMin"] + d["boundsMax"])
    if far and not d["flags"] & 1:
        raise ChunkError("WRLD has a non-zero origin or bounds above 2^20 but not the LARGE_COORDS flag")


chunk("WRLD", "S", [
    F("originX", f64), F("originY", f64), F("originZ", f64), F("boundsMin", vec3), F("boundsMax", vec3),
    F("cellSize", f32), F("cellsX", u32), F("cellsY", u32), F("cellsZ", u32), F("upAxis", u8(eq=1)),
    F("unitsPerMeter", f32), F("flags", u8(mask=1)),
], _wrld_check, extended_required=False, container_min=4, what="world definition: origin, bounds, cell grid")


def _cell_check(d, s):
    if d["unloadDistance"] < d["loadDistance"]:
        raise ChunkError("unloadDistance < loadDistance")


chunk("CIDX", "R", [
    F("cells", Array(Struct([
        F("min", vec3), F("max", vec3), F("loadDistance", f32), F("unloadDistance", f32), F("priority", u8),
        F("flags", u8(mask=0x1F)), F("layer", u16),
    ], _cell_check), expect=_world_cells), note="`array<cell>`"),
], container_min=4, what="cell index: bounds, streaming, content flags")


# ------------------------------------------------------------------------------------------------ meshes, materials

chunk("MSHB", "R", [
    F("meshes", Array(Struct([
        F("name", STR), F("format", enum8(2)), F("aabb", Vec(6, f32)), F("data", Blob("byteCount")),
    ]), 0, 65535), note="`array<mesh>`"),
], container_min=4, instanced=True, what="mesh library")

chunk("MATB", "R", [
    F("materials", Array(Struct([
        F("name", STR), F("baseColor", Vec(4, f32)), F("emissive", color3), F("emissiveStrength", f32),
        F("metallic", f32), F("roughness", f32), F("normalScale", f32), F("occlusionStrength", f32),
        F("alphaMode", enum8(3)), F("alphaCutoff", f32), F("flags", u16(mask=0x1F)), F("baseColorTex", PATH),
        F("normalTex", PATH), F("ormTex", PATH), F("emissiveTex", PATH), F("uvOffset", vec2), F("uvScale", vec2),
        F("uvRotation", f32), F("clearcoat", f32), F("clearcoatRoughness", f32), F("windAmount", f32),
    ]), 0, 4096), note="`array<material>`"),
], container_min=4, what="PBR material library for meshes")

chunk("INST", "R", [
    F("cellOrigin", vec3), F("cellExtent", vec3),
    F("insts", Array(Struct([
        F("mesh", MESHREF), F("pos", Vec(3, u16), note="`qpos`"), F("rot", u32, note="`qrot`"),
        F("scale", Vec(3, u16), note="`f16x3 scale` raw binary16"), F("flags", u32(mask=0x3F)), F("lodBias", u16),
        F("layer", u16), F("cullDistance", u16), F("lightmap", u16),
        F("lightmapScaleOffset", Vec(4, u16), note="`f16[4]` raw binary16"), F("overrideCount", u8(0, 8)),
        F("materialOverride", Rep(u16, lambda s: s.cur["overrideCount"])),
    ]), 0, 1000000), note="`array<inst>`"),
], container_min=4, instanced=True, what="mesh instances")

chunk("LODG", "R", [
    F("proxies", Array(Struct([
        F("mesh", MESHREF), F("pos", vec3), F("rot", quat), F("scale", vec3), F("showBeyond", f32), F("fadeWidth", f32),
        F("replacesInstances", Array(u32, 0, 65535)),
    ]), 0, 65535), note="`array<proxy>`"),
], container_min=4, instanced=True, what="HLOD proxies")

chunk("OCCL", "R", [
    F("occluders", Array(Struct([
        F("kind", enum8(2)),
        F("center", vec3, field_in("kind", 0)), F("halfExtents", vec3, field_in("kind", 0)),
        F("mesh", MESHREF, field_in("kind", 1)), F("pos", vec3, field_in("kind", 1)),
        F("rot", quat),
        F("scale", vec3, field_in("kind", 1)),
    ]), 0, 4096), note="`array<occluder>`"),
    F("rooms", Array(Struct([F("name", STR), F("min", vec3), F("max", vec3)]), 0, 1024), note="`array<room>`"),
    F("portals", Array(Struct([
        F("quad", Vec(12, f32), note="`vec3[4] quad` flattened to 12 floats"), F("roomA", u16), F("roomB", u16),
        F("flags", u8(mask=1)),
    ]), 0, 4096), note="`array<portal>`"),
], container_min=4, what="occluders and portals")


def _lmap_check(d, s):
    if not (1 <= d["width"] <= 16384 and 1 <= d["height"] <= 16384):
        raise ChunkError("lightmap size outside 1..16384")


chunk("LMAP", "R", [
    F("width", u32), F("height", u32), F("format", enum8(3)), F("kind", enum8(2)),
    F("data", Blob("byteCount")),
    F("dirData", Blob("dirByteCount"), field_in("kind", 1), note="kind 1: the second `byteCount` + bytes (direction)"),
], _lmap_check, container_min=4, instanced=True, what="lightmap atlas")

PROBE_GRID_3D = [
    F("gridOrigin", vec3), F("gridSpacing", vec3), F("nx", u32), F("ny", u32), F("nz", u32),
    F("shData", RawBytes(lambda s: s.cur["nx"] * s.cur["ny"] * s.cur["nz"] * 27 * 2),
      note="`nx*ny*nz*27` binary16 values (raw u16)"),
]


def _prbv_check(d, s):
    if d["nx"] * d["ny"] * d["nz"] > (1 << 22):
        raise ChunkError("probe grid has more than 2^22 probes")


chunk("PRBV", "R", PROBE_GRID_3D, _prbv_check, container_min=4, instanced=True, what="probe volume")

chunk("ANIM", "R", [
    F("clips", Array(Struct([
        F("name", STR), F("duration", f32), F("loop", u8(0, 1)),
        F("channels", Array(Struct([
            F("instanceCell", u32), F("instanceIndex", u32), F("target", enum8(3)),
            F("keys", Array(Struct([F("t", f32), F("value", Vec(4, f32))]), 1, 65535)),
        ]), 0, 65535), note="`array<channel>`"),
    ]), 0, 1024), note="`array<clip>`"),
    F("players", Array(Struct([
        F("clip", STR), F("speed", f32), F("phase", f32), F("layer", u16), F("triggerKind", enum8(2)),
    ]), 0, 4096), note="`array<player>`"),
], lambda d, s: unique(d["clips"], lambda c: c["name"], "clip name"), container_min=4,
    what="rigid-transform animation clips and players")

chunk("VOLR", "R", [
    F("volumes", Array(Struct([
        F("kind", enum8(4)), F("shapeKind", enum8(2)), F("center", vec3), F("halfExtents", vec3), F("rot", quat),
        F("blendDistance", f32), F("priority", i16), F("layer", u16),
        F("color", color3, field_in("kind", 0)), F("density", f32, field_in("kind", 0)),
        F("heightFalloff", f32, field_in("kind", 0)),
        F("exposureEV", f32, field_in("kind", 1)), F("saturation", f32, field_in("kind", 1)),
        F("contrast", f32, field_in("kind", 1)),
        F("preset", STR, field_in("kind", 2)),
        F("ambientMul", f32, field_in("kind", 3)),
        F("tint", color3, lambda s: s.cur["kind"] in (1, 3)),
    ]), 0, 4096), note="`array<volume>`"),
], container_min=4, what="render volumes (fog, post, reverb, light override)")


# ------------------------------------------------------------------------------------------------ sim chunks

chunk("SLYR", "S", [
    F("layers", Array(Struct([F("name", STR), F("defaultOn", u8(0, 1))]), 0, 64), note="`array<layer>`"),
], lambda d, s: unique(d["layers"], lambda l: l["name"], "sim layer name"), container_min=4,
    what="sim layers toggled by script")


def _tri_check(d, s):
    if d["indexCount"] % 3:
        raise ChunkError("indexCount %d is not a multiple of 3" % d["indexCount"])
    if any(i >= d["vertexCount"] for i in d["indices"]):
        raise ChunkError("an index refers past the %d vertices" % d["vertexCount"])


BLOCKS = u16(mask=0x7F)

chunk("COLL", "S", [
    F("tris", Array(Struct([
        F("vertexCount", u32), F("vertices", Rep(fx10vec3, lambda s: s.cur["vertexCount"])),
        F("indexCount", u32), F("indices", Rep(u32, lambda s: s.cur["indexCount"])),
        F("surfaceMode", enum8(2)), F("surface", u16),
        F("triangleSurfaces", Rep(u16, lambda s: s.cur["indexCount"] // 3), field_in("surfaceMode", 1),
          note="per-triangle `u16[indexCount/3]`"),
        F("blocks", BLOCKS), F("simLayer", u16),
    ], _tri_check), 0, 4096), note="`array<tri>`"),
    F("hulls", Array(Struct([
        F("vertices", Array(fx10vec3, 4, 256)), F("surface", u16), F("blocks", BLOCKS), F("simLayer", u16),
    ]), 0, 4096), note="`array<hull>`"),
    F("prims", Array(Struct([F("shape", SHAPE3D), F("surface", u16), F("blocks", BLOCKS), F("simLayer", u16)]), 0, 65535),
      note="`array<prim>`"),
], container_min=4, instanced=True, what="collision")


def _surf_dims(s):
    return s.cur["x1"] - s.cur["x0"] + 1, s.cur["z1"] - s.cur["z0"] + 1


def _navs_surface_check(d, s):
    if d["kind"] == 0:
        if d["x1"] < d["x0"] or d["z1"] < d["z0"]:
            raise ChunkError("surface %d: rectangle corners are not ordered" % d["id"])
    else:
        if d["indexCount"] % 3:
            raise ChunkError("surface %d: indexCount is not a multiple of 3" % d["id"])
        if any(i >= len(d["vertices"]) for i in d["indices"]):
            raise ChunkError("surface %d: an index refers past the vertices" % d["id"])
    if d["clearance"] < 0:
        raise ChunkError("surface %d: negative clearance" % d["id"])


def _navs_check(d, s):
    unique(d["surfaces"], lambda x: x["id"], "surface id")
    ids = set(x["id"] for x in d["surfaces"]) | {0}
    for l in d["links"]:
        if l["fromSurface"] not in ids or l["toSurface"] not in ids:
            raise ChunkError("link between unknown surfaces %d and %d" % (l["fromSurface"], l["toSurface"]))


chunk("NAVS", "S", [
    F("surfaces", Array(Struct([
        F("id", u16), F("name", STR), F("kind", enum8(2)), F("moveMask", u8(mask=0xF)), F("clearance", fx16),
        F("simLayer", u16),
        F("x0", i32, field_in("kind", 0)), F("z0", i32, field_in("kind", 0)),
        F("x1", i32, field_in("kind", 0)), F("z1", i32, field_in("kind", 0)),
        F("heights", Plane(2, _surf_dims), field_in("kind", 0), note="kind 0 `plane<u16>` heights"),
        F("walkable", BitMask(_surf_dims), field_in("kind", 0), note="kind 0 walkable bitmask"),
        F("vertices", Array(fx10vec3), field_in("kind", 1), note="kind 1 `array<fx10vec3>`"),
        F("indexCount", u32, field_in("kind", 1)),
        F("indices", Rep(u32, lambda s: s.cur["indexCount"]), field_in("kind", 1)),
    ], _navs_surface_check), 0, 4096), note="`array<surface>`"),
    F("links", Array(Struct([
        F("fromSurface", u16), F("from", fx10vec3), F("toSurface", u16), F("to", fx10vec3), F("kind", enum8(5)),
        F("moveMask", u8(mask=0xF)), F("cost", fx16(0)), F("bidirectional", u8(0, 1)),
    ]), 0, 65535), note="`array<link>`"),
], _navs_check, container_min=4, what="multi-layer navigation surfaces and links")

chunk("VOLS", "S", [
    F("volumes", Array(Struct([
        F("name", STR), F("shape", SHAPE3D), F("flags", u32(mask=0xF)), F("army", i16(-1)),
        F("tags", Array(STR, 0, 16)),
    ]), 0, 4096), note="`array<volume>`"),
], container_min=4, what="trigger volumes")


# ------------------------------------------------------------------------------------------------ native mesh body

COMPONENT_BYTES = (4, 2, 2, 1, 1, 1, 2, 2)     # f32 f16 snorm16 unorm8 snorm8 u8 u16 unorm16


def attr_size(a):
    """Bytes of one attribute inside a vertex: component size x count, each attribute 4-byte aligned."""
    return (COMPONENT_BYTES[a["component"]] * a["count"] + 3) // 4 * 4


def _native_stride(s):
    return sum(attr_size(a) for a in s.cur["attrs"])


def _native_check(d, s):
    if d["vertexCount"] > 0 and not d["attrs"]:
        raise ChunkError("vertices without attributes")
    if d["indexWidth"] == 2 and d["vertexCount"] > 65536:
        raise ChunkError("16 bit indices cannot address %d vertices" % d["vertexCount"])
    for sm in d["submeshes"]:
        if sm["firstIndex"] + sm["indexCount"] > d["indexCount"]:
            raise ChunkError("a submesh reads past the index data")
    for l in d["lods"]:
        if l["firstSubmesh"] + l["submeshCount"] > len(d["submeshes"]):
            raise ChunkError("a lod refers past the submesh list")
    w = d["indexWidth"]
    data = d["indexData"]
    for i in range(d["indexCount"]):
        if int.from_bytes(data[i * w:(i + 1) * w], "little") >= d["vertexCount"]:
            raise ChunkError("index %d refers past the vertices" % i)


# Not a chunk: the body of an MSHB mesh with format 1 (FULL3D.md, MSHB). Validated by the file loader.
NATIVE_MESH = Struct([
    F("vertexCount", u32), F("indexCount", u32), F("indexWidth", u8(2, 4)),
    F("attrs", Array(Struct([F("semantic", enum8(8)), F("component", enum8(8)), F("count", u8(1, 4))]), 0, 8),
      note="`array<attr>`"),
    F("vertexData", RawBytes(lambda s: s.cur["vertexCount"] * _native_stride(s)), note="interleaved vertex data"),
    F("indexData", RawBytes(lambda s: s.cur["indexCount"] * s.cur["indexWidth"]), note="index data"),
    F("submeshes", Array(Struct([F("firstIndex", u32), F("indexCount", u32), F("materialSlot", u16)]), 0, 256),
      note="`array<submesh>`"),
    F("lods", Array(Struct([F("screenSize", f32), F("firstSubmesh", u32), F("submeshCount", u32)]), 0, 8),
      note="`array<lod>`"),
], _native_check)
