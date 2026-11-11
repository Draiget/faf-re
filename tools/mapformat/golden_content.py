"""Deterministic content for the golden maps: every chunk with plausible values, fixed seeds, integer arithmetic for
anything that feeds a sample (no libm, so the bytes do not depend on the platform).

All floats are dyadic or rounded to binary32 by `norm()`, so decode(encode(d)) == d holds for every dict built here.
"""
import hashlib
import math
import struct
import sys
import zlib
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mapfmt import scatter                      # noqa: E402
from mapfmt.container import crc32, deflate_raw  # noqa: E402,F401
from mapfmt.loadmap import height_value         # noqa: E402
from mapfmt.schema import f32_round, plane      # noqa: E402

W, H = 64, 48              # cells of the non-square golden grid


class Rng(object):
    """SplitMix64 stream: deterministic on every platform and Python version."""

    def __init__(self, seed):
        self.s = seed & scatter.M64

    def u64(self):
        self.s = (self.s + 0x9E3779B97F4A7C15) & scatter.M64
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & scatter.M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & scatter.M64
        return z ^ (z >> 31)

    def below(self, n):
        return self.u64() % n

    def bytes(self, n):
        out = bytearray()
        while len(out) < n:
            out += struct.pack("<Q", self.u64())
        return bytes(out[:n])


def norm(v, skip=("originX", "originY", "originZ")):
    """Round every float in a nested dict / list to binary32 (the f64 origin keys stay)."""
    if isinstance(v, dict):
        return dict((k, v[k] if k in skip else norm(v[k], skip)) for k in v)
    if isinstance(v, (list, tuple)):
        return [norm(x, skip) for x in v]
    if isinstance(v, float):
        return f32_round(v)
    return v


def pack_u16(vals):
    return struct.pack("<%dH" % len(vals), *vals)


def half(x):
    """Raw binary16 of a number."""
    return struct.unpack("<H", struct.pack("<e", x))[0]


def png(w, h, seed):
    """A real (tiny) PNG, 8 bit RGB, built with zlib so it is valid for any viewer."""
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    rows = b"".join(b"\0" + bytes(v for x in range(w) for v in ((x * 40 + seed) & 255, (y * 40) & 255, 128))
                    for y in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


# ------------------------------------------------------------------------------------------------ terrain

def sample_u16(x, z):
    """Hill + ridges + hashed noise, pure integer arithmetic. x in 0..W, z in 0..H (grid samples)."""
    dx, dz = x - 32, z - 24
    bump = max(0, 900 - (dx * dx + dz * dz)) * 20
    ridge = ((x * 5 + z * 3) % 32) * 12
    noise = (scatter.splitmix64(x * 65536 + z + 77) >> 20) & 63
    return 12000 + bump + ridge + noise


def height_plane(cells_x, cells_z, fn=sample_u16):
    return [fn(x, z) for z in range(cells_z + 1) for x in range(cells_x + 1)]


def grid_hght(cells_x, cells_z, min_height, step_log2, predictor, vals=None):
    vals = vals if vals is not None else height_plane(cells_x, cells_z)
    lo = height_value(min(vals), min_height, step_log2)
    hi = height_value(max(vals), min_height, step_log2)
    grid = {"cellsX": cells_x, "cellsZ": cells_z, "cellSize": 1.0, "originX": 0.0, "originZ": 0.0,
            "minElevation": lo, "maxElevation": hi, "reserved": 0}
    hght = {"minHeight": min_height, "stepLog2": step_log2, "predictor": predictor, "tileSize": 0,
            "samples": pack_u16(vals)}
    return grid, hght, vals


def bitmask(cols, rows, fn):
    """bitmask(W,H): rows of ceil(W/8) bytes, LSB first, row 0 = z 0."""
    rb = (cols + 7) // 8
    out = bytearray(rb * rows)
    for z in range(rows):
        for x in range(cols):
            if fn(x, z):
                out[z * rb + x // 8] |= 1 << (x % 8)
    return bytes(out)


def meta(name, kind=0, nlocs=1):
    return {
        "name": name,
        "locs": [{"lang": "de", "name": name + " (de)", "description": "Eine Testkarte über Hügel"}][:nlocs]
        + ([{"lang": "fr", "name": name + " (fr)", "description": "Carte d'essai"}] if nlocs > 1 else []),
        "author": "faf-re golden generator", "version": "1.0", "license": "CC0-1.0",
        "website": "https://example.invalid/maps",
        "tags": ["golden", "test"][:2 if nlocs > 1 else 1], "mapType": 0, "minPlayers": 2, "maxPlayers": 4,
        "reqs": [{"kind": "feature", "id": "RENDER_PBR_MATERIALS", "minVersion": "1"}] if nlocs > 1 else [],
        "createdUtc": 1730678400, "modifiedUtc": 1730764800, "toolName": "make_golden.py", "toolVersion": "1",
    }


# ------------------------------------------------------------------------------------------------ extended_min

def _n(chunks):
    return [(c, i, norm(d), z) for c, i, d, z in chunks]


def extended_min():
    grid, hght, vals = grid_hght(W, H, 0.0, -7, 1)
    return _n([
        ("META", 0, meta("Golden Min"), False),
        ("GRID", 0, grid, False),
        ("HGHT", 0, hght, True),
        ("PLAY", 0, {"x0": 2, "z0": 2, "x1": 62, "z1": 46, "borderMode": 1, "polygon": []}, False),
        ("GPLY", 0, {
            "legacyTerrainIds": 1,
            "surfaces": [{"id": 0, "name": "Default", "flags": 0, "speedMul": 256, "effectsKey": ""}],
            "idWidth": 1, "ids": plane(bytes(W * H), 0), "masks": []}, False),
        ("WBOD", 0, {"bodies": [{"id": 0, "name": "Sea", "kind": 0, "level": 95.0, "extentKind": 0}]}, False),
    ])


# ------------------------------------------------------------------------------------------------ extended_full

def surface_ids():
    """Blocky surface id map: 0 default, 1 mud, 2 rock, 7 shallow water margin."""
    out = []
    for z in range(H):
        for x in range(W):
            v = 0
            if 8 <= x < 20 and 6 <= z < 16:
                v = 1
            elif 40 <= x < 56 and 20 <= z < 40:
                v = 2
            elif z >= 44:
                v = 7
            out.append(v)
    return out


def extended_full():
    rng = Rng(2026110401)
    vals = height_plane(W, H)
    grid, hght, vals = grid_hght(W, H, -4.0, -8, 3, [v for v in vals])
    chunks = []

    def add(cid, d, compress=False, inst=0):
        chunks.append((cid, inst, norm(d), compress))

    # metadata
    add("META", meta("Golden Full", nlocs=2))
    add("PREV", {"kind": 0, "width": 4, "height": 4, "data": png(4, 4, 1)})
    add("GENR", {"generator": "make_golden.py", "generatorVersion": "1", "seed": 2026110401,
                 "json": b'{"hills":3,"erosion":{"iterations":40,"strength":0.5},"symmetry":"none"}',
                 "notes": [{"key": "purpose", "value": "reference golden"}, {"key": "note", "value": "café \"quoted\" \\ tab\t"}]})
    add("SIGN", {"algo": 1, "publicKey": rng.bytes(32), "signature": rng.bytes(64), "keyName": "golden-key"})
    add("ASST", {"assets": [
        {"name": "textures/test_albedo.dds", "kind": 0, "data": b"DDS " + rng.bytes(60)},
        {"name": "data/params.json", "kind": 5, "data": b'{"a":1}'}]}, inst=0)
    add("ASST", {"assets": [{"name": "textures/preview.png", "kind": 1, "data": png(4, 4, 9)}]}, inst=1)

    # sim
    add("GRID", grid)
    add("HGHT", hght, True)
    poly = [(4 * 256, 2 * 256), (58 * 256, 2 * 256), (62 * 256, 8 * 256), (62 * 256, 40 * 256), (56 * 256, 46 * 256),
            (6 * 256, 46 * 256), (2 * 256, 40 * 256), (2 * 256, 8 * 256)]
    add("PLAY", {"x0": 2, "z0": 2, "x1": 62, "z1": 46, "borderMode": 1, "polygon": [list(p) for p in poly]})
    ids = surface_ids()
    add("GPLY", {
        "legacyTerrainIds": 0,
        "surfaces": [
            {"id": 0, "name": "Default", "flags": 0, "speedMul": 256, "effectsKey": ""},
            {"id": 1, "name": "Mud", "flags": 8, "speedMul": 160, "effectsKey": "Mud"},
            {"id": 2, "name": "Rock", "flags": 2, "speedMul": 256, "effectsKey": "Rock"},
            {"id": 7, "name": "Shallows", "flags": 8 | 4, "speedMul": 200, "effectsKey": "Water"}],
        "idWidth": 2, "ids": plane(pack_u16(ids), 1),
        "masks": [
            {"name": "buildable_override", "kind": 1, "data": bitmask(W, H, lambda x, z: 10 <= x < 14 and 8 <= z < 12)},
            {"name": "walk_land", "kind": 1, "data": bitmask(W, H, lambda x, z: not (x % 16 == 15 and 20 < z < 30))},
            {"name": "heat", "kind": 8, "data": plane(bytes((x * 4 + z) & 255 for z in range(H) for x in range(W)), 2)}]}, True)
    mask_river = bitmask(W, H, lambda x, z: 28 <= x < 32 and z >= 6 and z < 44)
    add("WBOD", {"bodies": [
        {"id": 0, "name": "Sea", "kind": 0, "level": 50.0, "extentKind": 0},
        {"id": 1, "name": "Lake", "kind": 1, "level": 80.0, "extentKind": 2,
         "polygon": [[10 * 256, 30 * 256], [20 * 256, 30 * 256], [20 * 256, 40 * 256], [10 * 256, 40 * 256]]},
        {"id": 2, "name": "River", "kind": 2, "level": 70.0, "extentKind": 1, "mask": mask_river}]})
    add("LEVL", {"decks": [
        {"id": 1, "name": "Bridge", "x0": 20, "z0": 10, "x1": 27, "z1": 12, "mode": 0, "h0": 90.0, "h1": 90.0,
         "axis": 0, "clearanceBelow": 4.0, "flags": 1 | 2 | 4,
         "portals": [{"a": [20 * 256, 10 * 256], "b": [20 * 256, 13 * 256], "targetDeck": 0xFFFF},
                     {"a": [28 * 256, 10 * 256], "b": [28 * 256, 13 * 256], "targetDeck": 2}]},
        {"id": 2, "name": "Ramp", "x0": 28, "z0": 10, "x1": 35, "z1": 12, "mode": 1, "h0": 90.0, "h1": 100.0,
         "axis": 0, "clearanceBelow": 0.0, "flags": 1, "portals": []},
        {"id": 3, "name": "Cave", "x0": 40, "z0": 30, "x1": 47, "z1": 35, "mode": 2, "h0": 0.0, "h1": 0.0, "axis": 0,
         "patch": plane(pack_u16([22000 + ((x + z) % 4) * 16 for z in range(6) for x in range(8)]), 1),
         "clearanceBelow": 2.5, "flags": 1 | 2 | 8, "portals": []}]})
    markers = []

    def mk(t, name, x, z, yaw=0.0, army=-1, props=(), links=()):
        markers.append({"type": t, "name": name, "pos": [x, 100.0, z], "yawDeg": yaw, "army": army, "flags": 0,
                        "props": list(props), "links": list(links)})

    mk(1, "ARMY_1", 8.5, 8.5, 0.0, 0)
    mk(1, "ARMY_2", 55.5, 39.5, 180.0, 1)
    mk(2, "Mass 01", 12.5, 10.5, props=[{"key": "amount", "vtype": 2, "value": 100.0}])
    mk(2, "Mass 02", 52.5, 36.5, props=[{"key": "amount", "vtype": 2, "value": 100.0}])
    mk(3, "Hydro 01", 30.5, 24.5, props=[{"key": "amount", "vtype": 2, "value": 100.0}])
    mk(4, "Expansion 01", 20.5, 40.5, props=[{"key": "tag", "vtype": 0, "value": "west"}, {"key": "tier", "vtype": 1, "value": -2},
                                             {"key": "safe", "vtype": 3, "value": 1}], links=[6])
    mk(7, "Land_Path_01", 16.5, 20.5, links=[6, 7])
    mk(7, "Land_Path_02", 40.5, 22.5, links=[6])
    mk(10, "Amphib_Path_01", 28.5, 30.5, links=[])
    mk(13, "Camera_01", 32.5, 24.5, 45.0)
    add("MRKR", {"markers": markers}, True)
    add("AREA", {"areas": [
        {"name": "NorthPlateau", "shape": {"kind": 0, "x0": 4.0, "z0": 3.0, "x1": 20.0, "z1": 14.0}, "flags": 1, "yMin": 90.0,
         "yMax": 140.0, "tags": ["plateau", "start"]},
        {"name": "Basin", "shape": {"kind": 1, "points": [[30.0, 30.0], [44.0, 28.0], [46.0, 42.0], [32.0, 44.0]]}, "flags": 0,
         "tags": []},
        {"name": "Ring", "shape": {"kind": 2, "cx": 32.0, "cz": 24.0, "r": 6.5}, "flags": 0, "tags": ["center"]}]})
    add("PROP", {"blueprints": ["/env/common/props/rocks/rock01_prop.bp", "/env/common/props/trees/tree05_prop.bp",
                                "/env/common/props/ruins/wall02_prop.bp"],
                 "props": [{"blueprintIndex": i % 3, "pos": [10.0 + 7 * i, 100.0, 12.0 + 3 * i], "rot": [0.0, 0.0, 0.0, 1.0],
                            "scale": [1.0, 1.0, 1.0], "flags": 0} for i in range(6)]}, True)
    add("HINT", {
        "regions": [{"id": 1, "name": "Main land", "kind": 0, "area": 2500.0, "centroid": [32.0, 24.0], "neighbors": [2, 3]},
                    {"id": 2, "name": "Lake island", "kind": 1, "area": 120.0, "centroid": [15.0, 35.0], "neighbors": [1]},
                    {"id": 3, "name": "Sea", "kind": 2, "area": 400.0, "centroid": [32.0, 46.0], "neighbors": [1]}],
        "chokes": [{"pos": [28.0, 30.0], "width": 6.0, "regionA": 1, "regionB": 2, "layerMask": 0b0101},
                   {"pos": [30.0, 44.0], "width": 12.0, "regionA": 1, "regionB": 3, "layerMask": 0b0010}],
        "candidates": [{"pos": [20.5, 40.5], "layer": 0, "score": 0.75, "markerIds": [5]},
                       {"pos": [52.5, 36.5], "layer": 0, "score": 0.5, "markerIds": [3, 1]}]})

    # render
    add("LAYR", {"layers": [{"name": "decor", "defaultVisible": 1, "flags": 0}, {"name": "winter", "defaultVisible": 0, "flags": 0}]})
    add("MATL", {"materials": [
        {"id": i, "name": n, "albedo": "/maps/golden/embedded/%s_a.dds" % n.lower(), "normal": "/maps/golden/embedded/%s_n.dds" % n.lower(),
         "orm": "/maps/golden/embedded/%s_orm.dds" % n.lower() if i != 3 else "", "height": "/maps/golden/embedded/%s_h.dds" % n.lower() if i % 2 == 0 else "",
         "flags": 0b11010 | (i & 1), "tileSize": 8.0 * (i + 1), "rotationDeg": 15.0 * i, "normalStrength": 1.0,
         "roughnessScale": 1.0, "metalness": 0.0, "parallaxScale": 0.03125, "heightBlendSharpness": 4.0, "macroInfluence": 0.5,
         "gameplaySurface": [0, 1, 2, 0xFFFF][i]} for i, n in enumerate(["Grass", "Mud", "Rock", "Sand"])]})
    sw, sh = 32, 24
    idx, wts = bytearray(), bytearray()
    for z in range(sh):
        for x in range(sw):
            a, b = (x // 11) % 4, (x // 11 + 1) % 4
            w = ((x % 11) * 255) // 10
            idx += bytes((a, b, 2, 3))
            wts += bytes((255 - w, w, 0, 0))
    add("SPLT", {"width": sw, "height": sh, "mode": 0, "indices": plane(idx, 1), "weights": plane(wts, 1)}, True)
    add("NRML", {"width": 16, "height": 12, "format": 0, "data": rng.bytes(16 * 12 * 2)})
    add("AOMP", {"width": 8, "height": 8, "kind": 1, "format": 1, "data": rng.bytes(32)})
    hd = []
    mm = 2
    for z in range(H * mm + 1):
        for x in range(W * mm + 1):
            hd.append(((scatter.splitmix64(x * 4096 + z + 5) >> 30) % 9) - 4)
    add("HDET", {"log2Mult": 1, "lsb": 0.00390625, "predictor": 1,
                 "samples": struct.pack("<%dh" % len(hd), *hd)}, True)
    add("HOLE", {"mask": bitmask(W, H, lambda x, z: 44 <= x < 48 and 6 <= z < 10)})
    add("MACR", {"width": 8, "height": 6, "format": 0, "strength": 0.25, "data": rng.bytes(8 * 6 * 3)})
    add("LITE", {"sunDir": [0.5, 0.75, 0.4330127], "sunColor": [1.0, 0.96, 0.9], "sunIntensity": 1.5, "sunAngularDeg": 0.53125,
                 "hasMoon": 1, "moon": {"dir": [-0.5, 0.5, 0.0], "color": [0.25, 0.3, 0.5], "intensity": 0.125, "angularDeg": 0.5},
                 "ambientMode": 2, "ambient": [0.25, 0.3, 0.4], "ground": [0.125, 0.109375, 0.09375], "ambientIntensity": 1.0,
                 "sh": [0.0625 * (i % 7) - 0.125 for i in range(27)], "shadowFill": [0.0625, 0.0625, 0.09375],
                 "shadowDistance": 600.0, "cascades": 3, "shadowBias": 0.001953125, "shadowStrength": 0.875, "fogMode": 3,
                 "fogColor": [0.6, 0.7, 0.8], "fogStart": 100.0, "fogEnd": 900.0, "fogDensity": 0.001953125,
                 "fogHeightFalloff": 0.0078125, "fogBaseHeight": 40.0, "toneMap": 1, "exposureEV": 0.5, "bloomIntensity": 0.25,
                 "bloomThreshold": 1.0, "lut": "/maps/golden/embedded/grade_32.dds"})
    add("LLGT", {"lights": [
        {"type": 0, "pos": [12.5, 105.0, 10.5], "dir": [0.0, -1.0, 0.0], "color": [1.0, 0.5, 0.25], "intensity": 4.0, "range": 12.0,
         "innerDeg": 0.0, "outerDeg": 0.0, "flags": 0b1101, "flickerAmp": 0.25, "flickerHz": 6.0, "layer": 0},
        {"type": 1, "pos": [55.5, 110.0, 39.5], "dir": [-0.5, -0.75, 0.0], "color": [0.5, 0.75, 1.0], "intensity": 8.0, "range": 40.0,
         "innerDeg": 15.0, "outerDeg": 30.0, "flags": 0b0011, "flickerAmp": 0.0, "flickerHz": 0.0, "layer": 1}]})
    nx, ny, nz = 2, 1, 2
    add("PROB", {"reflProbes": [{"pos": [32.0, 110.0, 24.0], "halfExtents": [32.0, 40.0, 24.0], "blend": 4.0, "priority": 0,
                                 "cubemap": "/maps/golden/embedded/probe0.dds"}],
                 "gridOrigin": [0.0, 80.0, 0.0], "gridSpacing": [32.0, 32.0, 32.0], "nx": nx, "ny": ny, "nz": nz,
                 "shData": pack_u16([half(((i * 7) % 13) / 8.0) for i in range(nx * ny * nz * 27)])})
    key = lambda t, sun, amb, fog: {  # noqa: E731
        "t": t, "sunDir": sun, "sunColor": [1.0, 0.9, 0.8], "sunIntensity": 1.0 + t, "ambient": amb, "ground": [0.125, 0.125, 0.125],
        "ambientIntensity": 1.0, "fogColor": fog, "fogDensity": 0.001953125, "skyTint": [0.5, 0.625, 1.0], "exposureEV": 0.0,
        "starIntensity": 0.0 if t < 0.75 else 1.0}
    add("TODK", {"cycleSeconds": 600.0, "startPhase": 0.25, "keys": [
        key(0.0, [0.0, 1.0, 0.0], [0.3, 0.4, 0.5], [0.6, 0.7, 0.8]),
        key(0.25, [0.5, 0.5, 0.0], [0.5, 0.4, 0.3], [0.8, 0.6, 0.4]),
        key(0.75, [-0.5, -0.5, 0.0], [0.0625, 0.0625, 0.125], [0.0625, 0.0625, 0.125])]})
    add("ATMO", {"skyModel": 1, "cubemap": "/maps/golden/embedded/sky.dds", "skyIntensity": 1.0, "rotationDeg": 30.0,
                 "planetRadiusKm": 6360.0, "atmosphereHeightKm": 100.0, "rayleigh": [0.0058, 0.0135, 0.0331],
                 "rayleighScaleHeightKm": 8.0, "mie": 0.0035, "mieAnisotropy": 0.8, "mieScaleHeightKm": 1.2,
                 "ozone": [0.00065, 0.00188, 0.00008], "groundAlbedo": 0.3, "cloudMode": 2, "coverage": 0.5, "density": 0.75,
                 "baseAltitude": 1500.0, "thickness": 1000.0, "wind": [2.0, 0.5], "noiseShape": "/maps/golden/embedded/cloud_shape.dds",
                 "noiseDetail": "/maps/golden/embedded/cloud_detail.dds", "cloudShadowStrength": 0.5, "volumetricFog": 1,
                 "scattering": 0.25, "anisotropy": 0.5, "extinction": 0.03125, "maxDistance": 800.0,
                 "celestials": [{"texture": "/maps/golden/embedded/moon.dds", "dir": [-0.5, 0.5, 0.0], "sizeDeg": 2.0,
                                 "tint": [0.8, 0.8, 1.0], "intensity": 1.0}], "starIntensity": 0.5})
    add("WVIS", {"bodies": [
        {"bodyId": 0xFFFF, "shallow": [0.1, 0.4, 0.5], "deep": [0.0, 0.1, 0.25], "absorption": [0.4, 0.1, 0.05],
         "clarityMeters": 12.0, "reflection": 0.75, "refraction": 0.5, "waveModel": 1,
         "waves": [{"amplitude": 0.5, "wavelength": 12.0, "steepness": 0.25, "dirDeg": 20.0, "speed": 1.5},
                   {"amplitude": 0.25, "wavelength": 5.0, "steepness": 0.375, "dirDeg": 110.0, "speed": 2.0}],
         "foamAmount": 0.5, "foamTexture": "/maps/golden/embedded/foam.dds", "shoreFoamWidth": 1.5, "causticStrength": 0.5,
         "causticTexture": "/maps/golden/embedded/caustics.dds", "flowScale": 0.0, "flowMap": 0xFFFFFFFF,
         "underwaterFog": [0.0, 0.125, 0.1875], "underwaterDensity": 0.0625},
        {"bodyId": 2, "shallow": [0.2, 0.5, 0.4], "deep": [0.05, 0.2, 0.2], "absorption": [0.3, 0.1, 0.1], "clarityMeters": 6.0,
         "reflection": 0.5, "refraction": 0.25, "waveModel": 0,
         "normalMaps": [{"normalMap": "/maps/golden/embedded/river_n.dds", "tiling": 4.0, "speed": 0.5, "dir": [1.0, 0.0]}],
         "foamAmount": 0.25, "foamTexture": "", "shoreFoamWidth": 0.5, "causticStrength": 0.0, "causticTexture": "",
         "flowScale": 2.0, "flowMap": 0, "underwaterFog": [0.0, 0.125, 0.125], "underwaterDensity": 0.03125},
        {"bodyId": 1, "shallow": [0.3, 0.5, 0.5], "deep": [0.1, 0.2, 0.3], "absorption": [0.2, 0.1, 0.1], "clarityMeters": 8.0,
         "reflection": 0.5, "refraction": 0.5, "waveModel": 2, "windSpeed": 6.0, "windDirDeg": 45.0, "fetchKm": 2.0,
         "choppiness": 0.5, "patchSize": 64.0, "foamAmount": 0.0, "foamTexture": "", "shoreFoamWidth": 0.0, "causticStrength": 0.0,
         "causticTexture": "", "flowScale": 0.0, "flowMap": 0xFFFFFFFF, "underwaterFog": [0.0, 0.0, 0.0], "underwaterDensity": 0.0}]})
    for i in range(2):
        fw, fh = 8, 6
        flow = bytearray()
        for z in range(fh):
            for x in range(fw):
                flow += struct.pack("<bb", (x - 4) * 10 * (1 if i == 0 else -1), (z - 3) * 8)
        add("WFLW", {"width": fw, "height": fh, "maxSpeed": 2.0 + i, "flow": plane(flow, 3)}, True, inst=i)
    mat_variants = [{"kind": 0, "ref": "/env/common/props/rocks/rock01_prop.bp", "weight": 3.0, "scaleMin": 0.75, "scaleMax": 1.5},
                    {"kind": 1, "ref": "/maps/golden/embedded/rock_b.scm", "weight": 1.0, "scaleMin": 0.5, "scaleMax": 1.0}]
    add("SCAT", {"layers": [
        {"name": "Rocks", "seed": 123456789012345, "variants": mat_variants, "density": 20.5, "minSlopeDeg": 0.0, "maxSlopeDeg": 45.0,
         "minAltitude": -100.0, "maxAltitude": 1000.0, "allowedMaterials": [], "forbiddenSurfaces": [], "densityMap": -1, "jitter": 0.5,
         "flags": 0b00110, "cullDistance": 120.0, "windBend": 0.0, "windHz": 0.0, "tintVariation": 0.25, "layer": 0},
        {"name": "Grass", "seed": 987654321, "variants": [{"kind": 2, "ref": "/maps/golden/embedded/grass.dds", "weight": 1.0,
                                                           "scaleMin": 0.5, "scaleMax": 1.0}],
         "density": 6.0, "minSlopeDeg": 0.0, "maxSlopeDeg": 30.0, "minAltitude": 50.0, "maxAltitude": 120.0, "allowedMaterials": [0, 1],
         "forbiddenSurfaces": [2, 7], "densityMap": 0, "jitter": 1.0, "flags": 0b11011, "cullDistance": 60.0, "windBend": 0.25,
         "windHz": 0.75, "tintVariation": 0.125, "layer": 1}]})
    for i in range(2):
        dw, dh = 16, 12
        add("SCDM", {"width": dw, "height": dh, "density": plane(bytes(((x * 16) ^ (z * 21 * (i + 1))) & 255 for z in range(dh) for x in range(dw)), 2)},
            True, inst=i)
    add("SPLN", {"splines": [
        {"kind": 0, "name": "Road", "flags": 0b00110, "points": [
            {"pos": [8.5, 100.0, 8.5], "tangentIn": [4.0, 0.0, 0.0], "tangentOut": [4.0, 0.0, 0.0], "width": 2.0, "rollDeg": 0.0},
            {"pos": [30.5, 100.0, 24.5], "tangentIn": [6.0, 0.0, 3.0], "tangentOut": [6.0, 0.0, 3.0], "width": 2.0, "rollDeg": 0.0}],
         "decalTexture": "/maps/golden/embedded/road_a.dds", "mesh": "", "uvTile": 0.25, "paintWidth": 3.0, "paintMaterial": 1, "writeSurface": 0,
         "blendDistance": 1.0, "layer": 0},
        {"kind": 3, "name": "Fence", "flags": 0b10001, "points": [
            {"pos": [40.5, 100.0, 5.5], "tangentIn": [0.0, 0.0, 4.0], "tangentOut": [0.0, 0.0, 4.0], "width": 0.25, "rollDeg": 0.0},
            {"pos": [40.5, 100.0, 15.5], "tangentIn": [0.0, 0.0, 4.0], "tangentOut": [0.0, 0.0, 4.0], "width": 0.25, "rollDeg": 0.0},
            {"pos": [48.5, 100.0, 15.5], "tangentIn": [4.0, 0.0, 0.0], "tangentOut": [4.0, 0.0, 0.0], "width": 0.25, "rollDeg": 0.0}],
         "decalTexture": "", "mesh": "/maps/golden/embedded/fence.scm", "uvTile": 1.0, "paintWidth": 0.0, "paintMaterial": 0,
         "writeSurface": 0, "blendDistance": 0.0, "layer": 0}]})
    add("DECL", {"textures": ["/maps/golden/embedded/scorch_a.dds", "/maps/golden/embedded/scorch_n.dds"],
                 "decals": [{"type": t, "tex0": t % 2, "tex1": 0xFFFFFFFF if t != 0 else 1, "pos": [20.0 + 5 * t, 100.0, 20.0],
                             "rot": [0.0, 0.0, 0.0, 1.0], "size": [4.0, 2.0, 4.0], "lodMin": 0.0, "lodMax": 400.0,
                             "tint": [1.0, 1.0, 1.0, 0.75], "fadeDistance": 50.0, "order": t - 1, "layer": 0, "blend": t % 3}
                            for t in range(3)]})
    add("WTHR", {"defaultState": 0, "states": [
        {"name": "clear", "rain": 0.0, "snow": 0.0, "fogDensityMul": 1.0, "cloudCoverageAdd": 0.0, "windSpeed": 2.0, "windDirDeg": 45.0,
         "lightMul": 1.0, "wetness": 0.0},
        {"name": "storm", "rain": 0.875, "snow": 0.0, "fogDensityMul": 2.0, "cloudCoverageAdd": 0.5, "windSpeed": 12.0, "windDirDeg": 90.0,
         "lightMul": 0.5, "wetness": 1.0}],
        "zones": [{"name": "NorthStorm", "shape": {"kind": 0, "x0": 0.0, "z0": 0.0, "x1": 64.0, "z1": 12.0}, "state": 1, "yMin": 0.0,
                   "yMax": 400.0, "effect": "/effects/emitters/rain_01_emit.bp", "sound": "", "layer": 0}]})
    add("AUDI", {"ambientBed": "AMB_Wind_Light", "bedVolume": 0.5, "zones": [
        {"name": "Cave", "shape": {"kind": 2, "cx": 43.0, "cz": 32.0, "r": 5.0}, "loop": "AMB_Cave", "volume": 0.75, "fade": 2.0,
         "priority": 1, "reverbPreset": "cave"}], "cues": [{"state": "combat", "cue": "MUS_Battle_01"}, {"state": "peace", "cue": "MUS_Calm_01"}]})
    pose = lambda x, z, yaw: {"pos": [x, 140.0, z], "yawDeg": yaw, "pitchDeg": 55.0, "fovDeg": 50.0}  # noqa: E731
    add("CAMR", {"defaultPose": pose(32.0, 24.0, 0.0), "minZoom": 10.0, "maxZoom": 500.0, "pitchMin": 10.0, "pitchMax": 85.0,
                 "bounds": [0.0, 0.0, 64.0, 48.0],
                 "bookmarks": [{"name": "base1", "pose": pose(8.0, 8.0, 0.0)}, {"name": "base2", "pose": pose(55.0, 40.0, 180.0)}],
                 "paths": [{"name": "intro", "duration": 8.0, "keys": [
                     {"t": 0.0, "pos": [0.0, 200.0, 0.0], "rot": [0.0, 0.0, 0.0, 1.0], "fovDeg": 60.0, "ease": 1},
                     {"t": 8.0, "pos": [32.0, 120.0, 24.0], "rot": [0.0, 0.0, 0.0, 1.0], "fovDeg": 45.0, "ease": 0}]}]})
    add("MINI", {"kind": 1, "image": {"fmt": 0, "w": 8, "h": 8, "data": png(8, 8, 3)}, "contourInterval": 5.0,
                 "ramp": [{"height": 40.0, "color": [30, 90, 160]}, {"height": 70.0, "color": [60, 140, 70]}, {"height": 120.0, "color": [200, 200, 190]}],
                 "borderColor": [20, 20, 20], "strategicStyle": "classic"})
    add("POST", {"flags": 1, "bloom": 0.25, "vignette": 0.125, "chromaticAberration": 0.0, "filmGrain": 0.03125, "ssaoHint": 0.5,
                 "ssrHint": 0.25, "dofFocus": 150.0, "dofAperture": 2.8})
    return chunks, vals


def minmax_mips(vals, cells_x, cells_z):
    """DRVD minmax_mips payload: levels 1.. until one block covers the grid; (min, max) u16 pairs of raw samples."""
    sx = cells_x + 1
    out = bytearray()
    k = 1
    while True:
        bs = 1 << k
        nbx, nbz = -(-cells_x // bs), -(-cells_z // bs)
        for bz in range(nbz):
            for bx in range(nbx):
                xs = range(bx * bs, min(cells_x, (bx + 1) * bs) + 1)
                zs = range(bz * bs, min(cells_z, (bz + 1) * bs) + 1)
                blk = [vals[z * sx + x] for z in zs for x in xs]
                out += struct.pack("<HH", min(blk), max(blk))
        if nbx == 1 and nbz == 1:
            return bytes(out)
        k += 1


def drvd_chunks(raw_hght, raw_inputs, vals):
    """DRVD instances: minmax_mips, nav_cache (placeholder payload) and a kind nobody knows (must be ignored)."""
    rng = Rng(77)
    nav_in = hashlib.sha256(b"".join(raw_inputs)).digest()
    return [
        ("DRVD", 0, {"kind": "minmax_mips", "inputHash": hashlib.sha256(raw_hght).digest(),
                     "data": minmax_mips(vals, W, H)}, True),
        ("DRVD", 1, {"kind": "nav_cache", "inputHash": nav_in, "data": rng.bytes(48)}, False),
        ("DRVD", 2, {"kind": "vendor.example.cache", "inputHash": rng.bytes(32), "data": rng.bytes(8)}, False),
    ]


# ------------------------------------------------------------------------------------------------ classic equivalent

def classic_equiv():
    n = 64
    grid, hght, vals = grid_hght(n, n, 0.0, -7, 1, [sample_u16(x, z) for z in range(n + 1) for x in range(n + 1)])
    mk = lambda t, name, x, z, props=(): {"type": t, "name": name, "pos": [x, 120.0, z], "yawDeg": 0.0, "army": -1,  # noqa: E731
                                          "flags": 0, "props": list(props), "links": []}
    amt = [{"key": "amount", "vtype": 2, "value": 100.0}]
    sw = 64
    wa = bytes(max(0, 255 - (x * 4)) for z in range(sw) for x in range(sw))
    wb = bytes(255 - v for v in wa)
    return _n([
        ("META", 0, meta("Golden Classic"), False),
        ("GRID", 0, grid, False),
        ("HGHT", 0, hght, True),
        ("PLAY", 0, {"x0": 0, "z0": 0, "x1": n, "z1": n, "borderMode": 1, "polygon": []}, False),
        ("GPLY", 0, {"legacyTerrainIds": 1,
                     "surfaces": [{"id": 0, "name": "Default", "flags": 0, "speedMul": 256, "effectsKey": ""},
                                  {"id": 1, "name": "Dirt", "flags": 0, "speedMul": 256, "effectsKey": "Dirt"}],
                     "idWidth": 1, "ids": plane(bytes(1 if x > 40 else 0 for z in range(n) for x in range(n)), 1), "masks": []}, True),
        ("WBOD", 0, {"bodies": [{"id": 0, "name": "Water", "kind": 0, "level": 95.0, "extentKind": 0}]}, False),
        ("MRKR", 0, {"markers": [
            {"type": 1, "name": "ARMY_1", "pos": [10.5, 120.0, 10.5], "yawDeg": 0.0, "army": 0, "flags": 0, "props": [], "links": []},
            {"type": 1, "name": "ARMY_2", "pos": [53.5, 120.0, 53.5], "yawDeg": 0.0, "army": 1, "flags": 0, "props": [], "links": []},
            mk(2, "Mass 01", 14.5, 12.5, amt), mk(2, "Mass 02", 50.5, 50.5, amt), mk(3, "Hydro 01", 32.5, 32.5, amt)]}, False),
        ("PROP", 0, {"blueprints": ["/env/common/props/rocks/rock01_prop.bp"],
                     "props": [{"blueprintIndex": 0, "pos": [20.0 + 5 * i, 120.0, 25.0], "rot": [0.0, 0.0, 0.0, 1.0],
                                "scale": [1.0, 1.0, 1.0], "flags": 0} for i in range(3)]}, False),
        ("MATL", 0, {"materials": [
            {"id": i, "name": nme, "albedo": "/env/evergreen/layers/%s_albedo.dds" % nme.lower(), "normal": "/env/evergreen/layers/%s_normal.dds" % nme.lower(),
             "orm": "", "height": "", "flags": 0b10000, "tileSize": 10.0, "rotationDeg": 0.0, "normalStrength": 1.0, "roughnessScale": 1.0,
             "metalness": 0.0, "parallaxScale": 0.0, "heightBlendSharpness": 1.0, "macroInfluence": 0.0, "gameplaySurface": i}
            for i, nme in enumerate(["Grass", "Dirt"])]}, False),
        ("SPLT", 0, {"width": sw, "height": sw, "mode": 1, "layers": 2, "materialIds": [0, 1], "planes": [plane(wa, 1), plane(wb, 1)]}, True),
        ("LITE", 0, {"sunDir": [0.5, 0.75, 0.4330127], "sunColor": [1.0, 1.0, 1.0], "sunIntensity": 1.0, "sunAngularDeg": 0.5, "hasMoon": 0,
                     "ambientMode": 0, "ambient": [0.5, 0.5, 0.5], "ground": [0.5, 0.5, 0.5], "ambientIntensity": 1.0,
                     "shadowFill": [0.25, 0.25, 0.25], "shadowDistance": 500.0, "cascades": 1, "shadowBias": 0.001953125,
                     "shadowStrength": 1.0, "fogMode": 1, "fogColor": [0.75, 0.8, 0.9], "fogStart": 200.0, "fogEnd": 800.0,
                     "fogDensity": 0.0, "fogHeightFalloff": 0.0, "fogBaseHeight": 0.0, "toneMap": 0, "exposureEV": 0.0,
                     "bloomIntensity": 0.0, "bloomThreshold": 1.0, "lut": ""}, False),
    ])
