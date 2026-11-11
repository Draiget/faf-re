"""Deterministic Full3D content for the golden map (container 4): a 2 x 1 x 2 cell world with a few meshes,
instances, collision, navigation surfaces and volumes. See golden_content.py for the conventions."""
import struct

from golden_content import Rng, bitmask, half, norm, pack_u16
from mapfmt.schema import plane


def qrot(x, y, z, w):
    """Smallest-three quaternion: 2 bits index of the largest, 3 x 10 bits snorm (value * 511)."""
    c = [x, y, z, w]
    idx = max(range(4), key=lambda i: abs(c[i]))
    sign = -1.0 if c[idx] < 0 else 1.0
    v = idx << 30
    for j, o in enumerate([c[i] * sign for i in range(4) if i != idx]):
        v |= (int(round(o * 511)) & 0x3FF) << (20 - 10 * j)
    return v


def fx(x):
    """Number -> fx10 (1/1024)."""
    return int(round(x * 1024))


def fxv(x, y, z):
    return [fx(x), fx(y), fx(z)]


def native_quad():
    from mapfmt import chunks as C
    verts = b""
    for (x, z, u, v) in ((0, 0, 0, 0), (1, 0, 1, 0), (1, 1, 1, 1), (0, 1, 0, 1)):
        verts += struct.pack("<3f", x, 0.0, z) + struct.pack("<3h", 0, 32767, 0) + b"\0\0" + struct.pack("<2H", half(u), half(v))
    return C.encode_native_mesh({
        "vertexCount": 4, "indexCount": 6, "indexWidth": 2,
        "attrs": [{"semantic": 0, "component": 0, "count": 3}, {"semantic": 1, "component": 2, "count": 3},
                  {"semantic": 3, "component": 1, "count": 2}],
        "vertexData": verts, "indexData": struct.pack("<6H", 0, 1, 2, 0, 2, 3),
        "submeshes": [{"firstIndex": 0, "indexCount": 6, "materialSlot": 0}],
        "lods": [{"screenSize": 1.0, "firstSubmesh": 0, "submeshCount": 1}]})


def native_tri():
    from mapfmt import chunks as C
    return C.encode_native_mesh({
        "vertexCount": 3, "indexCount": 3, "indexWidth": 4, "attrs": [{"semantic": 0, "component": 0, "count": 3}],
        "vertexData": struct.pack("<9f", 0, 0, 0, 1, 0, 0, 0, 0, 1), "indexData": struct.pack("<3I", 0, 1, 2),
        "submeshes": [{"firstIndex": 0, "indexCount": 3, "materialSlot": 0}],
        "lods": [{"screenSize": 0.5, "firstSubmesh": 0, "submeshCount": 1}]})


def world3d_chunks():
    rng = Rng(424242)
    out = []

    def add(cid, d, compress=False, inst=0):
        out.append((cid, inst, norm(d), compress))

    add("WRLD", {"originX": 10000000.5, "originY": 0.0, "originZ": -20000000.25, "boundsMin": [0.0, 0.0, 0.0],
                 "boundsMax": [64.0, 64.0, 64.0], "cellSize": 32.0, "cellsX": 2, "cellsY": 1, "cellsZ": 2, "upAxis": 1,
                 "unitsPerMeter": 1.0, "flags": 1})
    cells = []
    for cz in range(2):
        for cx in range(2):
            i = cz * 2 + cx
            flags = (1 if i == 0 else 0) | (2 if i != 3 else 0) | (4 if i in (0, 2) else 0) | (8 if i == 0 else 0) | (16 if i in (0, 1) else 0)
            cells.append({"min": [cx * 32.0, 0.0, cz * 32.0], "max": [cx * 32.0 + 32.0, 64.0, cz * 32.0 + 32.0],
                          "loadDistance": 128.0, "unloadDistance": 160.0, "priority": i, "flags": flags, "layer": 0})
    add("CIDX", {"cells": cells})
    add("MSHB", {"meshes": [
        {"name": "quad_glb", "format": 0, "aabb": [0.0, 0.0, 0.0, 1.0, 0.0, 1.0],
         "data": b"glTF" + struct.pack("<II", 2, 12)},
        {"name": "quad_native", "format": 1, "aabb": [0.0, 0.0, 0.0, 1.0, 0.0, 1.0], "data": native_quad()}]}, False, inst=0)
    add("MSHB", {"meshes": [{"name": "tri_native", "format": 1, "aabb": [0.0, 0.0, 0.0, 1.0, 0.0, 1.0], "data": native_tri()}]},
        False, inst=1)
    add("MATB", {"materials": [
        {"name": "stone", "baseColor": [0.5, 0.5, 0.5, 1.0], "emissive": [0.0, 0.0, 0.0], "emissiveStrength": 1.0, "metallic": 0.0,
         "roughness": 0.875, "normalScale": 1.0, "occlusionStrength": 1.0, "alphaMode": 0, "alphaCutoff": 0.5, "flags": 0b10000,
         "baseColorTex": "/maps/golden/embedded/stone_a.dds", "normalTex": "/maps/golden/embedded/stone_n.dds",
         "ormTex": "/maps/golden/embedded/stone_orm.dds", "emissiveTex": "", "uvOffset": [0.0, 0.0], "uvScale": [1.0, 1.0],
         "uvRotation": 0.0, "clearcoat": 0.0, "clearcoatRoughness": 0.0, "windAmount": 0.0},
        {"name": "glass", "baseColor": [0.75, 0.875, 1.0, 0.25], "emissive": [0.0, 0.25, 0.5], "emissiveStrength": 2.0, "metallic": 0.0,
         "roughness": 0.0625, "normalScale": 1.0, "occlusionStrength": 1.0, "alphaMode": 2, "alphaCutoff": 0.5, "flags": 0b00101,
         "baseColorTex": "", "normalTex": "", "ormTex": "", "emissiveTex": "", "uvOffset": [0.5, 0.0], "uvScale": [2.0, 2.0],
         "uvRotation": 0.25, "clearcoat": 1.0, "clearcoatRoughness": 0.125, "windAmount": 0.0}]})
    one = half(1.0)
    for cell in range(3):
        cx, cz = cell % 2, cell // 2
        insts = []
        for k in range(3 + cell):
            ov = [k % 2] if k == 1 else []
            insts.append({"mesh": {"bundle": k % 2, "index": 1 if k % 2 == 0 else 0}, "pos": [8000 * k, 4096 * k, 65535 - 9000 * k],
                          "rot": qrot(0.0, 0.3826834, 0.0, 0.9238795) if k else qrot(0, 0, 0, 1),
                          "scale": [one, one, half(2.0) if k else one],
                          "flags": 0b000011 | (4 if k else 0), "lodBias": 0, "layer": 0, "cullDistance": 100 if k else 0,
                          "lightmap": 1 if (cell == 0 and k == 0) else 0,
                          "lightmapScaleOffset": [half(0.5), half(0.5), half(0.0), half(0.5)],
                          "overrideCount": len(ov), "materialOverride": ov})
        add("INST", {"cellOrigin": [cx * 32.0, 0.0, cz * 32.0], "cellExtent": [32.0, 64.0, 32.0], "insts": insts}, True, inst=cell)
    add("LODG", {"proxies": [{"mesh": {"bundle": 0, "index": 1}, "pos": [16.0, 0.0, 16.0], "rot": [0.0, 0.0, 0.0, 1.0],
                              "scale": [32.0, 1.0, 32.0], "showBeyond": 96.0, "fadeWidth": 8.0, "replacesInstances": [0, 1, 2]}]}, inst=0)
    add("OCCL", {"occluders": [
        {"kind": 0, "center": [16.0, 8.0, 16.0], "halfExtents": [8.0, 8.0, 0.5], "rot": [0.0, 0.0, 0.0, 1.0]},
        {"kind": 1, "mesh": {"bundle": 0, "index": 1}, "pos": [40.0, 0.0, 8.0], "rot": [0.0, 0.0, 0.0, 1.0], "scale": [4.0, 4.0, 4.0]}],
        "rooms": [{"name": "hall", "min": [0.0, 0.0, 0.0], "max": [30.0, 10.0, 30.0]},
                  {"name": "yard", "min": [30.0, 0.0, 0.0], "max": [60.0, 10.0, 30.0]}],
        "portals": [{"quad": [30.0, 0.0, 10.0, 30.0, 0.0, 14.0, 30.0, 4.0, 14.0, 30.0, 4.0, 10.0], "roomA": 0, "roomB": 1, "flags": 1}]})
    add("LMAP", {"width": 8, "height": 8, "format": 1, "kind": 1, "data": rng.bytes(8 * 8 * 4), "dirData": rng.bytes(8 * 8 * 4)}, inst=0)
    add("LMAP", {"width": 4, "height": 4, "format": 2, "kind": 0, "data": rng.bytes(4 * 4 * 8)}, inst=1)
    for cell in range(2):
        add("PRBV", {"gridOrigin": [cell * 32.0, 0.0, 0.0], "gridSpacing": [16.0, 32.0, 16.0], "nx": 2, "ny": 2, "nz": 2,
                     "shData": pack_u16([half(((i + cell) % 11) / 8.0) for i in range(2 * 2 * 2 * 27)])}, inst=cell)
    add("ANIM", {"clips": [{"name": "spin", "duration": 4.0, "loop": 1, "channels": [
        {"instanceCell": 0, "instanceIndex": 1, "target": 1,
         "keys": [{"t": 0.0, "value": [0.0, 0.0, 0.0, 1.0]}, {"t": 2.0, "value": [0.0, 1.0, 0.0, 0.0]},
                  {"t": 4.0, "value": [0.0, 0.0, 0.0, 1.0]}]}]}],
        "players": [{"clip": "spin", "speed": 1.0, "phase": 0.0, "layer": 0, "triggerKind": 0}]})
    add("VOLR", {"volumes": [
        {"kind": 0, "shapeKind": 0, "center": [16.0, 4.0, 16.0], "halfExtents": [16.0, 4.0, 16.0], "rot": [0.0, 0.0, 0.0, 1.0],
         "blendDistance": 4.0, "priority": 0, "layer": 0, "color": [0.5, 0.5, 0.625], "density": 0.0625, "heightFalloff": 0.125},
        {"kind": 1, "shapeKind": 1, "center": [48.0, 4.0, 16.0], "halfExtents": [10.0, 0.0, 0.0], "rot": [0.0, 0.0, 0.0, 1.0],
         "blendDistance": 2.0, "priority": 1, "layer": 0, "exposureEV": -1.0, "saturation": 0.75, "contrast": 1.125,
         "tint": [1.0, 0.875, 0.75]},
        {"kind": 2, "shapeKind": 0, "center": [16.0, 4.0, 48.0], "halfExtents": [16.0, 4.0, 16.0], "rot": [0.0, 0.0, 0.0, 1.0],
         "blendDistance": 0.0, "priority": -1, "layer": 0, "preset": "stone_hall"},
        {"kind": 3, "shapeKind": 0, "center": [48.0, 4.0, 48.0], "halfExtents": [16.0, 4.0, 16.0], "rot": [0.0, 0.0, 0.0, 1.0],
         "blendDistance": 1.0, "priority": 0, "layer": 0, "ambientMul": 0.5, "tint": [0.75, 0.75, 1.0]}]})
    add("SLYR", {"layers": [{"name": "gate_closed", "defaultOn": 1}, {"name": "bridge_up", "defaultOn": 0}]})
    verts = [fxv(0, 0, 0), fxv(8, 0, 0), fxv(8, 0, 8), fxv(0, 2, 8)]
    add("COLL", {
        "tris": [{"vertexCount": 4, "vertices": verts, "indexCount": 6, "indices": [0, 1, 2, 0, 2, 3], "surfaceMode": 1, "surface": 0,
                  "triangleSurfaces": [0, 2], "blocks": 0b0010111, "simLayer": 0}],
        "hulls": [{"vertices": [fxv(x, y, z) for x in (0, 2) for y in (0, 2) for z in (0, 2)], "surface": 2, "blocks": 0b1111,
                   "simLayer": 1}],
        "prims": [
            {"shape": {"kind": 0, "center": fxv(4, 1, 4), "halfExtents": fxv(1, 1, 1), "rot": [0, 0, 0, 32767]}, "surface": 0,
             "blocks": 1, "simLayer": 0},
            {"shape": {"kind": 1, "center": fxv(8, 1, 8), "radius": fx(1.5)}, "surface": 0, "blocks": 3, "simLayer": 0},
            {"shape": {"kind": 2, "vertices": [fxv(0, 0, 0), fxv(1, 0, 0), fxv(0, 1, 0), fxv(0, 0, 1)]}, "surface": 0,
             "blocks": 0b100, "simLayer": 0},
            {"shape": {"kind": 3, "polygon": [[0, 0], [256 * 4, 0], [0, 256 * 4]], "yMin": fx(0), "yMax": fx(3)}, "surface": 0,
             "blocks": 0b1000, "simLayer": 2},
            {"shape": {"kind": 4, "a": fxv(12, 0, 12), "b": fxv(12, 2, 12), "radius": fx(0.5)}, "surface": 0, "blocks": 1,
             "simLayer": 0}]}, True, inst=0)
    add("COLL", {"tris": [], "hulls": [], "prims": [
        {"shape": {"kind": 0, "center": fxv(40, 1, 40), "halfExtents": fxv(2, 1, 2), "rot": [0, 0, 0, 32767]}, "surface": 0,
         "blocks": 1, "simLayer": 0}]}, inst=2)
    add("NAVS", {"surfaces": [
        {"id": 1, "name": "Deck", "kind": 0, "moveMask": 0b0011, "clearance": 65536 * 3, "simLayer": 0, "x0": 0, "z0": 0, "x1": 7,
         "z1": 5, "heights": plane(pack_u16([24000 + 8 * ((x + z) % 3) for z in range(6) for x in range(8)]), 1),
         "walkable": bitmask(8, 6, lambda x, z: not (x == 3 and z == 2))},
        {"id": 2, "name": "Stairs", "kind": 1, "moveMask": 0b1001, "clearance": 0, "simLayer": 2,
         "vertices": [fxv(0, 0, 0), fxv(2, 0, 0), fxv(2, 1, 2), fxv(0, 1, 2)], "indexCount": 6, "indices": [0, 1, 2, 0, 2, 3]}],
        "links": [{"fromSurface": 0, "from": fxv(10, 0, 10), "toSurface": 1, "to": fxv(0, 1, 0), "kind": 0, "moveMask": 0b0011,
                   "cost": 65536, "bidirectional": 1},
                  {"fromSurface": 1, "from": fxv(7, 1, 5), "toSurface": 2, "to": fxv(0, 0, 0), "kind": 4, "moveMask": 0b1000,
                   "cost": 65536 * 2, "bidirectional": 0}]})
    add("VOLS", {"volumes": [
        {"name": "trigger_a", "shape": {"kind": 0, "center": fxv(10, 1, 10), "halfExtents": fxv(2, 2, 2), "rot": [0, 0, 0, 32767]},
         "flags": 0b0011, "army": -1, "tags": ["enter", "exit"]},
        {"name": "no_build", "shape": {"kind": 3, "polygon": [[0, 0], [256 * 6, 0], [256 * 6, 256 * 6]], "yMin": fx(0),
                                       "yMax": fx(10)}, "flags": 0b0100, "army": 0, "tags": []},
        {"name": "ball", "shape": {"kind": 1, "center": fxv(40, 2, 40), "radius": fx(4)}, "flags": 0b1000, "army": 1,
         "tags": ["vision"]}]})
    return out
