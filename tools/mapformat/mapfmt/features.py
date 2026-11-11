"""Feature bits (CONTAINER.md section 4) and the derivation of `requiredFeatures` from chunk content.

Rules of the writer (the spec says "set when ...", this file is the literal reading):
  sim bits (0-9, 32-37) are always REQUIRED when the content needs them: a reader that ignored them would misplay;
  render bits (16-19, 36) are OPTIONAL by default (the map still plays, drawn with the fallback); the caller promotes
  chosen ones with `render_required`.
"""

FEATURES = {
    0: "GRID_NONSQUARE", 1: "GRID_LARGE", 2: "HEIGHT_FINE", 3: "SURFACE_LAYERS", 4: "WATER_BODIES", 5: "LEVELS",
    6: "PLAYABLE_POLYGON", 7: "MARKERS_BINARY", 8: "PROPS_BINARY", 9: "HINTS",
    16: "RENDER_INDEXED_SPLAT", 17: "RENDER_PBR_MATERIALS", 18: "RENDER_VOLUMETRICS", 19: "RENDER_TOD",
    32: "WORLD_CELLS", 33: "WORLD_COLLISION", 34: "WORLD_NAV3D", 35: "WORLD_LARGE_COORDS", 36: "WORLD_LIGHTMAPS",
    37: "WORLD_VOLUMES_SIM", 63: "EXTENDED_FEATURES",
}
BIT = dict((v, k) for k, v in FEATURES.items())
SIM_BITS = sum(1 << b for b in list(range(0, 10)) + list(range(32, 38)))
RENDER_BITS = sum(1 << b for b in (16, 17, 18, 19, 36))
# Everything the reference implements: all named bits except the reserved word-extension bit 63.
SUPPORTED = sum(1 << b for b in FEATURES if b != 63)


def names(mask):
    """Names of the set bits, unknown bits as BIT<n>."""
    return [FEATURES.get(b, "BIT%d" % b) for b in range(64) if mask >> b & 1]


# GPLY mask names with defined sim semantics (EXTENDED.md GPLY); other names are ignored by the sim and need no feature.
SIM_MASKS = ("buildable_override", "walk_land", "walk_hover", "walk_amphib", "air_block", "no_fog", "vision_block",
             "reclaim_ok")


def derive_features(chunks, render_required=0):
    """chunks: {(id, instance): decoded dict}. Returns (requiredFeatures, optionalFeatures)."""
    req = opt = 0

    def ids(i):
        return [d for (cid, _), d in chunks.items() if cid == i]

    g = chunks.get(("GRID", 0))
    if g:
        if g["cellsX"] != g["cellsZ"]:
            req |= 1 << 0
        if g["cellsX"] > 4096 or g["cellsZ"] > 4096:
            req |= 1 << 1
    h = chunks.get(("HGHT", 0))
    if h and h["stepLog2"] < -7:
        req |= 1 << 2
    gp = chunks.get(("GPLY", 0))
    if gp and (any(m["name"] in SIM_MASKS for m in gp["masks"]) or any(s["speedMul"] != 256 for s in gp["surfaces"])):
        req |= 1 << 3
    wb = chunks.get(("WBOD", 0))
    if wb and (len(wb["bodies"]) > 1 or any(b["extentKind"] != 0 or b["kind"] != 0 for b in wb["bodies"])):
        req |= 1 << 4
    lv = chunks.get(("LEVL", 0))
    if lv and lv["decks"]:
        req |= 1 << 5
    pl = chunks.get(("PLAY", 0))
    if pl and pl["polygon"]:
        req |= 1 << 6
    if ("MRKR", 0) in chunks or ("AREA", 0) in chunks:
        req |= 1 << 7
    if ("PROP", 0) in chunks:
        req |= 1 << 8
    if ("HINT", 0) in chunks:
        req |= 1 << 9
    # render features
    if any(d["mode"] == 0 for d in ids("SPLT")):
        opt |= 1 << 16
    ml = chunks.get(("MATL", 0))
    if ml and any(m["orm"] or m["height"] for m in ml["materials"]):
        opt |= 1 << 17
    at = chunks.get(("ATMO", 0))
    if at and (at["cloudMode"] == 2 or at["volumetricFog"]):
        opt |= 1 << 18
    if ("TODK", 0) in chunks:
        opt |= 1 << 19
    # Full3D
    w = chunks.get(("WRLD", 0))
    if w:
        if w["cellsX"] * w["cellsY"] * w["cellsZ"] > 1 or ("CIDX", 0) in chunks:
            req |= 1 << 32
        if w["flags"] & 1:
            req |= 1 << 35
    if ids("COLL"):
        req |= 1 << 33
    if ("NAVS", 0) in chunks:
        req |= 1 << 34
    if ids("LMAP"):
        opt |= 1 << 36
    if ("VOLS", 0) in chunks:
        req |= 1 << 37
    promote = opt & render_required
    return req | promote, (opt & ~promote)
