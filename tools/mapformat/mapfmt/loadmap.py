"""Load and validate a whole map file: container, features, chunk classification, decoding, cross-chunk rules.

This is the "Required behaviour of a reader" of EXTENDED.md plus FULL3D.md section 3, in reference form:
  * unknown optional chunks (or a version newer than known) are skipped and reported, an unknown chunk with the
    REQUIRED flag refuses the map;
  * a container-4 chunk inside a container-3 file counts as unknown;
  * all sim chunks must be present and valid; render / metadata / derived problems are warnings in lenient mode;
  * GRID (and WRLD) are decoded first because other chunks need their sizes.
"""
import hashlib
import struct

from . import chunks as C
from .chunkdef import CHUNKS, ChunkDef
from .container import F_DERIVED, F_SIM, HF_SIGNATURE, REVISION, read_container
from .errors import ChunkError, MapFormatError
from .features import SIM_BITS, SUPPORTED, derive_features, names


class LoadedMap(object):
    def __init__(self, container):
        self.container = container
        self.chunks = {}          # (id, instance) -> decoded dict
        self.skipped = {}         # (id, instance) -> reason
        self.dropped = {}         # (id, instance) -> reason (lenient mode only)
        self.warnings = []
        self.ctx = {}
        self.derived_required = 0
        self.derived_optional = 0


def height_value(v, min_height, step_log2):
    """HGHT formula in binary32: ldexp(float(v), stepLog2) + minHeight (the ldexp is exact, the sum rounded once)."""
    import math
    x = math.ldexp(float(v), step_log2) + min_height
    return struct.unpack("<f", struct.pack("<f", x))[0]


def _classify(e, cont):
    """Return the ChunkDef when this reader decodes the chunk, else None (skipped or refused by the caller)."""
    cd = CHUNKS.get(e.id)
    if cd is None or cd.container_min > cont.container or not 1 <= e.version <= cd.version:
        return None
    return cd


def load_map(data, lenient=False, limits=None):
    cont = read_container(data, limits, lenient)
    if cont.revision < 1:
        raise MapFormatError("BAD_HEADER", "revision 0 does not exist")
    bad = cont.required & ~SUPPORTED
    if bad:
        raise MapFormatError("UNSUPPORTED_FEATURE", "map requires unsupported features: " + ", ".join(names(bad)))
    lm = LoadedMap(cont)

    work = []
    for e in cont.entries:
        key = (e.id, e.instance)
        cd = _classify(e, cont)
        if cd is None:
            if e.required:
                raise MapFormatError("UNKNOWN_REQUIRED_CHUNK", "chunk %s inst=%d ver=%d is required but unknown" %
                                     (e.id, e.instance, e.version))
            lm.skipped[key] = "unknown chunk or version"
            continue
        if bool(e.flags & F_SIM) != (cd.cls == "S") or bool(e.flags & F_DERIVED) != (cd.cls == "D"):
            raise MapFormatError("BAD_CHUNK", "%s: directory class flags do not match the chunk class %s" % (e.id, cd.cls))
        if e.instance and not cd.instanced:
            raise MapFormatError("BAD_CHUNK", "%s: singleton chunk with instance %d" % (e.id, e.instance))
        if e.error is not None:
            if cd.cls == "S" or e.required:
                raise e.error
            lm.dropped[key] = str(e.error)
            lm.warnings.append("%s inst=%d dropped: %s" % (e.id, e.instance, e.error))
            continue
        work.append((e, cd))

    # GRID and WRLD first: they size everything else.
    work.sort(key=lambda t: 0 if t[0].id in ("GRID", "WRLD") else 1)  # stable: directory order inside each group
    for e, cd in work:
        key = (e.id, e.instance)
        lm.ctx = C.context_from(dict((k[0], v) for k, v in lm.chunks.items() if k[1] == 0))
        try:
            lm.chunks[key] = C.decode_chunk(e.id, e.raw, lm.ctx)
        except ChunkError as err:
            if cd.cls == "S" or e.required or not lenient:
                raise
            lm.dropped[key] = str(err)
            lm.warnings.append("%s inst=%d dropped: %s" % (e.id, e.instance, err))
    lm.ctx = C.context_from(dict((k[0], v) for k, v in lm.chunks.items() if k[1] == 0))

    required_ids = list(C.EXTENDED_REQUIRED) + (["WRLD"] if cont.container == 4 else [])
    for cid in required_ids:
        if (cid, 0) not in lm.chunks:
            if cid == "META":
                lm.warnings.append("META is missing")      # "Missing META ... never refuse" (reader behaviour 1)
            else:
                raise MapFormatError("MISSING_CHUNK", "required chunk %s is missing" % cid)
    cross_check(lm, lenient)
    sig_flag = bool(cont.flags & HF_SIGNATURE)
    if sig_flag != (("SIGN", 0) in lm.chunks):
        lm.warnings.append("header signature flag disagrees with the presence of SIGN")
    lm.derived_required, lm.derived_optional = derive_features(lm.chunks)
    missing = lm.derived_required & SIM_BITS & ~cont.required
    if missing:
        raise MapFormatError("CROSS_CHUNK", "content needs features not in requiredFeatures: " + ", ".join(names(missing)))
    return lm


def _fail(msg):
    raise MapFormatError("CROSS_CHUNK", msg)


def _meshref_check(lm, what, ref):
    mb = lm.chunks.get(("MSHB", ref["bundle"]))
    if mb is None or ref["index"] >= len(mb["meshes"]):
        _fail("%s uses mesh (%d, %d) which does not exist" % (what, ref["bundle"], ref["index"]))


def cross_check(lm, lenient=False):
    """Rules that span chunks (the sizes and ids against GRID / GPLY were already enforced while decoding)."""
    ch = lm.chunks
    g, h = ch.get(("GRID", 0)), ch.get(("HGHT", 0))
    if g and h:
        samples = h["samples"]
        vals = struct.unpack("<%dH" % (len(samples) // 2), samples)
        lo, hi = height_value(min(vals), h["minHeight"], h["stepLog2"]), height_value(max(vals), h["minHeight"], h["stepLog2"])
        if g["minElevation"] > lo or g["maxElevation"] < hi:
            _fail("GRID min/max elevation [%r, %r] does not bound the heights [%r, %r]" %
                  (g["minElevation"], g["maxElevation"], lo, hi))
    gp, wb, ml = ch.get(("GPLY", 0)), ch.get(("WBOD", 0)), ch.get(("MATL", 0))
    surface_ids = set(s["id"] for s in gp["surfaces"]) if gp else set()
    if ml and gp:
        for m in ml["materials"]:
            if m["gameplaySurface"] != 0xFFFF and m["gameplaySurface"] not in surface_ids:
                _fail("material %d links to unknown gameplay surface %d" % (m["id"], m["gameplaySurface"]))
    mat_ids = set(m["id"] for m in ml["materials"]) if ml else None
    for key, d in ch.items():
        cid, inst = key
        if cid == "SPLT" and d["mode"] == 1 and mat_ids is not None:
            for mid in d["materialIds"]:
                if mid not in mat_ids:
                    _fail("SPLT inst=%d uses unknown material %d" % (inst, mid))
        if cid == "SCAT":
            for L in d["layers"]:
                if L["densityMap"] >= 0 and ("SCDM", L["densityMap"]) not in ch:
                    _fail("SCAT layer %r uses missing SCDM instance %d" % (L["name"], L["densityMap"]))
        if cid == "WVIS":
            body_ids = set(b["id"] for b in wb["bodies"]) if wb else set()
            for b in d["bodies"]:
                if b["bodyId"] != 0xFFFF and b["bodyId"] not in body_ids:
                    _fail("WVIS refers to unknown water body %d" % b["bodyId"])
                if b["flowMap"] != 0xFFFFFFFF and ("WFLW", b["flowMap"]) not in ch:
                    _fail("WVIS refers to missing WFLW instance %d" % b["flowMap"])
    hn = ch.get(("HINT", 0))
    if hn:
        nmark = len(ch[("MRKR", 0)]["markers"]) if ("MRKR", 0) in ch else 0
        for i, c in enumerate(hn["candidates"]):
            if any(m >= nmark for m in c["markerIds"]):
                _fail("HINT candidate %d refers to a marker outside MRKR (%d markers)" % (i, nmark))
    # Full3D
    world = ch.get(("WRLD", 0))
    if world:
        n = lm.ctx["worldCells"]
        for (cid, inst) in ch:
            if cid in ("INST", "LODG", "PRBV", "COLL") and inst >= n:
                _fail("%s instance %d is not a cell of the %d cell world" % (cid, inst, n))
        sl = ch.get(("SLYR", 0))
        nlayers = len(sl["layers"]) if sl else 0
        for (cid, inst), d in ch.items():
            if cid == "MSHB":
                for m in d["meshes"]:
                    if m["format"] == 1:
                        C.decode_native_mesh(m["data"])
            if cid == "INST":
                for i in d["insts"]:
                    _meshref_check(lm, "INST inst=%d" % inst, i["mesh"])
                    if i["lightmap"] and ("LMAP", i["lightmap"] - 1) not in ch:
                        _fail("INST uses missing lightmap atlas %d" % (i["lightmap"] - 1))
                    if i["overrideCount"]:
                        mb = ch.get(("MATB", 0))
                        if mb is None or any(o >= len(mb["materials"]) for o in i["materialOverride"]):
                            _fail("INST material override outside MATB")
            if cid == "LODG":
                for p in d["proxies"]:
                    _meshref_check(lm, "LODG inst=%d" % inst, p["mesh"])
            if cid == "OCCL":
                for o in d["occluders"]:
                    if o["kind"] == 1:
                        _meshref_check(lm, "OCCL", o["mesh"])
                nrooms = len(d["rooms"])
                for p in d["portals"]:
                    if p["roomA"] >= nrooms or p["roomB"] >= nrooms:
                        _fail("OCCL portal refers to a missing room")
            if cid == "COLL":
                sims = [t["simLayer"] for t in d["tris"]] + [t["simLayer"] for t in d["hulls"]] + [t["simLayer"] for t in d["prims"]]
                if any(s > nlayers for s in sims):
                    _fail("COLL inst=%d uses a sim layer beyond SLYR" % inst)
            if cid == "NAVS":
                if any(s["simLayer"] > nlayers for s in d["surfaces"]):
                    _fail("NAVS uses a sim layer beyond SLYR")
    # embedded assets: the bundles together stay below 1 GiB (CONTAINER.md section 7)
    if sum(len(a["data"]) for (cid, _), d in ch.items() if cid == "ASST" for a in d["assets"]) > (1 << 30):
        _fail("embedded assets exceed 1 GiB")
    # large coordinates: WRLD.flags bit0 must say so when the origin is not zero or the bounds exceed 2^20
    if world:
        far = any(world[k] != 0.0 for k in ("originX", "originY", "originZ")) or             any(abs(v) > (1 << 20) for v in world["boundsMin"] + world["boundsMax"])
        if far and not world["flags"] & 1:
            _fail("WRLD has a non-zero origin or huge bounds but not the LARGE_COORDS flag")
    # derived caches: a mismatch is never an error (the cache is ignored)
    for (cid, inst), d in ch.items():
        if cid == "DRVD" and d["kind"] == "minmax_mips":
            hg = lm.container.find("HGHT")
            if hg is not None and hashlib.sha256(hg.raw).digest() != d["inputHash"]:
                lm.warnings.append("DRVD inst=%d minmax_mips is stale (inputHash mismatch): ignored" % inst)
            elif g and len(d["data"]) != minmax_mips_size(g["cellsX"], g["cellsZ"]):
                lm.warnings.append("DRVD inst=%d minmax_mips has the wrong size: ignored" % inst)


def minmax_mips_size(cells_x, cells_z):
    """Bytes of the minmax_mips payload: levels 1.. until one block covers the grid, 4 bytes (u16 min, u16 max) a block."""
    total, k = 0, 1
    while True:
        bx, bz = (cells_x + (1 << k) - 1) >> k, (cells_z + (1 << k) - 1) >> k
        total += bx * bz * 4
        if bx == 1 and bz == 1:
            return total
        k += 1
