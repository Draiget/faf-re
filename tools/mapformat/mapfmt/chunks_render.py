"""Extended (container 3): render chunks and the derived-cache chunk (EXTENDED.md). See chunks_sim.py for conventions."""
from .chunkdef import chunk
from .chunks_sim import POSE, SHAPE, bit_set, field_in, grid_dims, kind_in, unique
from .errors import ChunkError
from .schema import (F, Array, BitMask, Blob, Bytes, Plane, RawBytes, Rep, Struct, PATH, STR, color3, enum8, f32, i16, i32,
                     quat, srgb8, u8, u16, u32, u64, vec2, vec3, vec4, Vec)

f32x4 = Vec(4, f32)


def _tex_dims(s):
    w, h = s.cur["width"], s.cur["height"]
    if not (1 <= w <= 16384 and 1 <= h <= 16384):
        raise ChunkError("texture size %dx%d outside 1..16384" % (w, h))
    return w, h


def _blocks(w, h):
    return ((w + 3) // 4) * ((h + 3) // 4)


# --------------------------------------------------------------------------------------------- layers, materials

chunk("LAYR", "R", [
    F("layers", Array(Struct([F("name", STR), F("defaultVisible", u8(0, 1)), F("flags", u8(eq=0))]), 0, 255),
      note="`array<layer>`"),
], what="sublevel layers")

chunk("MATL", "R", [
    F("materials", Array(Struct([
        F("id", u16), F("name", STR), F("albedo", PATH), F("normal", PATH), F("orm", PATH), F("height", PATH),
        F("flags", u16(mask=0x1F)), F("tileSize", f32), F("rotationDeg", f32), F("normalStrength", f32),
        F("roughnessScale", f32), F("metalness", f32), F("parallaxScale", f32), F("heightBlendSharpness", f32),
        F("macroInfluence", f32), F("gameplaySurface", u16),
    ]), 0, 1024), note="`array<material>`"),
], lambda d, s: unique(d["materials"], lambda m: m["id"], "material id"), what="material library")


def _splt_dims(s):
    w, h = s.cur["width"], s.cur["height"]
    if not (1 <= w <= 16384 and 1 <= h <= 16384):
        raise ChunkError("splat size %dx%d outside 1..16384" % (w, h))
    return w, h


def _splt_check(d, s):
    if d["mode"] == 0:
        idx, wts = d["indices"]["data"], d["weights"]["data"]
        for i in range(0, len(wts), 4):
            if wts[i] + wts[i + 1] + wts[i + 2] + wts[i + 3] != 255:
                raise ChunkError("weights of texel %d do not sum to 255" % (i // 4))


chunk("SPLT", "R", [
    F("width", u32), F("height", u32), F("mode", enum8(2)),
    F("indices", Plane(1, _splt_dims, 4), field_in("mode", 0), note="mode 0 first `plane<u8>`: RGBA indices"),
    F("weights", Plane(1, _splt_dims, 4), field_in("mode", 0), note="mode 0 second `plane<u8>`: RGBA weights"),
    F("layers", u8(1, 32), field_in("mode", 1)),
    F("materialIds", Array(u16, 0, 32, expect=lambda s: s.cur["layers"]), field_in("mode", 1)),
    F("planes", Rep(Plane(1, _splt_dims), lambda s: s.cur["layers"]), field_in("mode", 1),
      note="the `layers` x `plane<u8>(width,height)`"),
], _splt_check, what="splat weights")


def _nrml_bytes(s):
    w, h = _tex_dims(s)
    return w * h * 2 if s.cur["format"] == 0 else 16 * _blocks(w, h)


def _aomp_bytes(s):
    w, h = _tex_dims(s)
    return w * h if s.cur["format"] == 0 else 8 * _blocks(w, h)


def _macr_bytes(s):
    w, h = _tex_dims(s)
    return w * h * 3 if s.cur["format"] == 0 else 8 * _blocks(w, h)


chunk("NRML", "R", [
    F("width", u32), F("height", u32), F("format", enum8(2)),
    F("data", RawBytes(_nrml_bytes), note="the bytes (RG8: w*h*2, BC5: 16 per 4x4 block)"),
], what="baked normals")

chunk("AOMP", "R", [
    F("width", u32), F("height", u32), F("kind", enum8(2)), F("format", enum8(2)),
    F("data", RawBytes(_aomp_bytes), note="the bytes (R8: w*h, BC4: 8 per 4x4 block)"),
], what="baked AO / sky visibility")


def _hdet_dims(s):
    m = 1 << s.cur["log2Mult"]
    return s.need("cellsX") * m + 1, s.need("cellsZ") * m + 1


chunk("HDET", "R", [
    F("log2Mult", u8(1, 3)), F("lsb", f32), F("predictor", u8(0, 3)),
    F("samples", Plane(2, _hdet_dims, pred_field="predictor"), note="the `i16` delta samples"),
], what="render-only height detail")

chunk("HOLE", "R", [
    F("mask", BitMask(grid_dims), note="`bitmask(cellsX, cellsZ)`"),
], what="cut-out mask")

chunk("MACR", "R", [
    F("width", u32), F("height", u32), F("format", enum8(2)), F("strength", f32),
    F("data", RawBytes(_macr_bytes),
      note="the bytes (RGB8: w*h*3, BC1: 8 per 4x4 block)"),
], what="macro colour variation")


# --------------------------------------------------------------------------------------------- lighting

chunk("LITE", "R", [
    F("sunDir", vec3), F("sunColor", color3), F("sunIntensity", f32), F("sunAngularDeg", f32),
    F("hasMoon", u8(0, 1)),
    F("moon", Struct([F("dir", vec3), F("color", color3), F("intensity", f32), F("angularDeg", f32)]),
      field_in("hasMoon", 1), note="the moon block after `u8 hasMoon`"),
    F("ambientMode", enum8(3)), F("ambient", color3), F("ground", color3), F("ambientIntensity", f32),
    F("sh", Rep(f32, lambda s: 27), field_in("ambientMode", 2), note="SH2 mode `f32[27]`"),
    F("shadowFill", color3), F("shadowDistance", f32), F("cascades", u8(1, 4)), F("shadowBias", f32),
    F("shadowStrength", f32), F("fogMode", enum8(4)), F("fogColor", color3), F("fogStart", f32), F("fogEnd", f32),
    F("fogDensity", f32), F("fogHeightFalloff", f32), F("fogBaseHeight", f32), F("toneMap", enum8(3)),
    F("exposureEV", f32), F("bloomIntensity", f32), F("bloomThreshold", f32), F("lut", PATH),
], what="global lighting")

chunk("LLGT", "R", [
    F("lights", Array(Struct([
        F("type", enum8(2)), F("pos", vec3), F("dir", vec3), F("color", color3), F("intensity", f32), F("range", f32),
        F("innerDeg", f32), F("outerDeg", f32), F("flags", u8(mask=0xF)), F("flickerAmp", f32), F("flickerHz", f32),
        F("layer", u16),
    ]), 0, 8192), note="`array<light>`"),
], what="local lights")

PROBE_GRID = [
    F("gridOrigin", vec3), F("gridSpacing", vec3), F("nx", u32), F("ny", u32), F("nz", u32),
    F("shData", RawBytes(lambda s: s.cur["nx"] * s.cur["ny"] * s.cur["nz"] * 27 * 2),
      note="`nx*ny*nz*27` binary16 values (raw u16)"),
]


def _probe_grid_check(d, s):
    if d["nx"] * d["ny"] * d["nz"] > (1 << 22):
        raise ChunkError("probe grid has more than 2^22 probes")


chunk("PROB", "R", [
    F("reflProbes", Array(Struct([
        F("pos", vec3), F("halfExtents", vec3), F("blend", f32), F("priority", i16), F("cubemap", PATH),
    ]), 0, 1024), note="`array<reflProbe>`"),
] + PROBE_GRID, _probe_grid_check, what="reflection probes, SH probe grid")


def _todk_check(d, s):
    if not 0.0 <= d["startPhase"] <= 1.0:
        raise ChunkError("startPhase outside 0..1")
    if d["cycleSeconds"] < 0:
        raise ChunkError("cycleSeconds is negative")
    last = -1.0
    for k in d["keys"]:
        if not (0.0 <= k["t"] < 1.0) or k["t"] <= last:
            raise ChunkError("key times must be strictly increasing in [0,1)")
        last = k["t"]


chunk("TODK", "R", [
    F("cycleSeconds", f32), F("startPhase", f32),
    F("keys", Array(Struct([
        F("t", f32), F("sunDir", vec3), F("sunColor", color3), F("sunIntensity", f32), F("ambient", color3),
        F("ground", color3), F("ambientIntensity", f32), F("fogColor", color3), F("fogDensity", f32),
        F("skyTint", color3), F("exposureEV", f32), F("starIntensity", f32),
    ]), 1, 256), note="`array<key>`"),
], _todk_check, what="time-of-day keys")

chunk("ATMO", "R", [
    F("skyModel", enum8(3)), F("cubemap", PATH), F("skyIntensity", f32), F("rotationDeg", f32),
    F("planetRadiusKm", f32, field_in("skyModel", 1)), F("atmosphereHeightKm", f32, field_in("skyModel", 1)),
    F("rayleigh", color3, field_in("skyModel", 1)), F("rayleighScaleHeightKm", f32, field_in("skyModel", 1)),
    F("mie", f32, field_in("skyModel", 1)), F("mieAnisotropy", f32, field_in("skyModel", 1)),
    F("mieScaleHeightKm", f32, field_in("skyModel", 1)), F("ozone", color3, field_in("skyModel", 1)),
    F("groundAlbedo", f32, field_in("skyModel", 1)),
    F("cloudMode", enum8(3)), F("coverage", f32), F("density", f32), F("baseAltitude", f32), F("thickness", f32),
    F("wind", vec2), F("noiseShape", PATH), F("noiseDetail", PATH), F("cloudShadowStrength", f32),
    F("volumetricFog", u8(0, 1)), F("scattering", f32), F("anisotropy", f32), F("extinction", f32),
    F("maxDistance", f32),
    F("celestials", Array(Struct([
        F("texture", PATH), F("dir", vec3), F("sizeDeg", f32), F("tint", color3), F("intensity", f32),
    ]), 0, 16), note="`array<celestial>`"),
    F("starIntensity", f32),
], what="sky, atmosphere, clouds, volumetric fog")


def _wvis_check(d, s):
    unique(d["bodies"], lambda b: b["bodyId"], "bodyId")


chunk("WVIS", "R", [
    F("bodies", Array(Struct([
        F("bodyId", u16), F("shallow", color3), F("deep", color3), F("absorption", color3), F("clarityMeters", f32),
        F("reflection", f32), F("refraction", f32), F("waveModel", enum8(3)),
        F("normalMaps", Array(Struct([F("normalMap", PATH), F("tiling", f32), F("speed", f32), F("dir", vec2)]), 0, 4),
          field_in("waveModel", 0), note="model 0 `array<{path normalMap, ...}>`"),
        F("waves", Array(Struct([F("amplitude", f32), F("wavelength", f32), F("steepness", f32), F("dirDeg", f32),
                                 F("speed", f32)]), 0, 16),
          field_in("waveModel", 1), note="model 1 `array<{f32 amplitude, ...}>`"),
        F("windSpeed", f32, field_in("waveModel", 2)), F("windDirDeg", f32, field_in("waveModel", 2)),
        F("fetchKm", f32, field_in("waveModel", 2)), F("choppiness", f32, field_in("waveModel", 2)),
        F("patchSize", f32, field_in("waveModel", 2)),
        F("foamAmount", f32), F("foamTexture", PATH), F("shoreFoamWidth", f32), F("causticStrength", f32),
        F("causticTexture", PATH), F("flowScale", f32), F("flowMap", u32), F("underwaterFog", color3),
        F("underwaterDensity", f32),
    ]), 0, 256), note="`array<bodyVis>`"),
], _wvis_check, what="water visuals per body")


def _wflw_dims(s):
    w, h = s.cur["width"], s.cur["height"]
    if not (1 <= w <= 16384 and 1 <= h <= 16384):
        raise ChunkError("flow map size %dx%d outside 1..16384" % (w, h))
    return w, h


chunk("WFLW", "R", [
    F("width", u32), F("height", u32), F("maxSpeed", f32),
    F("flow", Plane(1, _wflw_dims, 2), note="`plane<u8 x2>` interleaved (i8 x, i8 z)"),
], instanced=True, what="water flow map")


# --------------------------------------------------------------------------------------------- scatter, splines, decals

SCAT_FLAGS = 0x1F


def _scat_check(d, s):
    for L in d["layers"]:
        if sum(v["weight"] for v in L["variants"]) <= 0 or any(v["weight"] < 0 for v in L["variants"]):
            raise ChunkError("layer %r: variant weights must be >= 0 with a positive sum" % L["name"])
        for v in L["variants"]:
            if v["scaleMax"] < v["scaleMin"]:
                raise ChunkError("layer %r: scaleMax < scaleMin" % L["name"])
        if L["density"] < 0:
            raise ChunkError("layer %r: negative density" % L["name"])
        if L["densityMap"] < -1:
            raise ChunkError("layer %r: densityMap below -1" % L["name"])


chunk("SCAT", "R", [
    F("layers", Array(Struct([
        F("name", STR), F("seed", u64),
        F("variants", Array(Struct([
            F("kind", enum8(3)), F("ref", PATH), F("weight", f32), F("scaleMin", f32), F("scaleMax", f32),
        ]), 1, 64), note="`array<variant>`"),
        F("density", f32), F("minSlopeDeg", f32), F("maxSlopeDeg", f32), F("minAltitude", f32), F("maxAltitude", f32),
        F("allowedMaterials", Array(u16, 0, 64)), F("forbiddenSurfaces", Array(u16, 0, 64)),
        F("densityMap", i32), F("jitter", f32), F("flags", u16(mask=SCAT_FLAGS)), F("cullDistance", f32),
        F("windBend", f32), F("windHz", f32), F("tintVariation", f32), F("layer", u16),
    ]), 0, 256), note="`array<layer>`"),
], _scat_check, what="scatter layers (vegetation, rocks)")


def _scdm_dims(s):
    w, h = s.cur["width"], s.cur["height"]
    if not (1 <= w <= 16384 and 1 <= h <= 16384):
        raise ChunkError("density map size %dx%d outside 1..16384" % (w, h))
    return w, h


chunk("SCDM", "R", [
    F("width", u32), F("height", u32), F("density", Plane(1, _scdm_dims), note="the `plane<u8>`"),
], instanced=True, what="scatter density map")

chunk("SPLN", "R", [
    F("splines", Array(Struct([
        F("kind", enum8(7)), F("name", STR), F("flags", u16(mask=0x1F)),
        F("points", Array(Struct([
            F("pos", vec3), F("tangentIn", vec3), F("tangentOut", vec3), F("width", f32), F("rollDeg", f32),
        ]), 2, 65536), note="`array<point>`"),
        F("decalTexture", PATH), F("mesh", PATH), F("uvTile", f32), F("paintWidth", f32), F("paintMaterial", u16),
        F("writeSurface", u16), F("blendDistance", f32), F("layer", u16),
    ]), 0, 4096), note="`array<spline>`"),
], what="splines (roads, rivers, cliffs, fences)")


def _decl_check(d, s):
    n = len(d["textures"])
    for i, x in enumerate(d["decals"]):
        if x["tex0"] >= n or (x["tex1"] != 0xFFFFFFFF and x["tex1"] >= n):
            raise ChunkError("decal %d uses a texture index outside the %d textures" % (i, n))


chunk("DECL", "R", [
    F("textures", Array(PATH, 0, 65535)),
    F("decals", Array(Struct([
        F("type", enum8(5)), F("tex0", u32), F("tex1", u32), F("pos", vec3), F("rot", quat), F("size", vec3),
        F("lodMin", f32), F("lodMax", f32), F("tint", f32x4), F("fadeDistance", f32), F("order", i16), F("layer", u16),
        F("blend", enum8(3)),
    ]), 0, 1000000), note="`array<decal>`"),
], _decl_check, what="decals")


def _wthr_check(d, s):
    n = len(d["states"])
    if d["defaultState"] >= n:
        raise ChunkError("defaultState %d, only %d states" % (d["defaultState"], n))
    for z in d["zones"]:
        if z["state"] >= n:
            raise ChunkError("zone %r uses state %d, only %d states" % (z["name"], z["state"], n))


chunk("WTHR", "R", [
    F("defaultState", u16),
    F("states", Array(Struct([
        F("name", STR), F("rain", f32), F("snow", f32), F("fogDensityMul", f32), F("cloudCoverageAdd", f32),
        F("windSpeed", f32), F("windDirDeg", f32), F("lightMul", f32), F("wetness", f32),
    ]), 1, 64), note="`array<state>`"),
    F("zones", Array(Struct([
        F("name", STR), F("shape", SHAPE), F("state", u16), F("yMin", f32), F("yMax", f32), F("effect", PATH),
        F("sound", PATH), F("layer", u16),
    ]), 0, 1024), note="`array<zone>`"),
], _wthr_check, what="weather zones and states")

chunk("AUDI", "R", [
    F("ambientBed", STR), F("bedVolume", f32),
    F("zones", Array(Struct([
        F("name", STR), F("shape", SHAPE), F("loop", STR), F("volume", f32), F("fade", f32), F("priority", i16),
        F("reverbPreset", STR),
    ]), 0, 1024), note="`array<zone>`"),
    F("cues", Array(Struct([F("state", STR), F("cue", STR)]), 0, 64), note="`array<cue>`"),
], what="ambient audio, reverb, music cues")

chunk("CAMR", "R", [
    F("defaultPose", POSE), F("minZoom", f32), F("maxZoom", f32), F("pitchMin", f32), F("pitchMax", f32),
    F("bounds", vec4),
    F("bookmarks", Array(Struct([F("name", STR), F("pose", POSE)]), 0, 64), note="`array<bookmark>`"),
    F("paths", Array(Struct([
        F("name", STR), F("duration", f32),
        F("keys", Array(Struct([
            F("t", f32), F("pos", vec3), F("rot", quat), F("fovDeg", f32), F("ease", enum8(2)),
        ]), 2, 4096), note="`array<key>`"),
    ]), 0, 256), note="camera `array<path>`"),
], what="camera defaults, bookmarks, paths")

chunk("MINI", "R", [
    F("kind", enum8(3)),
    F("image", Struct([F("fmt", enum8(2)), F("w", u32), F("h", u32), F("data", Blob("byteCount"))]),
      field_in("kind", 1), note="kind 1 embedded image `{u8 fmt, u32 w, h, byteCount, bytes}`"),
    F("contourInterval", f32),
    F("ramp", Array(Struct([F("height", f32), F("color", srgb8)]), 0, 64), note="the ramp `array<{f32 height, srgb8 color}>`"),
    F("borderColor", srgb8), F("strategicStyle", STR),
], what="strategic / minimap")

chunk("POST", "R", [
    F("flags", u32(mask=1)), F("bloom", f32), F("vignette", f32), F("chromaticAberration", f32), F("filmGrain", f32),
    F("ssaoHint", f32), F("ssrHint", f32), F("dofFocus", f32), F("dofAperture", f32),
], what="post-processing hints")

chunk("DRVD", "D", [
    F("kind", STR), F("inputHash", Bytes(32)), F("data", Blob("byteCount")),
], instanced=True, what="derived caches")
