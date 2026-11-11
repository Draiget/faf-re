// Extended map format (container 3, revision 1): METADATA and RENDER chunks (docs/mapformat/EXTENDED.md).
// META PREV GENR SIGN ASST LAYR MATL SPLT NRML AOMP HDET HOLE MACR LITE LLGT PROB TODK ATMO WVIS WFLW SCAT SCDM SPLN
// DECL WTHR AUDI CAMR MINI POST DRVD. None of these is read by the sim, so a bad one only costs the chunk (lenient
// readers drop it); the decoders are still strict: every count is checked against the remaining bytes and the
// per-chunk maximum of the spec before anything is allocated, and a payload must be consumed exactly.
//
// Conventions of this file
//  * `Blob` is a VIEW into the payload that was passed to Decode*: it is valid only while that buffer lives.
//    Decoded planes (predictor reversed) are owned `std::vector<std::uint8_t>` of little-endian elements.
//  * Arrays whose element has no name in the spec are named after the element type in the spec (`loc`, `req`,
//    `asset`, `light`, `layer`, `key`, ...); unnamed scalars get the short names listed in the dumper comments.
//  * Unknown enum values are errors (the chunks are optional, so the reader drops the chunk, never the map).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "moho/sim/mapformat/MapFormatCommon.h"

namespace moho::mapformat {

using Vec2 = std::array<float, 2>;
using Vec3 = std::array<float, 3>;
using Vec4 = std::array<float, 4>; // also quat (x y z w as stored)

/// Byte view into the chunk payload (no copy).
struct Blob
{
  const std::uint8_t* data = nullptr;
  std::uint64_t size = 0;
};

/// `shape` of EXTENDED.md: kind 0 rect (x0 z0 x1 z1), 1 polygon (3..1024 vec2), 2 circle (cx cz r).
struct Shape
{
  std::uint8_t kind = 0;
  Vec4 rect{};
  std::vector<Vec2> points;
  Vec3 circle{};
};

/// `pose` = vec3 pos, yawDeg, pitchDeg, fovDeg.
struct Pose
{
  Vec3 pos{};
  float yawDeg = 0, pitchDeg = 0, fovDeg = 0;
};

// ---------------------------------------------------------------------------------------------------- metadata

struct MetaLoc { std::string lang, name, description; };
struct MetaReq { std::string kind, id, minVersion; };
struct MetaChunk
{
  std::string name;
  std::vector<MetaLoc> loc;
  std::string author, version, license, website;
  std::vector<std::string> tags;
  std::uint8_t mapType = 0, minPlayers = 0, maxPlayers = 0;
  std::vector<MetaReq> req;
  std::uint64_t createdUtc = 0, modifiedUtc = 0;
  std::string toolName, toolVersion;
};

/// PREV: kind 0 PNG, 1 DDS. `data` is `byteCount` bytes.
struct PrevChunk
{
  std::uint8_t kind = 0;
  std::uint32_t width = 0, height = 0, byteCount = 0;
  Blob data;
};

struct GenrNote { std::string key, value; };
struct GenrChunk
{
  std::string generator, generatorVersion;
  std::uint64_t seed = 0;
  std::uint32_t jsonLen = 0;
  Blob json;
  std::vector<GenrNote> notes;
};

struct SignChunk
{
  std::uint8_t algo = 0;
  std::array<std::uint8_t, 32> publicKey{};
  std::array<std::uint8_t, 64> signature{};
  std::string keyName;
};

struct AsstAsset
{
  std::string name;
  std::uint8_t kind = 0; // 0 DDS, 1 PNG, 2 TGA, 3 SCM, 4 SCA, 5 JSON data
  std::uint64_t size = 0;
  Blob data;
};
struct AsstChunk { std::vector<AsstAsset> asset; };

// ---------------------------------------------------------------------------------------------------- render

struct LayrLayer { std::string name; std::uint8_t defaultVisible = 0, flags = 0; };
struct LayrChunk { std::vector<LayrLayer> layer; };

struct MatlMaterial
{
  std::uint16_t id = 0;
  std::string name, albedo, normal, orm, height;
  std::uint16_t flags = 0;
  float tileSize = 0, rotationDeg = 0, normalStrength = 0, roughnessScale = 0, metalness = 0, parallaxScale = 0,
        heightBlendSharpness = 0, macroInfluence = 0;
  std::uint16_t gameplaySurface = 0xFFFF;
};
struct MatlChunk { std::vector<MatlMaterial> material; };

/// SPLT. mode 0: `indices` / `weights` are width*height*4 decoded bytes (RGBA interleaved). mode 1: `planes[i]` is
/// width*height decoded bytes of layer i.
struct SpltChunk
{
  std::uint32_t width = 0, height = 0;
  std::uint8_t mode = 0;
  std::vector<std::uint8_t> indices, weights;
  std::uint8_t layers = 0;
  std::vector<std::uint16_t> materialIds;
  std::vector<std::vector<std::uint8_t>> planes;
};

/// NRML: format 0 RG8 (w*h*2 bytes), 1 BC5 (16 bytes per 4x4 block). Single mip level.
struct NrmlChunk
{
  std::uint32_t width = 0, height = 0;
  std::uint8_t format = 0;
  Blob data;
};

/// AOMP: kind 0 ambient occlusion, 1 sky visibility; format 0 R8 (w*h), 1 BC4 (8 bytes per block).
struct AompChunk
{
  std::uint32_t width = 0, height = 0;
  std::uint8_t kind = 0, format = 0;
  Blob data;
};

/// HDET: `samples` = decoded i16 little-endian, `width` x `height` = (cellsX*m+1) x (cellsZ*m+1), m = 2^log2Mult.
struct HdetChunk
{
  std::uint8_t log2Mult = 0;
  float lsb = 0;
  std::uint8_t predictor = 0;
  std::uint32_t width = 0, height = 0;
  std::vector<std::uint8_t> samples;
};

/// HOLE: bitmask(cellsX, cellsZ) as stored (LSB first).
struct HoleChunk { Blob mask; };

/// MACR: format 0 RGB8 (w*h*3), 1 BC1 (8 bytes per 4x4 block).
struct MacrChunk
{
  std::uint32_t width = 0, height = 0;
  std::uint8_t format = 0;
  float strength = 0;
  Blob data;
};

struct LiteMoon { Vec3 dir{}, color{}; float intensity = 0, angularDeg = 0; };
struct LiteChunk
{
  Vec3 sunDir{}, sunColor{};
  float sunIntensity = 0, sunAngularDeg = 0;
  std::uint8_t hasMoon = 0;
  LiteMoon moon;
  std::uint8_t ambientMode = 0; // 0 flat, 1 hemisphere, 2 SH2
  Vec3 ambient{}, ground{};
  float ambientIntensity = 0;
  std::array<float, 27> sh{}; // only ambientMode == 2
  Vec3 shadowFill{};
  float shadowDistance = 0;
  std::uint8_t cascades = 1;
  float shadowBias = 0, shadowStrength = 0;
  std::uint8_t fogMode = 0;
  Vec3 fogColor{};
  float fogStart = 0, fogEnd = 0, fogDensity = 0, fogHeightFalloff = 0, fogBaseHeight = 0;
  std::uint8_t toneMap = 0;
  float exposureEV = 0, bloomIntensity = 0, bloomThreshold = 0;
  std::string lut;
};

struct LlgtLight
{
  std::uint8_t type = 0; // 0 point, 1 spot
  Vec3 pos{}, dir{}, color{};
  float intensity = 0, range = 0, innerDeg = 0, outerDeg = 0;
  std::uint8_t flags = 0;
  float flickerAmp = 0, flickerHz = 0;
  std::uint16_t layer = 0;
};
struct LlgtChunk { std::vector<LlgtLight> light; };

struct ProbReflProbe
{
  Vec3 pos{}, halfExtents{};
  float blend = 0;
  std::int16_t priority = 0;
  std::string cubemap;
};
/// PROB. `shData` = nx*ny*nz*27 raw binary16 values (view).
struct ProbChunk
{
  std::vector<ProbReflProbe> reflProbe;
  Vec3 gridOrigin{}, gridSpacing{};
  std::uint32_t nx = 0, ny = 0, nz = 0;
  Blob shData;
};

struct TodkKey
{
  float t = 0;
  Vec3 sunDir{}, sunColor{};
  float sunIntensity = 0;
  Vec3 ambient{}, ground{};
  float ambientIntensity = 0;
  Vec3 fogColor{};
  float fogDensity = 0;
  Vec3 skyTint{};
  float exposureEV = 0, starIntensity = 0;
};
struct TodkChunk
{
  float cycleSeconds = 0, startPhase = 0;
  std::vector<TodkKey> key;
};

struct AtmoCelestial
{
  std::string texture;
  Vec3 dir{};
  float sizeDeg = 0;
  Vec3 tint{};
  float intensity = 0;
};
struct AtmoChunk
{
  std::uint8_t skyModel = 0; // 0 cube map, 1 procedural, 2 HDRI
  std::string cubemap;
  float skyIntensity = 0, rotationDeg = 0;
  // present only when skyModel == 1
  float planetRadiusKm = 0, atmosphereHeightKm = 0;
  Vec3 rayleigh{};
  float rayleighScaleHeightKm = 0, mie = 0, mieAnisotropy = 0, mieScaleHeightKm = 0;
  Vec3 ozone{};
  float groundAlbedo = 0;
  std::uint8_t cloudMode = 0; // 0 none, 1 layered textures, 2 volumetric
  float coverage = 0, density = 0, baseAltitude = 0, thickness = 0;
  Vec2 wind{};
  std::string noiseShape, noiseDetail;
  float cloudShadowStrength = 0;
  std::uint8_t volumetricFog = 0;
  float scattering = 0, anisotropy = 0, extinction = 0, maxDistance = 0;
  std::vector<AtmoCelestial> celestial;
  float starIntensity = 0;
};

struct WvisNormalMap { std::string normalMap; float tiling = 0, speed = 0; Vec2 dir{}; };
struct WvisWave { float amplitude = 0, wavelength = 0, steepness = 0, dirDeg = 0, speed = 0; };
struct WvisBodyVis
{
  std::uint16_t bodyId = 0xFFFF;
  Vec3 shallow{}, deep{}, absorption{};
  float clarityMeters = 0, reflection = 0, refraction = 0;
  std::uint8_t waveModel = 0; // 0 stock normal maps, 1 Gerstner, 2 FFT
  std::vector<WvisNormalMap> normalMaps; // model 0 (<=4)
  std::vector<WvisWave> waves;           // model 1 (<=16)
  float windSpeed = 0, windDirDeg = 0, fetchKm = 0, choppiness = 0, patchSize = 0; // model 2
  float foamAmount = 0;
  std::string foamTexture;
  float shoreFoamWidth = 0, causticStrength = 0;
  std::string causticTexture;
  float flowScale = 0;
  std::uint32_t flowMap = 0xFFFFFFFFu;
  Vec3 underwaterFog{};
  float underwaterDensity = 0;
};
struct WvisChunk { std::vector<WvisBodyVis> bodyVis; };

/// WFLW: `plane` = width*height*2 decoded bytes (i8 x, i8 z interleaved).
struct WflwChunk
{
  std::uint32_t width = 0, height = 0;
  float maxSpeed = 0;
  std::vector<std::uint8_t> plane;
};

// SCAT (placement of these layers: Scatter.h).
struct ScatterVariant
{
  std::uint8_t kind = 0; // 0 prop blueprint, 1 mesh path, 2 billboard texture
  std::string ref;
  float weight = 0, scaleMin = 1, scaleMax = 1;
};
namespace ScatterFlags {
constexpr std::uint16_t AlignToNormal = 1, RandomYaw = 2, CastShadow = 4, Wind = 8, AvoidStructures = 16;
}
struct ScatterLayer
{
  std::string name;
  std::uint64_t seed = 0;
  std::vector<ScatterVariant> variant;
  float density = 0; // instances per 1024 square world units
  float minSlopeDeg = 0, maxSlopeDeg = 90, minAltitude = -1e30f, maxAltitude = 1e30f;
  std::vector<std::uint16_t> allowedMaterials, forbiddenSurfaces;
  std::int32_t densityMap = -1;
  float jitter = 0;
  std::uint16_t flags = 0;
  float cullDistance = 0, windBend = 0, windHz = 0, tintVariation = 0;
  std::uint16_t layer = 0;
};
struct ScatChunk { std::vector<ScatterLayer> layer; };

/// SCDM: `plane` = width*height decoded bytes.
struct ScdmChunk
{
  std::uint32_t width = 0, height = 0;
  std::vector<std::uint8_t> plane;
};

struct SplnPoint { Vec3 pos{}, tangentIn{}, tangentOut{}; float width = 0, rollDeg = 0; };
struct SplnSpline
{
  std::uint8_t kind = 0;
  std::string name;
  std::uint16_t flags = 0;
  std::vector<SplnPoint> point;
  std::string decalTexture, mesh;
  float uvTile = 0, paintWidth = 0;
  std::uint16_t paintMaterial = 0, writeSurface = 0;
  float blendDistance = 0;
  std::uint16_t layer = 0;
};
struct SplnChunk { std::vector<SplnSpline> spline; };

struct DeclDecal
{
  std::uint8_t type = 0;
  std::uint32_t tex0 = 0, tex1 = 0xFFFFFFFFu;
  Vec3 pos{};
  Vec4 rot{};
  Vec3 size{};
  float lodMin = 0, lodMax = 0;
  Vec4 tint{};
  float fadeDistance = 0;
  std::int16_t order = 0;
  std::uint16_t layer = 0;
  std::uint8_t blend = 0;
};
struct DeclChunk
{
  std::vector<std::string> textures;
  std::vector<DeclDecal> decal;
};

struct WthrState
{
  std::string name;
  float rain = 0, snow = 0, fogDensityMul = 0, cloudCoverageAdd = 0, windSpeed = 0, windDirDeg = 0, lightMul = 0,
        wetness = 0;
};
struct WthrZone
{
  std::string name;
  Shape shape;
  std::uint16_t state = 0;
  float yMin = 0, yMax = 0;
  std::string effect, sound;
  std::uint16_t layer = 0;
};
struct WthrChunk
{
  std::uint16_t defaultState = 0;
  std::vector<WthrState> state;
  std::vector<WthrZone> zone;
};

struct AudiZone
{
  std::string name;
  Shape shape;
  std::string loop;
  float volume = 0, fade = 0;
  std::int16_t priority = 0;
  std::string reverbPreset;
};
struct AudiCue { std::string state, cue; };
struct AudiChunk
{
  std::string ambientBed;
  float bedVolume = 0;
  std::vector<AudiZone> zone;
  std::vector<AudiCue> cue;
};

struct CamrBookmark { std::string name; Pose pose; };
struct CamrKey
{
  float t = 0;
  Vec3 pos{};
  Vec4 rot{};
  float fovDeg = 0;
  std::uint8_t ease = 0;
};
struct CamrPath
{
  std::string name;
  float duration = 0;
  std::vector<CamrKey> key;
};
struct CamrChunk
{
  Pose defaultPose;
  float minZoom = 0, maxZoom = 0, pitchMin = 0, pitchMax = 0;
  Vec4 bounds{};
  std::vector<CamrBookmark> bookmark;
  std::vector<CamrPath> path;
};

struct MiniRamp { float height = 0; std::array<std::uint8_t, 3> color{}; };
struct MiniChunk
{
  std::uint8_t kind = 0; // 0 none, 1 embedded image, 2 generated
  std::uint8_t imgFmt = 0; // kind 1: 0 PNG, 1 DDS
  std::uint32_t imgWidth = 0, imgHeight = 0, imgByteCount = 0;
  Blob imgData;
  float contourInterval = 0;
  std::vector<MiniRamp> ramp;
  std::array<std::uint8_t, 3> borderColor{};
  std::string strategicStyle;
};

struct PostChunk
{
  std::uint32_t flags = 0;
  float bloom = 0, vignette = 0, chromaticAberration = 0, filmGrain = 0, ssaoHint = 0, ssrHint = 0, dofFocus = 0,
        dofAperture = 0;
};

struct DrvdChunk
{
  std::string kind;
  std::array<std::uint8_t, 32> inputHash{};
  std::uint32_t byteCount = 0;
  Blob data;
};

// ---------------------------------------------------------------------------------------------------- API
// Decode*: strict. `ctx.cellsX/cellsZ` must be non-zero for HDET and HOLE (error otherwise). On failure `err` is
// "ID: reason" and `out` is unspecified. Dump*: appends `ID.field = value` lines (see file comment).

#define MF_RENDER_CHUNK_API(Name)                                                                                   \
  bool Decode##Name(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, Name##Chunk& out, std::string& err);       \
  void Dump##Name(TextDump& dump, const Name##Chunk& c);

MF_RENDER_CHUNK_API(Meta)
MF_RENDER_CHUNK_API(Prev)
MF_RENDER_CHUNK_API(Genr)
MF_RENDER_CHUNK_API(Sign)
MF_RENDER_CHUNK_API(Asst)
MF_RENDER_CHUNK_API(Layr)
MF_RENDER_CHUNK_API(Matl)
MF_RENDER_CHUNK_API(Splt)
MF_RENDER_CHUNK_API(Nrml)
MF_RENDER_CHUNK_API(Aomp)
MF_RENDER_CHUNK_API(Hdet)
MF_RENDER_CHUNK_API(Hole)
MF_RENDER_CHUNK_API(Macr)
MF_RENDER_CHUNK_API(Lite)
MF_RENDER_CHUNK_API(Llgt)
MF_RENDER_CHUNK_API(Prob)
MF_RENDER_CHUNK_API(Todk)
MF_RENDER_CHUNK_API(Atmo)
MF_RENDER_CHUNK_API(Wvis)
MF_RENDER_CHUNK_API(Wflw)
MF_RENDER_CHUNK_API(Scat)
MF_RENDER_CHUNK_API(Scdm)
MF_RENDER_CHUNK_API(Spln)
MF_RENDER_CHUNK_API(Decl)
MF_RENDER_CHUNK_API(Wthr)
MF_RENDER_CHUNK_API(Audi)
MF_RENDER_CHUNK_API(Camr)
MF_RENDER_CHUNK_API(Mini)
MF_RENDER_CHUNK_API(Post)
MF_RENDER_CHUNK_API(Drvd)

#undef MF_RENDER_CHUNK_API

/// True for the 30 chunk ids of this family.
bool IsRenderChunkId(const std::string& id);

/// Family entry point: decodes the chunk `id` (version must be 1) and appends its dump lines to `dump`.
/// NotMine for ids outside the family; Error (with `err`) for an unsupported version or a malformed payload.
DecodeStatus DumpChunkRender(const std::string& id, std::uint16_t version, const std::uint8_t* data, std::size_t size,
                             ChunkCtx& ctx, TextDump& dump, std::string& err);

} // namespace moho::mapformat
