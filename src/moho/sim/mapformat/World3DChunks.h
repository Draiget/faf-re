// Decoders and text dumpers for the Full3D RENDER chunks (docs/mapformat/FULL3D.md section 2):
//   CIDX MSHB MATB INST LODG OCCL LMAP PRBV ANIM VOLR
// (the sim chunks WRLD SLYR COLL NAVS VOLS are the sim family's: SimChunks.h).
//
// Every `DecodeXxx` is strict (the payload must be consumed exactly), bounds-checked, allocates nothing from a count
// without checking it against the remaining bytes, and returns false with `err` set ("XXXX: why") on any problem.
// Structs that point into the payload (`ByteSpan`) are valid only while the payload buffer lives.
// Dump rule (CONTAINER.md section 8): lines are `ID.field = value`, field names are the spec's camelCase names, arrays are
// `ID.name.count = N` then `ID.name[i].field`; the array name is the plural of the spec's element name.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "moho/sim/mapformat/MapFormatCommon.h"

namespace moho::mapformat {

/// Non-owning view of bytes inside the decoded chunk payload.
struct ByteSpan
{
  const std::uint8_t* data = nullptr;
  std::size_t size = 0;
};

/// Counts the spec states (FULL3D.md section 2), as limits of the decoders.
namespace world3d {
constexpr std::uint32_t kMaxCells = 1U << 22; ///< WRLD: cells product <= 2^22
constexpr std::uint32_t kMaxMeshes = 65535;
constexpr std::uint32_t kMaxMaterials = 4096;
constexpr std::uint32_t kMaxInstances = 1000000;
constexpr std::uint32_t kMaxProxies = 65535;
constexpr std::uint32_t kMaxReplaced = 65535;
constexpr std::uint32_t kMaxOccluders = 4096;
constexpr std::uint32_t kMaxRooms = 1024;
constexpr std::uint32_t kMaxPortals = 4096;
constexpr std::uint32_t kMaxClips = 1024;
constexpr std::uint32_t kMaxChannels = 65535;
constexpr std::uint32_t kMaxKeys = 65535;
constexpr std::uint32_t kMaxPlayers = 4096;
constexpr std::uint32_t kMaxVolumes = 4096;
constexpr std::uint32_t kMaxAttributes = 8;
constexpr std::uint32_t kMaxSubmeshes = 256;
constexpr std::uint32_t kMaxLods = 8;
constexpr std::uint32_t kMaxMaterialOverrides = 8;
constexpr std::uint32_t kMaxProbeCells = 1U << 22; ///< PRBV: nx*ny*nz <= 2^22
constexpr std::uint32_t kMaxLightmapDim = 16384;   ///< not in the spec: a sanity cap (largest D3D11 texture)
} // namespace world3d

struct MeshRef
{
  std::uint16_t bundle = 0; ///< MSHB instance
  std::uint16_t index = 0;  ///< entry inside that bundle
};

// ---- CIDX v1 ----
struct CidxCell
{
  float min[3] = {0, 0, 0}, max[3] = {0, 0, 0};
  float loadDistance = 0, unloadDistance = 0;
  std::uint8_t priority = 0;
  std::uint8_t flags = 0; ///< bit0 ALWAYS_LOADED, bit1 HAS_INST, bit2 HAS_COLL, bit3 HAS_LODG, bit4 HAS_PRBV
  std::uint16_t layer = 0;
};
struct Cidx
{
  std::vector<CidxCell> cells;
};

// ---- MSHB v1 (instance = bundle) ----
struct MshbAttribute
{
  std::uint8_t semantic = 0;  ///< 0 position, 1 normal, 2 tangent, 3 uv0, 4 uv1/lightmap, 5 color, 6 joints, 7 weights
  std::uint8_t component = 0; ///< 0 f32, 1 f16, 2 snorm16, 3 unorm8, 4 snorm8, 5 u8, 6 u16, 7 unorm16
  std::uint8_t count = 0;     ///< 1..4
};
struct MshbSubmesh
{
  std::uint32_t firstIndex = 0, indexCount = 0;
  std::uint16_t materialSlot = 0;
};
struct MshbLod
{
  float screenSize = 0;
  std::uint32_t firstSubmesh = 0, submeshCount = 0;
};
/// Contents of a format 1 mesh (the `bytes` of the entry).
struct MshbNative
{
  std::uint32_t vertexCount = 0, indexCount = 0;
  std::uint8_t indexWidth = 2; ///< 2 or 4
  std::vector<MshbAttribute> attributes;
  std::uint32_t stride = 0; ///< bytes per vertex: each attribute rounded up to 4 bytes
  ByteSpan vertexData;      ///< vertexCount * stride
  ByteSpan indexData;       ///< indexCount * indexWidth
  std::vector<MshbSubmesh> submeshes;
  std::vector<MshbLod> lods;
};
struct MshbMesh
{
  std::string name;
  std::uint8_t format = 0; ///< 0 = glTF 2.0 .glb (opaque here: the mesh loader validates it), 1 = native
  float aabb[6] = {0, 0, 0, 0, 0, 0};
  std::uint32_t byteCount = 0;
  ByteSpan bytes;
  MshbNative native; ///< filled when format == 1
};
struct Mshb
{
  std::vector<MshbMesh> meshes;
};

// ---- MATB v1 ----
struct MatbMaterial
{
  std::string name;
  float baseColor[4] = {1, 1, 1, 1};
  float emissive[3] = {0, 0, 0};
  float emissiveStrength = 1;
  float metallic = 0, roughness = 1, normalScale = 1, occlusionStrength = 1;
  std::uint8_t alphaMode = 0; ///< 0 opaque, 1 mask, 2 blend
  float alphaCutoff = 0.5f;
  std::uint16_t flags = 0; ///< bit0 DOUBLE_SIDED, bit1 UNLIT, bit2 CLEARCOAT, bit3 WIND_SWAY, bit4 CAST_SHADOW_OFF
  std::string baseColorTex, normalTex, ormTex, emissiveTex;
  float uvOffset[2] = {0, 0}, uvScale[2] = {1, 1};
  float uvRotation = 0;
  float clearcoat = 0, clearcoatRoughness = 0;
  float windAmount = 0;
};
struct Matb
{
  std::vector<MatbMaterial> materials;
};

// ---- INST v1 (instance = cell) ----
struct InstInstance
{
  MeshRef mesh;
  std::uint16_t pos[3] = {0, 0, 0}; ///< qpos: 0..65535 spans the cell
  std::uint32_t rot = 0;            ///< qrot: smallest-three, raw
  std::uint16_t scale[3] = {0, 0, 0};  ///< raw binary16
  std::uint32_t flags = 0;             ///< bit0 STATIC, bit1 CAST_SHADOW, bit2 RECEIVE_SHADOW, bit3 CONTRIBUTE_GI, bit4 OCCLUDER, bit5 NO_LOD_FADE
  std::uint16_t lodBias = 0, layer = 0;
  std::uint16_t cullDistance = 0;      ///< world units / 4, 0 = mesh default
  std::uint16_t lightmap = 0;          ///< atlas index + 1, 0 = none
  std::uint16_t lightmapScaleOffset[4] = {0, 0, 0, 0}; ///< raw binary16
  std::uint8_t overrideCount = 0;      ///< 0..8
  std::uint16_t materialOverride[8] = {0, 0, 0, 0, 0, 0, 0, 0};
};
struct Inst
{
  float cellOrigin[3] = {0, 0, 0};
  float cellExtent[3] = {0, 0, 0};
  std::vector<InstInstance> instances;
};

// ---- LODG v1 (instance = cell) ----
struct LodgProxy
{
  MeshRef mesh;
  float pos[3] = {0, 0, 0};
  float rot[4] = {0, 0, 0, 1};
  float scale[3] = {1, 1, 1};
  float showBeyond = 0, fadeWidth = 0;
  std::vector<std::uint32_t> replacesInstances; ///< empty = replaces the whole cell content
};
struct Lodg
{
  std::vector<LodgProxy> proxies;
};

// ---- OCCL v1 ----
struct OcclOccluder
{
  std::uint8_t kind = 0; ///< 0 box, 1 mesh
  float center[3] = {0, 0, 0}, halfExtents[3] = {0, 0, 0}; ///< box
  MeshRef mesh;                                              ///< mesh
  float pos[3] = {0, 0, 0}, scale[3] = {1, 1, 1};            ///< mesh
  float rot[4] = {0, 0, 0, 1};                               ///< both
};
struct OcclRoom
{
  std::string name;
  float min[3] = {0, 0, 0}, max[3] = {0, 0, 0};
};
struct OcclPortal
{
  float quad[4][3] = {};
  std::uint16_t roomA = 0, roomB = 0; ///< not cross-checked against the room count here
  std::uint8_t flags = 0;             ///< bit0 OPEN
};
struct Occl
{
  std::vector<OcclOccluder> occluders;
  std::vector<OcclRoom> rooms;
  std::vector<OcclPortal> portals;
};

// ---- LMAP v1 (instance = atlas) ----
struct Lmap
{
  std::uint32_t width = 0, height = 0;
  std::uint8_t format = 0; ///< 0 BC6H, 1 RGBM8, 2 RGBA16F
  std::uint8_t kind = 0;   ///< 0 irradiance, 1 irradiance + dominant direction
  std::uint32_t byteCount = 0;
  ByteSpan bytes;
  std::uint32_t directionByteCount = 0; ///< kind 1 only
  ByteSpan directionBytes;              ///< kind 1 only (RGBA8)
};

// ---- PRBV v1 (instance = cell) ----
struct Prbv
{
  float gridOrigin[3] = {0, 0, 0}, gridSpacing[3] = {0, 0, 0};
  std::uint32_t nx = 0, ny = 0, nz = 0;
  ByteSpan coefficients; ///< nx*ny*nz*27 binary16 values (raw u16, little endian)
};

// ---- ANIM v1 ----
struct AnimKey
{
  float t = 0;
  float value[4] = {0, 0, 0, 0};
};
struct AnimChannel
{
  std::uint32_t instanceCell = 0, instanceIndex = 0;
  std::uint8_t target = 0; ///< 0 position, 1 rotation, 2 scale
  std::vector<AnimKey> keys;
};
struct AnimClip
{
  std::string name;
  float duration = 0;
  std::uint8_t loop = 0;
  std::vector<AnimChannel> channels;
};
struct AnimPlayer
{
  std::string clip;
  float speed = 1, phase = 0;
  std::uint16_t layer = 0;
  std::uint8_t triggerKind = 0; ///< 0 always, 1 script-started
};
struct Anim
{
  std::vector<AnimClip> clips;
  std::vector<AnimPlayer> players;
};

// ---- VOLR v1 ----
struct VolrVolume
{
  std::uint8_t kind = 0;      ///< 0 fog, 1 post, 2 reverb, 3 light override
  std::uint8_t shapeKind = 0; ///< 0 box, 1 sphere (halfExtents.x = radius)
  float center[3] = {0, 0, 0}, halfExtents[3] = {0, 0, 0};
  float rot[4] = {0, 0, 0, 1};
  float blendDistance = 0;
  std::int16_t priority = 0;
  std::uint16_t layer = 0;
  // kind 0 (fog): color, density, heightFalloff. kind 1 (post): exposureEV, saturation, contrast, tint.
  // kind 2 (reverb): preset. kind 3 (light override): ambientMul, tint.
  float color[3] = {0, 0, 0};
  float density = 0, heightFalloff = 0;
  float exposureEV = 0, saturation = 0, contrast = 0;
  float tint[3] = {0, 0, 0};
  std::string preset;
  float ambientMul = 0;
};
struct Volr
{
  std::vector<VolrVolume> volumes;
};

// ---- decoders (strict) and dumpers ----
bool DecodeCidx(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Cidx& out, std::string& err);
bool DecodeMshb(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Mshb& out, std::string& err);
bool DecodeMatb(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Matb& out, std::string& err);
bool DecodeInst(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Inst& out, std::string& err);
bool DecodeLodg(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Lodg& out, std::string& err);
bool DecodeOccl(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Occl& out, std::string& err);
bool DecodeLmap(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Lmap& out, std::string& err);
bool DecodePrbv(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Prbv& out, std::string& err);
bool DecodeAnim(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Anim& out, std::string& err);
bool DecodeVolr(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Volr& out, std::string& err);

void DumpCidx(const Cidx& v, TextDump& d);
void DumpMshb(const Mshb& v, TextDump& d);
void DumpMatb(const Matb& v, TextDump& d);
void DumpInst(const Inst& v, TextDump& d);
void DumpLodg(const Lodg& v, TextDump& d);
void DumpOccl(const Occl& v, TextDump& d);
void DumpLmap(const Lmap& v, TextDump& d);
void DumpPrbv(const Prbv& v, TextDump& d);
void DumpAnim(const Anim& v, TextDump& d);
void DumpVolr(const Volr& v, TextDump& d);

/// Family entry point: decodes the chunk and appends its dump lines. NotMine for ids other than the ten above and for
/// every id when `ctx.container < 4` (these chunks are only valid in container 4); Error (message in `err`) for a
/// chunk version other than 1 or a malformed payload.
DecodeStatus DumpChunkWorld3D(const std::string& id, std::uint16_t version, const std::uint8_t* data, std::size_t size, ChunkCtx& ctx,
                              TextDump& dump, std::string& err);

} // namespace moho::mapformat
