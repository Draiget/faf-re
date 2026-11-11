// Decoders, dumpers and the cross-chunk validator for the SIM chunks of containers 3 (Extended) and 4 (Full3D):
// GRID HGHT PLAY GPLY WBOD LEVL MRKR AREA PROP HINT (docs/mapformat/EXTENDED.md) and WRLD SLYR COLL NAVS VOLS
// (docs/mapformat/FULL3D.md). Standard library only; the decoders never throw and never trust a count from the file.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "moho/sim/mapformat/FeatureBits.h"
#include "moho/sim/mapformat/MapFormatCommon.h"

namespace moho::mapformat {

/// `fxvec2`: two fx32 (i32 / 256). Kept as raw integers so no float math is involved anywhere in the sim path.
struct FxVec2
{
  std::int32_t x = 0;
  std::int32_t z = 0;
};

/// `fx10vec3`: three fx10 (i32 / 1024), raw integers.
struct Fx10Vec3
{
  std::int32_t x = 0;
  std::int32_t y = 0;
  std::int32_t z = 0;
};

// ---------------------------------------------------------------------------------------------------------------------
// Extended sim chunks (version 1)
// ---------------------------------------------------------------------------------------------------------------------

struct GridChunk
{
  std::uint32_t cellsX = 0;
  std::uint32_t cellsZ = 0;
  float cellSize = 1.0f;
  float originX = 0.0f;
  float originZ = 0.0f;
  float minElevation = 0.0f;
  float maxElevation = 0.0f;
  std::uint8_t reserved = 0;
};

struct HghtChunk
{
  float minHeight = 0.0f;
  std::int8_t stepLog2 = -7;
  std::uint8_t predictor = 0;
  std::uint16_t tileSize = 0;
  std::uint32_t width = 0;   // cellsX + 1
  std::uint32_t height = 0;  // cellsZ + 1
  std::vector<std::uint16_t> samples; // width * height raw samples, predictor already reversed
};

struct PlayChunk
{
  std::int32_t x0 = 0, z0 = 0, x1 = 0, z1 = 0;
  std::uint8_t borderMode = 0;
  std::vector<FxVec2> polygon; // empty = the rectangle
};

struct GplySurface
{
  std::uint16_t id = 0;
  std::string name;
  std::uint32_t flags = 0;
  std::uint16_t speedMul = 256;
  std::string effectsKey;
};

struct GplyMask
{
  std::string name;
  std::uint8_t kind = 1;      // 1 bitmask, 8 u8 plane
  std::uint8_t predictor = 0; // kind 8 only
  std::vector<std::uint8_t> data; // kind 1: bitmask(cellsX, cellsZ) bytes; kind 8: decoded cellsX*cellsZ samples
};

struct GplyChunk
{
  std::uint8_t legacyTerrainIds = 0;
  std::vector<GplySurface> surfaces;
  std::uint8_t idWidth = 1;
  std::uint8_t idsPredictor = 0;
  std::uint32_t width = 0;  // cellsX
  std::uint32_t height = 0; // cellsZ
  std::vector<std::uint16_t> ids; // width * height surface ids, predictor already reversed
  std::vector<GplyMask> masks;
};

struct WbodBody
{
  std::uint16_t id = 0;
  std::string name;
  std::uint8_t kind = 0;       // 0 sea, 1 lake, 2 river
  float level = 0.0f;
  std::uint8_t extentKind = 0; // 0 global, 1 mask, 2 polygon
  std::vector<std::uint8_t> mask;  // extentKind 1: bitmask(cellsX, cellsZ)
  std::vector<FxVec2> polygon;     // extentKind 2: 3..4096 points
};

struct WbodChunk
{
  std::vector<WbodBody> bodies;
};

struct LevlPortal
{
  FxVec2 a;
  FxVec2 b;
  std::uint16_t targetDeck = 0xFFFF; // 0xFFFF = ground
};

struct LevlDeck
{
  std::uint16_t id = 0;
  std::string name;
  std::int32_t x0 = 0, z0 = 0, x1 = 0, z1 = 0; // cells, inclusive
  std::uint8_t mode = 0;  // 0 flat, 1 ramp, 2 patch
  float h0 = 0.0f;
  float h1 = 0.0f;
  std::uint8_t axis = 0;  // 0 x, 1 z
  std::uint8_t patchPredictor = 0;
  std::vector<std::uint16_t> patch; // mode 2: (x1-x0+1)*(z1-z0+1) raw samples, predictor reversed
  float clearanceBelow = 0.0f;
  std::uint32_t flags = 0;
  std::vector<LevlPortal> portals;
};

struct LevlChunk
{
  std::vector<LevlDeck> decks;
};

struct MarkerProp
{
  std::string key;
  std::uint8_t vtype = 0; // 0 str, 1 i32, 2 f32, 3 bool
  std::string strValue;
  std::int32_t intValue = 0; // vtype 1; vtype 3 uses 0/1
  float floatValue = 0.0f;   // vtype 2
};

struct Marker
{
  std::uint8_t type = 0;
  std::string name;
  float pos[3] = {0, 0, 0};
  float yawDeg = 0.0f;
  std::int16_t army = -1;
  std::uint32_t flags = 0;
  std::vector<MarkerProp> props;
  std::vector<std::uint32_t> links;
};

struct MrkrChunk
{
  std::vector<Marker> markers;
};

/// 2D `shape` (EXTENDED.md "Common sub-structures"): f32 coordinates.
struct Shape2D
{
  std::uint8_t kind = 0; // 0 rect, 1 polygon, 2 circle
  float x0 = 0, z0 = 0, x1 = 0, z1 = 0; // rect
  std::vector<std::array<float, 2>> polygon;
  float cx = 0, cz = 0, r = 0; // circle
};

struct Area
{
  std::string name;
  Shape2D shape;
  std::uint8_t flags = 0; // bit0 HAS_Y_RANGE
  float yMin = 0.0f;
  float yMax = 0.0f;
  std::vector<std::string> tags;
};

struct AreaChunk
{
  std::vector<Area> areas;
};

struct PropItem
{
  std::uint32_t blueprintIndex = 0;
  float pos[3] = {0, 0, 0};
  float rot[4] = {0, 0, 0, 1};
  float scale[3] = {1, 1, 1};
  std::uint32_t flags = 0;
};

struct PropChunk
{
  std::vector<std::string> blueprints;
  std::vector<PropItem> props;
};

struct HintRegion
{
  std::uint32_t id = 0;
  std::string name;
  std::uint8_t kind = 0;
  float area = 0.0f;
  float centroid[2] = {0, 0};
  std::vector<std::uint32_t> neighbors;
};

struct HintChoke
{
  float pos[2] = {0, 0};
  float width = 0.0f;
  std::uint32_t regionA = 0;
  std::uint32_t regionB = 0;
  std::uint8_t layerMask = 0;
};

struct HintCandidate
{
  float pos[2] = {0, 0};
  std::uint8_t layer = 0;
  float score = 0.0f;
  std::vector<std::uint32_t> markerIds;
};

struct HintChunk
{
  std::vector<HintRegion> regions;
  std::vector<HintChoke> chokes;
  std::vector<HintCandidate> candidates;
};

// ---------------------------------------------------------------------------------------------------------------------
// Full3D sim chunks (version 1)
// ---------------------------------------------------------------------------------------------------------------------

/// `shape3d` (FULL3D.md "Common sub-structures"): fx10 fixed point.
struct Shape3D
{
  std::uint8_t kind = 0; // 0 box, 1 sphere, 2 convex hull, 3 extruded polygon, 4 capsule
  Fx10Vec3 center;       // box, sphere
  Fx10Vec3 halfExtents;  // box
  std::int16_t rot[4] = {0, 0, 0, 0}; // box, snorm quaternion
  std::int32_t radius = 0;            // sphere, capsule (fx10)
  std::vector<Fx10Vec3> points;       // convex hull (4..256)
  std::vector<FxVec2> polygon;        // extruded polygon (3..1024)
  std::int32_t yMin = 0;              // extruded polygon (fx10)
  std::int32_t yMax = 0;
  Fx10Vec3 a;                         // capsule
  Fx10Vec3 b;
};

struct WrldChunk
{
  double originX = 0, originY = 0, originZ = 0;
  float boundsMin[3] = {0, 0, 0};
  float boundsMax[3] = {0, 0, 0};
  float cellSize = 0.0f;
  std::uint32_t cellsX = 0, cellsY = 0, cellsZ = 0;
  std::uint8_t upAxis = 1;
  float unitsPerMeter = 1.0f;
  std::uint8_t flags = 0; // bit0 LARGE_COORDS
};

struct SlyrLayer
{
  std::string name;
  std::uint8_t defaultOn = 0;
};

struct SlyrChunk
{
  std::vector<SlyrLayer> layers;
};

struct CollTri
{
  std::vector<Fx10Vec3> vertices;
  std::vector<std::uint32_t> indices; // multiple of 3, each < vertices.size()
  std::uint8_t surfaceMode = 0;       // 0 one surface id for all, 1 per triangle
  std::uint16_t surface = 0;
  std::vector<std::uint16_t> triSurfaces; // surfaceMode 1: indices.size() / 3 entries
  std::uint16_t blocks = 0;
  std::uint16_t simLayer = 0;
};

struct CollHull
{
  std::vector<Fx10Vec3> points; // 4..256
  std::uint16_t surface = 0;
  std::uint16_t blocks = 0;
  std::uint16_t simLayer = 0;
};

struct CollPrim
{
  Shape3D shape;
  std::uint16_t surface = 0;
  std::uint16_t blocks = 0;
  std::uint16_t simLayer = 0;
};

struct CollChunk
{
  std::vector<CollTri> tris;
  std::vector<CollHull> hulls;
  std::vector<CollPrim> prims;
};

struct NavsSurface
{
  std::uint16_t id = 0;
  std::string name;
  std::uint8_t kind = 0; // 0 height patch, 1 triangle mesh
  std::uint8_t moveMask = 0;
  std::int32_t clearance = 0; // fx16
  std::uint16_t simLayer = 0;
  // kind 0
  std::int32_t x0 = 0, z0 = 0, x1 = 0, z1 = 0; // inclusive
  std::uint8_t heightsPredictor = 0;
  std::vector<std::uint16_t> heights;   // (x1-x0+1)*(z1-z0+1), predictor reversed
  std::vector<std::uint8_t> walkable;   // bitmask(x1-x0+1, z1-z0+1)
  // kind 1
  std::vector<Fx10Vec3> vertices;
  std::vector<std::uint32_t> indices;   // multiple of 3, each < vertices.size()
};

struct NavsLink
{
  std::uint16_t fromSurface = 0;
  Fx10Vec3 from;
  std::uint16_t toSurface = 0;
  Fx10Vec3 to;
  std::uint8_t kind = 0; // 0 walk, 1 ladder, 2 jump, 3 teleport, 4 lift
  std::uint8_t moveMask = 0;
  std::int32_t cost = 0; // fx16
  std::uint8_t bidirectional = 0;
};

struct NavsChunk
{
  std::vector<NavsSurface> surfaces;
  std::vector<NavsLink> links;
};

struct VolsVolume
{
  std::string name;
  Shape3D shape;
  std::uint32_t flags = 0;
  std::int16_t army = -1;
  std::vector<std::string> tags;
};

struct VolsChunk
{
  std::vector<VolsVolume> volumes;
};

// ---------------------------------------------------------------------------------------------------------------------
// Decoders and dumpers. Decoders are strict (exact consumption), return false with `err` set on any malformed payload
// and leave `out` unspecified then. DecodeGrid sets ctx.cellsX / ctx.cellsZ on success; HGHT, GPLY (always) and
// WBOD (mask extents) need them and fail when ctx.cellsX is 0.
// ---------------------------------------------------------------------------------------------------------------------

bool DecodeGrid(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, GridChunk& out, std::string& err);
bool DecodeHght(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, HghtChunk& out, std::string& err);
bool DecodePlay(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, PlayChunk& out, std::string& err);
bool DecodeGply(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, GplyChunk& out, std::string& err);
bool DecodeWbod(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, WbodChunk& out, std::string& err);
bool DecodeLevl(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, LevlChunk& out, std::string& err);
bool DecodeMrkr(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, MrkrChunk& out, std::string& err);
bool DecodeArea(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, AreaChunk& out, std::string& err);
bool DecodeProp(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, PropChunk& out, std::string& err);
bool DecodeHint(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, HintChunk& out, std::string& err);
bool DecodeWrld(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, WrldChunk& out, std::string& err);
bool DecodeSlyr(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, SlyrChunk& out, std::string& err);
bool DecodeColl(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, CollChunk& out, std::string& err);
bool DecodeNavs(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, NavsChunk& out, std::string& err);
bool DecodeVols(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, VolsChunk& out, std::string& err);

void DumpGrid(TextDump& dump, const GridChunk& c);
void DumpHght(TextDump& dump, const HghtChunk& c);
void DumpPlay(TextDump& dump, const PlayChunk& c);
void DumpGply(TextDump& dump, const GplyChunk& c);
void DumpWbod(TextDump& dump, const WbodChunk& c);
void DumpLevl(TextDump& dump, const LevlChunk& c);
void DumpMrkr(TextDump& dump, const MrkrChunk& c);
void DumpArea(TextDump& dump, const AreaChunk& c);
void DumpProp(TextDump& dump, const PropChunk& c);
void DumpHint(TextDump& dump, const HintChunk& c);
void DumpWrld(TextDump& dump, const WrldChunk& c);
void DumpSlyr(TextDump& dump, const SlyrChunk& c);
void DumpColl(TextDump& dump, const CollChunk& c);
void DumpNavs(TextDump& dump, const NavsChunk& c);
void DumpVols(TextDump& dump, const VolsChunk& c);

/// Family entry point. Handles ids GRID HGHT PLAY GPLY WBOD LEVL MRKR AREA PROP HINT WRLD SLYR COLL NAVS VOLS
/// (anything else: NotMine). Only version 1 exists; other versions give Error. On Ok the chunk text was appended
/// to `dump`; on Error `err` explains and nothing is appended. GRID updates ctx.cellsX / ctx.cellsZ.
DecodeStatus DumpChunkSim(const std::string& id, std::uint16_t version, const std::uint8_t* data, std::size_t size,
                          ChunkCtx& ctx, TextDump& dump, std::string& err);

/// `height(v) = ldexp(float(v), stepLog2) + minHeight` in binary32 (EXTENDED.md HGHT). Exact for the stock
/// conversion (minHeight 0, stepLog2 -7: equals v / 128.0f for all 65536 values).
float DecodeHeight(const HghtChunk& c, std::uint16_t v);

// ---------------------------------------------------------------------------------------------------------------------
// Cross-chunk validation
// ---------------------------------------------------------------------------------------------------------------------

/// The decoded sim chunks of one map. GRID HGHT PLAY GPLY WBOD are required (Extended); the rest is optional.
/// `container` is 3 or 4; Full3D (4) additionally requires WRLD. COLL is one entry per directory instance.
struct MapSimData
{
  struct CollEntry
  {
    std::uint32_t instance = 0; // cell index (0 if no cells)
    CollChunk chunk;
  };

  int container = 3;
  std::optional<GridChunk> grid;
  std::optional<HghtChunk> hght;
  std::optional<PlayChunk> play;
  std::optional<GplyChunk> gply;
  std::optional<WbodChunk> wbod;
  std::optional<LevlChunk> levl;
  std::optional<MrkrChunk> mrkr;
  std::optional<AreaChunk> area;
  std::optional<PropChunk> prop;
  std::optional<HintChunk> hint;
  std::optional<WrldChunk> wrld;
  std::optional<SlyrChunk> slyr;
  std::vector<CollEntry> coll;
  std::optional<NavsChunk> navs;
  std::optional<VolsChunk> vols;
};

/// "Required behaviour of a reader" rule 2 of EXTENDED.md plus the Full3D cross references. Returns false and sets
/// `err` (first problem found) when the map must be refused.
bool ValidateSimData(const MapSimData& m, std::string& err);

/// Feature bits (FeatureBits.h) the data needs, as a mask. MARKERS_BINARY, PROPS_BINARY and HINTS are decided by chunk
/// presence only (MRKR or AREA / PROP / HINT).
std::uint64_t RequiredFeatureMaskFor(const MapSimData& m);

/// The same set as spec names (FeatureName), lowest bit first.
std::vector<std::string> RequiredFeatureBitsFor(const MapSimData& m);

} // namespace moho::mapformat
