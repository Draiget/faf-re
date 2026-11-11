// Map format identification (docs/mapformat/README.md "Detection"): which of the four formats a file is, decided from
// its first 8 bytes, plus the log line and the feature mask this exe supports. Standard library only.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "moho/sim/mapformat/FeatureBits.h"

namespace moho::mapformat {

/// Ids 3 and 4 equal the container version on purpose.
enum class EMapFormat
{
  Unknown = 0,
  Classic = 1,   ///< stock .scmap, container 2
  Legacy25D = 2, ///< container 2 + mesh-terrain manifest (scenario says TerrainSystem = 'mesh')
  Extended = 3,  ///< container 3
  Full3D = 4,    ///< container 4
};

const char* MapFormatName(EMapFormat f);

/// What the engine knows about a map after detection (and, for containers 3/4, header validation).
struct SMapFormatInfo
{
  EMapFormat id = EMapFormat::Unknown;
  std::uint32_t container = 0; ///< container version from the file (0 when unknown)
  std::uint32_t revision = 0;  ///< container revision (containers 3/4 only)
  std::uint64_t requiredFeatures = 0;
  std::uint64_t optionalFeatures = 0;
  std::array<std::uint8_t, 32> simHash{}; ///< from the header (containers 3/4 only; all zero otherwise)
  std::string reason;                     ///< why the format is Unknown (empty otherwise)

  bool IsChunked() const { return id == EMapFormat::Extended || id == EMapFormat::Full3D; }
};

/// README "Detection" steps 1-3 on the first 8 bytes of a file (`n` may be larger, extra bytes are ignored).
/// Magic must be 0x1A70614D ('Map\x1A'); container 2 is Classic, or Legacy25D when `scenarioSaysMesh`; 3 Extended;
/// 4 Full3D. Anything else is Unknown and `*reason` (optional) says why, starting with "NotAMap" or
/// "UnsupportedContainer". Never reads more than min(n, 8) bytes.
EMapFormat DetectFromHeader(const std::uint8_t* first8, std::size_t n, bool scenarioSaysMesh, std::string* reason = nullptr);

/// Feature bits (CONTAINER.md section 4) this build implements, revision 1. A map whose `requiredFeatures` has a bit
/// outside this mask is refused with the names of those bits.
///
/// Policy: every bit the READER can decode is supported; bits that need engine behaviour that does not exist yet are
/// NOT, so such maps are refused instead of misplayed. Move a bit to `kSupportedFeatures` when the engine stage lands
/// (FULL3D.md section 4):
///   sim stage 4:    SURFACE_LAYERS (speedMul), WATER_BODIES (several bodies), LEVELS, WORLD_COLLISION, WORLD_NAV3D,
///                   WORLD_VOLUMES_SIM
///   always refused: EXTENDED_FEATURES (second feature word, later revision)
constexpr std::uint64_t kUnsupportedFeatures = kFeat_SurfaceLayers | kFeat_WaterBodies | kFeat_Levels | kFeat_WorldCollision |
                                               kFeat_WorldNav3d | kFeat_WorldVolumesSim | kFeat_ExtendedFeatures;
constexpr std::uint64_t kKnownFeatures = kFeat_GridNonSquare | kFeat_GridLarge | kFeat_HeightFine | kFeat_SurfaceLayers |
                                         kFeat_WaterBodies | kFeat_Levels | kFeat_PlayablePolygon | kFeat_MarkersBinary |
                                         kFeat_PropsBinary | kFeat_Hints | kFeat_RenderIndexedSplat | kFeat_RenderPbrMaterials |
                                         kFeat_RenderVolumetrics | kFeat_RenderTod | kFeat_WorldCells | kFeat_WorldCollision |
                                         kFeat_WorldNav3d | kFeat_WorldLargeCoords | kFeat_WorldLightmaps | kFeat_WorldVolumesSim |
                                         kFeat_ExtendedFeatures;
constexpr std::uint64_t SupportedFeaturesMask() { return kKnownFeatures & ~kUnsupportedFeatures; }

/// What the ENGINE honours today (stage 1: the Classic bridge, docs/mapformat/FULL3D.md section 4). The container reader
/// above accepts more; a map that REQUIRES one of these bits is refused with its name instead of being played wrong:
///   GRID_LARGE           the terrain code is built for 4096 cells per axis
///   PLAYABLE_POLYGON     the playable area is the scenario's rectangle
///   MARKERS_BINARY       markers still come from the save file; MRKR / AREA are additive copies until the Lua side reads them
///   HINTS                no AI reads them yet
///   WORLD_CELLS, WORLD_LARGE_COORDS, WORLD_LIGHTMAPS   the Full3D renderer stages
constexpr std::uint64_t kEngineUnsupportedFeatures =
  kUnsupportedFeatures | kFeat_GridLarge | kFeat_PlayablePolygon | kFeat_MarkersBinary | kFeat_Hints | kFeat_WorldCells |
  kFeat_WorldLargeCoords | kFeat_WorldLightmaps;
constexpr std::uint64_t EngineSupportedFeaturesMask() { return kKnownFeatures & ~kEngineUnsupportedFeatures; }

/// "WATER_BODIES, LEVELS" (comma + space separated names of the set bits, lowest first); empty for 0.
std::string FeatureNamesText(std::uint64_t mask);

/// The log line: "MapFormat: Extended rev 1 features req=0x3 opt=0x1fa simhash=0123456789abcdef..." (lower-case hex without
/// leading zeros for the masks, the first 8 bytes of simHash). Classic / Legacy25D / Unknown have no revision or
/// features: "MapFormat: Classic", "MapFormat: Unknown (reason)".
std::string DescribeFormat(const SMapFormatInfo& info);

} // namespace moho::mapformat
