// Feature bits of containers 3 and 4 (docs/mapformat/CONTAINER.md section 4). Header only, standard library only.
// A reader refuses a map whose requiredFeatures has a bit it does not implement and names the feature.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace moho::mapformat {

// Sim features (Extended).
constexpr std::uint64_t kFeat_GridNonSquare = 1ULL << 0;
constexpr std::uint64_t kFeat_GridLarge = 1ULL << 1;
constexpr std::uint64_t kFeat_HeightFine = 1ULL << 2;
constexpr std::uint64_t kFeat_SurfaceLayers = 1ULL << 3;
constexpr std::uint64_t kFeat_WaterBodies = 1ULL << 4;
constexpr std::uint64_t kFeat_Levels = 1ULL << 5;
constexpr std::uint64_t kFeat_PlayablePolygon = 1ULL << 6;
constexpr std::uint64_t kFeat_MarkersBinary = 1ULL << 7;
constexpr std::uint64_t kFeat_PropsBinary = 1ULL << 8;
constexpr std::uint64_t kFeat_Hints = 1ULL << 9;
// Render features (normally optional).
constexpr std::uint64_t kFeat_RenderIndexedSplat = 1ULL << 16;
constexpr std::uint64_t kFeat_RenderPbrMaterials = 1ULL << 17;
constexpr std::uint64_t kFeat_RenderVolumetrics = 1ULL << 18;
constexpr std::uint64_t kFeat_RenderTod = 1ULL << 19;
// Full3D features.
constexpr std::uint64_t kFeat_WorldCells = 1ULL << 32;
constexpr std::uint64_t kFeat_WorldCollision = 1ULL << 33;
constexpr std::uint64_t kFeat_WorldNav3d = 1ULL << 34;
constexpr std::uint64_t kFeat_WorldLargeCoords = 1ULL << 35;
constexpr std::uint64_t kFeat_WorldLightmaps = 1ULL << 36;
constexpr std::uint64_t kFeat_WorldVolumesSim = 1ULL << 37;
constexpr std::uint64_t kFeat_ExtendedFeatures = 1ULL << 63;

/// Name of feature bit `bit` (0..63, a bit index, not a mask) as written in the spec table, or "BIT_<n>" when the
/// spec defines none. Used in the refusal message "map requires unsupported feature(s): ...".
inline std::string FeatureName(unsigned bit)
{
  switch (bit) {
  case 0: return "GRID_NONSQUARE";
  case 1: return "GRID_LARGE";
  case 2: return "HEIGHT_FINE";
  case 3: return "SURFACE_LAYERS";
  case 4: return "WATER_BODIES";
  case 5: return "LEVELS";
  case 6: return "PLAYABLE_POLYGON";
  case 7: return "MARKERS_BINARY";
  case 8: return "PROPS_BINARY";
  case 9: return "HINTS";
  case 16: return "RENDER_INDEXED_SPLAT";
  case 17: return "RENDER_PBR_MATERIALS";
  case 18: return "RENDER_VOLUMETRICS";
  case 19: return "RENDER_TOD";
  case 32: return "WORLD_CELLS";
  case 33: return "WORLD_COLLISION";
  case 34: return "WORLD_NAV3D";
  case 35: return "WORLD_LARGE_COORDS";
  case 36: return "WORLD_LIGHTMAPS";
  case 37: return "WORLD_VOLUMES_SIM";
  case 63: return "EXTENDED_FEATURES";
  default: return "BIT_" + std::to_string(bit);
  }
}

/// Names of every set bit of `mask`, lowest bit first.
inline std::vector<std::string> FeatureNames(std::uint64_t mask)
{
  std::vector<std::string> names;
  for (unsigned b = 0; b < 64; ++b) {
    if ((mask >> b) & 1ULL) names.push_back(FeatureName(b));
  }
  return names;
}

} // namespace moho::mapformat
