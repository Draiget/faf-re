// Extended / Full3D map -> Classic `.scmap` (container 2, terrain payload version 56) built in memory.
//
// Two uses:
//   1. The engine loads container 3 / 4 maps by exporting them to Classic bytes and feeding those to the existing
//      terrain, strata, water and prop loaders. Every Extended map therefore works in the engine before any new renderer
//      exists; the new render chunks are consumed by their own stages on top of this.
//   2. A map editor's "export for older game versions" (the writer is the same code).
//
// What survives: heights (quantised to the engine's 1/128 steps), terrain types, one water plane (the first global body),
// lighting (LITE), up to 9 blended material layers (MATL + SPLT, dense or indexed), props, the preview image.
// Everything else is dropped; `notes` lists every approximation so the log says what the picture lost.
//
// Layout reference: the engine's own loaders (CWldTerrainRes::Load, CWaterShaderProperties::Load, CDecalManager::Load,
// CWldProps::Load) and tools/meshmaps/scmap.py of FA-MeshTerrain, which has been used in game.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "moho/sim/mapformat/ExtendedMap.h"

namespace moho::mapformat {

struct ClassicExportOptions
{
  /// Heights that are not exact multiples of 1/128 (finer steps, a fractional minHeight) are rounded; false refuses them.
  bool quantizeHeights = true;
  /// DECL -> Classic decals (albedo, normal, glow). Off by default: the rotation convention is not verified in game.
  bool exportDecals = false;
};

struct ClassicExportResult
{
  std::vector<std::uint8_t> bytes;    ///< a complete .scmap
  std::vector<std::string> notes;     ///< approximations and dropped features
  float maxHeightError = 0.0f;        ///< largest rounding error of the height quantisation (world units)
};

bool ExportClassic(const ExtendedMap& map, const ClassicExportOptions& options, ClassicExportResult& out, std::string& err);

/// Quaternion (x, y, z, w) -> the three local axes in world space, as Classic stores a prop's rotation (rows vX, vY, vZ).
void QuatToAxes(const float q[4], float axes[9]);

/// Uncompressed A8R8G8B8 DDS with a 128 byte header; `bgra` is width*height*4 bytes (may be empty = transparent black).
std::vector<std::uint8_t> MakeArgbDds(std::uint32_t width, std::uint32_t height, const std::uint8_t* bgra);
/// DXT5 DDS of one flat colour.
std::vector<std::uint8_t> MakeDxt5FlatDds(std::uint32_t width, std::uint32_t height, std::uint8_t r, std::uint8_t g,
                                           std::uint8_t b, std::uint8_t a);

} // namespace moho::mapformat
