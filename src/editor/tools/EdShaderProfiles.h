#pragma once

// What a mapper has to know about each terrain shader (FAF Studio's shaders.lua, from FAF's effects/terrain.fx): what
// it does, how its textures have to be made (one row per layer: what its albedo and normal map hold), which layers it
// paints, and how it reads the masks (RemappedStrata). No engine types: tested on its own
// (tests/editor/ShaderProfileTests.cpp).

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace faf::editor
{
  /** The groups of the shader browser. */
  enum class ShaderFamily
  {
    Original,
    Extended, // Terrain0xx
    Pbr,      // Terrain1xx
    Splat,    // Terrain2xx: PBR with height splatting
    Older,    // Terrain301 and shaders the table doesn't know
  };
  [[nodiscard]] const char* ShaderFamilyName(ShaderFamily family);

  /** One layer's textures for a shader. */
  struct ShaderLayerRow
  {
    std::string layer; // Base, Layer 1 .. Layer 8, Upper
    std::string albedo;
    std::string normal;
  };

  struct ShaderProfile
  {
    std::string name;
    ShaderFamily family = ShaderFamily::Older;
    /** False for a shader the table has no notes about (its texts say so). */
    bool known = false;
    std::string summary;
    std::string instructions;
    std::string layout;
    std::vector<ShaderLayerRow> rows;
    std::vector<std::string> notes;
    /** The painted layers it blends: 4 (TTerrain, TTerrainGlow), 7 (layer 8 holds data) or 8. */
    int painted = 8;
    /** Strata read through saturate(2m - 1) (RemappedStrata): the masks' range. */
    std::uint8_t remapped = 0xFF;
    /** The editor converts layers to and from it (FAF Studio leaves Terrain301 and unknown shaders out). */
    bool convertible = true;
  };

  /** The profile of a shader by its technique name (case kept as given; an unknown name gets a plain entry). */
  [[nodiscard]] ShaderProfile ShaderProfileOf(std::string_view name);

  /** How a profile reads its masks, in words: "half range", "full range", or "half range, layer 8 full". */
  [[nodiscard]] std::string MaskRangeText(std::uint8_t remapped);
} // namespace faf::editor
