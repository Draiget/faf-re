#pragma once

#include "editor/tools/EdGroundKind.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The roughness / height atlas of the Terrain1xx and Terrain2xx shaders (FAF Studio's alphagen.lua). Those shaders
   * read no albedo alpha: every layer's roughness and the height the 2xx splatting compares (the higher layer wins
   * where two overlap) come from the Upper layer, a 2 x 2 atlas: the tiles of the Base layer and layers 1-3 (top left,
   * top right, bottom left, bottom right) hold roughness in R and height in G, layers 4-7 the same tiles in B and A.
   * The shader reads the middle half of a tile, so a tile holds its picture twice in each direction.
   *
   * A layer's tile: its texture's detail (brightness) normalised so every texture has the same height contrast, the
   * relief of its normal map (the slopes integrated into a height), a step by its kind of ground (rock above grass
   * above wet ground), and a roughness by the kind of ground moved by the detail.
   */
  struct AtlasSettings
  {
    float spread = 1.0f;      // x the height contrast inside a texture
    float biasScale = 1.0f;   // x the height step between the kinds of ground
    float cavity = 0.35f;     // how much the normal map's relief counts (0..1)
    float roughDetail = 1.0f; // x how much bright and dark spots move the roughness
  };

  /**
   * A named style (default, soft, patchy) fills the settings and the Terrain2xx splat softness / contrast (0 = leave
   * the map's); custom (or another name) leaves them as they are.
   */
  void ApplyAtlasStyle(const std::string& style, AtlasSettings& settings, float& splatSoft, float& splatContrast);

  /** A tile's data: kAtlasTile x kAtlasTile values, rows along z. */
  inline constexpr int kAtlasTile = 256;
  struct AtlasTile
  {
    std::vector<float> height;
    std::vector<float> rough;
  };

  /** A kind of ground's roughness and height step (Studio's ROLE_ROUGH, ROLE_HEIGHT); Unknown: 0.65 and 0. */
  [[nodiscard]] float KindRoughness(GroundKind kind);
  [[nodiscard]] float KindHeightStep(GroundKind kind);

  /**
   * A layer's tile from its albedo and (optional, empty) normal map, each kAtlasTile x kAtlasTile BGRA bytes. False
   * with `error` when the albedo has the wrong size or the integration fails.
   */
  bool MakeAtlasTile(
    const std::vector<std::uint8_t>& albedo,
    const std::vector<std::uint8_t>& normal,
    GroundKind kind,
    const AtlasSettings& settings,
    AtlasTile& out,
    std::string& error
  );

  /**
   * The atlas, `size` x `size` RGBA 0..1 (rows top to bottom): each layer's tile, or for a layer without one (null)
   * the neutral roughness 0.65 and the height step of its kind.
   */
  void PackAtlas(
    const std::array<const AtlasTile*, 8>& tiles,
    const std::array<GroundKind, 8>& kinds,
    const AtlasSettings& settings,
    int size,
    std::vector<float>& rgba
  );
} // namespace faf::editor
