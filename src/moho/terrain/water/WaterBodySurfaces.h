#pragma once

// Engine addition, not in the binary: how the client draws a map's water bodies
// (.plans/water-levels/PLAN.md). Without bodies nothing here is used and every water
// pass draws exactly what it drew before.

#include <cstdint>
#include <vector>

#include "boost/shared_ptr.h"

namespace moho
{
  class CD3DIndexSheet;
  class CD3DVertexSheet;
  class ID3DRenderTarget;
  class IWldTerrainRes;
  class STIMap;

  /// The water of one 2 x 2-cell block, one texel of the terrain's half-resolution water map.
  struct SWaterOfBlock
  {
    /// `kWaterBodyNoWater` where there is none (a dry body, or the sea when the map has none).
    float level;
    float deep;
    float abyss;
    /// 0 for the sea.
    std::uint8_t body;
  };

  /// The water of the block whose first corner is vertex `(x, z)`: its body's, else the sea's.
  [[nodiscard]] SWaterOfBlock WaterOfBlock(const STIMap& map, std::int32_t x, std::int32_t z) noexcept;

  /// The `CWaterBodies::Generation` of the map's bodies, 0 without bodies.
  [[nodiscard]] std::uint32_t WaterBodiesGeneration(const STIMap& map) noexcept;

  /**
   * The level the terrain shader's `WaterElevation` takes. The shader colours terrain under
   * water by the water map's depth and also tests `terrain height < WaterElevation`; with
   * bodies the highest water level makes that test pass under every body, so each lake bed
   * is coloured as the sea bed is. Without bodies the sea level, as before.
   */
  [[nodiscard]] float WaterBodyTerrainShaderLevel(const STIMap& map) noexcept;

  /**
   * The water surfaces of a map with bodies: one mesh per water (the sea and each wet body),
   * covering the water-map texels that water owns, so a dry body has no water over it and
   * every lake sits at its own level. The water shaders put each vertex at `WaterElevation`,
   * so a level is drawn by setting that and drawing its mesh.
   */
  class WaterBodySurfaces
  {
  public:
    struct Chunk
    {
      CD3DVertexSheet* vertices{nullptr};
      CD3DIndexSheet* indices{nullptr};
    };

    struct Level
    {
      float elevation{0.0f};
      /// The sea: the only level the planar reflection is mirrored at.
      bool sea{false};
      std::vector<Chunk> chunks;
    };

    /// The levels of `terrainRes`'s map, rebuilt when its bodies changed; null without bodies.
    [[nodiscard]] static const std::vector<Level>* For(IWldTerrainRes* terrainRes);

    /// Drops the meshes and targets, with the device (`WRenViewport::D3DWindowOnDeviceExit`).
    static void Release();

    /**
     * The reflection a body's surface samples: the meshes mirrored at its level when it is the
     * level `SetBodyReflection` was given, otherwise a cleared target, so a lake reflects the
     * sky and not units mirrored at the sea.
     */
    [[nodiscard]] static boost::shared_ptr<ID3DRenderTarget> ReflectionFor(float level);

    /// Set by the reflection pass each frame: the body level it mirrored at (or none) and the targets.
    static void SetBodyReflection(
      bool mirrored,
      float level,
      const boost::shared_ptr<ID3DRenderTarget>& bodyTarget,
      const boost::shared_ptr<ID3DRenderTarget>& emptyTarget
    );
  };
} // namespace moho
