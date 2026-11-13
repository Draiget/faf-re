#pragma once

// Engine addition, not in the binary: how the client draws a map's water bodies
// (.plans/water-levels/PLAN.md). Without bodies nothing here is used and every water
// pass draws exactly what it drew before.

#include <cstdint>
#include <vector>

#include <memory>

namespace moho
{
  class CD3DDynamicTextureSheet;
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

  /// The water of the block whose first corner is vertex `(x, z)`: its body's, else the sea's. A river's block has the
  /// level of its own place, the mean of its four corners' (`RiverBlockCorners`), and its shading depths below that.
  [[nodiscard]] SWaterOfBlock WaterOfBlock(const STIMap& map, std::int32_t x, std::int32_t z) noexcept;

  /**
   * The levels of the four corners of the river block whose first corner is vertex `(x, z)` (the even vertices
   * `(x, z)`, `(x + 2, z)`, `(x, z + 2)`, `(x + 2, z + 2)`, in that order): the river's level field there, a corner
   * outside the field taking the mean of the others. False when the block is not a river's.
   */
  [[nodiscard]] bool RiverBlockCorners(const STIMap& map, std::int32_t x, std::int32_t z, float (&level)[4]) noexcept;

  /**
   * The levels of the nine vertices of the river block whose first corner is vertex `(x, z)`, row by row (`level[3 * j
   * + i]` is vertex `(x + i, z + j)`): the river's level field there, a vertex outside the field taking the mean of the
   * others. A river's mesh is drawn in quads of one cell with these as the heights of their corners, the surface the
   * sim's `GetSurfaceHeight` sees. False when the block is not a river's.
   */
  [[nodiscard]] bool RiverBlockVertices(const STIMap& map, std::int32_t x, std::int32_t z, float (&level)[9]) noexcept;

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
   * so a level is drawn by setting that and drawing its mesh. A river's mesh keeps the heights of its vertices instead
   * (`Level::river`, `water::BindRiverMesh`).
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
      /// The number of the water: 0 the sea, else the body (`SWaterOfBlock::body`).
      std::uint8_t body{0};
      /// A river: its meshes are quads of one cell with the river's level at their corners (`elevation` is its highest
      /// level), drawn with the vertices' own height and never as a projected grid.
      bool river{false};
      /// The rectangle of its blocks in world units, for the projected grid's screen window.
      float x0{0.0f};
      float z0{0.0f};
      float x1{0.0f};
      float z1{0.0f};
      std::vector<Chunk> chunks;
    };

    /// The levels of `terrainRes`'s map, rebuilt when its bodies changed; null without bodies.
    [[nodiscard]] static const std::vector<Level>* For(IWldTerrainRes* terrainRes);

    /**
     * One 8-bit texel per 2 x 2 block (the layout of the water map): the number of the water that owns the block
     * (`WaterOfBlock(...).body`, 0 the sea). The water pixel shader of a projected grid drops the pixels of blocks it
     * does not own. Rebuilt with the levels when the bodies change; null without bodies.
     */
    [[nodiscard]] static std::shared_ptr<CD3DDynamicTextureSheet> OwnerTexture(IWldTerrainRes* terrainRes);

    /**
     * The terrain's water level map: one 32-bit texel per 2 x 2 block with the level and abyss of the water that owns
     * the block (WaterLevelTexel.h), which the patched terrain effect reads instead of the water map's baked depth.
     * Rebuilt with the bodies; null without bodies.
     */
    [[nodiscard]] static std::shared_ptr<CD3DDynamicTextureSheet> LevelTexture(IWldTerrainRes* terrainRes);

    /// Drops the meshes and targets, with the device (`WRenViewport::D3DWindowOnDeviceExit`).
    static void Release();

    /**
     * The reflection a body's surface samples: the meshes mirrored at its level when it is the
     * level `SetBodyReflection` was given, otherwise a cleared target, so a lake reflects the
     * sky and not units mirrored at the sea.
     */
    [[nodiscard]] static std::shared_ptr<ID3DRenderTarget> ReflectionFor(float level);

    /// The cleared reflection target: what a water that is no mirror at a plane (a river) samples.
    [[nodiscard]] static std::shared_ptr<ID3DRenderTarget> EmptyReflection();

    /// Set by the reflection pass each frame: the body level it mirrored at (or none) and the targets.
    static void SetBodyReflection(
      bool mirrored,
      float level,
      const std::shared_ptr<ID3DRenderTarget>& bodyTarget,
      const std::shared_ptr<ID3DRenderTarget>& emptyTarget
    );
  };
} // namespace moho
