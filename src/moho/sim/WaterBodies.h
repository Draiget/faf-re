#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace moho
{
  /// The water level of a place with no water, as every reader of `STIMap`'s level uses it.
  inline constexpr float kWaterBodyNoWater = -10000.0f;

  /// Segments per span when a body's outline spline is turned into a polygon.
  inline constexpr std::int32_t kWaterBodyOutlineSteps = 8;

  /**
   * Engine addition: the polygon of a closed uniform Catmull-Rom spline through `points`
   * (`x, z` pairs), `kWaterBodyOutlineSteps` points per span, as `x, z` pairs. Empty when there
   * are fewer than 3 points.
   */
  [[nodiscard]] std::vector<float> WaterBodyOutlinePolygon(const std::vector<float>& points);

  /// Engine addition: even-odd test of `(x, z)` against `polygon` (`x, z` pairs).
  [[nodiscard]] bool WaterBodyPolygonContains(const std::vector<float>& polygon, float x, float z) noexcept;

  /**
   * Engine addition, not in the binary: one water body as a map describes it
   * (`ScenarioInfo.WaterBodies`, see .plans/water-levels/PLAN.md). Its water
   * fills the terrain connected to the seed that lies below `fillTo`, up to
   * `elevation`.
   */
  struct SWaterBodyDesc
  {
    /// The water level; ignored when `dry`.
    float elevation{0.0f};
    /// Shading levels, as the map's `mWaterElevationDeep` and `mWaterElevationAbyss`.
    float deep{0.0f};
    float abyss{0.0f};
    /// The fill admits a height-field vertex whose terrain is below this.
    float fillTo{0.0f};
    /// World position inside the body; its nearest vertex starts the fill. Without a seed (only
    /// allowed with an outline) every vertex inside the outline and below `fillTo` is the body's.
    bool hasSeed{true};
    float seedX{0.0f};
    float seedZ{0.0f};
    /**
     * Optional outline: control points `x0, z0, x1, z1, ...` (world units) of a closed uniform
     * Catmull-Rom spline, at least 3 points. The fill stays inside the curve. Tessellated with
     * `kWaterBodyOutlineSteps` segments per span, then tested even-odd, all in float with no
     * library maths, so every machine gets the same vertices.
     */
    std::vector<float> outline;
    /// No water: a dry area below a surrounding level (for example a polder below the sea).
    bool dry{false};
    /// When set, the fill stays inside vertices `[x0, x1] x [z0, z1]`.
    bool hasBounds{false};
    std::int32_t x0{0};
    std::int32_t z0{0};
    std::int32_t x1{0};
    std::int32_t z1{0};
  };

  /// One filled body.
  struct SWaterBody
  {
    /// `kWaterBodyNoWater` for a dry body.
    float elevation{kWaterBodyNoWater};
    float deep{kWaterBodyNoWater};
    float abyss{kWaterBodyNoWater};
    /// Cells it owns, and the rectangle of cells `[x0, x1) x [z0, z1)` holding them.
    std::uint32_t cellCount{0};
    std::int32_t x0{0};
    std::int32_t z0{0};
    std::int32_t x1{0};
    std::int32_t z1{0};
  };

  /**
   * Engine addition, not in the binary: the water bodies of one map, filled over
   * its height field. Each height-field vertex and each cell belongs to the sea
   * (0) or to one body (1..255). A cell belongs to the lowest-numbered body that
   * owns one of its four corners, so a body's cells cover every point whose
   * terrain lies below its level.
   */
  class CWaterBodies
  {
  public:
    /**
     * Fills `descs` in order over `heights` (`width * height` vertex samples, row
     * by row, each times `heightScale` in world units). A vertex taken by an
     * earlier body stays with it. A body whose seed is off the map or not below
     * its fill level, or past the 255th, is skipped and a line saying why is added
     * to `log`. Null when no body owns a cell.
     */
    [[nodiscard]] static std::unique_ptr<CWaterBodies> Build(
      const std::uint16_t* heights,
      std::int32_t width,
      std::int32_t height,
      float heightScale,
      const std::vector<SWaterBodyDesc>& descs,
      std::vector<std::string>* log
    );

    CWaterBodies(const CWaterBodies&) = default;
    CWaterBodies& operator=(const CWaterBodies&) = default;

    [[nodiscard]] std::int32_t CellWidth() const noexcept { return mVertexWidth - 1; }
    [[nodiscard]] std::int32_t CellHeight() const noexcept { return mVertexHeight - 1; }

    /// Number of bodies; body numbers run from 1 to this.
    [[nodiscard]] std::size_t BodyCount() const noexcept { return mBodies.size(); }

    /// Body `number` (1-based).
    [[nodiscard]] const SWaterBody& Body(std::uint8_t number) const { return mBodies[number - 1u]; }

    /// The body of a cell, clamped to the map; 0 for the sea.
    [[nodiscard]] std::uint8_t BodyOfCell(std::int32_t x, std::int32_t z) const noexcept;

    /// The body of a vertex, clamped to the map; 0 for the sea.
    [[nodiscard]] std::uint8_t BodyOfVertex(std::int32_t x, std::int32_t z) const noexcept;

    /// The water level at world `(x, z)`: its cell's body's, else `seaLevel`.
    [[nodiscard]] float LevelAt(float x, float z, float seaLevel) const noexcept;

    /// The water level at vertex `(x, z)`: its body's, else `seaLevel`.
    [[nodiscard]] float LevelOfVertex(std::int32_t x, std::int32_t z, float seaLevel) const noexcept;

    /// The highest water level of any body.
    [[nodiscard]] float HighestLevel() const noexcept;

    /**
     * The body of the 2 x 2 cells whose first corner is vertex `(x, z)`, one texel of the
     * terrain's half-resolution water map: the lowest body number among them, else 0.
     */
    [[nodiscard]] std::uint8_t BodyOfBlock(std::int32_t x, std::int32_t z) const noexcept;

    /// Different for every `Build` in this process (a copy keeps it), so a renderer can tell
    /// that the bodies it drew are no longer the map's.
    [[nodiscard]] std::uint32_t Generation() const noexcept { return mGeneration; }

  private:
    CWaterBodies() = default;

    std::uint32_t mGeneration{0};
    std::int32_t mVertexWidth{0};
    std::int32_t mVertexHeight{0};
    std::vector<std::uint8_t> mVertexBody;
    std::vector<std::uint8_t> mCellBody;
    std::vector<SWaterBody> mBodies;
  };
} // namespace moho
