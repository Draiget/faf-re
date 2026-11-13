#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace moho
{
  /// Segments per span when a river's centreline spline is turned into a polyline.
  inline constexpr std::int32_t kRiverDefaultSteps = 8;
  inline constexpr std::int32_t kRiverMaxSteps = 32;
  /// Units of level field kept beyond the half width (the bilinear lookup needs the rim).
  inline constexpr float kRiverDefaultMargin = 2.0f;
  inline constexpr float kRiverMinMargin = 1.0f;
  inline constexpr float kRiverMaxMargin = 16.0f;
  inline constexpr float kRiverMinHalfWidth = 1.0f;
  inline constexpr float kRiverMaxHalfWidth = 64.0f;
  inline constexpr std::size_t kRiverMinPoints = 2u;
  inline constexpr std::size_t kRiverMaxPoints = 256u;
  inline constexpr std::size_t kRiverMaxFalls = 16u;
  /// A river's vertex rectangle may hold at most this many vertices, and at most a quarter of the map's.
  inline constexpr std::size_t kRiverMaxVertices = 4u * 1024u * 1024u;
  /// The level difference between two wet corners of one cell that makes the cell a fall: a step in the
  /// surface that no unit crosses. A sim constant (the replays of a map with falls depend on it).
  inline constexpr float kRiverFallDrop = 0.75f;
  /// Levels of the field are stored in 1/128 unit steps (the height field's own), in 16 bits above a base.
  inline constexpr float kRiverLevelQuantum = 128.0f;
  /// The largest spread between a river's highest and lowest level (16 bit field minus the base's margin).
  inline constexpr float kRiverMaxLevelSpread = 500.0f;

  /// One point of a river's centreline, as `River = { Points = { { x, z, Level = , HalfWidth = , Fall = , Below = } }
  /// }`.
  struct SRiverPoint
  {
    float x{0.0f};
    float z{0.0f};
    /// The water surface where the point is; for a fall point the surface above the lip.
    float level{0.0f};
    float halfWidth{kRiverMinHalfWidth};
    /// A fall: the surface steps from `level` to `below` here.
    bool fall{false};
    float below{0.0f};
  };

  /// What a map describes for one river (the `River` key of a water body).
  struct SRiverDesc
  {
    /// Downstream order.
    std::vector<SRiverPoint> points;
    std::int32_t steps{kRiverDefaultSteps};
    float margin{kRiverDefaultMargin};
    /// Render only: multiplies the visual speed.
    float flowScale{1.0f};
  };

  /// A fall as the renderer and the editor want it: the exact line, not the staircase of fall cells.
  struct SRiverFall
  {
    float x{0.0f};
    float z{0.0f};
    /// Unit flow direction at the fall.
    float tx{0.0f};
    float tz{0.0f};
    float halfWidth{0.0f};
    float top{0.0f};
    float bottom{0.0f};
  };

  /// One straight piece of the centreline polyline.
  struct SRiverSegment
  {
    float x0{0.0f};
    float z0{0.0f};
    float x1{0.0f};
    float z1{0.0f};
    float level0{0.0f};
    float level1{0.0f};
    float half0{0.0f};
    float half1{0.0f};
    /// Distance along the river at the start of the segment, and the segment's length.
    float s0{0.0f};
    float length{0.0f};
    /// Unit direction of the segment.
    float tx{0.0f};
    float tz{0.0f};
  };

  /// The reason a river is not usable, or an empty string. Checks counts, ranges, order of levels and falls.
  [[nodiscard]] std::string ValidateRiver(const SRiverDesc& desc);

  /**
   * The centreline as a polyline: an open uniform Catmull-Rom spline through the points (end points
   * duplicated), `desc.steps` segments per span, as `WaterBodyOutlinePolygon` does for outlines: float
   * only, no library maths, so every machine gets the same segments. A fall point is a break: the span
   * before it ends at its `level`, the span after it starts at its `below`, and no segment joins them.
   * Level and half width are linear in the span parameter. `falls`, when given, receives the falls.
   * The description must be valid (`ValidateRiver`).
   */
  [[nodiscard]] std::vector<SRiverSegment> RiverSegments(const SRiverDesc& desc, std::vector<SRiverFall>* falls);

  /**
   * Engine addition, not in the binary: the water of one river over its map, derived once at load from the
   * centreline and the height field with `+ - * / sqrt` only (no pow, sin, cos or atan2), so every client
   * and every replay gets the same bytes. Immutable after `Build`.
   *
   * Per vertex of the river's rectangle: the level of the nearest centreline segment (ties: the lower
   * segment), in 1/128 unit steps; the unit flow direction as two signed bytes; whether the vertex is wet
   * (within the half width of the centreline and above the terrain); per cell: whether it is a fall (two
   * wet corners whose levels differ by `kRiverFallDrop` or more).
   */
  class CWaterRiver
  {
  public:
    /**
     * Derives the river over `heights` (`width * height` vertex samples, row by row, each times
     * `heightScale` in world units). Null with `error` set when the description is invalid, the river is
     * too large for the limits, or no vertex of it is wet.
     */
    [[nodiscard]] static std::shared_ptr<const CWaterRiver> Build(
      const SRiverDesc& desc,
      const std::uint16_t* heights,
      std::int32_t width,
      std::int32_t height,
      float heightScale,
      std::string* error
    );

    /// The vertex rectangle of the field, inclusive.
    [[nodiscard]] std::int32_t X0() const noexcept
    {
      return mX0;
    }
    [[nodiscard]] std::int32_t Z0() const noexcept
    {
      return mZ0;
    }
    [[nodiscard]] std::int32_t X1() const noexcept
    {
      return mX1;
    }
    [[nodiscard]] std::int32_t Z1() const noexcept
    {
      return mZ1;
    }

    /// The lowest and highest water level of the river (falls included).
    [[nodiscard]] float LevelMin() const noexcept
    {
      return mLevelMin;
    }
    [[nodiscard]] float LevelMax() const noexcept
    {
      return mLevelMax;
    }

    [[nodiscard]] float FlowScale() const noexcept
    {
      return mFlowScale;
    }

    /// The level field's value at vertex `(x, z)`; false outside the support.
    [[nodiscard]] bool VertexLevel(std::int32_t x, std::int32_t z, float& level) const noexcept;

    /// Whether vertex `(x, z)` is water of this river (before another body's claim).
    [[nodiscard]] bool IsWetVertex(std::int32_t x, std::int32_t z) const noexcept;

    /**
     * The surface level at world `(x, z)`: bilinear over the four corners of its cell (clamped to the
     * map), a corner outside the support taking the mean of the others. False when the cell has no corner
     * in the support.
     */
    [[nodiscard]] bool LevelAt(float x, float z, float& level) const noexcept;

    /// The unit flow direction at the vertex nearest `(x, z)`; false outside the support.
    [[nodiscard]] bool FlowAt(float x, float z, float& fx, float& fz) const noexcept;

    /// Whether cell `(cx, cz)` is a fall.
    [[nodiscard]] bool IsFallCell(std::int32_t cx, std::int32_t cz) const noexcept;

    [[nodiscard]] bool HasFalls() const noexcept
    {
      return mFallCellCount != 0u;
    }
    [[nodiscard]] std::uint32_t FallCellCount() const noexcept
    {
      return mFallCellCount;
    }
    [[nodiscard]] std::uint32_t WetVertexCount() const noexcept
    {
      return mWetVertexCount;
    }
    [[nodiscard]] const std::vector<SRiverFall>& Falls() const noexcept
    {
      return mFalls;
    }
    /// The centreline polyline, for the renderer's emitters and the editor.
    [[nodiscard]] const std::vector<SRiverSegment>& Segments() const noexcept
    {
      return mSegments;
    }

    /// FNV-1a over everything the field holds, for golden tests across builds and architectures.
    [[nodiscard]] std::uint32_t Checksum() const noexcept;

  private:
    CWaterRiver() = default;

    [[nodiscard]] std::size_t VertexIndex(
      std::int32_t x,
      std::int32_t z
    ) const noexcept
    {
      return static_cast<std::size_t>(z - mZ0) * static_cast<std::size_t>(mX1 - mX0 + 1) +
        static_cast<std::size_t>(x - mX0);
    }
    [[nodiscard]] bool InRect(
      std::int32_t x,
      std::int32_t z
    ) const noexcept
    {
      return x >= mX0 && x <= mX1 && z >= mZ0 && z <= mZ1;
    }

    std::int32_t mMapVertexWidth{0};
    std::int32_t mMapVertexHeight{0};
    std::int32_t mX0{0};
    std::int32_t mZ0{0};
    std::int32_t mX1{0};
    std::int32_t mZ1{0};
    float mBaseLevel{0.0f};
    float mLevelMin{0.0f};
    float mLevelMax{0.0f};
    float mFlowScale{1.0f};
    std::uint32_t mFallCellCount{0};
    std::uint32_t mWetVertexCount{0};
    /// Per vertex of the rectangle: (level - base) * 128 rounded, 0xFFFF outside the support.
    std::vector<std::uint16_t> mLevel;
    /// Per vertex: unit flow x, z times 127, two bytes; 0, 0 outside the support.
    std::vector<std::int8_t> mFlow;
    /// Per vertex, one bit: wet.
    std::vector<std::uint8_t> mWet;
    /// Per cell of the rectangle (`X1 - X0` by `Z1 - Z0`), one bit: fall.
    std::vector<std::uint8_t> mFallBits;
    std::vector<SRiverFall> mFalls;
    std::vector<SRiverSegment> mSegments;
  };
} // namespace moho
