#include "ResourceDeposit.h"

#include <algorithm>
#include <limits>

#include "moho/collision/CGeomSolid3.h"
#include "moho/sim/STIMap.h"

namespace
{
  constexpr float kTerrainHeightWordScale = 1.0f / 128.0f;

  [[nodiscard]] int ClampTerrainSampleIndex(const int value, const int maxInclusive) noexcept
  {
    // Preserve binary clamp order: upper clamp first, then clamp to zero.
    int clamped = value;
    if (clamped >= maxInclusive) {
      clamped = maxInclusive;
    }
    if (clamped < 0) {
      clamped = 0;
    }
    return clamped;
  }

  void ExtendBoundsWithTerrainCorner(
    Wm3::AxisAlignedBox3f& bounds, const moho::CHeightField& field, const int worldX, const int worldZ
  ) noexcept
  {
    const int sampleX = ClampTerrainSampleIndex(worldX, field.width - 1);
    const int sampleZ = ClampTerrainSampleIndex(worldZ, field.height - 1);
    const float terrainY = static_cast<float>(field.data[sampleX + sampleZ * field.width]) * kTerrainHeightWordScale;

    const float pointX = static_cast<float>(worldX);
    const float pointZ = static_cast<float>(worldZ);
    bounds.Min.x = std::min(bounds.Min.x, pointX);
    bounds.Min.y = std::min(bounds.Min.y, terrainY);
    bounds.Min.z = std::min(bounds.Min.z, pointZ);
    bounds.Max.x = std::max(bounds.Max.x, pointX);
    bounds.Max.y = std::max(bounds.Max.y, terrainY);
    bounds.Max.z = std::max(bounds.Max.z, pointZ);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00546170 (Moho::ResourceDeposit::Intersects)
   *
   * Moho::CGeomSolid3 const&, Moho::CHeightField const&
   *
   * What it does:
   * Samples terrain heights at the deposit rectangle corners, builds a world-space
   * AABB, and tests it against the clipping solid.
   */
  bool ResourceDeposit::Intersects(const CGeomSolid3& solid, const CHeightField& field) const
  {
    Wm3::AxisAlignedBox3f bounds{
      {std::numeric_limits<float>::max(), std::numeric_limits<float>::max(), std::numeric_limits<float>::max()},
      {-std::numeric_limits<float>::max(), -std::numeric_limits<float>::max(), -std::numeric_limits<float>::max()}
    };

    ExtendBoundsWithTerrainCorner(bounds, field, footprintRect.x0, footprintRect.z0);
    ExtendBoundsWithTerrainCorner(bounds, field, footprintRect.x0, footprintRect.z1);
    ExtendBoundsWithTerrainCorner(bounds, field, footprintRect.x1, footprintRect.z0);
    ExtendBoundsWithTerrainCorner(bounds, field, footprintRect.x1, footprintRect.z1);
    return solid.Intersects(bounds);
  }
} // namespace moho
