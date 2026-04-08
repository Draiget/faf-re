#include "moho/render/tess/CTesselator.h"

namespace moho
{
  extern float ren_ShoreErrorCoeff;
  extern float ren_maxViewError;

  namespace
  {
    enum IntersectionResult : int
    {
      kSplit = 1,
      kAccept = 2,
      kReject = 3,
    };

    /**
     * Address: 0x00472340 (FUN_00472340)
     *
     * What it does:
     * Selects one AABB corner from `{Min, Max}` using a three-bit axis mask.
     */
    [[nodiscard]]
    Wm3::Vector3f SelectAabbCornerByMask(const Wm3::AxisAlignedBox3f& bounds, const std::uint32_t axisMask)
    {
      const Wm3::Vector3f* const extrema[2] = {&bounds.Min, &bounds.Max};

      Wm3::Vector3f out{};
      out.x = extrema[(axisMask >> 0u) & 1u]->x;
      out.y = extrema[(axisMask >> 1u) & 1u]->y;
      out.z = extrema[(axisMask >> 2u) & 1u]->z;
      return out;
    }
  } // namespace

  /**
   * Address: 0x0080E020 (FUN_0080E020, Moho::CTesselator::GetIntersectionResult)
   *
   * What it does:
   * Builds one tier-cell AABB, optionally clips it against active frustum
   * planes, then compares tier max error against view-scaled threshold.
   */
  int CTesselator::GetIntersectionResult(
    const int x,
    const int z,
    const int tier,
    std::uint32_t* const activePlaneMask
  )
  {
    const int cellX = x << tier;
    const int cellZ = z << tier;
    if (cellX < 0 || cellZ < 0) {
      return kReject;
    }

    if (cellX >= (mField->width - 1) || cellZ >= (mField->height - 1)) {
      return kReject;
    }

    const Wm3::Vector2f tierBounds = mField->GetTierBounds(x, z, tier);

    Wm3::AxisAlignedBox3f bounds{};
    bounds.Min.x = static_cast<float>(cellX);
    bounds.Min.y = tierBounds.x;
    bounds.Min.z = static_cast<float>(cellZ);
    bounds.Max.x = static_cast<float>(cellX + (1 << tier));
    bounds.Max.y = tierBounds.y;
    bounds.Max.z = static_cast<float>(cellZ + (1 << tier));

    const float waterElevation = mWaterElevation;
    const bool crossesWaterSurface = (waterElevation >= tierBounds.x) && (tierBounds.y >= waterElevation);

    if (*activePlaneMask != 0u) {
      float clippedMaxY = tierBounds.y;
      if (waterElevation > clippedMaxY) {
        clippedMaxY = waterElevation;
      }
      bounds.Max.y = clippedMaxY;

      if (!mGeomSolid.Intersects(bounds, activePlaneMask)) {
        return kReject;
      }

      bounds.Max.y = tierBounds.y;
    }

    const Wm3::Vector3f testCorner = SelectAabbCornerByMask(bounds, mCornerSelectionMask);
    const float tierMaxError = mField->GetTierMaxError(tier, x, z);
    const float shoreErrorCoeff = crossesWaterSurface ? ren_ShoreErrorCoeff : 1.0f;

    const Vector4f& row1 = mCam->viewport.r[1];
    const float projectedDepth =
      (row1.z * testCorner.z) + (row1.y * testCorner.y) + (row1.x * testCorner.x) + row1.w;

    const float maxAllowedError = shoreErrorCoeff * projectedDepth * ren_maxViewError;
    return (tierMaxError < maxAllowedError) ? kAccept : kSplit;
  }
} // namespace moho
