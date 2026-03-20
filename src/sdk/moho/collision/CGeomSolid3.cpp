#include "CGeomSolid3.h"

#include <cmath>

namespace
{
  [[nodiscard]] float
  SelectSupportCoordinate(const float planeAxis, const float minValue, const float maxValue) noexcept
  {
    // Binary helper selects by sign bit, including negative zero.
    return std::signbit(planeAxis) ? minValue : maxValue;
  }

  [[nodiscard]] bool IsAabbInsidePlane(const Wm3::Plane3f& plane, const Wm3::AxisAlignedBox3f& bounds) noexcept
  {
    const float supportX = SelectSupportCoordinate(plane.Normal.x, bounds.Min.x, bounds.Max.x);
    const float supportY = SelectSupportCoordinate(plane.Normal.y, bounds.Min.y, bounds.Max.y);
    const float supportZ = SelectSupportCoordinate(plane.Normal.z, bounds.Min.z, bounds.Max.z);

    const float signedDistance =
      plane.Normal.x * supportX + plane.Normal.y * supportY + plane.Normal.z * supportZ - plane.Constant;
    return signedDistance < 0.0f;
  }
} // namespace

namespace moho
{
  CGeomSolid3::CGeomSolid3(const CGeomSolid3& rhs)
  {
    vec_.Reserve(rhs.vec_.Size());
    for (const Wm3::Plane3f& plane : rhs.vec_) {
      vec_.PushBack(plane);
    }
  }

  CGeomSolid3& CGeomSolid3::operator=(const CGeomSolid3& rhs)
  {
    if (this == &rhs) {
      return *this;
    }

    vec_.Clear();
    vec_.Reserve(rhs.vec_.Size());
    for (const Wm3::Plane3f& plane : rhs.vec_) {
      vec_.PushBack(plane);
    }

    return *this;
  }

  /**
   * Address: 0x00473610 (?Intersects@CGeomSolid3@Moho@@QBE_NABV?$AxisAlignedBox3@M@Wm3@@@Z)
   *
   * Wm3::AxisAlignedBox3<float> const&
   *
   * What it does:
   * Returns true only when the AABB remains inside every clipping plane.
   */
  bool CGeomSolid3::Intersects(const Wm3::AxisAlignedBox3f& bounds) const
  {
    for (const Wm3::Plane3f& plane : vec_) {
      if (!IsAabbInsidePlane(plane, bounds)) {
        return false;
      }
    }
    return true;
  }
} // namespace moho
