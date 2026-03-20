#pragma once
#include "gpg/core/containers/FastVector.h"
#include "wm3/AABB.h"
#include "wm3/Plane3.h"

namespace moho
{
  class CGeomSolid3
  {
  public:
    CGeomSolid3() = default;
    CGeomSolid3(const CGeomSolid3& rhs);
    CGeomSolid3& operator=(const CGeomSolid3& rhs);
    CGeomSolid3(CGeomSolid3&&) = default;
    CGeomSolid3& operator=(CGeomSolid3&&) = default;

    gpg::core::FastVector<Wm3::Plane3f> vec_;

    /**
     * Address: 0x00473610 (?Intersects@CGeomSolid3@Moho@@QBE_NABV?$AxisAlignedBox3@M@Wm3@@@Z)
     *
     * Wm3::AxisAlignedBox3<float> const&
     *
     * What it does:
     * Returns true when the AABB lies on the inside side of every clipping
     * plane in the solid.
     */
    [[nodiscard]] bool Intersects(const Wm3::AxisAlignedBox3f& bounds) const;
  };

  static_assert(sizeof(CGeomSolid3) == 0x0C, "CGeomSolid3 size must be 0x0C");
} // namespace moho
