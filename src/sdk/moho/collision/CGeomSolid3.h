#pragma once
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Box3.h"
#include "Wm3Plane3.h"

namespace moho
{
  class CGeomSolid3
  {
  public:
    CGeomSolid3() = default;

    /**
     * Address: 0x004731A0 (FUN_004731A0, Moho::CGeomSolid3::CGeomSolid3)
     *
     * Wm3::Box3<float> const&
     *
     * What it does:
     * Builds six clipping planes from one oriented box center/axis/extent
     * representation.
     */
    explicit CGeomSolid3(const Wm3::Box3f& box);

    /**
     * Address: 0x004718F0 (FUN_004718F0, Moho::CGeomSolid3::CGeomSolid3)
     *
     * Moho::CGeomSolid3 const&
     *
     * What it does:
     * Rebinds this solid to inline storage and deep-copies all clipping planes.
     */
    CGeomSolid3(const CGeomSolid3& rhs);

    /**
     * Address: 0x00471A30 (FUN_00471A30, Moho::CGeomSolid3::operator=)
     *
     * Moho::CGeomSolid3 const&
     *
     * What it does:
     * Replaces this solid's plane list with rhs while preserving existing
     * allocation when capacity is sufficient.
     */
    CGeomSolid3& operator=(const CGeomSolid3& rhs);

    CGeomSolid3(CGeomSolid3&&) = default;
    CGeomSolid3& operator=(CGeomSolid3&&) = default;

    /**
     * Address: 0x00471950 (FUN_00471950)
     *
     * unsigned int, Wm3::Plane3<float> const&
     *
     * What it does:
     * Resizes the clipping plane array and fills appended entries with
     * `fillPlane`.
     */
    void ResizePlanes(std::uint32_t planeCount, const Wm3::Plane3f& fillPlane);

    gpg::core::FastVectorN<Wm3::Plane3f, 6> planes_;

    /**
     * Address: 0x00473610 (?Intersects@CGeomSolid3@Moho@@QBE_NABV?$AxisAlignedBox3@M@Wm3@@@Z)
     *
     * Wm3::AxisAlignedBox3<float> const&
     *
     * What it does:
     * Returns true when the AABB is not wholly outside any clipping plane.
     */
    [[nodiscard]] bool Intersects(const Wm3::AxisAlignedBox3f& bounds) const;

    /**
     * Address: 0x004733A0 (?Intersects@CGeomSolid3@Moho@@QBE_NABV?$Box3@M@Wm3@@@Z)
     *
     * Wm3::Box3<float> const&
     *
     * What it does:
     * Projects this solid into the oriented-box basis and tests against an
     * axis-aligned box in that local space.
     */
    [[nodiscard]] bool Intersects(const Wm3::Box3f& box) const;

    /**
     * Address: 0x00473660 (?Intersects@CGeomSolid3@Moho@@QBE_NABV?$AxisAlignedBox3@M@Wm3@@PAI@Z)
     *
     * Wm3::AxisAlignedBox3<float> const&, unsigned int*
     *
     * What it does:
     * Plane-mask variant of AABB intersection; clears mask bits for planes
     * where the box is fully inside and early-outs on first outside plane.
     */
    [[nodiscard]] bool Intersects(const Wm3::AxisAlignedBox3f& bounds, std::uint32_t* activePlaneMask) const;
  };

  static_assert(sizeof(CGeomSolid3) == 0x70, "CGeomSolid3 size must be 0x70");
} // namespace moho
