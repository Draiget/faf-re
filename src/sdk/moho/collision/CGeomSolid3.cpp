#include "CGeomSolid3.h"

#include <cstddef>
#include <cmath>

namespace
{
  [[nodiscard]] float SelectRejectCoordinate(const float planeAxis, const float minValue, const float maxValue) noexcept
  {
    // Reject-test corner selection (sub_472380): choose the corner that yields
    // the smallest signed distance against the plane.
    return std::signbit(planeAxis) ? maxValue : minValue;
  }

  [[nodiscard]] float SelectSupportCoordinate(const float planeAxis, const float minValue, const float maxValue) noexcept
  {
    // Inside-test corner selection (sub_472430): choose the corner that yields
    // the largest signed distance against the plane.
    return std::signbit(planeAxis) ? minValue : maxValue;
  }

  [[nodiscard]] bool IsAabbNotOutsidePlane(const Wm3::Plane3f& plane, const Wm3::AxisAlignedBox3f& bounds) noexcept
  {
    const float rejectX = SelectRejectCoordinate(plane.Normal.x, bounds.Min.x, bounds.Max.x);
    const float rejectY = SelectRejectCoordinate(plane.Normal.y, bounds.Min.y, bounds.Max.y);
    const float rejectZ = SelectRejectCoordinate(plane.Normal.z, bounds.Min.z, bounds.Max.z);

    const float rejectDistance =
      plane.Normal.x * rejectX + plane.Normal.y * rejectY + plane.Normal.z * rejectZ - plane.Constant;
    return rejectDistance < 0.0f;
  }

  [[nodiscard]] bool IsAabbFullyInsidePlane(const Wm3::Plane3f& plane, const Wm3::AxisAlignedBox3f& bounds) noexcept
  {
    const float supportX = SelectSupportCoordinate(plane.Normal.x, bounds.Min.x, bounds.Max.x);
    const float supportY = SelectSupportCoordinate(plane.Normal.y, bounds.Min.y, bounds.Max.y);
    const float supportZ = SelectSupportCoordinate(plane.Normal.z, bounds.Min.z, bounds.Max.z);

    const float signedDistance =
      plane.Normal.x * supportX + plane.Normal.y * supportY + plane.Normal.z * supportZ - plane.Constant;
    return signedDistance <= 0.0f;
  }

  [[nodiscard]] Wm3::Plane3f TransformPlaneToBoxBasis(const Wm3::Plane3f& plane, const Wm3::Box3f& box) noexcept
  {
    Wm3::Plane3f transformedPlane{};
    transformedPlane.Normal.x =
      (plane.Normal.x * box.Axis[0][0]) + (plane.Normal.y * box.Axis[0][1]) + (plane.Normal.z * box.Axis[0][2]);
    transformedPlane.Normal.y =
      (plane.Normal.x * box.Axis[1][0]) + (plane.Normal.y * box.Axis[1][1]) + (plane.Normal.z * box.Axis[1][2]);
    transformedPlane.Normal.z =
      (plane.Normal.x * box.Axis[2][0]) + (plane.Normal.y * box.Axis[2][1]) + (plane.Normal.z * box.Axis[2][2]);
    transformedPlane.Constant = plane.Constant;
    return transformedPlane;
  }

  [[nodiscard]] Wm3::Vector3f ProjectBoxCenterToBasis(const Wm3::Box3f& box) noexcept
  {
    const float centerX = box.Center[0];
    const float centerY = box.Center[1];
    const float centerZ = box.Center[2];
    return {
      (centerX * box.Axis[0][0]) + (centerY * box.Axis[0][1]) + (centerZ * box.Axis[0][2]),
      (centerX * box.Axis[1][0]) + (centerY * box.Axis[1][1]) + (centerZ * box.Axis[1][2]),
      (centerX * box.Axis[2][0]) + (centerY * box.Axis[2][1]) + (centerZ * box.Axis[2][2]),
    };
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004731A0 (FUN_004731A0, Moho::CGeomSolid3::CGeomSolid3)
   *
   * Wm3::Box3<float> const&
   *
   * What it does:
   * Builds six clipping planes from one oriented box center/axis/extent
   * representation.
   */
  CGeomSolid3::CGeomSolid3(const Wm3::Box3f& box)
  {
    ResizePlanes(6u, Wm3::Plane3f{});

    const float centerX = box.Center[0];
    const float centerY = box.Center[1];
    const float centerZ = box.Center[2];

    for (std::size_t axisIndex = 0; axisIndex < 3; ++axisIndex) {
      const float axisX = box.Axis[axisIndex][0];
      const float axisY = box.Axis[axisIndex][1];
      const float axisZ = box.Axis[axisIndex][2];
      const float centerProjection = (centerX * axisX) + (centerY * axisY) + (centerZ * axisZ);

      Wm3::Plane3f& positivePlane = planes_[axisIndex * 2u];
      positivePlane.Normal = {axisX, axisY, axisZ};
      positivePlane.Constant = box.Extent[axisIndex] + centerProjection;

      Wm3::Plane3f& negativePlane = planes_[axisIndex * 2u + 1u];
      negativePlane.Normal = {-0.0f - axisX, -0.0f - axisY, -0.0f - axisZ};
      negativePlane.Constant = box.Extent[axisIndex] - centerProjection;
    }
  }

  /**
   * Address: 0x004718F0 (FUN_004718F0, Moho::CGeomSolid3::CGeomSolid3)
   *
   * Moho::CGeomSolid3 const&
   *
   * What it does:
   * Rebinds this solid to inline storage and deep-copies all clipping planes.
   */
  CGeomSolid3::CGeomSolid3(const CGeomSolid3& rhs)
  {
    *this = rhs;
  }

  /**
   * Address: 0x00471A30 (FUN_00471A30, Moho::CGeomSolid3::operator=)
   *
   * Moho::CGeomSolid3 const&
   *
   * What it does:
   * Replaces this solid's plane list with rhs while preserving existing
   * allocation when capacity is sufficient.
   */
  CGeomSolid3& CGeomSolid3::operator=(const CGeomSolid3& rhs)
  {
    if (this == &rhs) {
      return *this;
    }

    const std::size_t planeCount = rhs.planes_.Size();
    planes_.Resize(planeCount);
    for (std::size_t planeIndex = 0; planeIndex < planeCount; ++planeIndex) {
      planes_[planeIndex] = rhs.planes_[planeIndex];
    }

    return *this;
  }

  /**
   * Address: 0x00471950 (FUN_00471950)
   *
   * unsigned int, Wm3::Plane3<float> const&
   *
   * What it does:
   * Resizes the clipping plane array and fills appended entries with
   * `fillPlane`.
   */
  void CGeomSolid3::ResizePlanes(const std::uint32_t planeCount, const Wm3::Plane3f& fillPlane)
  {
    planes_.Resize(planeCount, fillPlane);
  }

  /**
   * Address: 0x00473610 (?Intersects@CGeomSolid3@Moho@@QBE_NABV?$AxisAlignedBox3@M@Wm3@@@Z)
   *
   * Wm3::AxisAlignedBox3<float> const&
   *
   * What it does:
   * Returns true when the AABB is not wholly outside any clipping plane.
   */
  bool CGeomSolid3::Intersects(const Wm3::AxisAlignedBox3f& bounds) const
  {
    for (const Wm3::Plane3f& plane : planes_) {
      if (!IsAabbNotOutsidePlane(plane, bounds)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Address: 0x004733A0 (?Intersects@CGeomSolid3@Moho@@QBE_NABV?$Box3@M@Wm3@@@Z)
   *
   * Wm3::Box3<float> const&
   *
   * What it does:
   * Projects this solid into the oriented-box basis and tests against an
   * axis-aligned box in that local space.
   */
  bool CGeomSolid3::Intersects(const Wm3::Box3f& box) const
  {
    CGeomSolid3 transformedSolid;
    transformedSolid.ResizePlanes(static_cast<std::uint32_t>(planes_.Size()), Wm3::Plane3f{});
    for (std::size_t planeIndex = 0; planeIndex < planes_.Size(); ++planeIndex) {
      transformedSolid.planes_[planeIndex] = TransformPlaneToBoxBasis(planes_[planeIndex], box);
    }

    const Wm3::Vector3f projectedCenter = ProjectBoxCenterToBasis(box);
    Wm3::AxisAlignedBox3f boxSpaceBounds{};
    boxSpaceBounds.Min.x = projectedCenter.x - box.Extent[0];
    boxSpaceBounds.Min.y = projectedCenter.y - box.Extent[1];
    boxSpaceBounds.Min.z = projectedCenter.z - box.Extent[2];
    boxSpaceBounds.Max.x = projectedCenter.x + box.Extent[0];
    boxSpaceBounds.Max.y = projectedCenter.y + box.Extent[1];
    boxSpaceBounds.Max.z = projectedCenter.z + box.Extent[2];
    return transformedSolid.Intersects(boxSpaceBounds);
  }

  /**
   * Address: 0x00473660 (?Intersects@CGeomSolid3@Moho@@QBE_NABV?$AxisAlignedBox3@M@Wm3@@PAI@Z)
   *
   * Wm3::AxisAlignedBox3<float> const&, unsigned int*
   *
   * What it does:
   * Plane-mask variant of AABB intersection; clears mask bits for planes
   * where the box is fully inside and early-outs on first outside plane.
   */
  bool CGeomSolid3::Intersects(const Wm3::AxisAlignedBox3f& bounds, std::uint32_t* const activePlaneMask) const
  {
    const std::size_t planeCount = planes_.Size();
    if (planeCount == 0) {
      return true;
    }

    for (std::size_t planeIndex = 0; planeIndex < planeCount; ++planeIndex) {
      const std::uint32_t planeBit = 1u << static_cast<std::uint32_t>(planeIndex);
      if ((planeBit & *activePlaneMask) == 0u) {
        continue;
      }

      const Wm3::Plane3f& plane = planes_[planeIndex];
      if (!IsAabbNotOutsidePlane(plane, bounds)) {
        return false;
      }

      if (IsAabbFullyInsidePlane(plane, bounds)) {
        *activePlaneMask &= ~planeBit;
      }
    }

    return true;
  }
} // namespace moho
