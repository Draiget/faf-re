#pragma once

// Engine addition: a collision box with no rotation, for units and their weapons.

#include "Wm3Box3.h"
#include "moho/math/Vector3f.h"

namespace moho
{
  [[nodiscard]] inline Wm3::Box3f BuildAxisAlignedCollisionProbe(
    const Wm3::Vec3f& center,
    const Wm3::Vec3f& extents
  ) noexcept
  {
    Wm3::Box3f probe{};
    probe.Center[0] = center.x;
    probe.Center[1] = center.y;
    probe.Center[2] = center.z;

    probe.Axis[0][0] = 1.0f;
    probe.Axis[0][1] = 0.0f;
    probe.Axis[0][2] = 0.0f;
    probe.Axis[1][0] = 0.0f;
    probe.Axis[1][1] = 1.0f;
    probe.Axis[1][2] = 0.0f;
    probe.Axis[2][0] = 0.0f;
    probe.Axis[2][1] = 0.0f;
    probe.Axis[2][2] = 1.0f;

    probe.Extent[0] = extents.x;
    probe.Extent[1] = extents.y;
    probe.Extent[2] = extents.z;
    return probe;
  }
} // namespace moho
