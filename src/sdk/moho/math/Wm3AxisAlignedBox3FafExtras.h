#pragma once
// FAF SDK extras: forward declaration of `moho::Empty<T>()` template helpers
// (from src/sdk/wm3/AABB.h before that directory was removed). The
// `Wm3::AxisAlignedBox3f` specialization is defined in
// Wm3AxisAlignedBox3FafExtras.cpp.
#include "Wm3AxisAlignedBox3.h"

namespace moho
{
    template <class T>
    [[nodiscard]] const T& Empty();

    /**
     * Address: 0x00472BB0 (FUN_00472BB0, Moho::Empty<Wm3::AxisAlignedBox3<float>>)
     */
    template <>
    [[nodiscard]] const Wm3::AxisAlignedBox3f& Empty<Wm3::AxisAlignedBox3f>();
}
