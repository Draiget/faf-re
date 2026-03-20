#pragma once

#include "Vector3.h"

namespace Wm3
{
    template <class T>
    struct AxisAlignedBox3
    {
        Vector3<T> Min{};
        Vector3<T> Max{};
    };

    using AxisAlignedBox3f = AxisAlignedBox3<float>;
    using AABBf = AxisAlignedBox3f;

    static_assert(sizeof(AxisAlignedBox3f) == 0x18, "AxisAlignedBox3f size must be 0x18");
    static_assert(sizeof(AABBf) == 0x18, "AABBf size must be 0x18");
}

namespace moho
{
    // Compatibility alias; owning layout is Wm3::AxisAlignedBox3<float>.
    using AABBf = Wm3::AxisAlignedBox3f;
    static_assert(sizeof(AABBf) == 0x18, "AABBf size must be 0x18");
}
