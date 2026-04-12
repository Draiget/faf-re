#include "Wm3AxisAlignedBox3.h"

#include <limits>

// FAF SDK helper recovered from FA at FUN_00472BB0. Lives outside
// dependencies/WildMagic3p8/ because it's FAF SDK glue. Used to live at
// src/sdk/wm3/AABB.cpp.
namespace moho
{
    template <class T>
    [[nodiscard]] const T& Empty();

    /**
     * Address: 0x00472BB0 (FUN_00472BB0, Moho::Empty<Wm3::AxisAlignedBox3<float>>)
     */
    template <>
    const Wm3::AxisAlignedBox3f& Empty<Wm3::AxisAlignedBox3f>()
    {
        static const float kPositiveInfinity = std::numeric_limits<float>::infinity();
        static const Wm3::AxisAlignedBox3f kEmpty{
            Wm3::Vector3f{kPositiveInfinity, kPositiveInfinity, kPositiveInfinity},
            Wm3::Vector3f{-kPositiveInfinity, -kPositiveInfinity, -kPositiveInfinity},
        };
        return kEmpty;
    }
} // namespace moho
