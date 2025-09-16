#pragma once
#include <array>

namespace Wm3
{
    /** Row-major 3x4 matrix (3 rows, 4 columns) used as local transform */
    template <class T>
    struct Mat34 {
        // m[0..2]  = axis X
        // m[3]     = translation X
        // m[4..6]  = axis Y
        // m[7]     = translation Y
        // m[8..10] = axis Z
        // m[11]    = translation Z
        std::array<T, 12> m{};
    };
}
