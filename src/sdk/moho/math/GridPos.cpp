#include "GridPos.h"
#include <cmath>
using namespace moho;

GridPos::GridPos(Wm3::Vec3f* wldPos, int gridSize) noexcept
    : x(0), z(0)
{
#if defined(USE_X87_COMPATIBILITY)
    // Original-style path: float reciprocal then x87-like rounding fix
    const float inv_f = 1.0f / static_cast<float>(gridSize);

    const double gx = static_cast<double>(wldPos->x * inv_f);
    const double gz = static_cast<double>(wldPos->z * inv_f);

    const double rx = std::nearbyint(gx); // round-to-nearest (ties-to-even), like FRNDINT in default mode
    const double rz = std::nearbyint(gz);

    long long ix = static_cast<long long>(rx);
    long long iz = static_cast<long long>(rz);
    if (gx < rx) --ix; // emulate: if (v < rounded) rounded -= 1 => floor(v)
    if (gz < rz) --iz;

    x = static_cast<int>(ix);
    z = static_cast<int>(iz);
#else
    // Optimized path: compute in double and use std::floor (clear & fast on modern CPUs)
    const double inv = 1.0 / static_cast<double>(gridSize);
    x = static_cast<int>(std::floor(static_cast<double>(wldPos->x) * inv));
    z = static_cast<int>(std::floor(static_cast<double>(wldPos->z) * inv));
#endif
}
