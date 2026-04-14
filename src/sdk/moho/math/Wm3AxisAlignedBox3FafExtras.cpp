#include "Wm3AxisAlignedBox3FafExtras.h"

#include <cmath>
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

    namespace
    {
        // Smallest positive normal float; matches `1.1754944e-38` literal used by
        // the binary at FUN_00473DF0 to gate near-degenerate ray directions.
        constexpr float kRaySlabMinDirMagnitude = std::numeric_limits<float>::min();

        /**
         * Per-axis slab clip lane lifted from FUN_00473DF0. Mirrors the binary's
         * branchy behavior: pick the entry/exit ordering by direction sign so the
         * caller never has to do an `fabs(dir)` swap.
         */
        void ClipAxis(
            const float origin,
            const float direction,
            const float boxMin,
            const float boxMax,
            float& tEnter,
            float& tExit
        ) noexcept
        {
            if (std::fabs(direction) < kRaySlabMinDirMagnitude) {
                return;
            }

            const float invDir = 1.0f / direction;
            float t0 = (boxMin - origin) * invDir;
            float t1 = (boxMax - origin) * invDir;

            if (direction <= 0.0f) {
                if (t1 > tEnter) {
                    tEnter = t1;
                }
                if (t0 < tExit) {
                    tExit = t0;
                }
            } else {
                if (t0 > tEnter) {
                    tEnter = t0;
                }
                if (t1 < tExit) {
                    tExit = t1;
                }
            }
        }
    } // namespace

    /**
     * Address: 0x00473DF0 (FUN_00473DF0, sub_473DF0)
     *
     * IDA signature:
     * BOOL __fastcall sub_473DF0(float* a1@<ecx>, Wm3::AxisAlignedBox3f* a2@<edx>);
     *
     * What it does:
     * Slab-clip a ray against an axis-aligned box. The ray state holds origin
     * + direction + a running `[tEnter, tExit]` interval; each axis with a
     * non-degenerate direction component contributes a slab and trims the
     * interval. Returns true when the interval is still non-empty.
     */
    bool RayBoxSlabClip(RaySlabState& state, const Wm3::AxisAlignedBox3f& box) noexcept
    {
        ClipAxis(state.originX, state.dirX, box.Min.x, box.Max.x, state.tEnter, state.tExit);
        ClipAxis(state.originY, state.dirY, box.Min.y, box.Max.y, state.tEnter, state.tExit);
        ClipAxis(state.originZ, state.dirZ, box.Min.z, box.Max.z, state.tEnter, state.tExit);
        return state.tExit >= state.tEnter;
    }
} // namespace moho
