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

    /**
     * Ray slab-clip state used by spatial-shard ray queries.
     *
     * Layout matches the binary's hand-rolled ray state record consumed by
     * `RayBoxSlabClip` (FUN_00473DF0): origin and direction packed as 3+3
     * floats, followed by a `[tEnter, tExit]` interval that the slab clip
     * narrows in place.
     */
    struct RaySlabState
    {
        float originX{0.0f};   // +0x00
        float originY{0.0f};   // +0x04
        float originZ{0.0f};   // +0x08
        float dirX{0.0f};      // +0x0C
        float dirY{0.0f};      // +0x10
        float dirZ{0.0f};      // +0x14
        float tEnter{0.0f};    // +0x18
        float tExit{0.0f};     // +0x1C
    };

    static_assert(sizeof(RaySlabState) == 0x20, "RaySlabState size must be 0x20");

    /**
     * Address: 0x00473DF0 (FUN_00473DF0, sub_473DF0)
     *
     * What it does:
     * Clips the `[tEnter, tExit]` interval in `state` against the AABB along
     * each axis (slab method). For each axis where the direction component
     * is non-degenerate, intersects the per-slab `[t0, t1]` with the running
     * `[tEnter, tExit]` lane. Returns true when the interval is still
     * non-empty (i.e. the ray clipped the box).
     */
    [[nodiscard]] bool RayBoxSlabClip(RaySlabState& state, const Wm3::AxisAlignedBox3f& box) noexcept;
}
