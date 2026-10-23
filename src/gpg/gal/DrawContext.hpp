#pragma once

#include <cstdint>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47B30
     * COL:     0x00E53080
     *
     * One non-indexed draw: `Device::DrawPrimitive` (slot 47) takes it.
     */
    class DrawContext
    {
    public:
        /**
         * Primitive topology of a draw (`gpg::gal::DrawContext::TOPOLOGY`,
         * named by the mangled `DrawIndexedContext` constructor). Zero is not a
         * topology: both backends throw "invalid topology specified" for it.
         * The values index `D3DPRIMITIVETYPE` at 0x00D421CC one-for-one.
         */
        enum TOPOLOGY
        {
            TOPOLOGY_POINTLIST = 1,
            TOPOLOGY_LINELIST = 2,
            TOPOLOGY_LINESTRIP = 3,
            TOPOLOGY_TRIANGLELIST = 4,
            TOPOLOGY_TRIANGLESTRIP = 5,
        };

        /**
         * Address: 0x0093F060 (FUN_0093F060)
         *
         * What it does:
         * Stores the topology, the vertex count and the first vertex.
         */
        DrawContext(TOPOLOGY topology, std::uint32_t vertexCount, std::uint32_t startVertex);

        /**
         * Address: 0x0093F080 (FUN_0093F080, gpg::gal::DrawContext::~DrawContext)
         * Address: 0x0093F140 (FUN_0093F140, scalar deleting destructor)
         *
         * What it does:
         * Restores the DrawContext vtable.
         */
        virtual ~DrawContext();

        /**
         * Address: 0x0093F470 (FUN_0093F470)
         *
         * What it does:
         * The number of primitives `vertexCount_` vertices make in this
         * topology.
         */
        [[nodiscard]] std::uint32_t GetPrimitiveCount() const;

        /**
         * Address: 0x0093F180 (FUN_0093F180)
         *
         * What it does:
         * Converts `count` vertices (or indices) into a primitive count for
         * `topology`, throwing `gpg::gal::Error` ("DrawContext.cpp") when the
         * count does not fit the topology or the topology is unknown.
         */
        [[nodiscard]] static std::uint32_t CountPrimitives(TOPOLOGY topology, std::uint32_t count);

        TOPOLOGY topology_;            // +0x04
        std::uint32_t vertexCount_;    // +0x08 D3D10 Draw takes it as is; D3D9 converts it
        std::uint32_t startVertex_;    // +0x0C
    };

    static_assert(sizeof(DrawContext) == 0x10, "DrawContext size must be 0x10");
}
