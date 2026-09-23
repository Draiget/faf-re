#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/DrawContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47B38
     * COL:     0x00E530C8
     *
     * One indexed draw: `Device::DrawIndexedPrimitive` (slot 46) takes it.
     * The fields are the arguments of `IDirect3DDevice9::DrawIndexedPrimitive`,
     * except that the index count stands where the primitive count goes.
     */
    class DrawIndexedContext
    {
    public:
        /**
         * Address: 0x0093F090 (FUN_0093F090)
         * Mangled: ??0DrawIndexedContext@gal@gpg@@QAE@XZ
         *
         * What it does:
         * Zeroes every field.
         */
        DrawIndexedContext();

        /**
         * Address: 0x0093F0B0 (FUN_0093F0B0)
         * Mangled: ??0DrawIndexedContext@gal@gpg@@QAE@W4TOPOLOGY@DrawContext@12@IIII@Z
         *
         * What it does:
         * A draw whose minimum vertex index is zero.
         */
        DrawIndexedContext(
            DrawContext::TOPOLOGY topology,
            std::uint32_t vertexCount,
            std::uint32_t indexCount,
            std::uint32_t startIndex,
            std::uint32_t baseVertexIndex
        );

        /**
         * Address: 0x0093F0F0 (FUN_0093F0F0)
         *
         * What it does:
         * A draw with an explicit minimum vertex index.
         */
        DrawIndexedContext(
            DrawContext::TOPOLOGY topology,
            std::uint32_t minVertexIndex,
            std::uint32_t vertexCount,
            std::uint32_t indexCount,
            std::uint32_t startIndex,
            std::int32_t baseVertexIndex
        );

        /**
         * Address: 0x0093F130 (FUN_0093F130, gpg::gal::DrawIndexedContext::~DrawIndexedContext)
         * Address: 0x0093F160 (FUN_0093F160, scalar deleting destructor)
         *
         * What it does:
         * Restores the DrawIndexedContext vtable.
         */
        virtual ~DrawIndexedContext();

        /**
         * Address: 0x0093F490 (FUN_0093F490)
         *
         * What it does:
         * The number of primitives `indexCount_` indices make in this
         * topology.
         */
        [[nodiscard]] std::uint32_t GetPrimitiveCount() const;

        DrawContext::TOPOLOGY topology_; // +0x04
        std::uint32_t minVertexIndex_;   // +0x08
        std::uint32_t vertexCount_;      // +0x0C
        std::uint32_t indexCount_;       // +0x10 D3D10 DrawIndexed takes it as is; D3D9 converts it
        std::uint32_t startIndex_;       // +0x14
        std::int32_t baseVertexIndex_;   // +0x18
    };

    static_assert(offsetof(DrawIndexedContext, topology_) == 0x04, "DrawIndexedContext::topology_ offset must be 0x04");
    static_assert(offsetof(DrawIndexedContext, indexCount_) == 0x10, "DrawIndexedContext::indexCount_ offset must be 0x10");
    static_assert(offsetof(DrawIndexedContext, baseVertexIndex_) == 0x18, "DrawIndexedContext::baseVertexIndex_ offset must be 0x18");
    static_assert(sizeof(DrawIndexedContext) == 0x1C, "DrawIndexedContext size must be 0x1C");
}
