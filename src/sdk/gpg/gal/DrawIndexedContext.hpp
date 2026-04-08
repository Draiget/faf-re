#pragma once

#include <cstdint>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47B38
     * COL:     0x00E530C8
     */
    class DrawIndexedContext
    {
    public:
        /**
         * Address: 0x0093F090 (FUN_0093F090, gpg::gal::DrawIndexedContext::DrawIndexedContext)
         * Mangled: ??0DrawIndexedContext@gal@gpg@@QAE@XZ
         *
         * What it does:
         * Initializes indexed-draw payload lanes to their zero/default values.
         */
        DrawIndexedContext();

        /**
         * Address: 0x0093F0B0 (FUN_0093F0B0, gpg::gal::DrawIndexedContext::DrawIndexedContext)
         * Mangled: ??0DrawIndexedContext@gal@gpg@@QAE@W4TOPOLOGY@DrawContext@12@IIII@Z
         *
         * What it does:
         * Initializes indexed-draw payload lanes for topology, vertex count,
         * primitive count, start index, and base vertex index.
         */
        DrawIndexedContext(int topology, int numVertices, int primCount, int startIndex, int baseVertIndex);

        /**
         * Address: 0x0093F0F0 (FUN_0093F0F0, gpg::gal::DrawIndexedContext::DrawIndexedContext)
         * Mangled: ??0DrawIndexedContext@gal@gpg@@QAE@@Z
         *
         * What it does:
         * Initializes indexed-draw payload lanes, including explicit minimum
         * vertex index and base-vertex bias.
         */
        DrawIndexedContext(
            std::uint32_t topologyToken,
            std::uint32_t minVertexIndex,
            std::uint32_t vertexCount,
            std::uint32_t primitiveCountInput,
            std::uint32_t startIndex,
            std::int32_t baseVertexIndex
        );

        /**
         * Address: 0x0093F130 (FUN_0093F130, gpg::gal::DrawIndexedContext::~DrawIndexedContext)
         * Address: 0x0093F160 (FUN_0093F160)
         *
         * What it does:
         * Restores DrawIndexedContext vftable ownership and services deleting
         * destructor thunk teardown.
         */
        virtual ~DrawIndexedContext();

        std::uint32_t topologyToken_ = 0;       // +0x04
        std::uint32_t minVertexIndex_ = 0;      // +0x08
        std::uint32_t vertexCount_ = 0;         // +0x0C
        std::uint32_t primitiveCountInput_ = 0; // +0x10
        std::uint32_t startIndex_ = 0;          // +0x14
        std::int32_t baseVertexIndex_ = 0;      // +0x18
    };

    static_assert(sizeof(DrawIndexedContext) == 0x1C, "DrawIndexedContext size must be 0x1C");
}
