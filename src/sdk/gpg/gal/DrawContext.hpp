#pragma once

#include <cstdint>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47B30
     * COL:     0x00E53080
     */
    class DrawContext
    {
    public:
        /**
         * Address: 0x0093F060 (FUN_0093F060)
         *
         * What it does:
         * Initializes non-indexed draw payload lanes for topology token,
         * primitive-count input, and start-vertex offset.
         */
        DrawContext(std::uint32_t topologyToken, std::uint32_t primitiveCountInput, std::uint32_t startVertex);

        /**
         * Address: 0x0093F080 (FUN_0093F080, gpg::gal::DrawContext::~DrawContext)
         * Address: 0x0093F140 (FUN_0093F140)
         *
         * What it does:
         * Restores DrawContext vftable ownership and services deleting
         * destructor thunk teardown.
         */
        virtual ~DrawContext();

        std::uint32_t topologyToken_ = 0;       // +0x04
        std::uint32_t primitiveCountInput_ = 0; // +0x08
        std::uint32_t startVertex_ = 0;         // +0x0C
    };

    static_assert(sizeof(DrawContext) == 0x10, "DrawContext size must be 0x10");
}
