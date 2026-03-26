#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D420AC
     * COL:     0x00E503E0
     */
    class CubeRenderTargetContext
    {
    public:
        /**
         * Address: 0x008E6550 (FUN_008E6550)
         *
         * What it does:
         * Initializes cube render-target context dimensions/format lanes to zero.
         */
        CubeRenderTargetContext();

        /**
         * Address: 0x008E6570 (FUN_008E6570)
         *
         * What it does:
         * Initializes cube render-target context with explicit dimension and format.
         */
        CubeRenderTargetContext(std::uint32_t dimension, std::uint32_t format);

        /**
         * Address: 0x008E65A0 (FUN_008E65A0)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for cube render-target context handles.
         */
        virtual ~CubeRenderTargetContext();

    public:
        std::uint32_t dimension_ = 0; // +0x04
        std::uint32_t format_ = 0;    // +0x08
    };

    static_assert(offsetof(CubeRenderTargetContext, dimension_) == 0x04, "CubeRenderTargetContext::dimension_ offset must be 0x04");
    static_assert(offsetof(CubeRenderTargetContext, format_) == 0x08, "CubeRenderTargetContext::format_ offset must be 0x08");
    static_assert(sizeof(CubeRenderTargetContext) == 0x0C, "CubeRenderTargetContext size must be 0x0C");
}
