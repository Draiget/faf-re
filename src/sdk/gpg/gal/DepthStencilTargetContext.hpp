#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47B28
     * COL:     0x00E53038
     */
    class DepthStencilTargetContext
    {
    public:
        /**
         * Address: 0x0093EF90 (FUN_0093EF90)
         *
         * What it does:
         * Initializes depth-stencil context dimensions/format/flag lanes to zero.
         */
        DepthStencilTargetContext();

        /**
         * Address: 0x0093EFB0 (FUN_0093EFB0)
         *
         * What it does:
         * Initializes depth-stencil context with explicit dimensions, format, and flag.
         */
        DepthStencilTargetContext(std::uint32_t width, std::uint32_t height, std::uint32_t format, bool field0x10);

        /**
         * Address: 0x0093EFF0 (FUN_0093EFF0)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for depth-stencil context handles.
         */
        virtual ~DepthStencilTargetContext();

    public:
        std::uint32_t width_ = 0;      // +0x04
        std::uint32_t height_ = 0;     // +0x08
        std::uint32_t format_ = 0;     // +0x0C
        bool field0x10_ = false;       // +0x10
        std::uint8_t padding0x11_[3]{}; // +0x11
    };

    static_assert(offsetof(DepthStencilTargetContext, width_) == 0x04, "DepthStencilTargetContext::width_ offset must be 0x04");
    static_assert(offsetof(DepthStencilTargetContext, height_) == 0x08, "DepthStencilTargetContext::height_ offset must be 0x08");
    static_assert(offsetof(DepthStencilTargetContext, format_) == 0x0C, "DepthStencilTargetContext::format_ offset must be 0x0C");
    static_assert(offsetof(DepthStencilTargetContext, field0x10_) == 0x10, "DepthStencilTargetContext::field0x10_ offset must be 0x10");
    static_assert(sizeof(DepthStencilTargetContext) == 0x14, "DepthStencilTargetContext size must be 0x14");
}
