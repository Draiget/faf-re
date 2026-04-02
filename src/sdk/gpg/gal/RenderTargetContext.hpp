#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D42188
     * COL:     0x00E5F78C
     */
    class RenderTargetContext
    {
    public:
        /**
         * Address: 0x008E79C0 (FUN_008E79C0)
         *
         * What it does:
         * Initializes render-target context dimensions/format lanes to zero.
         */
        RenderTargetContext();

        /**
         * Address: 0x00442050 (FUN_00442050, sub_442050)
         *
         * What it does:
         * Copies render-target width/height/format lanes from another context.
         */
        RenderTargetContext(const RenderTargetContext& other);

        /**
         * Address: 0x00442080 (FUN_00442080)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for render-target context handles.
         */
        virtual ~RenderTargetContext();

    public:
        std::uint32_t width_ = 0;  // +0x04
        std::uint32_t height_ = 0; // +0x08
        std::uint32_t format_ = 0; // +0x0C
    };

    static_assert(offsetof(RenderTargetContext, width_) == 0x04, "RenderTargetContext::width_ offset must be 0x04");
    static_assert(offsetof(RenderTargetContext, height_) == 0x08, "RenderTargetContext::height_ offset must be 0x08");
    static_assert(offsetof(RenderTargetContext, format_) == 0x0C, "RenderTargetContext::format_ offset must be 0x0C");
    static_assert(sizeof(RenderTargetContext) == 0x10, "RenderTargetContext size must be 0x10");
}
