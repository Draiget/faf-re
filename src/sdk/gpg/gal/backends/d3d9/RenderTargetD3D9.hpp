#pragma once

#include <cstddef>

#include "gpg/gal/RenderTargetContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D42EBC
     * COL:  0x00E50A68
     */
    class RenderTargetD3D9
    {
    public:
        /**
         * Address: 0x008F5450 (FUN_008F5450)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates to render-target teardown helpers.
         */
        virtual ~RenderTargetD3D9();

        /**
         * Address: 0x008F52C0 (FUN_008F52C0)
         *
         * What it does:
         * Returns the embedded render-target context lane at `this+0x04`.
         */
        virtual RenderTargetContext* GetContext();

        /**
         * Address: 0x008F52E0 (FUN_008F52E0)
         *
         * What it does:
         * Returns the retained render-target surface pointer lane at `this+0x18`.
         */
        void* GetRenderSurface();

        /**
         * Address: 0x008F5300 (FUN_008F5300)
         *
         * What it does:
         * Returns surface level 0 from the retained render-target texture handle.
         */
        virtual void* GetSurfaceLevel0();

    public:
        RenderTargetContext context_{}; // +0x04
        void* renderTexture_ = nullptr; // +0x14
        void* renderSurface_ = nullptr; // +0x18
    };

    static_assert(offsetof(RenderTargetD3D9, context_) == 0x04, "RenderTargetD3D9::context_ offset must be 0x04");
    static_assert(offsetof(RenderTargetD3D9, renderTexture_) == 0x14, "RenderTargetD3D9::renderTexture_ offset must be 0x14");
    static_assert(offsetof(RenderTargetD3D9, renderSurface_) == 0x18, "RenderTargetD3D9::renderSurface_ offset must be 0x18");
    static_assert(sizeof(RenderTargetD3D9) == 0x1C, "RenderTargetD3D9 size must be 0x1C");
}
