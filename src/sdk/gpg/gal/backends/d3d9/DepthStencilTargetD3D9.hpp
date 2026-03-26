#pragma once

#include <cstddef>

#include "gpg/gal/DepthStencilTargetContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D421C4
     * COL:  0x00E504BC
     */
    class DepthStencilTargetD3D9
    {
    public:
        /**
         * Address: 0x008E80F0 (FUN_008E80F0)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates to depth-stencil teardown helpers.
         */
        virtual ~DepthStencilTargetD3D9();

        /**
         * Address: 0x008E7F00 (FUN_008E7F00)
         *
         * What it does:
         * Returns the embedded depth-stencil context lane at `this+0x04`.
         */
        virtual DepthStencilTargetContext* GetContext();

        /**
         * Address: 0x008E7F40 (FUN_008E7F40)
         *
         * What it does:
         * Returns the retained native depth-stencil surface lane at `this+0x18`.
         */
        void* GetSurface() const;

    public:
        DepthStencilTargetContext context_{}; // +0x04
        void* depthStencilSurface_ = nullptr; // +0x18
    };

    static_assert(offsetof(DepthStencilTargetD3D9, context_) == 0x04, "DepthStencilTargetD3D9::context_ offset must be 0x04");
    static_assert(offsetof(DepthStencilTargetD3D9, depthStencilSurface_) == 0x18, "DepthStencilTargetD3D9::depthStencilSurface_ offset must be 0x18");
    static_assert(sizeof(DepthStencilTargetD3D9) == 0x1C, "DepthStencilTargetD3D9 size must be 0x1C");
}
