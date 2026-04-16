#pragma once

#include <cstddef>

#include "gpg/gal/DepthStencilTargetContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D487D0
     * COL:  0x00E537C0
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\DepthStencilTargetD3D10.cpp
     */
    class DepthStencilTargetD3D10
    {
    public:
        /**
         * Address: 0x0094B2D0 (FUN_0094B2D0)
         *
         * DepthStencilTargetContext const *,void *,void *,void *
         *
         * What it does:
         * Initializes one D3D10 depth-stencil wrapper from context + texture/DSV/SRV lanes.
         */
        DepthStencilTargetD3D10(
            const DepthStencilTargetContext* context,
            void* depthStencilTexture,
            void* depthStencilView,
            void* shaderResourceView
        );

        /**
         * Address: 0x0094B2B0 (FUN_0094B2B0)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates body lanes to `FUN_0094B210`.
         */
        virtual ~DepthStencilTargetD3D10();

        /**
         * Address: 0x0094B160 (FUN_0094B160)
         *
         * What it does:
         * Returns the embedded depth-stencil context lane at `this+0x04`.
         */
        virtual DepthStencilTargetContext* GetContext();

        /**
         * Address: 0x0094B1A0 (FUN_0094B1A0)
         *
         * What it does:
         * Releases retained depth-stencil texture/view pointers and resets context lanes.
         */
        void DestroyState();

        /**
         * Address: 0x0094B370 (FUN_0094B370)
         *
         * What it does:
         * Validates and returns the retained depth-stencil-texture lane.
         */
        void* GetDepthStencilTextureOrThrow();

        /**
         * Address: 0x0094B420 (FUN_0094B420)
         *
         * What it does:
         * Validates and returns the retained depth-stencil-view lane.
         */
        void* GetDepthStencilViewOrThrow();

        /**
         * Address: 0x0094B4D0 (FUN_0094B4D0)
         *
         * What it does:
         * Validates and returns the retained shader-resource-view lane.
         */
        void* GetShaderResourceViewOrThrow();

    public:
        DepthStencilTargetContext context_{}; // +0x04
        void* depthStencilTexture_ = nullptr; // +0x18
        void* depthStencilView_ = nullptr;    // +0x1C
        void* shaderResourceView_ = nullptr;  // +0x20
    };

    static_assert(offsetof(DepthStencilTargetD3D10, context_) == 0x04, "DepthStencilTargetD3D10::context_ offset must be 0x04");
    static_assert(offsetof(DepthStencilTargetD3D10, depthStencilTexture_) == 0x18, "DepthStencilTargetD3D10::depthStencilTexture_ offset must be 0x18");
    static_assert(offsetof(DepthStencilTargetD3D10, depthStencilView_) == 0x1C, "DepthStencilTargetD3D10::depthStencilView_ offset must be 0x1C");
    static_assert(offsetof(DepthStencilTargetD3D10, shaderResourceView_) == 0x20, "DepthStencilTargetD3D10::shaderResourceView_ offset must be 0x20");
    static_assert(sizeof(DepthStencilTargetD3D10) == 0x24, "DepthStencilTargetD3D10 size must be 0x24");
}
