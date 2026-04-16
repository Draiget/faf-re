#pragma once

#include <cstddef>

#include "gpg/gal/RenderTargetContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D43794
     * COL:  0x00E5114C
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\RenderTargetD3D10.cpp
     */
    class RenderTargetD3D10
    {
    public:
        /**
         * Address: 0x00902D20 (FUN_00902D20, ??0RenderTargetD3D10@gal@gpg@@QAE@@Z)
         *
         * What it does:
         * Initializes default context lanes and clears retained D3D10 pointers.
         */
        RenderTargetD3D10();

        /**
         * Address: 0x00902FE0 (FUN_00902FE0)
         *
         * void *,void *,void *
         *
         * What it does:
         * Initializes one render-target wrapper from retained texture/view pointers and
         * derives context width/height/format from the source texture descriptor.
         */
        RenderTargetD3D10(void* renderTexture, void* renderTargetView, void* shaderResourceView);

        /**
         * Address: 0x00903050 (FUN_00903050)
         *
         * RenderTargetContext const *,void *,void *,void *
         *
         * What it does:
         * Initializes one render-target wrapper from caller-provided context metadata and
         * retained texture/view pointers.
         */
        RenderTargetD3D10(
            const RenderTargetContext* context,
            void* renderTexture,
            void* renderTargetView,
            void* shaderResourceView
        );

        /**
         * Address: 0x00902FC0 (FUN_00902FC0)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates body lanes to `FUN_00902EB0`.
         */
        virtual ~RenderTargetD3D10();

        /**
         * Address: 0x00902D80 (FUN_00902D80)
         *
         * What it does:
         * Returns the embedded render-target context lane at `this+0x04`.
         */
        virtual RenderTargetContext* GetContext();

        /**
         * Address: 0x00902D70 (FUN_00902D70)
         *
         * What it does:
         * D3D10 render-target slot returns null surface-level payload.
         */
        virtual void* GetSurfaceLevel0();

        /**
         * Address: 0x00902E30 (FUN_00902E30)
         *
         * What it does:
         * Releases retained D3D10 resource/view pointers and resets context lanes.
         */
        void DestroyState();

        /**
         * Address: 0x00902F10 (FUN_00902F10)
         *
         * void *,void *,void *
         *
         * What it does:
         * Reinitializes state from retained texture/view pointers and rebuilds context
         * width/height/format from texture descriptor lanes.
         */
        void InitializeFromResource(void* renderTexture, void* renderTargetView, void* shaderResourceView);

        /**
         * Address: 0x009030E0 (FUN_009030E0)
         *
         * What it does:
         * Validates and returns the retained render-texture lane.
         */
        void* GetRenderTextureOrThrow();

        /**
         * Address: 0x00903190 (FUN_00903190)
         *
         * What it does:
         * Validates and returns the retained render-target-view lane.
         */
        void* GetRenderTargetViewOrThrow();

        /**
         * Address: 0x00903240 (FUN_00903240)
         *
         * What it does:
         * Validates and returns the retained shader-resource-view lane.
         */
        void* GetShaderResourceViewOrThrow();

    public:
        RenderTargetContext context_{};    // +0x04
        void* renderTexture_ = nullptr;    // +0x14
        void* renderTargetView_ = nullptr; // +0x18
        void* shaderResourceView_ = nullptr; // +0x1C
    };

    static_assert(offsetof(RenderTargetD3D10, context_) == 0x04, "RenderTargetD3D10::context_ offset must be 0x04");
    static_assert(offsetof(RenderTargetD3D10, renderTexture_) == 0x14, "RenderTargetD3D10::renderTexture_ offset must be 0x14");
    static_assert(offsetof(RenderTargetD3D10, renderTargetView_) == 0x18, "RenderTargetD3D10::renderTargetView_ offset must be 0x18");
    static_assert(offsetof(RenderTargetD3D10, shaderResourceView_) == 0x1C, "RenderTargetD3D10::shaderResourceView_ offset must be 0x1C");
    static_assert(sizeof(RenderTargetD3D10) == 0x20, "RenderTargetD3D10 size must be 0x20");
}
