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
        RenderTargetD3D9() = default;

        /**
         * Address: 0x008F5620 (FUN_008F5620)
         *
         * What it does:
         * Initializes one render-target wrapper and binds caller context plus
         * one native texture payload.
         */
        RenderTargetD3D9(const RenderTargetContext* context, void* renderTexture);

        /**
         * Address: 0x008F5470 (FUN_008F5470, gpg::gal::RenderTargetD3D9::RenderTargetD3D9 `_0` overload)
         * Mangled: ??0RenderTargetD3D9@gal@gpg@@QAE@@Z_0
         *
         * What it does:
         * Surface-wrap overload used by `DeviceD3D9::CreateHeads`. Wraps one
         * pre-existing `IDirect3DSurface9*` without an owning render-target
         * context, resets lane state, stores the surface as the retained
         * render-target payload, then queries surface width/height from the
         * D3D9 surface description and caches them into the embedded
         * `RenderTargetContext` dimension lane.
         */
        explicit RenderTargetD3D9(void* backBufferSurface);

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
         * Address: 0x008F52D0 (FUN_008F52D0, Moho::D3DSurface::GetSurface)
         * Mangled: ?GetSurface@D3DSurface@Moho@@QAEPAUIDirect3DSurface9@@XZ
         *
         * What it does:
         * Returns the retained render-target texture/surface payload lane at
         * `this+0x14`. Callers in `DeviceD3D9::StretchRect`,
         * `CreateRenderTarget`, `Func4`, and `ClearTarget` use this lane as an
         * `IDirect3DSurface9*` handle.
         */
        void* GetSurface();

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

        /**
         * Address: 0x008F5500 (FUN_008F5500)
         *
         * What it does:
         * Resets prior render-target state, stores one context + texture payload,
         * then acquires and caches level-0 render surface state.
         */
        void* SetRenderTexture(const RenderTargetContext* context, void* renderTexture);

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
