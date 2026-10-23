#pragma once

#include <cstddef>

#include <d3d9.h>

#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/RenderTargetContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D42EBC
     * COL:  0x00E50A68
     */
    class RenderTargetD3D9 : public RenderTarget
    {
    public:
        /**
         * Address: 0x008F5260 (FUN_008F5260)
         *
         * What it does:
         * Initializes one empty D3D9 render-target wrapper with default context
         * and cleared retained texture/surface lanes.
         */
        RenderTargetD3D9();

        /**
         * Address: 0x008F5620 (FUN_008F5620)
         *
         * What it does:
         * Initializes one render-target wrapper and binds caller context plus
         * one native texture payload.
         */
        RenderTargetD3D9(const RenderTargetContext* context, IDirect3DTexture9* renderTexture);

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
        explicit RenderTargetD3D9(IDirect3DSurface9* backBufferSurface);

        /**
         * Address: 0x008F53B0 (FUN_008F53B0)
         * Address: 0x008F5450 (FUN_008F5450, scalar deleting destructor)
         *
         * What it does:
         * Releases the surface and the texture.
         */
        ~RenderTargetD3D9() override;

        /**
         * Address: 0x008F5350 (FUN_008F5350)
         *
         * What it does:
         * Releases the surface and the texture and empties the context.
         */
        void Reset();

        /**
         * Address: 0x008F5410 (FUN_008F5410)
         *
         * What it does:
         * Takes `surface` over and sizes the context from its description.
         * The surface constructor (0x008F5470) inlines it.
         */
        void SetSurface(IDirect3DSurface9* surface);

        /**
         * Address: 0x008F52C0 (FUN_008F52C0)
         *
         * What it does:
         * Returns the embedded render-target context lane at `this+0x04`.
         */
        RenderTargetContext* GetContext() override;

        /**
         * Address: 0x008F52D0 (FUN_008F52D0, Moho::D3DSurface::GetSurface)
         * Mangled: ?GetSurface@D3DSurface@Moho@@QAEPAUIDirect3DSurface9@@XZ
         *
         * What it does:
         * Returns the retained `IDirect3DSurface9*` lane at `this+0x14`. All
         * five callers consume it as a surface: `DeviceD3D9::StretchRect`
         * (both operands), `CreateRenderTarget`, `Func4`
         * (`D3DXSaveSurfaceToFile`), and `ClearTarget` (`SetRenderTarget`).
         */
        IDirect3DSurface9* GetSurface();

        /**
         * Address: 0x008F52E0 (FUN_008F52E0)
         *
         * What it does:
         * Returns the texture at `this+0x18`. Its single caller is
         * `EffectVariableD3D9::SetRenderTarget`, which hands it straight to
         * `ID3DXEffect::SetTexture` - the texture, not the surface derived
         * from it.
         */
        IDirect3DTexture9* GetTexture();

        /**
         * Address: 0x008F5300 (FUN_008F5300)
         *
         * IDA signature:
         * int __userpurge sub_8F5300@<eax>(RenderTargetD3D9 *this@<ecx>);
         *
         * What it does:
         * Returns a GDI device context for the retained render surface -
         * `IDirect3DSurface9::GetDC` (vtable slot 15) on the `this+0x14`
         * lane - or null when there is no surface.
         */
        HDC GetDC() override;

        /**
         * Address: 0x008F5500 (FUN_008F5500)
         *
         * What it does:
         * Resets prior render-target state, stores one context + texture payload,
         * then acquires and caches level-0 render surface state.
         */
        void SetRenderTexture(const RenderTargetContext* context, IDirect3DTexture9* renderTexture);

    public:
        RenderTargetContext context_{}; // +0x04
        // `SetRenderTexture` (0x008F5500) stores the caller's texture at +0x18
        // and writes `GetSurfaceLevel(texture, 0)` into +0x14; the surface lane
        // is then the object `GetDesc` (slot 12) and `GetDC` (slot 15) are
        // dispatched on. Keep the two apart - handing D3DX the surface where a
        // texture belongs faults inside the d3d9 draw, not at bind time.
        IDirect3DSurface9* surface_ = nullptr; // +0x14
        IDirect3DTexture9* texture_ = nullptr; // +0x18
    };

    static_assert(offsetof(RenderTargetD3D9, context_) == 0x04, "RenderTargetD3D9::context_ offset must be 0x04");
    static_assert(offsetof(RenderTargetD3D9, surface_) == 0x14, "RenderTargetD3D9::surface_ offset must be 0x14");
    static_assert(offsetof(RenderTargetD3D9, texture_) == 0x18, "RenderTargetD3D9::texture_ offset must be 0x18");
    static_assert(sizeof(RenderTargetD3D9) == 0x1C, "RenderTargetD3D9 size must be 0x1C");
}
