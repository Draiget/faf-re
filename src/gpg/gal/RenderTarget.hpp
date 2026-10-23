#pragma once

#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.h"
#include "platform/Platform.h"

namespace gpg::gal
{
    class RenderTargetContext;

    /**
     * VFTABLE: 0x00D42EAC
     * COL:  0x00E50A1C
     *
     * The backend-neutral colour target. `RenderTargetD3D9` (vtable 0x00D42EBC)
     * and `RenderTargetD3D10` (0x00D43794) implement it; everything above the
     * backends holds one as `boost::shared_ptr<RenderTarget>` - the shipped
     * symbols spell it that way, e.g.
     * `?Render@Cartographic@Moho@@QAEXV?$shared_ptr@VRenderTarget@gal@gpg@@@boost@@...`.
     * The RTTI base array puts `boost::noncopyable` at mdisp 4 with the
     * private-base attribute (0x4D).
     */
    class RenderTarget : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x008F5250 (FUN_008F5250)
         *
         * What it does:
         * Installs the abstract render-target vtable.
         */
        RenderTarget();

        /**
         * Slot: 0 (`_purecall` in the base table, so the destructor is pure)
         *
         * What it does:
         * Derived destructors reinstall 0x00D42EAC as their last step
         * (0x008F53F1 in `RenderTargetD3D9`, 0x00902EF1 in `RenderTargetD3D10`).
         */
        virtual ~RenderTarget() = 0;

        /**
         * Address: 0x008E7A10 (FUN_008E7A10)
         *
         * What it does:
         * Creates one render target on the active device - slot 11
         * (`[vtbl+0x2C]`) of `Device::GetInstance()`. Same shape as
         * `Effect::Create` (0x0093F5B0), whose export spells it
         * `?Create@Effect@gal@gpg@@SA?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@ABVEffectContext@23@@Z`.
         */
        static boost::shared_ptr<RenderTarget> Create(const RenderTargetContext& context);

        /**
         * Slot: 1
         *
         * What it does:
         * Returns the creation descriptor the target was built from.
         */
        virtual RenderTargetContext* GetContext() = 0;

        /**
         * Slot: 2
         *
         * What it does:
         * Returns a GDI device context for the target's surface
         * (`IDirect3DSurface9::GetDC` on D3D9; D3D10 answers null).
         */
        virtual HDC GetDC() = 0;
    };

    static_assert(sizeof(RenderTarget) == 0x04, "RenderTarget size must be 0x04");
} // namespace gpg::gal
