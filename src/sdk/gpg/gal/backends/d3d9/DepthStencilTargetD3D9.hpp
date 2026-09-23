#pragma once

#include <cstddef>

#include "gpg/gal/DepthStencilTarget.hpp"
#include "gpg/gal/DepthStencilTargetContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D421C4
     * COL:  0x00E504BC
     */
    class DepthStencilTargetD3D9 : public DepthStencilTarget
    {
    public:
        /**
         * Address: 0x008E8110 (FUN_008E8110, gpg::gal::DepthStencilTargetD3D9::DepthStencilTargetD3D9)
         *
         * What it does:
         * Initializes one depth-stencil target object, default-constructs the
         * embedded context lane, and binds the provided context/surface payload.
         */
        DepthStencilTargetD3D9(const DepthStencilTargetContext* context, void* depthStencilSurface);

        /**
         * Address: 0x008E80F0 (FUN_008E80F0)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates to depth-stencil teardown helpers.
         */
        ~DepthStencilTargetD3D9() override;

        /**
         * Address: 0x008E7F00 (FUN_008E7F00)
         *
         * What it does:
         * Returns the embedded depth-stencil context lane at `this+0x04`.
         */
        DepthStencilTargetContext* GetContext() override;

        /**
         * Address: 0x008E7F40 (FUN_008E7F40)
         *
         * What it does:
         * Returns the retained native depth-stencil surface lane at `this+0x18`.
         */
        void* GetSurface() const;

        /**
         * Address: 0x008E8070 (FUN_008E8070, gpg::gal::DepthStencilTargetD3D9::SetSurface)
         * Address: 0x008E7F80 (FUN_008E7F80 -- the reset-only half of this: release the surface through its COM vtable, null +0x18, then copy a default DepthStencilTargetContext over +0x04. Zero callers; formerly `ResetDepthStencilTargetOwnerRuntime` over a DepthStencilTargetOwnerRuntimeView in gpg/gal/ContextInterfaces.cpp, which had the +0x18 lane typed `boost::detail::sp_counted_base*` and called its `release()` -- the binary does `call [[handle]+8]` with `handle` pushed, which is `IUnknown::Release`, not the shared-count one. Removed 2026-09-18.)
         *
         * What it does:
         * Releases the previously retained depth-stencil surface (if any),
         * resets context lanes to defaults, then installs the provided
         * context/surface payload.
         */
        void* SetSurface(const DepthStencilTargetContext* context, void* depthStencilSurface);

    public:
        DepthStencilTargetContext context_{}; // +0x04
        void* depthStencilSurface_ = nullptr; // +0x18
    };

    static_assert(offsetof(DepthStencilTargetD3D9, context_) == 0x04, "DepthStencilTargetD3D9::context_ offset must be 0x04");
    static_assert(offsetof(DepthStencilTargetD3D9, depthStencilSurface_) == 0x18, "DepthStencilTargetD3D9::depthStencilSurface_ offset must be 0x18");
    static_assert(sizeof(DepthStencilTargetD3D9) == 0x1C, "DepthStencilTargetD3D9 size must be 0x1C");
}
