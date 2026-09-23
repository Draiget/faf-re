#pragma once

#include <cstddef>

#include <d3d9.h>

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
         * Address: 0x008E7EB0 (FUN_008E7EB0)
         *
         * What it does:
         * An empty depth-stencil target.
         */
        DepthStencilTargetD3D9();

        /**
         * Address: 0x008E8110 (FUN_008E8110, gpg::gal::DepthStencilTargetD3D9::DepthStencilTargetD3D9)
         *
         * What it does:
         * Initializes one depth-stencil target object, default-constructs the
         * embedded context lane, and binds the provided context/surface payload.
         */
        DepthStencilTargetD3D9(const DepthStencilTargetContext* context, IDirect3DSurface9* depthStencilSurface);

        /**
         * Address: 0x008E7FD0 (FUN_008E7FD0)
         * Address: 0x008E80F0 (FUN_008E80F0, scalar deleting destructor)
         *
         * What it does:
         * Releases the surface.
         */
        ~DepthStencilTargetD3D9() override;

        /**
         * Address: 0x008E7F80 (FUN_008E7F80)
         *
         * What it does:
         * Releases the surface and empties the context. The destructor and
         * `SetSurface` inline it.
         */
        void Reset();

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
        IDirect3DSurface9* GetSurface() const;

        /**
         * Address: 0x008E8070 (FUN_008E8070, gpg::gal::DepthStencilTargetD3D9::SetSurface)
         *
         * What it does:
         * Replaces the surface and the context.
         */
        void SetSurface(const DepthStencilTargetContext* context, IDirect3DSurface9* depthStencilSurface);

    public:
        DepthStencilTargetContext context_{}; // +0x04
        IDirect3DSurface9* depthStencilSurface_ = nullptr; // +0x18
    };

    static_assert(offsetof(DepthStencilTargetD3D9, context_) == 0x04, "DepthStencilTargetD3D9::context_ offset must be 0x04");
    static_assert(offsetof(DepthStencilTargetD3D9, depthStencilSurface_) == 0x18, "DepthStencilTargetD3D9::depthStencilSurface_ offset must be 0x18");
    static_assert(sizeof(DepthStencilTargetD3D9) == 0x1C, "DepthStencilTargetD3D9 size must be 0x1C");
}
