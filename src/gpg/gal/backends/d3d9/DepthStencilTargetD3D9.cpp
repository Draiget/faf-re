#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{

    /**
     * Address: 0x008E7EB0 (FUN_008E7EB0)
     *
     * What it does:
     * An empty depth-stencil target.
     */
    DepthStencilTargetD3D9::DepthStencilTargetD3D9()
        : context_()
        , depthStencilSurface_(nullptr)
    {}

    /**
     * Address: 0x008E8110 (FUN_008E8110)
     *
     * What it does:
     * Wraps `depthStencilSurface` as a depth-stencil target of `context`.
     */
    DepthStencilTargetD3D9::DepthStencilTargetD3D9(
        const DepthStencilTargetContext* const context,
        IDirect3DSurface9* const depthStencilSurface
    )
        : context_()
        , depthStencilSurface_(nullptr)
    {
        SetSurface(context, depthStencilSurface);
    }

    /**
     * Address: 0x008E7FD0 (FUN_008E7FD0)
     * Address: 0x008E80F0 (FUN_008E80F0, scalar deleting destructor)
     *
     * What it does:
     * Releases the surface.
     */
    DepthStencilTargetD3D9::~DepthStencilTargetD3D9()
    {
        Reset();
    }

    /**
     * Address: 0x008E7F80 (FUN_008E7F80)
     *
     * What it does:
     * Releases the surface and empties the context. The destructor and
     * `SetSurface` inline it.
     */
    void DepthStencilTargetD3D9::Reset()
    {
        SafeRelease(depthStencilSurface_);
        context_ = DepthStencilTargetContext();
    }

    /**
     * Address: 0x008E7F00 (FUN_008E7F00)
     *
     * What it does:
     * Returns the target's context.
     */
    DepthStencilTargetContext* DepthStencilTargetD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x008E7F40 (FUN_008E7F40)
     *
     * What it does:
     * Returns the depth-stencil surface.
     */
    IDirect3DSurface9* DepthStencilTargetD3D9::GetSurface() const
    {
        return depthStencilSurface_;
    }

    /**
     * Address: 0x008E8070 (FUN_008E8070)
     *
     * What it does:
     * Replaces the surface and the context.
     */
    void DepthStencilTargetD3D9::SetSurface(
        const DepthStencilTargetContext* const context,
        IDirect3DSurface9* const depthStencilSurface
    )
    {
        Reset();
        context_ = *context;
        depthStencilSurface_ = depthStencilSurface;
    }
}

