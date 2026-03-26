#pragma once

#include <cstddef>

#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/backends/d3d9/RenderTargetD3D9.hpp"
#include "moho/containers/TDatList.h"
#include "moho/render/ID3DRenderTarget.h"

namespace moho
{
  class CD3DDevice;

  class CD3DRenderTarget : public ID3DRenderTarget
  {
  public:
    using SurfaceHandle = ID3DRenderTarget::SurfaceHandle;

    /**
     * Address: 0x0043EBC0 (FUN_0043EBC0)
     *
     * What it does:
     * Initializes intrusive-list links, clears owner lane, and seeds empty
     * render-target context/surface ownership state.
     */
    CD3DRenderTarget();

    /**
     * Address: 0x0043EC60 (FUN_0043EC60)
     *
     * CD3DDevice *,boost::shared_ptr<gpg::gal::RenderTargetD3D9>
     *
     * What it does:
     * Initializes intrusive-list links, stores owner lane, and captures one
     * incoming render-surface ownership handle.
     */
    CD3DRenderTarget(CD3DDevice* ownerDevice, SurfaceHandle surface);

    /**
     * Address: 0x0043EC30 (FUN_0043EC30, deleting thunk)
     * Address: 0x0043ED10 (FUN_0043ED10, non-deleting body)
     *
     * What it does:
     * Releases owned render-surface state, destroys embedded context lanes, and
     * unlinks this node from its intrusive ring.
     */
    ~CD3DRenderTarget() override;

    /**
     * Address: 0x0043EFF0 (FUN_0043EFF0)
     *
     * What it does:
     * Deletes this wrapper instance through the virtual destructor path.
     */
    void Destroy() override;

    /**
     * Address: 0x0043EFC0 (FUN_0043EFC0)
     *
     * boost::shared_ptr<gpg::gal::RenderTargetD3D9> &
     *
     * What it does:
     * Copies retained render-surface ownership into caller storage.
     */
    SurfaceHandle& GetSurface(SurfaceHandle& outSurface) override;

  public:
    TDatListItem<CD3DRenderTarget, void> mLink;         // +0x04
    CD3DDevice* mOwnerDevice;                           // +0x0C
    gpg::gal::RenderTargetContext mRenderTargetContext; // +0x10
    SurfaceHandle mSurface;                             // +0x20
  };

  static_assert(sizeof(CD3DRenderTarget::SurfaceHandle) == 0x08, "CD3DRenderTarget::SurfaceHandle size must be 0x08");
  static_assert(offsetof(CD3DRenderTarget, mLink) == 0x04, "CD3DRenderTarget::mLink offset must be 0x04");
  static_assert(
    offsetof(CD3DRenderTarget, mOwnerDevice) == 0x0C, "CD3DRenderTarget::mOwnerDevice offset must be 0x0C"
  );
  static_assert(
    offsetof(CD3DRenderTarget, mRenderTargetContext) == 0x10,
    "CD3DRenderTarget::mRenderTargetContext offset must be 0x10"
  );
  static_assert(offsetof(CD3DRenderTarget, mSurface) == 0x20, "CD3DRenderTarget::mSurface offset must be 0x20");
  static_assert(sizeof(CD3DRenderTarget) == 0x28, "CD3DRenderTarget size must be 0x28");
} // namespace moho
