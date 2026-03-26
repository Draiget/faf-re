#pragma once

#include <cstddef>

#include "gpg/gal/DepthStencilTargetContext.hpp"
#include "gpg/gal/backends/d3d9/DepthStencilTargetD3D9.hpp"
#include "moho/containers/TDatList.h"
#include "moho/render/ID3DDepthStencil.h"

namespace moho
{
  class CD3DDevice;

  class CD3DDepthStencil : public ID3DDepthStencil
  {
  public:
    using SurfaceHandle = ID3DDepthStencil::SurfaceHandle;

    /**
     * Address: 0x0043F000 (FUN_0043F000)
     *
     * What it does:
     * Initializes intrusive-list links, clears owner lane, and seeds empty
     * depth-stencil context/surface ownership state.
     */
    CD3DDepthStencil();

    /**
     * Address: 0x0043F0A0 (FUN_0043F0A0)
     *
     * CD3DDevice *,boost::shared_ptr<gpg::gal::DepthStencilTargetD3D9>
     *
     * What it does:
     * Initializes intrusive-list links, stores owner lane, and captures one
     * incoming depth-stencil surface ownership handle.
     */
    CD3DDepthStencil(CD3DDevice* ownerDevice, SurfaceHandle surface);

    /**
     * Address: 0x0043F070 (FUN_0043F070, deleting thunk)
     * Address: 0x0043F150 (FUN_0043F150, non-deleting body)
     *
     * What it does:
     * Releases owned depth-stencil surface state, destroys embedded context
     * lanes, and unlinks this node from its intrusive ring.
     */
    ~CD3DDepthStencil() override;

    /**
     * Address: 0x0043F3D0 (FUN_0043F3D0)
     *
     * What it does:
     * Deletes this wrapper instance through the virtual destructor path.
     */
    void Destroy() override;

    /**
     * Address: 0x0043F3E0 (FUN_0043F3E0)
     *
     * boost::shared_ptr<gpg::gal::DepthStencilTargetD3D9> &
     *
     * What it does:
     * Copies retained depth-stencil surface ownership into caller storage.
     */
    SurfaceHandle& GetSurface(SurfaceHandle& outSurface) override;

  public:
    TDatListItem<CD3DDepthStencil, void> mLink;        // +0x04
    CD3DDevice* mOwnerDevice;                          // +0x0C
    gpg::gal::DepthStencilTargetContext mDepthContext; // +0x10
    SurfaceHandle mSurface;                            // +0x24
  };

  static_assert(
    sizeof(CD3DDepthStencil::SurfaceHandle) == 0x08, "CD3DDepthStencil::SurfaceHandle size must be 0x08"
  );
  static_assert(offsetof(CD3DDepthStencil, mLink) == 0x04, "CD3DDepthStencil::mLink offset must be 0x04");
  static_assert(
    offsetof(CD3DDepthStencil, mOwnerDevice) == 0x0C, "CD3DDepthStencil::mOwnerDevice offset must be 0x0C"
  );
  static_assert(
    offsetof(CD3DDepthStencil, mDepthContext) == 0x10, "CD3DDepthStencil::mDepthContext offset must be 0x10"
  );
  static_assert(offsetof(CD3DDepthStencil, mSurface) == 0x24, "CD3DDepthStencil::mSurface offset must be 0x24");
  static_assert(sizeof(CD3DDepthStencil) == 0x2C, "CD3DDepthStencil size must be 0x2C");
} // namespace moho
