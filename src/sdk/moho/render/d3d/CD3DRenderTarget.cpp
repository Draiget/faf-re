#include "CD3DRenderTarget.h"

namespace moho
{
  /**
   * Address: 0x0043EBC0 (FUN_0043EBC0)
   *
   * What it does:
   * Initializes intrusive-list links, clears owner lane, and seeds empty
   * render-target context/surface ownership state.
   */
  CD3DRenderTarget::CD3DRenderTarget()
    : mLink()
    , mOwnerDevice(nullptr)
    , mRenderTargetContext()
    , mSurface()
  {}

  /**
   * Address: 0x0043EC60 (FUN_0043EC60)
   *
   * CD3DDevice *,boost::shared_ptr<gpg::gal::RenderTargetD3D9>
   *
   * What it does:
   * Initializes intrusive-list links, stores owner lane, and captures one
   * incoming render-surface ownership handle.
   */
  CD3DRenderTarget::CD3DRenderTarget(
    CD3DDevice* const ownerDevice, const SurfaceHandle surface
  )
    : mLink()
    , mOwnerDevice(ownerDevice)
    , mRenderTargetContext()
    , mSurface(surface)
  {}

  /**
   * Address: 0x0043EC30 (FUN_0043EC30, deleting thunk)
   * Address: 0x0043ED10 (FUN_0043ED10, non-deleting body)
   *
   * What it does:
   * Releases owned render-surface state, destroys embedded context lanes, and
   * unlinks this node from its intrusive ring.
   */
  CD3DRenderTarget::~CD3DRenderTarget()
  {
    mSurface.reset();
    mLink.ListUnlink();
  }

  /**
   * Address: 0x0043EFF0 (FUN_0043EFF0)
   *
   * What it does:
   * Deletes this wrapper instance through the virtual destructor path.
   */
  void CD3DRenderTarget::Destroy()
  {
    delete this;
  }

  /**
   * Address: 0x0043EFC0 (FUN_0043EFC0)
   *
   * boost::shared_ptr<gpg::gal::RenderTargetD3D9> &
   *
   * What it does:
   * Copies retained render-surface ownership into caller storage.
   */
  CD3DRenderTarget::SurfaceHandle& CD3DRenderTarget::GetSurface(SurfaceHandle& outSurface)
  {
    outSurface = mSurface;
    return outSurface;
  }
} // namespace moho
