#include "CD3DDepthStencil.h"

namespace moho
{
  /**
   * Address: 0x0043F000 (FUN_0043F000)
   *
   * What it does:
   * Initializes intrusive-list links, clears owner lane, and seeds empty
   * depth-stencil context/surface ownership state.
   */
  CD3DDepthStencil::CD3DDepthStencil()
    : mLink()
    , mOwnerDevice(nullptr)
    , mDepthContext()
    , mSurface()
  {}

  /**
   * Address: 0x0043F0A0 (FUN_0043F0A0)
   *
   * CD3DDevice *,boost::shared_ptr<gpg::gal::DepthStencilTarget>
   *
   * What it does:
   * Initializes intrusive-list links, stores owner lane, and captures one
   * incoming depth-stencil surface ownership handle.
   */
  CD3DDepthStencil::CD3DDepthStencil(
    CD3DDevice* const ownerDevice, const SurfaceHandle surface
  )
    : mLink()
    , mOwnerDevice(ownerDevice)
    , mDepthContext()
    , mSurface(surface)
  {}

  /**
   * Address: 0x0043F070 (FUN_0043F070, deleting thunk)
   * Address: 0x0043F150 (FUN_0043F150, non-deleting body)
   *
   * What it does:
   * Releases owned depth-stencil surface state, destroys embedded context
   * lanes, and unlinks this node from its intrusive ring.
   */
  CD3DDepthStencil::~CD3DDepthStencil()
  {
    ReleaseSurfaceHandle();
    mLink.ListUnlink();
  }

  /**
   * Address: 0x0043F3D0 (FUN_0043F3D0)
   *
   * What it does:
   * Deletes this wrapper instance through the virtual destructor path.
   */
  void CD3DDepthStencil::Destroy()
  {
    delete this;
  }

  /**
   * Address: 0x0043F3E0 (FUN_0043F3E0)
   *
   * boost::shared_ptr<gpg::gal::DepthStencilTarget> &
   *
   * What it does:
   * Copies retained depth-stencil surface ownership into caller storage.
   */
  CD3DDepthStencil::SurfaceHandle& CD3DDepthStencil::GetSurface(SurfaceHandle& outSurface)
  {
    outSurface = mSurface;
    return outSurface;
  }

  /**
   * Address: 0x0043F320 (FUN_0043F320, sub_43F320)
   *
   * What it does:
   * Releases retained depth-stencil surface ownership and clears handle lanes.
   */
  void CD3DDepthStencil::ReleaseSurfaceHandle()
  {
    mSurface.reset();
  }

  /**
   * Address: 0x0043F230 (FUN_0043F230, sub_43F230)
   *
   * What it does:
   * Recreates the surface from the retained context through
   * `gpg::gal::DepthStencilTarget::Create` (0x0093F010).
   */
  bool CD3DDepthStencil::RecreateFromContext()
  {
    mSurface = gpg::gal::DepthStencilTarget::Create(mDepthContext);
    return true;
  }

  /**
   * Address: 0x0043F360 (FUN_0043F360, sub_43F360)
   */
  bool CD3DDepthStencil::ConfigureAndRecreate(
    CD3DDevice* const ownerDevice,
    const int width,
    const int height,
    const int format
  )
  {
    ReleaseSurfaceHandle();
    mOwnerDevice = ownerDevice;
    mDepthContext.width_ = static_cast<std::uint32_t>(width);
    mDepthContext.height_ = static_cast<std::uint32_t>(height);
    mDepthContext.format_ = static_cast<std::uint32_t>(format);
    return RecreateFromContext();
  }
} // namespace moho
