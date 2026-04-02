#include "CD3DRenderTarget.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"

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
    ReleaseSurfaceHandle();
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

  /**
   * Address: 0x0043EF10 (FUN_0043EF10, sub_43EF10)
   *
   * What it does:
   * Releases retained render-target surface ownership and clears handle lanes.
   */
  void CD3DRenderTarget::ReleaseSurfaceHandle()
  {
    mSurface.reset();
  }

  /**
   * Address: 0x0043EDF0 (FUN_0043EDF0, sub_43EDF0)
   */
  bool CD3DRenderTarget::RecreateFromContext()
  {
    SurfaceHandle recreatedSurface{};
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    device->CreateVolumeTexture(&recreatedSurface, &mRenderTargetContext);
    mSurface = recreatedSurface;
    return true;
  }

  /**
   * Address: 0x0043EF50 (FUN_0043EF50, sub_43EF50)
   */
  bool CD3DRenderTarget::ConfigureAndRecreate(
    CD3DDevice* const ownerDevice,
    const int width,
    const int height,
    const int format
  )
  {
    ReleaseSurfaceHandle();
    mOwnerDevice = ownerDevice;
    mRenderTargetContext.width_ = static_cast<std::uint32_t>(width);
    mRenderTargetContext.height_ = static_cast<std::uint32_t>(height);
    mRenderTargetContext.format_ = static_cast<std::uint32_t>(format);
    return RecreateFromContext();
  }
} // namespace moho
