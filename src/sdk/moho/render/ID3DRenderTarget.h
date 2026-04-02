#pragma once

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class RenderTargetD3D9;
}

namespace moho
{
  class ID3DRenderTarget
  {
  public:
    using SurfaceHandle = boost::shared_ptr<gpg::gal::RenderTargetD3D9>;

    /**
     * Address: 0x0043EC50 (FUN_0043EC50, sub_43EC50)
     *
     * What it does:
     * Initializes the base interface vftable lane for derived render targets.
     */
    ID3DRenderTarget();

    /**
     * Address: 0x0043CC90 (FUN_0043CC90, sub_43CC90)
     *
     * What it does:
     * Resets base vftable state and owns the deleting-destructor entrypoint.
     */
    virtual ~ID3DRenderTarget();

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Virtual release contract implemented by concrete render-target wrappers.
     */
    virtual void Destroy() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Copies one concrete surface handle into caller storage.
     */
    virtual SurfaceHandle& GetSurface(SurfaceHandle& outSurface) = 0;
  };

  static_assert(sizeof(ID3DRenderTarget) == 0x04, "ID3DRenderTarget size must be 0x04");
} // namespace moho
