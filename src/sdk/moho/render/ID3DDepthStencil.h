#pragma once

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class DepthStencilTargetD3D9;
}

namespace moho
{
  class ID3DDepthStencil
  {
  public:
    using SurfaceHandle = boost::shared_ptr<gpg::gal::DepthStencilTargetD3D9>;

    /**
     * Address: 0x0043CCC0 (FUN_0043CCC0, sub_43CCC0)
     *
     * What it does:
     * Resets base vftable state and owns the deleting-destructor entrypoint.
     */
    virtual ~ID3DDepthStencil();

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Virtual release contract implemented by concrete depth-stencil wrappers.
     */
    virtual void Destroy() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Copies one concrete depth-stencil surface handle into caller storage.
     */
    virtual SurfaceHandle& GetSurface(SurfaceHandle& outSurface) = 0;
  };

  static_assert(sizeof(ID3DDepthStencil) == 0x04, "ID3DDepthStencil size must be 0x04");
} // namespace moho
