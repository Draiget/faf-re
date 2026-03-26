#include "CD3DVertexFormat.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexFormatD3D9.hpp"

namespace moho
{
  /**
   * Address: 0x0043CFC0 (FUN_0043CFC0)
   *
   * std::uint32_t
   *
   * What it does:
   * Requests one gal vertex-format wrapper for the incoming format token and
   * stores retained ownership.
   */
  CD3DVertexFormat::CD3DVertexFormat(const std::uint32_t formatCode)
    : mFormat()
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return;
    }

    auto* const d3dDevice = reinterpret_cast<gpg::gal::DeviceD3D9*>(device);
    d3dDevice->CreateVertexFormat(&mFormat, formatCode);
  }

  /**
   * Address: 0x0043F430 (FUN_0043F430)
   *
   * What it does:
   * Returns the number of retained 32-bit vertex-element tokens.
   */
  std::uint32_t CD3DVertexFormat::GetElementCount() const
  {
    const auto* const vertexFormat = mFormat.get();
    if ((vertexFormat == nullptr) || (vertexFormat->elementArrayBegin_ == nullptr)) {
      return 0;
    }

    return static_cast<std::uint32_t>(vertexFormat->elementArrayEnd_ - vertexFormat->elementArrayBegin_);
  }

  /**
   * Address: 0x0043F450 (FUN_0043F450)
   *
   * std::uint32_t
   *
   * What it does:
   * Returns one retained vertex-element token by index.
   */
  std::uint32_t CD3DVertexFormat::GetElement(const std::uint32_t elementIndex) const
  {
    const auto* const vertexFormat = mFormat.get();
    if ((vertexFormat == nullptr) || (vertexFormat->elementArrayBegin_ == nullptr)) {
      return 0;
    }

    return vertexFormat->elementArrayBegin_[elementIndex];
  }

  /**
   * Address: 0x0043F460 (FUN_0043F460)
   *
   * What it does:
   * Binds the retained vertex declaration on the active gal device.
   */
  bool CD3DVertexFormat::SetVertexDeclaration()
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }

    auto* const d3dDevice = reinterpret_cast<gpg::gal::DeviceD3D9*>(device);
    d3dDevice->SetVertexDeclaration(mFormat);
    return true;
  }
} // namespace moho
