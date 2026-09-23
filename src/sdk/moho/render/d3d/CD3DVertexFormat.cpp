#include "CD3DVertexFormat.h"

#include "gpg/core/utils/Global.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/VertexFormat.hpp"

namespace moho
{
  /**
   * Address: 0x0043F410 (FUN_0043F410, sub_43F410)
   *
   * What it does:
   * Initializes vftable state and clears retained vertex-format ownership lanes.
   */
  CD3DVertexFormat::CD3DVertexFormat()
    : mFormat()
  {}

  /**
   * Address: 0x0043CFC0 (FUN_0043CFC0)
   *
   * What it does:
   * Creates gal vertex format `formatCode` on the active device (through
   * `VertexFormat::Create`, 0x0043CFE6) and keeps it.
   */
  CD3DVertexFormat::CD3DVertexFormat(const std::uint32_t formatCode)
    : CD3DVertexFormat()
  {
    mFormat = gpg::gal::VertexFormat::Create(formatCode);
  }

  /**
   * Address: 0x00440CB0 (FUN_00440CB0, non-deleting body)
   * Address: 0x00440C70 (FUN_00440C70, deleting thunk)
   *
   * What it does:
   * Releases retained gal vertex-format ownership lanes during destruction.
   */
  CD3DVertexFormat::~CD3DVertexFormat() = default;

  /**
   * Address: 0x0043F430 (FUN_0043F430)
   *
   * What it does:
   * Returns the number of retained 32-bit vertex-element tokens.
   */
  std::uint32_t CD3DVertexFormat::GetElementCount() const
  {
    const auto* const vertexFormat = mFormat.get();
    if (vertexFormat == nullptr) {
      return 0;
    }

    return static_cast<std::uint32_t>(vertexFormat->streamStrides_.size());
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
    if (vertexFormat == nullptr) {
      return 0;
    }

    if (elementIndex >= vertexFormat->streamStrides_.size()) {
      return 0;
    }

    return vertexFormat->streamStrides_.data()[elementIndex];
  }

  /**
   * Address: 0x0043F460 (FUN_0043F460)
   *
   * What it does:
   * Binds the retained vertex declaration on the active gal device (slot 40,
   * `[vtbl+0xA0]`). A gal error is fatal: the handler at 0x0043F4D1 hands the
   * error's file, line and text to `gpg::Die`.
   */
  bool CD3DVertexFormat::SetVertexDeclaration()
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    try {
      device->SetVertexDeclaration(mFormat);
    } catch (const gpg::gal::Error& error) {
      gpg::Die("%s(%d) %s", error.GetRuntimeMessage(), error.GetRuntimeLine(), error.what());
    }
    return true;
  }
} // namespace moho
