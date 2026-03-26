#pragma once

#include <cstdint>

#include "platform/Platform.h"

namespace gpg::gal
{
  enum class MohoD3DLockFlags : std::uint32_t
  {
    None = 0x0,
    Discard = 0x1,
    NoOverwrite = 0x2,
    ReadOnly = 0x4,
  };

  //
// Minimal cross-platform aliases for D3D9 state enums.
// On Windows include <d3d9types.h>; elsewhere fall back to uint32_t.
//
#if defined(_WIN32)
#include <d3d9types.h>
  namespace d3d9
  {
    using RenderState = _D3DRENDERSTATETYPE;
    using SamplerState = _D3DSAMPLERSTATETYPE;
    using TextureStageState = _D3DTEXTURESTAGESTATETYPE;
  } // namespace d3d9
#else
  namespace d3d9
  {
    enum class RenderState : std::uint32_t
    {
    };
    enum class SamplerState : std::uint32_t
    {
    };
    enum class TextureStageState : std::uint32_t
    {
    };
  } // namespace d3d9
#endif
} // namespace gpg::gal
