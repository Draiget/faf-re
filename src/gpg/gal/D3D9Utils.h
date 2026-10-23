#pragma once

#include <cstdint>

#include "gpg/gal/SafeRelease.h"
#include "platform/Platform.h"

//
// Minimal cross-platform aliases for D3D9 state enums.
// On Windows the real <d3d9types.h> declares them - at global scope, where the
// SDK's own headers (<d3d9.h>, <d3dx9.h>) expect to find them.
//
#if defined(_WIN32)
#include <d3d9types.h>
#endif

namespace gpg::gal
{
  /**
   * gal buffer/texture lock flags. Every backend `Lock` translates them bit by
   * bit (0x008F5950 vertex buffer, 0x008F4E10 index buffer, 0x0094A150
   * texture): Discard -> D3DLOCK_DISCARD, ReadOnly -> D3DLOCK_READONLY, and -
   * vertex buffers only - NoOverwrite -> D3DLOCK_NOOVERWRITE.
   */
  enum class MohoD3DLockFlags : std::uint32_t
  {
    None = 0x0,
    Discard = 0x1,
    ReadOnly = 0x2,
    NoOverwrite = 0x4,
  };

#if defined(_WIN32)
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
