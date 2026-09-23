#pragma once

#include <cstdint>

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

  /**
   * Address: 0x008E8710 (FUN_008E8710, SafeRelease<ID3DXBuffer>)
   * Address: 0x008E8730 (FUN_008E8730, SafeRelease<ID3DXEffectCompiler>)
   * Address: 0x008E8750 (FUN_008E8750, SafeRelease<ID3DXEffect>)
   * Address: 0x00941290 (FUN_00941290, CubeRenderTargetD3D9.cpp's copy)
   * Address: 0x0094AC70 (FUN_0094AC70, VertexFormatD3D9.cpp's copy)
   *
   * What it does:
   * Releases a COM object the caller owns and clears the pointer. Every D3D9
   * wrapper releases its interfaces this way - `DeviceD3D9::Shutdown`
   * (0x008F2F70), the render-target reset (0x008F5350),
   * `DepthStencilTargetD3D9::SetSurface` (0x008E8070) all inline it. The
   * effect-creation handlers call it out of line: 0x008E8730 on the compiler,
   * 0x008E8710 on the compiled code and error buffers, 0x008E8750 on the
   * effect (0x008F0F55..0x008F0F70, 0x008F12E7, 0x008F12F0). The copies at
   * 0x00941290 and 0x0094AC70 are emitted in their wrappers' files and never
   * called.
   */
  template <class T>
  void SafeRelease(T*& object)
  {
    if (object != nullptr)
    {
      object->Release();
    }
    object = nullptr;
  }

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
