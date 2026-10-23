#pragma once

namespace gpg::gal
{
  /**
   * Address: 0x008E8710 (FUN_008E8710, SafeRelease<ID3DXBuffer>)
   * Address: 0x008E8730 (FUN_008E8730, SafeRelease<ID3DXEffectCompiler>)
   * Address: 0x008E8750 (FUN_008E8750, SafeRelease<ID3DXEffect>)
   * Address: 0x00941290 (FUN_00941290, CubeRenderTargetD3D9.cpp's copy)
   * Address: 0x0094AC70 (FUN_0094AC70, VertexFormatD3D9.cpp's copy)
   * Address: 0x008F8D90 (FUN_008F8D90, DeviceD3D10::CreateEffect's error blob)
   * Address: 0x008F8DF0 (FUN_008F8DF0, the three objects of DeviceD3D10::UpdateSurface)
   * Address: 0x008F8E10 (FUN_008F8E10)
   * Address: 0x008F8E30 (FUN_008F8E30)
   * Address: 0x008F5330 (FUN_008F5330, never called)
   *
   * What it does:
   * Releases a COM object the caller owns and clears the pointer. Both
   * backends release their interfaces this way; most sites inline it and the
   * addresses above are the out-of-line copies the compiler kept.
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
} // namespace gpg::gal
