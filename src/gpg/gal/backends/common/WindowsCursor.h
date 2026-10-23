#pragma once

// FAF addition, not in the shipped binary: the Windows cursor the D3D10
// backend uses in place of a hardware cursor (CursorD3D10), shared by the
// Direct3D 12 and Vulkan backends. The engine takes it for every API but
// Direct3D 9 (moho::d3d_WindowsCursor).

#include <windows.h>

namespace gpg::gal
{
  class CursorContext;
  class Texture;

  class WindowsCursor
  {
  public:
    /** True when the texture's locked bytes are R,G,B,A (else B,G,R,A, D3D9's order). */
    using RgbaQuery = bool (*)(Texture& texture);

    explicit WindowsCursor(RgbaQuery isRgba) noexcept
      : mIsRgba(isRgba)
    {}
    WindowsCursor(const WindowsCursor&) = delete;
    WindowsCursor& operator=(const WindowsCursor&) = delete;
    ~WindowsCursor();

    void Destroy() noexcept;
    HCURSOR SetCursor(const CursorContext& context);
    HCURSOR InitCursor();
    int ShowCursor(bool show);

  private:
    RgbaQuery mIsRgba = nullptr;
    HCURSOR mPreviousCursor = nullptr;
    HICON mCursorIcon = nullptr;
  };
} // namespace gpg::gal
