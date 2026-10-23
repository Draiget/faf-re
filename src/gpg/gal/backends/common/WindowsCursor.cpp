// FAF addition, not in the shipped binary: see WindowsCursor.h.

#include "WindowsCursor.h"

#include <cstdint>

#include "BackendErrors.h"
#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/Texture.hpp"

namespace gpg::gal
{
  namespace
  {
    /**
     * A 32x32 colour cursor from the cursor texture, as the D3D10 backend's
     * `BuildCursorIcon` (0x008F8130) builds it: rows bottom-up, in the DIB's
     * B,G,R,A order.
     */
    HICON BuildCursorIcon(const int hotspotX, const int hotspotY, Texture& texture, const bool rgbaSource)
    {
      BITMAPV5HEADER bitmapInfo{};
      bitmapInfo.bV5Size = sizeof(BITMAPV5HEADER);
      bitmapInfo.bV5Width = 32L;
      bitmapInfo.bV5Height = 32L;
      bitmapInfo.bV5Planes = 1;
      bitmapInfo.bV5BitCount = 32;
      bitmapInfo.bV5Compression = BI_BITFIELDS;
      bitmapInfo.bV5RedMask = 0x00FF0000U;
      bitmapInfo.bV5GreenMask = 0x0000FF00U;
      bitmapInfo.bV5BlueMask = 0x000000FFU;
      bitmapInfo.bV5AlphaMask = 0xFF000000U;

      HDC const dc = ::GetDC(nullptr);
      void* dibPixels = nullptr;
      HBITMAP const colorBitmap =
        ::CreateDIBSection(dc, reinterpret_cast<const BITMAPINFO*>(&bitmapInfo), DIB_RGB_COLORS, &dibPixels, nullptr, 0U);
      ::ReleaseDC(nullptr, dc);
      if (colorBitmap == nullptr || dibPixels == nullptr) {
        return nullptr;
      }

      const RECT wholeSurface{};
      const TextureLockRect lock = texture.Lock(0, wholeSurface, static_cast<int>(MohoD3DLockFlags::ReadOnly));
      auto* const destination = static_cast<std::uint32_t*>(dibPixels);
      const auto* const sourceBytes = static_cast<const std::uint8_t*>(lock.bits);
      for (std::uint32_t y = 0U; y < 32U; ++y) {
        const auto* const sourceRow =
          reinterpret_cast<const std::uint32_t*>(sourceBytes + static_cast<std::size_t>(lock.pitch) * (31U - y));
        for (std::uint32_t x = 0U; x < 32U; ++x) {
          const std::uint32_t pixel = sourceRow[x];
          destination[y * 32U + x] =
            rgbaSource ? ((pixel & 0xFF00FF00U) | ((pixel & 0x000000FFU) << 16U) | ((pixel & 0x00FF0000U) >> 16U)) : pixel;
        }
      }
      static_cast<void>(texture.Unlock(lock));

      HBITMAP const maskBitmap = ::CreateBitmap(32, 32, 1U, 1U, nullptr);
      ICONINFO iconInfo{};
      iconInfo.fIcon = FALSE;
      iconInfo.xHotspot = static_cast<DWORD>(hotspotX);
      iconInfo.yHotspot = static_cast<DWORD>(hotspotY);
      iconInfo.hbmMask = maskBitmap;
      iconInfo.hbmColor = colorBitmap;
      HICON const icon = ::CreateIconIndirect(&iconInfo);
      ::DeleteObject(colorBitmap);
      ::DeleteObject(maskBitmap);
      return icon;
    }
  } // namespace

  WindowsCursor::~WindowsCursor()
  {
    Destroy();
  }

  void WindowsCursor::Destroy() noexcept
  {
    if (mCursorIcon != nullptr) {
      ::SetCursor(mPreviousCursor);
      ::DestroyIcon(mCursorIcon);
    }
    mPreviousCursor = nullptr;
    mCursorIcon = nullptr;
  }

  HCURSOR WindowsCursor::SetCursor(const CursorContext& context)
  {
    HICON const icon = (context.texture_ != nullptr)
      ? BuildCursorIcon(context.hotspotX_, context.hotspotY_, *context.texture_, mIsRgba != nullptr && mIsRgba(*context.texture_))
      : nullptr;
    HICON const previousIcon = mCursorIcon;
    mCursorIcon = icon;
    HCURSOR const previous = ::SetCursor(mCursorIcon);
    if (previousIcon == nullptr) {
      mPreviousCursor = previous;
    } else {
      ::DestroyIcon(previousIcon);
    }
    return previous;
  }

  HCURSOR WindowsCursor::InitCursor()
  {
    if (mCursorIcon == nullptr) {
      backend::ThrowError("WindowsCursor.cpp", __LINE__, "attempt to use uninitialized cursor");
    }
    return ::SetCursor(mCursorIcon);
  }

  int WindowsCursor::ShowCursor(const bool show)
  {
    if (mCursorIcon == nullptr) {
      backend::ThrowError("WindowsCursor.cpp", __LINE__, "attempt to use uninitialized cursor");
    }
    int count = 0;
    if (show) {
      do {
        count = ::ShowCursor(TRUE);
      } while (count < 0);
    } else {
      do {
        count = ::ShowCursor(FALSE);
      } while (count >= 0);
    }
    return count;
  }
} // namespace gpg::gal
