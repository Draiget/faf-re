#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
namespace
{

    std::uint32_t ConvertCursorPixelRgbaToBgra(const std::uint32_t rgba) noexcept
    {
      return (rgba & 0xFF000000U) | ((rgba & 0x000000FFU) << 16U) | (rgba & 0x0000FF00U) |
        ((rgba & 0x00FF0000U) >> 16U);
    }

    /**
     * Address: 0x008F8130 (FUN_008F8130)
     *
     * What it does:
     * Builds a 32x32 ARGB cursor icon from the cursor texture: locks level 0
     * read-only (flags 2), copies the rows bottom-up with red and blue
     * swapped, and unlocks through the by-value `Unlock` (slot 4). The texture
     * handle arrives by value; its release on the way out is the parameter's
     * destruction.
     */
    HICON BuildCursorIcon(const int hotspotX, const int hotspotY, const boost::shared_ptr<Texture> texture)
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
      HBITMAP const colorBitmap = ::CreateDIBSection(
        dc, reinterpret_cast<const BITMAPINFO*>(&bitmapInfo), DIB_RGB_COLORS, &dibPixels, nullptr, 0U
      );
      ::ReleaseDC(nullptr, dc);

      const RECT wholeSurface{};
      const TextureLockRect transfer = texture->Lock(0, wholeSurface, 2);

      auto* const destinationPixels = reinterpret_cast<std::uint32_t*>(dibPixels);
      const auto* const sourceBytes = static_cast<const std::uint8_t*>(transfer.bits);
      const std::uint32_t rowPitchBytes = static_cast<std::uint32_t>(transfer.pitch);
      const auto* sourceRow = reinterpret_cast<const std::uint32_t*>(sourceBytes + (rowPitchBytes * 31U));

      for (std::uint32_t y = 0; y < 32U; ++y) {
        for (std::uint32_t x = 0; x < 32U; ++x) {
          destinationPixels[(y * 32U) + x] = ConvertCursorPixelRgbaToBgra(sourceRow[x]);
        }

        sourceRow =
          reinterpret_cast<const std::uint32_t*>(reinterpret_cast<const std::uint8_t*>(sourceRow) - rowPitchBytes);
      }

      static_cast<void>(texture->Unlock(transfer));

      HBITMAP const maskBitmap = ::CreateBitmap(32, 32, 1U, 1U, nullptr);
      ICONINFO iconInfo{};
      iconInfo.fIcon = FALSE;
      iconInfo.xHotspot = static_cast<DWORD>(hotspotX);
      iconInfo.yHotspot = static_cast<DWORD>(hotspotY);
      iconInfo.hbmMask = maskBitmap;
      iconInfo.hbmColor = colorBitmap;

      HICON const iconHandle = ::CreateIconIndirect(&iconInfo);
      ::DeleteObject(colorBitmap);
      ::DeleteObject(maskBitmap);
      return iconHandle;
    }
}


  /**
   * Address: 0x008F8100 (FUN_008F8100)
   *
   * What it does:
   * Applies the non-deleting destructor body lanes for `CursorD3D10`.
   */
  void DestroyCursorD3D10Body(CursorD3D10* const cursor) noexcept
  {
    cursor->Destroy();
  }

  /**
   * Address: 0x008F8090 (FUN_008F8090)
   *
   * What it does:
   * Initializes one cursor wrapper and clears retained cursor/icon handle lanes.
   */
  CursorD3D10::CursorD3D10()
    : previousCursor_(nullptr)
    , cursorIcon_(nullptr)
  {}

  /**
   * Address: 0x008F80B0 (FUN_008F80B0)
   *
   * void *
   *
   * What it does:
   * Rebinds one cursor instance to `CursorD3D10` vtable ownership, clears the
   * icon lane, and preserves the existing retained cursor-handle lane.
   */
  CursorD3D10* InitializeCursorD3D10WithRetainedCursorLane(
    CursorD3D10* const cursor,
    void* const reserved
  ) noexcept
  {
    if (cursor == nullptr) {
      return nullptr;
    }

    const HCURSOR retainedCursor = cursor->previousCursor_;
    ::new (static_cast<void*>(cursor)) CursorD3D10();
    cursor->previousCursor_ = retainedCursor;
    static_cast<void>(reserved);
    return cursor;
  }

  /**
   * Address: 0x008F8360 (FUN_008F8360)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to `FUN_008F8100`.
   */
  CursorD3D10::~CursorD3D10()
  {
    DestroyCursorD3D10Body(this);
  }

  /**
   * Address: 0x008F80D0 (FUN_008F80D0)
   *
   * What it does:
   * Restores the previous native cursor, destroys retained icon state, and
   * clears both cursor/icon handle lanes.
   */
  void CursorD3D10::Destroy()
  {
    ::SetCursor(previousCursor_);
    if (cursorIcon_ != nullptr) {
      ::DestroyIcon(cursorIcon_);
    }

    previousCursor_ = nullptr;
    cursorIcon_ = nullptr;
  }

  /**
   * Address: 0x008F83B0 (FUN_008F83B0)
   *
   * CursorContext const *
   *
   * What it does:
   * Resets prior cursor/icon state, builds one icon from caller cursor context,
   * applies it as the active native cursor, and stores the returned prior cursor.
   */
  HCURSOR CursorD3D10::SetCursor(const CursorContext* const context)
  {
    Destroy();

    cursorIcon_ = BuildCursorIcon(context->hotspotX_, context->hotspotY_, context->texture_);
    previousCursor_ = ::SetCursor(cursorIcon_);
    return previousCursor_;
  }

  /**
   * Address: 0x008F8430 (FUN_008F8430)
   *
   * What it does:
   * Validates icon initialization state and applies the retained icon as
   * current native cursor.
   */
  HCURSOR CursorD3D10::InitCursor()
  {
    if (cursorIcon_ == nullptr) {
      ThrowGalError("CursorD3D10.cpp", 70, "attempt to use uninitialized cursor");
    }

    return ::SetCursor(cursorIcon_);
  }

  /**
   * Address: 0x008F84F0 (FUN_008F84F0)
   *
   * bool
   *
   * What it does:
   * Validates icon initialization state and drives native show/hide cursor
   * count loops until the binary stop conditions are reached.
   */
  int CursorD3D10::ShowCursor(const bool show)
  {
    if (cursorIcon_ == nullptr) {
      ThrowGalError("CursorD3D10.cpp", 76, "attempt to use uninitialized cursor");
    }

    int result = 0;
    if (show) {
      do {
        result = ::ShowCursor(TRUE);
      } while (result < 0);
    } else {
      do {
        result = ::ShowCursor(FALSE);
      } while (result >= 0);
    }

    return result;
  }
}

