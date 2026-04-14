#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"

namespace moho
{
  struct VisibilityRect
  {
    std::int32_t minX;
    std::int32_t minZ;
    std::int32_t maxX;
    std::int32_t maxZ;

    // Identity-layout view as a gpg::Rect2i (same 4-int storage). The binary
    // routinely treats VisibilityRect and gpg::Rect2i interchangeably; this
    // keeps callers explicit at the boundary.
    [[nodiscard]] const gpg::Rect2i& AsRect2i() const noexcept
    {
      return *reinterpret_cast<const gpg::Rect2i*>(this);
    }

    [[nodiscard]] gpg::Rect2i& AsRect2i() noexcept
    {
      return *reinterpret_cast<gpg::Rect2i*>(this);
    }

    [[nodiscard]] static const VisibilityRect& FromRect2i(const gpg::Rect2i& rect) noexcept
    {
      return *reinterpret_cast<const VisibilityRect*>(&rect);
    }
  };
  static_assert(sizeof(VisibilityRect) == 0x10, "VisibilityRect size must be 0x10");
  static_assert(offsetof(VisibilityRect, minX) == 0x00, "VisibilityRect::minX offset must be 0");
  static_assert(offsetof(VisibilityRect, minZ) == 0x04, "VisibilityRect::minZ offset must be 4");
  static_assert(offsetof(VisibilityRect, maxX) == 0x08, "VisibilityRect::maxX offset must be 8");
  static_assert(offsetof(VisibilityRect, maxZ) == 0x0C, "VisibilityRect::maxZ offset must be 12");
} // namespace moho
