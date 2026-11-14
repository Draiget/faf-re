#pragma once

#include <algorithm>
#include <cstdint>

namespace gpg::gal
{
  /**
   * A rectangle copy of one surface into another: the source box [left, right) x [top, bottom) goes to (x, y) of the
   * destination. Engine addition. Direct3D 9's StretchRect and UpdateSurface fail a copy whose box or destination
   * reaches past a surface; the engine's callers (the refraction copy of a split-screen view passes the view
   * rectangle, which can be a row taller than a window) rely on a cut copy instead. The device APIs treat such a box
   * as invalid (Direct3D 12 makes the command list unusable, Vulkan's validation layers reject it, and Direct3D 11
   * leaves the result undefined), so every backend cuts the box with this first.
   */
  struct CopyRegion
  {
    std::int64_t left = 0;
    std::int64_t top = 0;
    std::int64_t right = 0;
    std::int64_t bottom = 0;
    std::int64_t x = 0;
    std::int64_t y = 0;
  };

  /**
   * Cuts `region` to the source surface and to what fits at (x, y) in the destination surface. A part that lies before
   * a surface's origin is dropped, with the destination (or source) position moving along, so the pixels that stay
   * keep their place. Returns false when nothing is left to copy.
   */
  inline bool ClampCopyRegion(
    CopyRegion& region,
    const std::int64_t sourceWidth,
    const std::int64_t sourceHeight,
    const std::int64_t destinationWidth,
    const std::int64_t destinationHeight
  ) noexcept
  {
    if (region.left < 0) {
      region.x -= region.left;
      region.left = 0;
    }
    if (region.top < 0) {
      region.y -= region.top;
      region.top = 0;
    }
    if (region.x < 0) {
      region.left -= region.x;
      region.x = 0;
    }
    if (region.y < 0) {
      region.top -= region.y;
      region.y = 0;
    }
    if (region.x >= destinationWidth || region.y >= destinationHeight) {
      return false;
    }
    region.right = std::min({region.right, sourceWidth, region.left + (destinationWidth - region.x)});
    region.bottom = std::min({region.bottom, sourceHeight, region.top + (destinationHeight - region.y)});
    return region.left < region.right && region.top < region.bottom;
  }
} // namespace gpg::gal
