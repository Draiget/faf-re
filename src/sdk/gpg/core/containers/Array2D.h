#pragma once

#include <cstddef>

namespace gpg
{
  class Array2D
  {
  public:
    int* mData; // +0x00
    int mSizeX; // +0x04
    int mSizeY; // +0x08

    /**
     * Address: 0x005C55F0 (FUN_005C55F0, gpg::Array2D::ContainsRect)
     *
     * What it does:
     * Clamps one candidate rectangle to valid map bounds and returns true when
     * any cell in the clamped area contains a strictly positive value.
     */
    [[nodiscard]] bool ContainsRect(int x, int z, int w, int h) const;
  };

  static_assert(offsetof(Array2D, mData) == 0x00, "Array2D::mData offset must be 0x00");
  static_assert(offsetof(Array2D, mSizeX) == 0x04, "Array2D::mSizeX offset must be 0x04");
  static_assert(offsetof(Array2D, mSizeY) == 0x08, "Array2D::mSizeY offset must be 0x08");
  static_assert(sizeof(Array2D) == 0x0C, "Array2D size must be 0x0C");
} // namespace gpg
