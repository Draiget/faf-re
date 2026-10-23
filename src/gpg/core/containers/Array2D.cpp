#include "gpg/core/containers/Array2D.h"

namespace gpg
{
  /**
   * Address: 0x005C55F0 (FUN_005C55F0, gpg::Array2D::ContainsRect)
   *
   * What it does:
   * Clamps one candidate rectangle to valid map bounds and returns true when
   * any cell in the clamped area contains a strictly positive value.
   */
  bool Array2D::ContainsRect(int x, int z, int w, int h) const
  {
    int minX = x;
    int maxX = x + w;
    int maxZ = z + h;

    if (minX < 0 || z < 0 || maxX >= mSizeX || maxZ >= mSizeY) {
      if (minX < 0) {
        minX = 0;
      }
      if (z < 0) {
        z = 0;
      }
      if (maxX >= mSizeX) {
        maxX = mSizeX;
      }
      if (maxZ >= mSizeY) {
        maxZ = mSizeY;
      }
    }

    if (maxX <= minX || z >= maxZ) {
      return false;
    }

    int row = z;
    int baseIndex = z * mSizeX;
    while (row < maxZ) {
      for (int col = minX; col < maxX; ++col) {
        if (mData[baseIndex + col] > 0) {
          return true;
        }
      }

      ++row;
      baseIndex += mSizeX;
    }

    return false;
  }
} // namespace gpg
