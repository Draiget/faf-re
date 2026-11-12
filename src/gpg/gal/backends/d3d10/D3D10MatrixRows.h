#pragma once

// The vertex formatters' matrix copy, apart from D3D10Private.h so that the formatters, which
// Direct3D 11, 12 and Vulkan share, build without the Direct3D 10 headers (the Linux client,
// issue #255). D3D10Private.h includes this, so the backend's files see it as before.

#include "gpg/gal/Matrix.h"

namespace gpg::gal
{
  namespace
  {
    /**
     * Address: 0x0094D490 (FUN_0094D490)
     *
     * What it does:
     * Copies rows `(0,1,2)`, `(4,5,6)`, `(8,9,10)`, `(12,13,14)` from one
     * source 4x4 matrix into four contiguous 3-float destination rows.
     */
    [[maybe_unused]] const Matrix* CopyMatrix4x3Rows(
      float* const outRow0,
      float* const outRow1,
      float* const outRow2,
      float* const outRow3,
      const Matrix& matrix
    )
    {
      float* const outRows[4] = {outRow0, outRow1, outRow2, outRow3};
      for (int row = 0; row < 4; ++row) {
        outRows[row][0] = matrix.r[row].x;
        outRows[row][1] = matrix.r[row].y;
        outRows[row][2] = matrix.r[row].z;
      }

      return &matrix;
    }
  } // namespace
} // namespace gpg::gal
