#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal stub for typeid() / TypeInfo registration.
   * Full layout recovery pending.
   */
  class CUIWorldMesh
  {
    unsigned char mPadding[0x38];
  };

  static_assert(sizeof(CUIWorldMesh) == 0x38, "CUIWorldMesh size must be 0x38");
} // namespace moho
