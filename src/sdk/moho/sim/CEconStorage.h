#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal stub for typeid() / TypeInfo registration.
   * Full layout recovery pending.
   */
  class CEconStorage
  {
    unsigned char mPadding[0x0C];
  };

  static_assert(sizeof(CEconStorage) == 0x0C, "CEconStorage size must be 0x0C");
} // namespace moho
