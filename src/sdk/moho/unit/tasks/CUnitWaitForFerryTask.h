#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal recovered object shell for wait-for-ferry task RTTI ownership.
   * Runtime construction and field-lane initialization are recovered in
   * `CUnitWaitForFerryTaskTypeInfo`.
   */
  class CUnitWaitForFerryTask
  {
  public:
    unsigned char mStorage[0x60];
  };

  static_assert(sizeof(CUnitWaitForFerryTask) == 0x60, "CUnitWaitForFerryTask size must be 0x60");
} // namespace moho

