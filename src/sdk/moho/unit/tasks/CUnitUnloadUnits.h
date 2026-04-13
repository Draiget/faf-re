#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal recovered layout owner for `CUnitUnloadUnits` type lanes.
   */
  class CUnitUnloadUnits
  {
  public:
    /**
     * Address: 0x00625E80 (FUN_00625E80, Moho::CUnitUnloadUnits::CUnitUnloadUnits)
     *
     * What it does:
     * Constructs one unload-units task instance in place.
     */
    CUnitUnloadUnits();

  private:
    unsigned char mPadding[0x88];
  };

  static_assert(sizeof(CUnitUnloadUnits) == 0x88, "CUnitUnloadUnits size must be 0x88");
} // namespace moho

