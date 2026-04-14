#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal recovered object shell for carrier-landing task RTTI ownership.
   * Runtime construction and field-lane initialization are recovered in
   * `CUnitCarrierLandTypeInfo`.
   */
  class CUnitCarrierLand
  {
  public:
    unsigned char mStorage[0x68];
  };

  static_assert(sizeof(CUnitCarrierLand) == 0x68, "CUnitCarrierLand size must be 0x68");
} // namespace moho

