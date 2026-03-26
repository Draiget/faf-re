#pragma once

#include <cstddef>

namespace gpg
{
  class RType;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1B360
   * COL:  0x00E707D4
   */
  class IAiCommandDispatch
  {
  public:
    /**
     * Address: 0x00598A00 (FUN_00598A00, scalar deleting thunk)
     *
     * VFTable SLOT: 0
     */
    virtual ~IAiCommandDispatch();

  public:
    static gpg::RType* sType;
  };

  static_assert(sizeof(IAiCommandDispatch) == 0x04, "IAiCommandDispatch size must be 0x04");
} // namespace moho
