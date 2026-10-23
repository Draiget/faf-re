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
     * Address: 0x005989F0 (FUN_005989F0, ??0IAiCommandDispatch@Moho@@QAE@XZ)
     * Address: 0x00599110 (FUN_00599110, the same constructor emitted with
     *   `this` in EAX rather than ECX -- `mov [eax], 0xE1B360` against
     *   `mov [ecx], 0xE1B360`. One byte apart in the ModRM register field, so
     *   /OPT:ICF could not fold them. Both have zero callers because every
     *   derived constructor inlines this body; `IAiCommandDispatchImpl` names
     *   it in its initializer list, which is what instantiates it.)
     *
     * What it does:
     * Initializes one AI-command-dispatch base object with interface vtable
     * ownership.
     */
    IAiCommandDispatch();

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
