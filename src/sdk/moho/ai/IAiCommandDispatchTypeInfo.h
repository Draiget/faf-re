#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1B37C
   * COL:  0x00E70638
   */
  class IAiCommandDispatchTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00598C50 (FUN_00598C50, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~IAiCommandDispatchTypeInfo() override;

    /**
     * Address: 0x00598C40 (FUN_00598C40, ?GetName@IAiCommandDispatchTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00598C20 (FUN_00598C20, ?Init@IAiCommandDispatchTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(IAiCommandDispatchTypeInfo) == 0x64, "IAiCommandDispatchTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCBE80 (FUN_00BCBE80, register_IAiCommandDispatchTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI storage for `IAiCommandDispatch` and
   * installs process-exit cleanup.
   */
  int register_IAiCommandDispatchTypeInfo();

  /**
   * Address: 0x00BCBE10 (FUN_00BCBE10, register_IAiCommandDispatchTypeInfoStartupStatsCleanup)
   *
   * What it does:
   * Registers process-exit cleanup for one startup-owned engine-stats slot.
   */
  int register_IAiCommandDispatchTypeInfoStartupStatsCleanup();
} // namespace moho
