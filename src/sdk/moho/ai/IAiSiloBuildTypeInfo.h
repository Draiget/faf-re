#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DCF4
   * COL:  0x00E74C24
   */
  class IAiSiloBuildTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005CE940 (FUN_005CE940, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~IAiSiloBuildTypeInfo() override;

    /**
     * Address: 0x005CE930 (FUN_005CE930, ?GetName@IAiSiloBuildTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005CE910 (FUN_005CE910, ?Init@IAiSiloBuildTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  /**
   * Address: 0x00BCE010 (FUN_00BCE010, register_IAiSiloBuildTypeInfo)
   *
   * What it does:
   * Constructs and preregisters `IAiSiloBuildTypeInfo`, then schedules
   * process-exit cleanup for its static storage.
   */
  int register_IAiSiloBuildTypeInfo();

  static_assert(sizeof(IAiSiloBuildTypeInfo) == 0x64, "IAiSiloBuildTypeInfo size must be 0x64");
} // namespace moho
