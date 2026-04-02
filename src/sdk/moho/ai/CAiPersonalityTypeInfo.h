#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1CA28
   * COL:  0x00E72C2C
   */
  class CAiPersonalityTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005B68A0 (FUN_005B68A0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiPersonalityTypeInfo() override;

    /**
     * Address: 0x005B6890 (FUN_005B6890, ?GetName@CAiPersonalityTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005B6870 (FUN_005B6870, ?Init@CAiPersonalityTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiPersonalityTypeInfo) == 0x64, "CAiPersonalityTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCD600 (FUN_00BCD600, register_CAiPersonalityTypeInfo)
   *
   * What it does:
   * Constructs/preregisters CAiPersonality RTTI storage and installs
   * process-exit cleanup.
   */
  int register_CAiPersonalityTypeInfo();
} // namespace moho
