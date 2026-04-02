#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1B4EC
   * COL:  0x00E70B30
   */
  class CAiFormationInstanceTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0059BD80 (FUN_0059BD80, ctor/preregister lane)
     *
     * What it does:
     * Initializes RTTI base lanes and preregisters `CAiFormationInstance`
     * reflection ownership.
     */
    CAiFormationInstanceTypeInfo();

    /**
     * Address: 0x0059BE30 (FUN_0059BE30, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiFormationInstanceTypeInfo() override;

    /**
     * Address: 0x0059BE20 (FUN_0059BE20, ?GetName@CAiFormationInstanceTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0059BDE0 (FUN_0059BDE0, ?Init@CAiFormationInstanceTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiFormationInstanceTypeInfo) == 0x64, "CAiFormationInstanceTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCC130 (FUN_00BCC130, register_CAiFormationInstanceTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `CAiFormationInstanceTypeInfo` storage and installs
   * process-exit cleanup.
   */
  void register_CAiFormationInstanceTypeInfo();
} // namespace moho
