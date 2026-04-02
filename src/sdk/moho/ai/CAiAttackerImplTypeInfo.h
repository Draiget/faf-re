#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1EA58
   * COL: 0x00E75A94
   */
  class CAiAttackerImplTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005D5DE0 (FUN_005D5DE0, Moho::CAiAttackerImplTypeInfo::CAiAttackerImplTypeInfo)
     *
     * What it does:
     * Preregisters `CAiAttackerImpl` RTTI into the reflection lookup table.
     */
    CAiAttackerImplTypeInfo();

    /**
     * Address: 0x005D5E80 (FUN_005D5E80, scalar deleting thunk)
     */
    ~CAiAttackerImplTypeInfo() override;

    /**
     * Address: 0x005D5E70 (FUN_005D5E70, Moho::CAiAttackerImplTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005D5E40 (FUN_005D5E40, Moho::CAiAttackerImplTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CAiAttackerImplTypeInfo) == 0x64, "CAiAttackerImplTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCE810 (FUN_00BCE810, register_CAiAttackerImplTypeInfo)
   *
   * What it does:
   * Constructs the recovered `CAiAttackerImpl` type-info helper and installs
   * process-exit cleanup.
   */
  void register_CAiAttackerImplTypeInfo();
} // namespace moho
