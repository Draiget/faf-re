#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1EA94
   * COL: 0x00E7599C
   */
  class LAiAttackerImplTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005D6040 (FUN_005D6040, Moho::LAiAttackerImplTypeInfo::LAiAttackerImplTypeInfo)
     *
     * What it does:
     * Preregisters `LAiAttackerImpl` RTTI into the reflection lookup table.
     */
    LAiAttackerImplTypeInfo();

    /**
     * Address: 0x005D60F0 (FUN_005D60F0, scalar deleting thunk)
     */
    ~LAiAttackerImplTypeInfo() override;

    /**
     * Address: 0x005D60E0 (FUN_005D60E0, Moho::LAiAttackerImplTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005D60A0 (FUN_005D60A0, Moho::LAiAttackerImplTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(LAiAttackerImplTypeInfo) == 0x64, "LAiAttackerImplTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCE830 (FUN_00BCE830, register_LAiAttackerImplTypeInfo)
   *
   * What it does:
   * Constructs the recovered `LAiAttackerImpl` type-info helper and installs
   * process-exit cleanup.
   */
  void register_LAiAttackerImplTypeInfo();
} // namespace moho
