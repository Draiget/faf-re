#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F2C4
   */
  class SAttachPointTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005E4230 (FUN_005E4230, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~SAttachPointTypeInfo() override;

    /**
     * Address: 0x005E4220 (FUN_005E4220, SAttachPointTypeInfo::GetName)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005E4200 (FUN_005E4200, SAttachPointTypeInfo::Init)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  /**
   * Address: 0x00BCEDD0 (FUN_00BCEDD0, register_SAttachPointTypeInfo)
   *
   * What it does:
   * Registers `SAttachPoint` type-info and installs process-exit cleanup.
   */
  int register_SAttachPointTypeInfo();

  static_assert(sizeof(SAttachPointTypeInfo) == 0x64, "SAttachPointTypeInfo size must be 0x64");
} // namespace moho

