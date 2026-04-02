#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C86C
   * COL:  0x00E72610
   */
  class SContinueInfoTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005B21E0 (FUN_005B21E0, scalar deleting thunk)
     */
    ~SContinueInfoTypeInfo() override;

    /**
     * Address: 0x005B21D0 (FUN_005B21D0)
     *
     * What it does:
     * Returns the reflection type name literal for `SContinueInfo`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005B21B0 (FUN_005B21B0)
     *
     * What it does:
     * Writes object size and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(SContinueInfoTypeInfo) == 0x64, "SContinueInfoTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCD2D0 (FUN_00BCD2D0, register_SContinueInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI descriptor for `SContinueInfo` and
   * installs process-exit cleanup.
   */
  int register_SContinueInfoTypeInfo();
} // namespace moho
