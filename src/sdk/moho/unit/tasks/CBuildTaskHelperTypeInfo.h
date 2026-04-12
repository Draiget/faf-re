#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CBuildTaskHelper;

  /**
   * VFTABLE: 0x00E1F9A8
   */
  class CBuildTaskHelperTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005F5820 (FUN_005F5820, ??0CBuildTaskHelperTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Preregisters `CBuildTaskHelper` RTTI into the reflection lookup table.
     */
    CBuildTaskHelperTypeInfo();

    /**
     * Address: 0x005F58B0 (FUN_005F58B0, scalar deleting thunk)
     */
    ~CBuildTaskHelperTypeInfo() override;

    /**
     * Address: 0x005F58A0 (FUN_005F58A0)
     *
     * What it does:
     * Returns the reflected type name literal for `CBuildTaskHelper`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005F5880 (FUN_005F5880)
     *
     * What it does:
     * Sets the reflected size (0x44) and finalizes metadata.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BCF810 (FUN_00BCF810, register_CBuildTaskHelperTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CBuildTaskHelperTypeInfo();

  static_assert(sizeof(CBuildTaskHelperTypeInfo) == 0x64, "CBuildTaskHelperTypeInfo size must be 0x64");
} // namespace moho
