#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class SBlackListInfoTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006D3840 (FUN_006D3840, sub_6D3840)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for `SBlackListInfo`.
     */
    SBlackListInfoTypeInfo();

    /**
     * Address: 0x006D38D0 (FUN_006D38D0, dtr lane)
     * Slot: 2
     *
     * What it does:
     * Releases the reflected `SBlackListInfoTypeInfo` object.
     */
    ~SBlackListInfoTypeInfo() override;

    /**
     * Address: 0x006D38C0 (FUN_006D38C0, Moho::SBlackListInfoTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `SBlackListInfo`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006D38A0 (FUN_006D38A0, Moho::SBlackListInfoTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected `SBlackListInfo` size metadata and finalizes the type.
     */
    void Init() override;
  };

  static_assert(sizeof(SBlackListInfoTypeInfo) == 0x64, "SBlackListInfoTypeInfo size must be 0x64");

  /**
   * Address: 0x00BFE620 (FUN_00BFE620, sub_BFE620)
   *
   * What it does:
   * Releases `SBlackListInfoTypeInfo` dynamic field/base arrays and resets the
   * type object to base `RObject` lane semantics.
   */
  void cleanup_SBlackListInfoTypeInfo();

  /**
   * Address: 0x00BD8810 (FUN_00BD8810, sub_BD8810)
   *
   * What it does:
   * Forces `SBlackListInfoTypeInfo` registration and schedules exit cleanup.
   */
  int register_SBlackListInfoTypeInfo();
} // namespace moho
