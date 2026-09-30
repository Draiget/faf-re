#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  struct SerHelperBase;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1C82C
   * COL:  0x00E7263C
   */
  class EPathTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005B2020 (FUN_005B2020, Moho::EPathTypeTypeInfo::EPathTypeTypeInfo)
     *
     * What it does:
     * Runs the `gpg::REnumType` base constructor, installs this descriptor's
     * vftable (0x00E1C82C) and pre-registers it against `typeid(EPathType)` so
     * the enum resolves through `gpg::LookupRType`.
     *
     * Byte-identical shape to `EAiNavigatorStatusTypeInfo::EAiNavigatorStatusTypeInfo`
     * (0x005A2EB0): the class declared no constructor, so the implicit one
     * built the base and stopped before the `PreRegisterRType` call at
     * 0x005B2063 ever ran.
     */
    EPathTypeTypeInfo();

    /**
     * Address: 0x005B20B0 (FUN_005B20B0, scalar deleting thunk)
     */
    ~EPathTypeTypeInfo() override;

    /**
     * Address: 0x005B20A0 (FUN_005B20A0)
     *
     * What it does:
     * Returns the reflection type name literal for `EPathType`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005B2080 (FUN_005B2080)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };


  static_assert(sizeof(EPathTypeTypeInfo) == 0x78, "EPathTypeTypeInfo size must be 0x78");

  /**
   * Address: 0x00BCD270 (FUN_00BCD270, register_EPathTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI descriptor for `EPathType`.
   */
  void register_EPathTypeTypeInfo();
} // namespace moho
