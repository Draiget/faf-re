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

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EPathType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EPathType@Moho@@H@gpg'`):
   * `FUN_00BCD290` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback` to
   * `FUN_005B4E90`/`FUN_005B4EB0`, installs the
   * `PrimitiveSerHelper<EPathType,int>` vtable, and pushes plain unmangled
   * `FUN_00BF7420` (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EPathTypePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `EPathTypeTypeInfoBootstrap` constructor -- absent from the real ctor's
   * disassembly; removed.
   */
  using EPathTypePrimitiveSerializer = gpg::PrimitiveSerHelper<EPathType, int>;

  static_assert(sizeof(EPathTypeTypeInfo) == 0x78, "EPathTypeTypeInfo size must be 0x78");

  /**
   * Address: 0x00BCD270 (FUN_00BCD270, register_EPathTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI descriptor for `EPathType` and
   * installs process-exit cleanup.
   */
  int register_EPathTypeTypeInfo();
} // namespace moho
