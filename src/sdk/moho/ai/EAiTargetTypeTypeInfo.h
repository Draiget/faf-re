#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1ECE4
   * COL:  0x00E763B4
   */
  class EAiTargetTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005E2400 (FUN_005E2400, scalar deleting thunk)
     */
    ~EAiTargetTypeTypeInfo() override;

    /**
     * Address: 0x005E23F0 (FUN_005E23F0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiTargetType.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005E23D0 (FUN_005E23D0)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005E2430 (FUN_005E2430)
     *
     * What it does:
     * Registers `EAiTargetType` enum option names/values.
     */
    void AddEnums();
  };

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiTargetType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiTargetType@Moho@@H@gpg'`):
   * `FUN_00BCEBF0` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback` to
   * `FUN_005E35B0`/`FUN_005E35D0`, installs the
   * `PrimitiveSerHelper<EAiTargetType,int>` vtable, and pushes plain
   * unmangled `FUN_00BF8880` (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EAiTargetTypePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `EAiTargetTypeTypeInfoBootstrap` constructor -- absent from the real
   * ctor's disassembly; removed.
   */
  using EAiTargetTypePrimitiveSerializer = gpg::PrimitiveSerHelper<EAiTargetType, int>;

  /**
   * Address: 0x00BCEBD0 (FUN_00BCEBD0, register_EAiTargetTypeTypeInfo)
   *
   * What it does:
   * Registers `EAiTargetType` enum type-info and installs process-exit
   * cleanup.
   */
  int register_EAiTargetTypeTypeInfo();

  static_assert(sizeof(EAiTargetTypeTypeInfo) == 0x78, "EAiTargetTypeTypeInfo size must be 0x78");
} // namespace moho
