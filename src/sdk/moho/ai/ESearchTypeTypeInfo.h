#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class ESearchTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005A9D90 (FUN_005A9D90, Moho::ESearchTypeTypeInfo::ESearchTypeTypeInfo)
     *
     * What it does:
     * Preregisters `ESearchType` enum metadata with the reflection runtime.
     */
    ESearchTypeTypeInfo();

    /**
     * Address: 0x005A9E20 (FUN_005A9E20, scalar deleting thunk)
     */
    ~ESearchTypeTypeInfo() override;

    /**
     * Address: 0x005A9E10 (FUN_005A9E10, Moho::ESearchTypeTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type name literal for `ESearchType`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A9DF0 (FUN_005A9DF0, Moho::ESearchTypeTypeInfo::Init)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(ESearchTypeTypeInfo) == 0x78, "ESearchTypeTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ESearchType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ESearchType@Moho@@H@gpg'`):
   * `FUN_00BCCD10` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback` to
   * `FUN_005AB520`/`FUN_005AB540`, installs the
   * `PrimitiveSerHelper<ESearchType,int>` vtable, and pushes plain unmangled
   * `FUN_00BF71B0` (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_ESearchTypePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `ESearchTypeTypeInfoBootstrap` constructor -- absent from the real
   * ctor's disassembly; removed. `FUN_005AB120`'s asm (lazy `LookupRType(
   * typeid(ESearchType))` into a cached global, two `GPG_ASSERT`-shaped
   * null checks, then `serLoadFunc_`/`serSaveFunc_` writes) matches this
   * template's generic `Init()` exactly and is now provided by
   * `gpg::PrimitiveSerHelper<T,int>::Init()` in Reflection.h.
   */
  using ESearchTypePrimitiveSerializer = gpg::PrimitiveSerHelper<ESearchType, int>;

  /**
   * Address: 0x00BCCCF0 (FUN_00BCCCF0, register_ESearchTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI descriptor for `ESearchType` and
   * installs process-exit cleanup.
   */
  int register_ESearchTypeTypeInfo();
} // namespace moho
