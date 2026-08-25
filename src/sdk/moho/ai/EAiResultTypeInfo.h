#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/EAiResult.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E20240
   * COL:  0x00E78BF0
   */
  class EAiResultTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00608C00 (FUN_00608C00, scalar deleting thunk)
     */
    ~EAiResultTypeInfo() override;

    /**
     * Address: 0x00608BF0 (FUN_00608BF0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiResult.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00608BD0 (FUN_00608BD0)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(EAiResultTypeInfo) == 0x78, "EAiResultTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiResult,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiResult@Moho@@H@gpg'`):
   * `FUN_00BD0530` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found for this instantiation). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds `mLoadCallback`/
   * `mSaveCallback` to `FUN_0060BCD0`/`FUN_0060BCF0`, installs the
   * `PrimitiveSerHelper<EAiResult,int>` vtable, and pushes plain unmangled
   * `FUN_00BF9AB0` (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target. `Init()` is
   * `FUN_0060B980`, found via a vtable-slot xref search on
   * `??_7?$PrimitiveSerHelper@W4EAiResult@Moho@@H@gpg@@6B@`; its body
   * matches the template's `Init()` exactly.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` (`EAiResultPrimitiveSerializer`) with bespoke free
   * `Deserialize_EAiResult`/`Serialize_EAiResult` functions at those same
   * two addresses -- redundant with the template's own generic
   * `Deserialize`/`Serialize`, so removed in favor of this alias.
   */
  using EAiResultPrimitiveSerializer = gpg::PrimitiveSerHelper<EAiResult, int>;
} // namespace moho
