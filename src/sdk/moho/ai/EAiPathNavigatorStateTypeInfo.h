#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C674
   * COL:  0x00E72584
   */
  class EAiPathNavigatorStateTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005AD2D0 (FUN_005AD2D0, scalar deleting thunk)
     */
    ~EAiPathNavigatorStateTypeInfo() override;

    /**
     * Address: 0x005AD2C0 (FUN_005AD2C0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiPathNavigatorState.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005AD2A0 (FUN_005AD2A0)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  /**
   * Demangled (real binary RTTI): gpg::PrimitiveSerHelper<enum Moho::CAiPathNavigator::State,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4State@CAiPathNavigator@Moho@@H@gpg'`):
   * `FUN_00BCCFE0` (real, sole writer for this global's storage). Raw asm
   * confirms the standard shape: default-constructs `gpg::SerHelperBase`,
   * binds `mLoadCallback`/`mSaveCallback` to `FUN_005B0290`/`FUN_005B02B0`,
   * installs the `PrimitiveSerHelper<CAiPathNavigator::State,int>` vtable,
   * and pushes plain unmangled `FUN_00BF7330` (bare unlink-then-self-link
   * shape, matching `SerHelperBase::ResetLinks()`) as its `atexit` target --
   * modeled by the template's own real destructor, no explicit `atexit`
   * call needed.
   *
   * KNOWN TYPE-IDENTITY DIVERGENCE (not fixed by this pass): the binary's
   * real RTTI names this instantiation's enum argument
   * `Moho::CAiPathNavigator::State` -- a NESTED enum inside `CAiPathNavigator`
   * -- but this repo's earlier recovery pass declared it as a free
   * namespace-scope `moho::EAiPathNavigatorState` in `CAiPathNavigator.h`
   * (used for the `mState` field and everywhere else in this file). Renaming/
   * re-nesting that enum to match the binary exactly touches
   * `CAiPathNavigator.h`/`.cpp` broadly and is out of scope for this
   * SerHelperBase-mimic conversion pass (those files are not in this
   * packet's file list); flagged here for a future dedicated pass. This
   * `using` alias intentionally keeps the existing (pre-established, if
   * imperfectly named) `EAiPathNavigatorState` type so the rest of this
   * file's already-correct enum-value table stays untouched.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EAiPathNavigatorStatePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `EAiPathNavigatorStateTypeInfoBootstrap` constructor -- absent from the
   * real ctor's disassembly; removed.
   */
  using EAiPathNavigatorStatePrimitiveSerializer = gpg::PrimitiveSerHelper<EAiPathNavigatorState, int>;

  /**
   * Address: 0x00BCCFC0 (FUN_00BCCFC0, register_EAiPathNavigatorStateTypeInfo)
   *
   * What it does:
   * Constructs and preregisters `EAiPathNavigatorState` type-info and installs
   * process-exit cleanup.
   */
  int register_EAiPathNavigatorStateTypeInfo();

  static_assert(sizeof(EAiPathNavigatorStateTypeInfo) == 0x78, "EAiPathNavigatorStateTypeInfo size must be 0x78");
} // namespace moho
