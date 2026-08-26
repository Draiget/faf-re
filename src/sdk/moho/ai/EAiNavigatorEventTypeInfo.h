#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1BFC8
   * COL:  0x00E71A54
   */
  class EAiNavigatorEventTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005A30B0 (FUN_005A30B0, scalar deleting thunk)
     */
    /**
     * Address: 0x005A3020 (FUN_005A3020,
     *   Moho::EAiNavigatorEventTypeInfo::EAiNavigatorEventTypeInfo)
     *
     * What it does:
     * Pre-registers the enum type descriptor for EAiNavigatorEvent.
     */
    EAiNavigatorEventTypeInfo();

    ~EAiNavigatorEventTypeInfo() override;

    /**
     * Address: 0x005A30A0 (FUN_005A30A0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiNavigatorEvent.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A3080 (FUN_005A3080)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005A30E0 (FUN_005A30E0)
     *
     * What it does:
     * Registers EAiNavigatorEvent enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAiNavigatorEventTypeInfo) == 0x78, "EAiNavigatorEventTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiNavigatorEvent,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiNavigatorEvent@Moho@@H@gpg'`):
   * `FUN_00BCC660` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found for this instantiation). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds `mLoadCallback`/
   * `mSaveCallback` to `FUN_005A7720`/`FUN_005A7740`, installs the
   * `PrimitiveSerHelper<EAiNavigatorEvent,int>` vtable, and pushes plain
   * unmangled `FUN_00BF6CD0` (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   * `FUN_005A3130`/`FUN_005A3160` are dead, zero-xref duplicate-emission
   * twins of that exact `FUN_00BF6CD0` body (function_sha256-confirmed),
   * formerly modeled in `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneN` and its two reset thunks; removed in
   * favor of this citation.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EAiNavigatorEventPrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `EAiNavigatorEventTypeInfoBootstrap` constructor -- absent from the real
   * ctor's disassembly (`FUN_00BCC660` already self-registers via `__xc_a`);
   * removed.
   */
  using EAiNavigatorEventPrimitiveSerializer = gpg::PrimitiveSerHelper<EAiNavigatorEvent, int>;

  /**
   * Address: 0x00BCC640 (FUN_00BCC640, register_EAiNavigatorEventTypeInfo)
   *
   * What it does:
   * Preregisters startup construction for the `EAiNavigatorEvent` enum RTTI
   * descriptor and installs exit-time teardown.
   */
  void register_EAiNavigatorEventTypeInfo();
} // namespace moho
