#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1E890
   * COL:  0x00E75E94
   */
  class EAiAttackerEventTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005D59A0 (FUN_005D59A0, Moho::EAiAttackerEventTypeInfo::EAiAttackerEventTypeInfo)
     *
     * What it does:
     * Preregisters `EAiAttackerEvent` enum metadata with the reflection runtime.
     */
    EAiAttackerEventTypeInfo();

    /**
     * Address: 0x005D5A30 (FUN_005D5A30, scalar deleting thunk)
     */
    ~EAiAttackerEventTypeInfo() override;

    /**
     * Address: 0x005D5A20 (FUN_005D5A20)
     *
     * What it does:
     * Returns the reflection type name literal for EAiAttackerEvent.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005D5A00 (FUN_005D5A00)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005D5A60 (FUN_005D5A60)
     *
     * What it does:
     * Registers EAiAttackerEvent enum option names/values.
     */
    void AddEnums();
  };

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiAttackerEvent,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiAttackerEvent@Moho@@H@gpg'`):
   * `FUN_00BCE770` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found for this instantiation). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds `mLoadCallback`/
   * `mSaveCallback` to `FUN_005DC390`/`FUN_005DC3B0`, installs the
   * `PrimitiveSerHelper<EAiAttackerEvent,int>` vtable, and pushes plain
   * unmangled `FUN_00BF8250` (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EAiAttackerEventPrimitiveSerializer()`
   * free function eagerly invoked a second time from `IAiAttacker.cpp`'s
   * `IAiAttackerReflectionBootstrap` constructor -- that second call is
   * absent from the real ctor's disassembly (`FUN_00BCE770` already
   * self-registers via `__xc_a` like every other `PrimitiveSerHelper<T,int>`
   * instantiation); removed from both files.
   */
  using EAiAttackerEventPrimitiveSerializer = gpg::PrimitiveSerHelper<EAiAttackerEvent, int>;

  /**
   * Address: 0x00BCE750 (FUN_00BCE750, sub_BCE750)
   *
   * What it does:
   * Registers `EAiAttackerEvent` enum type-info and installs process-exit
   * cleanup.
   */
  int register_EAiAttackerEventTypeInfo();

  static_assert(sizeof(EAiAttackerEventTypeInfo) == 0x78, "EAiAttackerEventTypeInfo size must be 0x78");
} // namespace moho
