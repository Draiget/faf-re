#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1BFD4
   * COL:  0x00E71A88
   */
  class EAiNavigatorStatusTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005A2EB0 (FUN_005A2EB0, Moho::EAiNavigatorStatusTypeInfo::EAiNavigatorStatusTypeInfo)
     *
     * What it does:
     * Runs the `gpg::REnumType` base constructor, installs this descriptor's
     * vftable (0x00E1BFD4) and pre-registers it against
     * `typeid(EAiNavigatorStatus)` so `gpg::LookupRType` can resolve the enum.
     *
     * The class previously declared no constructor at all, so the implicit one
     * built the base and stopped - the `PreRegisterRType` call at 0x005A2EF3
     * never happened and the descriptor stayed invisible to reflection.
     */
    EAiNavigatorStatusTypeInfo();

    /**
     * Address: 0x005A2F40 (FUN_005A2F40, scalar deleting thunk)
     */
    ~EAiNavigatorStatusTypeInfo() override;

    /**
     * Address: 0x005A2F30 (FUN_005A2F30)
     *
     * What it does:
     * Returns the reflection type name literal for EAiNavigatorStatus.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A2F10 (FUN_005A2F10)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005A2F70 (FUN_005A2F70)
     *
     * What it does:
     * Registers EAiNavigatorStatus enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAiNavigatorStatusTypeInfo) == 0x78, "EAiNavigatorStatusTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiNavigatorStatus,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiNavigatorStatus@Moho@@H@gpg'`):
   * `FUN_00BCC600` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found for this instantiation). This address's IDA export
   * already carried synthetic struct names (`gpg::PrimitiveSerHelper_
   * EAiNavigatorStatus`), confirming via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mDeserialize`/`mSerialize` to
   * `FUN_005A76B0`/`FUN_005A76D0`, installs the
   * `PrimitiveSerHelper<EAiNavigatorStatus,int>` vtable, and pushes
   * `FUN_00BF6C90` (IDA-labeled `??1PrimitiveSerHelper_EAiNavigatorStatus@
   * gpg@@QAE@@Z` -- a synthetic/heuristic name, not real MSVC mangling for
   * this template) as its `atexit` target; confirmed to be the same bare
   * unlink-then-self-link shape as every other instantiation's atexit
   * target, matching `SerHelperBase::ResetLinks()` -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EAiNavigatorStatusPrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `EAiNavigatorStatusTypeInfoBootstrap` constructor -- absent from the
   * real ctor's disassembly (`FUN_00BCC600` already self-registers via
   * `__xc_a`); removed.
   */
  using EAiNavigatorStatusPrimitiveSerializer = gpg::PrimitiveSerHelper<EAiNavigatorStatus, int>;

  /**
   * Address: 0x00BCC5E0 (FUN_00BCC5E0, register_EAiNavigatorStatusTypeInfo)
   *
   * What it does:
   * Preregisters startup construction for the `EAiNavigatorStatus` enum RTTI
   * descriptor and installs exit-time teardown.
   */
  void register_EAiNavigatorStatusTypeInfo();
} // namespace moho
