#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/EAirCombatState.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2AC68
   * COL:  0x00E841C4
   */
  class EAirCombatStateTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006B7700 (FUN_006B7700, scalar deleting thunk)
     */
    ~EAirCombatStateTypeInfo() override;

    /**
     * Address: 0x006B76F0 (FUN_006B76F0)
     *
     * What it does:
     * Returns the reflection type name literal for EAirCombatState.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006B76D0 (FUN_006B76D0)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(EAirCombatStateTypeInfo) == 0x78, "EAirCombatStateTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAirCombatState,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAirCombatState@Moho@@H@gpg'`):
   * `FUN_00BD71E0` (real, `__xc_a`-reachable; no dead duplicate found for
   * this instantiation). `Init()` confirmed at `FUN_006BA740` via the RTTI
   * vftable dump (`vftable@0xE2AC98` slot 0) -- previously mis-cited in
   * `ArchiveSerialization.cpp` as a generic
   * `InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EAirCombatState")`
   * dispatch; the real body does a direct `typeid`/cached-type lookup and
   * hardcoded callback install, matching this template's `Init()` exactly.
   */
  using EAirCombatStatePrimitiveSerializer = gpg::PrimitiveSerHelper<EAirCombatState, int>;
} // namespace moho
