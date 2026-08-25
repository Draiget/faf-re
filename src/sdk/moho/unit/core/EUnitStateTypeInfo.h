#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/core/IUnit.h"

namespace moho
{
  class EUnitStateTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0055BB10 (FUN_0055BB10, Moho::EUnitStateTypeInfo::EUnitStateTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EUnitState` with the reflection registry.
     */
    EUnitStateTypeInfo();

    /**
     * Address: 0x0055BBA0 (FUN_0055BBA0, Moho::EUnitStateTypeInfo::dtr)
     */
    ~EUnitStateTypeInfo() override;

    /**
     * Address: 0x0055BB90 (FUN_0055BB90, Moho::EUnitStateTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055BB70 (FUN_0055BB70, Moho::EUnitStateTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0055BBD0 (FUN_0055BBD0, Moho::EUnitStateTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EUnitState,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EUnitState@Moho@@H@gpg'`):
   * `FUN_00BCA520` (real, `__xc_a`-reachable; no dead duplicate found for
   * this instantiation). `Init()` confirmed at `FUN_0055C9A0` via the RTTI
   * vftable dump (`vftable@0xE1875C` slot 0) -- previously mis-cited in
   * `ArchiveSerialization.cpp` as a generic
   * `InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EUnitState")`
   * dispatch; the real body does a direct `typeid`/`sType`-cache lookup and
   * hardcoded callback install, matching this template's `Init()` exactly
   * (same mis-citation family already caught this session for
   * ESTITargetType/EResourceType/EUnitCommandType/CAniPose/CAniPoseBone).
   * `Deserialize`/`Serialize` at 0x0055D450/0x0055D470 already matched this
   * template's generic bodies exactly (no fabricated null-check).
   */
  using EUnitStatePrimitiveSerializer = gpg::PrimitiveSerHelper<EUnitState, int>;

  static_assert(sizeof(EUnitState) == 0x04, "EUnitState size must be 0x04");
  static_assert(sizeof(EUnitStateTypeInfo) == 0x78, "EUnitStateTypeInfo size must be 0x78");

  /**
   * Address: 0x0055BB10 (FUN_0055BB10, static-init lane)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  [[nodiscard]] gpg::REnumType* preregister_EUnitStateTypeInfo();
} // namespace moho
