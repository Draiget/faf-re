#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EFireState : std::int32_t
  {
    FIRESTATE_Mix = -1,
    FIRESTATE_ReturnFire = 0,
    FIRESTATE_HoldFire = 1,
    FIRESTATE_HoldGround = 2,
  };

  static_assert(sizeof(EFireState) == 0x4, "EFireState size must be 0x4");

  class EFireStateTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0055B990 (FUN_0055B990, Moho::EFireStateTypeInfo::EFireStateTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EFireState` with the reflection registry.
     */
    EFireStateTypeInfo();

    /**
     * Address: 0x0055BA20 (FUN_0055BA20, Moho::EFireStateTypeInfo::dtr)
     */
    ~EFireStateTypeInfo() override;

    /**
     * Address: 0x0055BA10 (FUN_0055BA10, Moho::EFireStateTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055B9F0 (FUN_0055B9F0, Moho::EFireStateTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0055BA50 (FUN_0055BA50, Moho::EFireStateTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EFireState,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EFireState@Moho@@H@gpg'`):
   * `FUN_00BCA4C0` (real, `__xc_a`-reachable; no dead duplicate found for
   * this instantiation). `Init()` confirmed at `FUN_0055C900` via the RTTI
   * vftable dump (`vftable@0xE1871C` slot 0) -- previously mis-cited in
   * `ArchiveSerialization.cpp` as a generic
   * `InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::EFireState")`
   * dispatch; the real body does a direct `typeid`/`sType`-cache lookup and
   * hardcoded callback install, matching this template's `Init()` exactly
   * (same mis-citation family already caught this session for
   * ESTITargetType/EResourceType/EUnitCommandType/CAniPose/CAniPoseBone).
   * `Deserialize`/`Serialize` at 0x0055D3E0/0x0055D400 already matched this
   * template's generic bodies exactly (no fabricated null-check).
   */
  using EFireStatePrimitiveSerializer = gpg::PrimitiveSerHelper<EFireState, int>;

  static_assert(sizeof(EFireStateTypeInfo) == 0x78, "EFireStateTypeInfo size must be 0x78");

  /**
   * Address: 0x0055B990 (FUN_0055B990, static-init lane)
   *
   * What it does:
   * Constructs the static `EFireStateTypeInfo` descriptor in place and
   * returns it; construction preregisters `EFireState` with the reflection
   * registry. Called from the CRT static-initializer array via FUN_00BCA4A0.
   */
  [[nodiscard]] gpg::REnumType* preregister_EFireStateTypeInfo();
} // namespace moho
