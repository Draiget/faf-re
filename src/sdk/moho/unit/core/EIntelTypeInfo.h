#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EIntel : std::int32_t
  {
    INTEL_None = 0,
    INTEL_Vision = 1,
    INTEL_WaterVision = 2,
    INTEL_Radar = 3,
    INTEL_Sonar = 4,
    INTEL_Omni = 5,
    INTEL_RadarStealthField = 6,
    INTEL_SonarStealthField = 7,
    INTEL_CloakField = 8,
    INTEL_Jammer = 9,
    INTEL_Spoof = 10,
    INTEL_Cloak = 11,
    INTEL_RadarStealth = 12,
    INTEL_SonarStealth = 13,
  };

  static_assert(sizeof(EIntel) == 0x04, "EIntel size must be 0x04");

  class EIntelTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0050A3A0 (FUN_0050A3A0, Moho::EIntelTypeInfo::EIntelTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EIntel` with the reflection registry.
     */
    EIntelTypeInfo();

    /**
     * Address: 0x0050A430 (FUN_0050A430, Moho::EIntelTypeInfo::dtr)
     */
    ~EIntelTypeInfo() override;

    /**
     * Address: 0x0050A420 (FUN_0050A420, Moho::EIntelTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050A400 (FUN_0050A400, Moho::EIntelTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0050A460 (FUN_0050A460, Moho::EIntelTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EIntelTypeInfo) == 0x78, "EIntelTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EIntel,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EIntel@Moho@@H@gpg'`): `FUN_00BC7BB0`
   * (real, `__xc_a`-reachable) vs. a dead, zero-xref duplicate ctor at
   * `FUN_0050A880` (same low-address/high-address shape already established
   * for every other `PrimitiveSerHelper<T,int>` instantiation). `Init()`
   * confirmed at `FUN_0050A8B0` via the RTTI vftable dump (`vftable@0xE0DB94`
   * slot 0) -- matches this template's `Init()` exactly.
   */
  using EIntelPrimitiveSerializer = gpg::PrimitiveSerHelper<EIntel, int>;

  /**
   * Address: 0x00BC7B90 (FUN_00BC7B90, register_EIntelTypeInfo)
   *
   * What it does:
   * Runs `EIntel` typeinfo preregistration and installs process-exit cleanup.
   */
  int register_EIntelTypeInfo();
} // namespace moho
