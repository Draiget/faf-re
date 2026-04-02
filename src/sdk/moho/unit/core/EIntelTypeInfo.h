#pragma once

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
} // namespace moho

