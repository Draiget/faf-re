#include "moho/unit/core/EIntelTypeInfo.h"

#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::EIntelTypeInfo) unsigned char gEIntelTypeInfoStorage[sizeof(moho::EIntelTypeInfo)]{};
  bool gEIntelTypeInfoConstructed = false;
  bool gEIntelTypeInfoPreregistered = false;

  /**
   * Address: 0x0050A3A0 (FUN_0050A3A0, startup preregister lane)
   *
   * What it does:
   * Constructs one static `EIntelTypeInfo` instance and preregisters RTTI
   * ownership for `EIntel`.
   */
  [[nodiscard]] gpg::REnumType* preregister_EIntelTypeInfo()
  {
    if (!gEIntelTypeInfoConstructed) {
      new (gEIntelTypeInfoStorage) moho::EIntelTypeInfo();
      gEIntelTypeInfoConstructed = true;
    }

    auto* const typeInfo = reinterpret_cast<moho::EIntelTypeInfo*>(gEIntelTypeInfoStorage);
    if (!gEIntelTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(moho::EIntel), typeInfo);
      gEIntelTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  struct EIntelTypeInfoBootstrap
  {
    EIntelTypeInfoBootstrap()
    {
      (void)preregister_EIntelTypeInfo();
    }
  };

  [[maybe_unused]] EIntelTypeInfoBootstrap gEIntelTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0050A430 (FUN_0050A430, Moho::EIntelTypeInfo::dtr)
   */
  EIntelTypeInfo::~EIntelTypeInfo() = default;

  /**
   * Address: 0x0050A420 (FUN_0050A420, Moho::EIntelTypeInfo::GetName)
   */
  const char* EIntelTypeInfo::GetName() const
  {
    return "EIntel";
  }

  /**
   * Address: 0x0050A400 (FUN_0050A400, Moho::EIntelTypeInfo::Init)
   */
  void EIntelTypeInfo::Init()
  {
    size_ = sizeof(EIntel);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0050A460 (FUN_0050A460, Moho::EIntelTypeInfo::AddEnums)
   */
  void EIntelTypeInfo::AddEnums()
  {
    mPrefix = "INTEL_";
    AddEnum(StripPrefix("INTEL_None"), INTEL_None);
    AddEnum(StripPrefix("INTEL_Vision"), INTEL_Vision);
    AddEnum(StripPrefix("INTEL_WaterVision"), INTEL_WaterVision);
    AddEnum(StripPrefix("INTEL_Radar"), INTEL_Radar);
    AddEnum(StripPrefix("INTEL_Sonar"), INTEL_Sonar);
    AddEnum(StripPrefix("INTEL_Omni"), INTEL_Omni);
    AddEnum(StripPrefix("INTEL_RadarStealthField"), INTEL_RadarStealthField);
    AddEnum(StripPrefix("INTEL_SonarStealthField"), INTEL_SonarStealthField);
    AddEnum(StripPrefix("INTEL_CloakField"), INTEL_CloakField);
    AddEnum(StripPrefix("INTEL_Jammer"), INTEL_Jammer);
    AddEnum(StripPrefix("INTEL_Spoof"), INTEL_Spoof);
    AddEnum(StripPrefix("INTEL_Cloak"), INTEL_Cloak);
    AddEnum(StripPrefix("INTEL_RadarStealth"), INTEL_RadarStealth);
    AddEnum(StripPrefix("INTEL_SonarStealth"), INTEL_SonarStealth);
  }
} // namespace moho

