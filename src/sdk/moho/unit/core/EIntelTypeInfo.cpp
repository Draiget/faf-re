#include "moho/unit/core/EIntelTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  gpg::StaticTypeInfoStorage<moho::EIntelTypeInfo> gEIntelTypeInfoStorage{};

  /**
   * Address: 0x00BF2010 (FUN_00BF2010, cleanup_EIntelTypeInfo)
   *
   * What it does:
   * Process-exit teardown for the `EIntelTypeInfo` descriptor. The real
   * ctor's atexit push at 0x00BC7B90 targets a plain destructor call, not a
   * mangled symbol.
   */
  void cleanup_EIntelTypeInfo()
  {
    gEIntelTypeInfoStorage.Destroy();
  }

  /**
   * Address: 0x00BC7BB0 (FUN_00BC7BB0, dynamic initializer for the global
   * `PrimitiveSerHelper<EIntel,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). This is an independent `__xc_a`
   * static initializer, separate from `EIntelTypeInfo`'s own initializer
   * below -- the prior recovery wrongly coupled both into one shared
   * bootstrap struct that also triple-registered the type info (bootstrap
   * ctor + two separate GPG_PREREGISTER_INIT entries for the same
   * descriptor).
   */
  moho::EIntelPrimitiveSerializer gEIntelPrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0050A3A0 (FUN_0050A3A0, Moho::EIntelTypeInfo::EIntelTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EIntel` with the reflection registry.
   */
  EIntelTypeInfo::EIntelTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EIntel), this);
  }

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

  /**
   * Address: 0x00BC7B90 (FUN_00BC7B90, register_EIntelTypeInfo)
   *
   * What it does:
   * Constructs the static `EIntelTypeInfo` descriptor in place and installs
   * its atexit teardown.
   */
  int register_EIntelTypeInfo()
  {
    (void)gEIntelTypeInfoStorage.Ensure();
    return std::atexit(&cleanup_EIntelTypeInfo);
  }
} // namespace moho

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EIntelTypeInfo_4aa76a, moho::register_EIntelTypeInfo)
