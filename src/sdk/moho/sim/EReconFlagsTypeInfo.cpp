#include "moho/sim/EReconFlagsTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiReconDB.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF5780 (FUN_00BF5780, atexit destructor of the EReconFlagsTypeInfo object)
   */
  [[nodiscard]] EReconFlagsTypeInfo& Acquire()
  {
    static EReconFlagsTypeInfo sInstance;
    return sInstance;
  }

  struct Bootstrap { Bootstrap() { moho::register_EReconFlagsTypeInfoStartup(); } };
  Bootstrap gBootstrap;
} // namespace

/** Address: 0x00564490 (FUN_00564490, sub_564490) */
EReconFlagsTypeInfo::EReconFlagsTypeInfo()
  : gpg::REnumType()
{
  gpg::PreRegisterRType(typeid(EReconFlags), this);
}

EReconFlagsTypeInfo::~EReconFlagsTypeInfo() = default;

/** Address: 0x00564510 (FUN_00564510) */
const char* EReconFlagsTypeInfo::GetName() const { return "EReconFlags"; }

/**
 * Address: 0x005644F0 (FUN_005644F0, Init)
 */
void EReconFlagsTypeInfo::Init()
{
  size_ = sizeof(EReconFlags);
  gpg::RType::Init();
  AddEnums(this);
  Finish();
}

/**
 * Address: 0x00564550 (FUN_00564550, AddEnums)
 *
 * What it does:
 * Sets prefix `RECON_` and registers all 12 EReconFlags bitmask values:
 * None, Radar, Sonar, Omni, LOSNow, LOSEver, KnownFake, MaybeDead, plus
 * combinations Exposed (28), AnyPing (7), RadarSonar (3), AnySense (15).
 */
void EReconFlagsTypeInfo::AddEnums(gpg::REnumType* const enumType)
{
  enumType->mPrefix = "RECON_";
  enumType->AddEnum(enumType->StripPrefix("RECON_None"), RECON_None);
  enumType->AddEnum(enumType->StripPrefix("RECON_Radar"), RECON_Radar);
  enumType->AddEnum(enumType->StripPrefix("RECON_Sonar"), RECON_Sonar);
  enumType->AddEnum(enumType->StripPrefix("RECON_Omni"), RECON_Omni);
  enumType->AddEnum(enumType->StripPrefix("RECON_LOSNow"), RECON_LOSNow);
  enumType->AddEnum(enumType->StripPrefix("RECON_LOSEver"), RECON_LOSEver);
  enumType->AddEnum(enumType->StripPrefix("RECON_KnownFake"), RECON_KnownFake);
  enumType->AddEnum(enumType->StripPrefix("RECON_MaybeDead"), RECON_MaybeDead);
  enumType->AddEnum(enumType->StripPrefix("RECON_Exposed"), RECON_Exposed);
  enumType->AddEnum(enumType->StripPrefix("RECON_AnyPing"), RECON_AnyPing);
  enumType->AddEnum(enumType->StripPrefix("RECON_RadarSonar"), RECON_RadarSonar);
  enumType->AddEnum(enumType->StripPrefix("RECON_AnySense"), RECON_AnySense);
}

/**
 * Address: 0x00BCA910 (FUN_00BCA910, register_EReconFlagsTypeInfo)
 */
void moho::register_EReconFlagsTypeInfoStartup()
{
  (void)Acquire();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EReconFlagsTypeInfoStartup_dc2936, moho::register_EReconFlagsTypeInfoStartup)
