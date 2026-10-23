#include "moho/sim/CDamageEMethodTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  bool gCDamageEMethodTypeInfoPreregistered = false;

  /**
   * Address: 0x00C00B70 (FUN_00C00B70, atexit destructor of the CDamageEMethodTypeInfo object)
   */
  [[nodiscard]] moho::CDamageEMethodTypeInfo* AcquireCDamageEMethodTypeInfo()
  {
    static moho::CDamageEMethodTypeInfo sInstance;
    return &sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00738440 (FUN_00738440, Moho::CDamageEMethodTypeInfo::dtr)
   */
  CDamageEMethodTypeInfo::~CDamageEMethodTypeInfo() = default;

  /**
   * Address: 0x00738430 (FUN_00738430, Moho::CDamageEMethodTypeInfo::GetName)
   */
  const char* CDamageEMethodTypeInfo::GetName() const
  {
    return "CDamage::EMethod";
  }

  /**
   * Address: 0x00738410 (FUN_00738410, Moho::CDamageEMethodTypeInfo::Init)
   */
  void CDamageEMethodTypeInfo::Init()
  {
    size_ = sizeof(CDamageMethod);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x00738470 (FUN_00738470, Moho::CDamageEMethodTypeInfo::AddEnums)
   */
  void CDamageEMethodTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    typeInfo->mPrefix = "CDamage::";
    typeInfo->AddEnum(typeInfo->StripPrefix("CDamage::SINGLE_TARGET"), static_cast<std::int32_t>(CDamage_SINGLE_TARGET));
    typeInfo->AddEnum(typeInfo->StripPrefix("CDamage::AREA_EFFECT"), static_cast<std::int32_t>(CDamage_AREA_EFFECT));
    typeInfo->AddEnum(typeInfo->StripPrefix("CDamage::RING_EFFECT"), static_cast<std::int32_t>(CDamage_RING_EFFECT));
  }

  /**
   * Address: 0x007383B0 (FUN_007383B0, preregister_CDamageEMethodTypeInfo)
   */
  gpg::REnumType* preregister_CDamageEMethodTypeInfo()
  {
    auto* const typeInfo = AcquireCDamageEMethodTypeInfo();
    if (!gCDamageEMethodTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(CDamageMethod), typeInfo);
      gCDamageEMethodTypeInfoPreregistered = true;
    }
    return typeInfo;
  }

  /**
   * Address: 0x00BDB710 (FUN_00BDB710, register_CDamageEMethodTypeInfo)
   */
  void register_CDamageEMethodTypeInfo()
  {
    (void)preregister_CDamageEMethodTypeInfo();
  }
} // namespace moho

namespace
{
  struct CDamageEMethodTypeInfoBootstrap
  {
    CDamageEMethodTypeInfoBootstrap()
    {
      (void)moho::register_CDamageEMethodTypeInfo();
    }
  };

  [[maybe_unused]] CDamageEMethodTypeInfoBootstrap gCDamageEMethodTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CDamageEMethodTypeInfo_ca3e35, moho::register_CDamageEMethodTypeInfo)

GPG_PREREGISTER_INIT(preregister_CDamageEMethodTypeInfo_ca3e35, moho::preregister_CDamageEMethodTypeInfo)
