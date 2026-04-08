#include "moho/sim/CDamageEMethodTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::CDamageEMethodTypeInfo)
    unsigned char gCDamageEMethodTypeInfoStorage[sizeof(moho::CDamageEMethodTypeInfo)];
  bool gCDamageEMethodTypeInfoConstructed = false;
  bool gCDamageEMethodTypeInfoPreregistered = false;

  [[nodiscard]] moho::CDamageEMethodTypeInfo* AcquireCDamageEMethodTypeInfo()
  {
    if (!gCDamageEMethodTypeInfoConstructed) {
      new (gCDamageEMethodTypeInfoStorage) moho::CDamageEMethodTypeInfo();
      gCDamageEMethodTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CDamageEMethodTypeInfo*>(gCDamageEMethodTypeInfoStorage);
  }

  /**
   * Address: 0x00C00B70 (FUN_00C00B70, cleanup_CDamageEMethodTypeInfo)
   *
   * What it does:
   * Tears down process-global `CDamageEMethodTypeInfo` storage.
   */
  void cleanup_CDamageEMethodTypeInfo()
  {
    if (!gCDamageEMethodTypeInfoConstructed) {
      return;
    }

    AcquireCDamageEMethodTypeInfo()->~CDamageEMethodTypeInfo();
    gCDamageEMethodTypeInfoConstructed = false;
    gCDamageEMethodTypeInfoPreregistered = false;
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
  int register_CDamageEMethodTypeInfo()
  {
    (void)preregister_CDamageEMethodTypeInfo();
    return std::atexit(&cleanup_CDamageEMethodTypeInfo);
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
