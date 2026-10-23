#include "moho/serialization/typeinfo/ECompareTypeTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  bool gECompareTypeTypeInfoPreregistered = false;

  /**
   * Address: 0x00BF61C0 (FUN_00BF61C0, atexit destructor of the ECompareTypeTypeInfo object)
   */
  [[nodiscard]] moho::ECompareTypeTypeInfo* AcquireECompareTypeTypeInfo()
  {
    static moho::ECompareTypeTypeInfo sInstance;
    return &sInstance;
  }

  struct ECompareTypeTypeInfoBootstrap
  {
    ECompareTypeTypeInfoBootstrap()
    {
      (void)moho::register_ECompareTypeTypeInfoStartup();
    }
  };

  [[maybe_unused]] ECompareTypeTypeInfoBootstrap gECompareTypeTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x005798A0 (FUN_005798A0, scalar deleting dtor lane)
   */
  ECompareTypeTypeInfo::~ECompareTypeTypeInfo() = default;

  /**
   * Address: 0x00579890 (FUN_00579890, Moho::ECompareTypeTypeInfo::GetName)
   */
  const char* ECompareTypeTypeInfo::GetName() const
  {
    return "ECompareType";
  }

  /**
   * Address: 0x00579870 (FUN_00579870, Moho::ECompareTypeTypeInfo::Init)
   */
  void ECompareTypeTypeInfo::Init()
  {
    size_ = sizeof(ECompareType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x005798D0 (FUN_005798D0, Moho::ECompareTypeTypeInfo::AddEnums)
   */
  void ECompareTypeTypeInfo::AddEnums()
  {
    mPrefix = "COMPARE_";
    AddEnum(StripPrefix("COMPARE_Closest"), static_cast<std::int32_t>(COMPARE_Closest));
    AddEnum(StripPrefix("COMPARE_Furthest"), static_cast<std::int32_t>(COMPARE_Furthest));
    AddEnum(StripPrefix("COMPARE_HighestValue"), static_cast<std::int32_t>(COMPARE_HighestValue));
    AddEnum(StripPrefix("COMPARE_LeastDefended"), static_cast<std::int32_t>(COMPARE_LeastDefended));
  }

  /**
   * Address: 0x00579810 (FUN_00579810, preregister_ECompareTypeTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `ECompareTypeTypeInfo` storage and preregisters RTTI.
   */
  gpg::REnumType* preregister_ECompareTypeTypeInfo()
  {
    auto* const typeInfo = AcquireECompareTypeTypeInfo();
    if (!gECompareTypeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(ECompareType), typeInfo);
      gECompareTypeTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BCB350 (FUN_00BCB350, register_ECompareTypeTypeInfoStartup)
   *
   * What it does:
   * Runs preregistration for `ECompareTypeTypeInfo`.
   */
  void register_ECompareTypeTypeInfoStartup()
  {
    (void)preregister_ECompareTypeTypeInfo();
  }
} // namespace moho



// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ECompareTypeTypeInfoStartup_358c70, moho::register_ECompareTypeTypeInfoStartup)

GPG_PREREGISTER_INIT(preregister_ECompareTypeTypeInfo_358c70, moho::preregister_ECompareTypeTypeInfo)
