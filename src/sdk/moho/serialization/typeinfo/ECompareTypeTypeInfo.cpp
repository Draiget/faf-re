#include "moho/serialization/typeinfo/ECompareTypeTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::ECompareTypeTypeInfo)
    unsigned char gECompareTypeTypeInfoStorage[sizeof(moho::ECompareTypeTypeInfo)];
  bool gECompareTypeTypeInfoConstructed = false;
  bool gECompareTypeTypeInfoPreregistered = false;

  [[nodiscard]] moho::ECompareTypeTypeInfo* AcquireECompareTypeTypeInfo()
  {
    if (!gECompareTypeTypeInfoConstructed) {
      new (gECompareTypeTypeInfoStorage) moho::ECompareTypeTypeInfo();
      gECompareTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::ECompareTypeTypeInfo*>(gECompareTypeTypeInfoStorage);
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
   * Address: 0x00BF61C0 (FUN_00BF61C0, cleanup_ECompareTypeTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `ECompareTypeTypeInfo` storage at process exit.
   */
  void cleanup_ECompareTypeTypeInfo()
  {
    if (!gECompareTypeTypeInfoConstructed) {
      return;
    }

    AcquireECompareTypeTypeInfo()->gpg::REnumType::~REnumType();
    gECompareTypeTypeInfoConstructed = false;
    gECompareTypeTypeInfoPreregistered = false;
  }

  /**
   * Address: 0x00BCB350 (FUN_00BCB350, register_ECompareTypeTypeInfoStartup)
   *
   * What it does:
   * Runs preregistration for `ECompareTypeTypeInfo` and installs exit cleanup.
   */
  int register_ECompareTypeTypeInfoStartup()
  {
    (void)preregister_ECompareTypeTypeInfo();
    return std::atexit(&cleanup_ECompareTypeTypeInfo);
  }
} // namespace moho

