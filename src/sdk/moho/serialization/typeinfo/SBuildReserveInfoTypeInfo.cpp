#include "moho/serialization/typeinfo/SBuildReserveInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::SBuildReserveInfoTypeInfo)
    unsigned char gSBuildReserveInfoTypeInfoStorage[sizeof(moho::SBuildReserveInfoTypeInfo)];
  bool gSBuildReserveInfoTypeInfoConstructed = false;
  bool gSBuildReserveInfoTypeInfoPreregistered = false;

  [[nodiscard]] moho::SBuildReserveInfoTypeInfo* AcquireSBuildReserveInfoTypeInfo()
  {
    if (!gSBuildReserveInfoTypeInfoConstructed) {
      new (gSBuildReserveInfoTypeInfoStorage) moho::SBuildReserveInfoTypeInfo();
      gSBuildReserveInfoTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::SBuildReserveInfoTypeInfo*>(gSBuildReserveInfoTypeInfoStorage);
  }

  struct SBuildReserveInfoTypeInfoBootstrap
  {
    SBuildReserveInfoTypeInfoBootstrap()
    {
      (void)moho::register_SBuildReserveInfoTypeInfoStartup();
    }
  };

  [[maybe_unused]] SBuildReserveInfoTypeInfoBootstrap gSBuildReserveInfoTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x005799C0 (FUN_005799C0, scalar deleting dtor lane)
   */
  SBuildReserveInfoTypeInfo::~SBuildReserveInfoTypeInfo() = default;

  /**
   * Address: 0x005799B0 (FUN_005799B0, Moho::SBuildReserveInfoTypeInfo::GetName)
   */
  const char* SBuildReserveInfoTypeInfo::GetName() const
  {
    return "SBuildReserveInfo";
  }

  /**
   * Address: 0x00579990 (FUN_00579990, Moho::SBuildReserveInfoTypeInfo::Init)
   */
  void SBuildReserveInfoTypeInfo::Init()
  {
    size_ = sizeof(SBuildReserveInfo);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00579930 (FUN_00579930, preregister_SBuildReserveInfoTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `SBuildReserveInfoTypeInfo` storage and preregisters RTTI.
   */
  gpg::RType* preregister_SBuildReserveInfoTypeInfo()
  {
    auto* const typeInfo = AcquireSBuildReserveInfoTypeInfo();
    if (!gSBuildReserveInfoTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(SBuildReserveInfo), typeInfo);
      gSBuildReserveInfoTypeInfoPreregistered = true;
    }

    SBuildReserveInfo::sType = typeInfo;
    return typeInfo;
  }

  /**
   * Address: 0x00BF61D0 (FUN_00BF61D0, cleanup_SBuildReserveInfoTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SBuildReserveInfoTypeInfo` storage at process exit.
   */
  void cleanup_SBuildReserveInfoTypeInfo()
  {
    if (!gSBuildReserveInfoTypeInfoConstructed) {
      return;
    }

    AcquireSBuildReserveInfoTypeInfo()->~SBuildReserveInfoTypeInfo();
    gSBuildReserveInfoTypeInfoConstructed = false;
    gSBuildReserveInfoTypeInfoPreregistered = false;
  }

  /**
   * Address: 0x00BCB370 (FUN_00BCB370, register_SBuildReserveInfoTypeInfoStartup)
   *
   * What it does:
   * Runs preregistration for `SBuildReserveInfoTypeInfo` and installs exit cleanup.
   */
  int register_SBuildReserveInfoTypeInfoStartup()
  {
    (void)preregister_SBuildReserveInfoTypeInfo();
    return std::atexit(&cleanup_SBuildReserveInfoTypeInfo);
  }
} // namespace moho

