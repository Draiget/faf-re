#include "moho/serialization/SBlackListInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/serialization/SBlackListInfo.h"

#pragma init_seg(lib)

namespace
{
  using TypeInfo = moho::SBlackListInfoTypeInfo;

  alignas(TypeInfo) unsigned char gSBlackListInfoTypeInfoStorage[sizeof(TypeInfo)];
  bool gSBlackListInfoTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireSBlackListInfoTypeInfo()
  {
    if (!gSBlackListInfoTypeInfoConstructed) {
      new (gSBlackListInfoTypeInfoStorage) TypeInfo();
      gSBlackListInfoTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gSBlackListInfoTypeInfoStorage);
  }

  [[nodiscard]] TypeInfo* PeekSBlackListInfoTypeInfo() noexcept
  {
    if (!gSBlackListInfoTypeInfoConstructed) {
      return nullptr;
    }

    return reinterpret_cast<TypeInfo*>(gSBlackListInfoTypeInfoStorage);
  }

  template <class TTypeInfo>
  void ResetTypeInfoVectors(TTypeInfo& typeInfo) noexcept
  {
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00BFE620 (FUN_00BFE620, typeinfo cleanup)
   *
   * What it does:
   * Releases cached `SBlackListInfoTypeInfo` field/base vector storage at exit.
   */
  void cleanup_SBlackListInfoTypeInfo_00BFE620_Impl()
  {
    TypeInfo* const typeInfo = PeekSBlackListInfoTypeInfo();
    if (!typeInfo) {
      return;
    }

    ResetTypeInfoVectors(*typeInfo);
  }

  /**
   * Address: 0x00BD8810 (FUN_00BD8810, startup registration + atexit cleanup)
   *
   * What it does:
   * Forces `SBlackListInfoTypeInfo` construction and schedules exit cleanup.
   */
  int register_SBlackListInfoTypeInfo_00BD8810_Impl()
  {
    (void)AcquireSBlackListInfoTypeInfo();
    return std::atexit(&cleanup_SBlackListInfoTypeInfo_00BFE620_Impl);
  }

  struct SBlackListInfoTypeInfoBootstrap
  {
    SBlackListInfoTypeInfoBootstrap()
    {
      (void)register_SBlackListInfoTypeInfo_00BD8810_Impl();
    }
  };

  SBlackListInfoTypeInfoBootstrap gSBlackListInfoTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x006D3840 (FUN_006D3840, sub_6D3840)
   */
  SBlackListInfoTypeInfo::SBlackListInfoTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SBlackListInfo), this);
  }

  /**
   * Address: 0x006D38D0 (FUN_006D38D0, dtr lane)
   */
  SBlackListInfoTypeInfo::~SBlackListInfoTypeInfo() = default;

  /**
   * Address: 0x006D38C0 (FUN_006D38C0, Moho::SBlackListInfoTypeInfo::GetName)
   */
  const char* SBlackListInfoTypeInfo::GetName() const
  {
    return "SBlackListInfo";
  }

  /**
   * Address: 0x006D38A0 (FUN_006D38A0, Moho::SBlackListInfoTypeInfo::Init)
   */
  void SBlackListInfoTypeInfo::Init()
  {
    size_ = sizeof(SBlackListInfo);
    gpg::RType::Init();
    Finish();
  }

} // namespace moho
