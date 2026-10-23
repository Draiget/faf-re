#include "moho/serialization/SBlackListInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/serialization/SBlackListInfo.h"

namespace
{
  using TypeInfo = moho::SBlackListInfoTypeInfo;

  /**
   * Address: 0x00BFE620 (FUN_00BFE620, atexit destructor of the SBlackListInfoTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireSBlackListInfoTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BD8810 (FUN_00BD8810, register_SBlackListInfoTypeInfo)
   *
   * What it does:
   * Forces `SBlackListInfoTypeInfo` construction.
   */
  void register_SBlackListInfoTypeInfo()
  {
    (void)AcquireSBlackListInfoTypeInfo();
  }

  struct SBlackListInfoTypeInfoBootstrap
  {
    SBlackListInfoTypeInfoBootstrap()
    {
      register_SBlackListInfoTypeInfo();
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
