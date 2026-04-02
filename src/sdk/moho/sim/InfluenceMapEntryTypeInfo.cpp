#include "moho/sim/InfluenceMapEntryTypeInfo.h"

#include <typeinfo>

#include "moho/sim/CInfluenceMap.h"

namespace
{
  moho::InfluenceMapEntryTypeInfo gInfluenceMapEntryTypeInfo;
}

namespace moho
{
  /**
   * Address: 0x007177B0 (FUN_007177B0, sub_7177B0)
   */
  InfluenceMapEntryTypeInfo::InfluenceMapEntryTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(InfluenceMapEntry), this);
  }

  /**
   * Address: 0x00BDA700 (FUN_00BDA700, sub_BDA700)
   *
   * What it does:
   * Forces InfluenceMapEntry RTTI preregistration bootstrap.
   */
  void register_InfluenceMapEntryTypeInfo()
  {
    (void)gInfluenceMapEntryTypeInfo;
  }

  /**
   * Address: 0x00717840 (FUN_00717840, Moho::InfluenceMapEntryTypeInfo::dtr)
   */
  InfluenceMapEntryTypeInfo::~InfluenceMapEntryTypeInfo() = default;

  /**
   * Address: 0x00717830 (FUN_00717830, Moho::InfluenceMapEntryTypeInfo::GetName)
   */
  const char* InfluenceMapEntryTypeInfo::GetName() const
  {
    return "InfluenceMapEntry";
  }

  /**
   * Address: 0x00717810 (FUN_00717810, Moho::InfluenceMapEntryTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::InfluenceMapEntryTypeInfo::Init(gpg::RType *this);
   */
  void InfluenceMapEntryTypeInfo::Init()
  {
    size_ = sizeof(InfluenceMapEntry);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

namespace
{
  struct InfluenceMapEntryTypeInfoBootstrap
  {
    InfluenceMapEntryTypeInfoBootstrap()
    {
      moho::register_InfluenceMapEntryTypeInfo();
    }
  };

  InfluenceMapEntryTypeInfoBootstrap gInfluenceMapEntryTypeInfoBootstrap;
} // namespace
