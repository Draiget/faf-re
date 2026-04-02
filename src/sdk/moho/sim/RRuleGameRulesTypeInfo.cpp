#include "moho/sim/RRuleGameRulesTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/RRuleGameRules.h"

namespace
{
  using TypeInfo = moho::RRuleGameRulesTypeInfo;

  alignas(TypeInfo) unsigned char gRRuleGameRulesTypeInfoStorage[sizeof(TypeInfo)];
  bool gRRuleGameRulesTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRRuleGameRulesTypeInfo()
  {
    if (!gRRuleGameRulesTypeInfoConstructed) {
      new (gRRuleGameRulesTypeInfoStorage) TypeInfo();
      gRRuleGameRulesTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRRuleGameRulesTypeInfoStorage);
  }

  void cleanup_RRuleGameRulesTypeInfo()
  {
    if (!gRRuleGameRulesTypeInfoConstructed) {
      return;
    }

    AcquireRRuleGameRulesTypeInfo().~TypeInfo();
    gRRuleGameRulesTypeInfoConstructed = false;
  }

  struct RRuleGameRulesTypeInfoBootstrap
  {
    RRuleGameRulesTypeInfoBootstrap()
    {
      (void)moho::register_RRuleGameRulesTypeInfoStartup();
    }
  };

  RRuleGameRulesTypeInfoBootstrap gRRuleGameRulesTypeInfoBootstrap;
} // namespace

namespace moho
{
  gpg::RType* RRuleGameRules::sType = nullptr;

  gpg::RType* RRuleGameRules::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RRuleGameRules));
    }
    return sType;
  }

  /**
   * Address: 0x0052B4A0 (FUN_0052B4A0, Moho::RRuleGameRulesTypeInfo::RRuleGameRulesTypeInfo)
   */
  RRuleGameRulesTypeInfo::RRuleGameRulesTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RRuleGameRules), this);
  }

  /**
   * Address: 0x0052B530 (FUN_0052B530)
   */
  RRuleGameRulesTypeInfo::~RRuleGameRulesTypeInfo() = default;

  /**
   * Address: 0x0052B520 (FUN_0052B520, Moho::RRuleGameRulesTypeInfo::GetName)
   */
  const char* RRuleGameRulesTypeInfo::GetName() const
  {
    return "RRuleGameRules";
  }

  /**
   * Address: 0x0052B500 (FUN_0052B500, Moho::RRuleGameRulesTypeInfo::Init)
   */
  void RRuleGameRulesTypeInfo::Init()
  {
    size_ = sizeof(RRuleGameRules);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC8ED0 (FUN_00BC8ED0, register_RRuleGameRulesTypeInfoStartup)
   */
  int register_RRuleGameRulesTypeInfoStartup()
  {
    (void)AcquireRRuleGameRulesTypeInfo();
    return std::atexit(&cleanup_RRuleGameRulesTypeInfo);
  }
} // namespace moho
