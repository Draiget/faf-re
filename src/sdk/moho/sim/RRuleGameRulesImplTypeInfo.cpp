#include "moho/sim/RRuleGameRulesImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/RRuleGameRules.h"

namespace
{
  using TypeInfo = moho::RRuleGameRulesImplTypeInfo;

  alignas(TypeInfo) unsigned char gRRuleGameRulesImplTypeInfoStorage[sizeof(TypeInfo)];
  bool gRRuleGameRulesImplTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRRuleGameRulesImplTypeInfo()
  {
    if (!gRRuleGameRulesImplTypeInfoConstructed) {
      new (gRRuleGameRulesImplTypeInfoStorage) TypeInfo();
      gRRuleGameRulesImplTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRRuleGameRulesImplTypeInfoStorage);
  }

  void cleanup_RRuleGameRulesImplTypeInfo()
  {
    if (!gRRuleGameRulesImplTypeInfoConstructed) {
      return;
    }

    AcquireRRuleGameRulesImplTypeInfo().~TypeInfo();
    gRRuleGameRulesImplTypeInfoConstructed = false;
  }

  struct RRuleGameRulesImplTypeInfoBootstrap
  {
    RRuleGameRulesImplTypeInfoBootstrap()
    {
      (void)moho::register_RRuleGameRulesImplTypeInfoStartup();
    }
  };

  RRuleGameRulesImplTypeInfoBootstrap gRRuleGameRulesImplTypeInfoBootstrap;
} // namespace

namespace moho
{
  gpg::RType* RRuleGameRulesImpl::sType = nullptr;

  gpg::RType* RRuleGameRulesImpl::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RRuleGameRulesImpl));
    }
    return sType;
  }

  /**
   * Address: 0x0052B5E0 (FUN_0052B5E0, Moho::RRuleGameRulesImplTypeInfo::RRuleGameRulesImplTypeInfo)
   */
  RRuleGameRulesImplTypeInfo::RRuleGameRulesImplTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RRuleGameRulesImpl), this);
  }

  /**
   * Address: 0x0052B670 (FUN_0052B670)
   */
  RRuleGameRulesImplTypeInfo::~RRuleGameRulesImplTypeInfo() = default;

  /**
   * Address: 0x0052B660 (FUN_0052B660, Moho::RRuleGameRulesImplTypeInfo::GetName)
   */
  const char* RRuleGameRulesImplTypeInfo::GetName() const
  {
    return "RRuleGameRulesImpl";
  }

  /**
   * Address: 0x0052B640 (FUN_0052B640, Moho::RRuleGameRulesImplTypeInfo::Init)
   */
  void RRuleGameRulesImplTypeInfo::Init()
  {
    size_ = sizeof(RRuleGameRulesImpl);
    gpg::RType::Init();
    AddBase_RRuleGameRules(this);
    Finish();
  }

  /**
    * Alias of FUN_0052B640 (non-canonical helper lane).
   */
  void RRuleGameRulesImplTypeInfo::AddBase_RRuleGameRules(gpg::RType* const typeInfo)
  {
    gpg::RField baseField{};
    baseField.mType = RRuleGameRules::StaticGetClass();
    baseField.mName = baseField.mType->GetName();
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BC8EF0 (FUN_00BC8EF0, register_RRuleGameRulesImplTypeInfoStartup)
   */
  int register_RRuleGameRulesImplTypeInfoStartup()
  {
    (void)AcquireRRuleGameRulesImplTypeInfo();
    return std::atexit(&cleanup_RRuleGameRulesImplTypeInfo);
  }
} // namespace moho
