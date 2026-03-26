#include "moho/sim/RRuleGameRulesImplTypeInfo.h"

#include <typeinfo>

#include "moho/sim/RRuleGameRules.h"

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
   * Address: 0x0052B640 setup tail (base registration)
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
} // namespace moho
