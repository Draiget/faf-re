#include "moho/sim/RRuleGameRulesTypeInfo.h"

#include <typeinfo>

#include "moho/sim/RRuleGameRules.h"

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
} // namespace moho
