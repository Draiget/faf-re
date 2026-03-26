#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E16264
   * COL:     0x00E6A0C0
   */
  class RRuleGameRulesImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0052B670 (FUN_0052B670)
     *
     * What it does:
     * Scalar deleting destructor thunk for RRuleGameRulesImplTypeInfo.
     */
    ~RRuleGameRulesImplTypeInfo() override;

    /**
     * Address: 0x0052B660 (FUN_0052B660, Moho::RRuleGameRulesImplTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for RRuleGameRulesImpl.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0052B640 (FUN_0052B640, Moho::RRuleGameRulesImplTypeInfo::Init)
     *
     * What it does:
     * Sets RRuleGameRulesImpl size metadata, registers the RRuleGameRules base,
     * and finalizes reflection type setup.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0052B640 setup tail (base registration)
     *
     * What it does:
     * Registers RRuleGameRules as reflected base at subobject offset +0x00.
     */
    static void AddBase_RRuleGameRules(gpg::RType* typeInfo);
  };

  static_assert(sizeof(RRuleGameRulesImplTypeInfo) == 0x64, "RRuleGameRulesImplTypeInfo size must be 0x64");
} // namespace moho
