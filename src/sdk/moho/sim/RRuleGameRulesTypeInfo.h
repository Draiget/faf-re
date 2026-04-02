#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E16234
   * COL:     0x00E6A110
   */
  class RRuleGameRulesTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0052B4A0 (FUN_0052B4A0, Moho::RRuleGameRulesTypeInfo::RRuleGameRulesTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RRuleGameRules`.
     */
    RRuleGameRulesTypeInfo();

    /**
     * Address: 0x0052B530 (FUN_0052B530)
     *
     * What it does:
     * Scalar deleting destructor thunk for RRuleGameRulesTypeInfo.
     */
    ~RRuleGameRulesTypeInfo() override;

    /**
     * Address: 0x0052B520 (FUN_0052B520, Moho::RRuleGameRulesTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type label for RRuleGameRules.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0052B500 (FUN_0052B500, Moho::RRuleGameRulesTypeInfo::Init)
     *
     * What it does:
     * Sets RRuleGameRules size metadata and finalizes reflection type setup.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC8ED0 (FUN_00BC8ED0, register_RRuleGameRulesTypeInfoStartup)
   *
   * What it does:
   * Materializes and startup-registers `RRuleGameRulesTypeInfo`.
   */
  int register_RRuleGameRulesTypeInfoStartup();

  static_assert(sizeof(RRuleGameRulesTypeInfo) == 0x64, "RRuleGameRulesTypeInfo size must be 0x64");
} // namespace moho
