#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"

namespace gpg
{
  class RField;
  class RType;
}

namespace moho
{
  class RRuleGameRules;

  /**
   * Address: 0x0050DC10 (FUN_0050DC10)
   *
   * What it does:
   * Reflection type init for the common blueprint base (`sizeof = 0x60`).
   */
  struct RBlueprint
  {
    static gpg::RType* sPointerType;

    void* mVTable;                  // +0x00
    RRuleGameRules* mOwner;         // +0x04
    msvc8::string mBlueprintId;     // +0x08
    msvc8::string mDescription;     // +0x24
    msvc8::string mSource;          // +0x40
    std::int32_t mBlueprintOrdinal; // +0x5C

    /**
     * Address: 0x0050DBA0 (FUN_0050DBA0)
     * Mangled: ?OnInitBlueprint@RBlueprint@Moho@@MAEXXZ
     *
     * What it does:
     * Base blueprint post-load hook; default implementation is empty.
     */
    void OnInitBlueprint();
  };

  class RBlueprintTypeInfo final
  {
  public:
    /**
     * Address: 0x0050DCF0 (FUN_0050DCF0, Moho::RBlueprintTypeInfo::AddFields)
     *
     * What it does:
     * Registers reflected field lanes for the base `RBlueprint` layout.
     */
    static gpg::RField* AddFields(gpg::RType* typeInfo);
  };

  static_assert(offsetof(RBlueprint, mOwner) == 0x04, "RBlueprint::mOwner offset must be 0x04");
  static_assert(offsetof(RBlueprint, mBlueprintId) == 0x08, "RBlueprint::mBlueprintId offset must be 0x08");
  static_assert(offsetof(RBlueprint, mDescription) == 0x24, "RBlueprint::mDescription offset must be 0x24");
  static_assert(offsetof(RBlueprint, mSource) == 0x40, "RBlueprint::mSource offset must be 0x40");
  static_assert(offsetof(RBlueprint, mBlueprintOrdinal) == 0x5C, "RBlueprint::mBlueprintOrdinal offset must be 0x5C");
  static_assert(sizeof(RBlueprint) == 0x60, "RBlueprint size must be 0x60");
} // namespace moho
