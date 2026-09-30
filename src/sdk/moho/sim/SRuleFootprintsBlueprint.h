#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/path/SNamedFootprint.h"

namespace gpg
{
  class RType;
} // namespace gpg

namespace moho
{
  /**
   * The rules' footprint table: every `SNamedFootprint` `/lua/footprints.lua`
   * specs through `SpecFootprints`, in spec order, so a footprint's `mIndex`
   * is its position in the list.
   *
   * `SRuleFootprintsBlueprintTypeInfo::Init` 0x00513ED0 reflects it as one
   * field, `Footprints`, of type `list<SNamedFootprint>` at offset 0
   * (`AddField` 0x005146E0). The owner's constructor 0x00529120 buys the list
   * head (`_Buy_head` 0x0052CB30) and its destructor 0x00529700 runs the
   * list's `_Tidy` 0x00514340: both are this member's construction and
   * destruction.
   */
  struct SRuleFootprintsBlueprint
  {
    static gpg::RType* sType;

    msvc8::list<SNamedFootprint> mFootprints; // +0x00
  };

  static_assert(
    offsetof(SRuleFootprintsBlueprint, mFootprints) == 0x00, "SRuleFootprintsBlueprint::mFootprints offset must be 0x00"
  );
  static_assert(sizeof(SRuleFootprintsBlueprint) == 0x0C, "SRuleFootprintsBlueprint size must be 0x0C");

  /**
   * Address: 0x00513E70 (FUN_00513E70, preregister_SRuleFootprintsBlueprintTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI storage for `SRuleFootprintsBlueprint`.
   */
  [[nodiscard]] gpg::RType* preregister_SRuleFootprintsBlueprintTypeInfo();

  /**
   * Address: 0x00BC8380 (FUN_00BC8380, register_SRuleFootprintsBlueprintTypeInfoStartup)
   *
   * What it does:
   * Preregisters `SRuleFootprintsBlueprint` RTTI.
   */
  void register_SRuleFootprintsBlueprintTypeInfoStartup();
} // namespace moho
