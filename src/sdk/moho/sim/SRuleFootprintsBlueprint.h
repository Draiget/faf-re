#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/path/SNamedFootprint.h"

namespace moho
{
  /**
   * Intrusive list node used by `SRuleFootprintsBlueprint`.
   *
   * Evidence:
   * - 0x0052AAE0 (FUN_0052AAE0): list walk uses node `next` at +0x00 and
   *   returns `node + 0x08` as `SNamedFootprint*`.
   */
  struct SRuleFootprintNode
  {
    SRuleFootprintNode* next; // +0x00
    SRuleFootprintNode* prev; // +0x04
    SNamedFootprint value;    // +0x08
  };

  static_assert(offsetof(SRuleFootprintNode, value) == 0x08, "SRuleFootprintNode::value offset must be 0x08");

  /**
   * Address: 0x00513ED0 (FUN_00513ED0, SRuleFootprintsBlueprintTypeInfo::Init)
   *
   * What it does:
   * Reflects runtime rule footprint table container (`sizeof = 0x0C`).
   */
  struct SRuleFootprintsBlueprint
  {
    void* mAllocProxy;         // +0x00
    SRuleFootprintNode* mHead; // +0x04 (circular list sentinel node)
    std::uint32_t mSize;       // +0x08
  };

  static_assert(
    offsetof(SRuleFootprintsBlueprint, mHead) == 0x04, "SRuleFootprintsBlueprint::mHead offset must be 0x04"
  );
  static_assert(
    offsetof(SRuleFootprintsBlueprint, mSize) == 0x08, "SRuleFootprintsBlueprint::mSize offset must be 0x08"
  );
  static_assert(sizeof(SRuleFootprintsBlueprint) == 0x0C, "SRuleFootprintsBlueprint size must be 0x0C");
} // namespace moho
