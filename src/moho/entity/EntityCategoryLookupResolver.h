#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/entity/EntityCategoryReflection.h"

namespace moho
{
  /**
   * Engine addition (sim_CategoryLookupCache): every `EntityCategoryLookupTable` built moves
   * this on, so a name cached against an earlier table, even one at the same address, misses.
   */
  void NoteEntityCategoryTableBuilt() noexcept;

  extern bool sim_CategoryLookupCache;

  struct SFootprint;
  struct SNamedFootprint;
  struct SRuleFootprintsBlueprint;

  // `RRuleGameRulesImpl::GetEntityCategory` (0x0052B1E0, RRuleGameRules vtable
  // slot 22) is defined in EntityCategoryLookupResolver.cpp next to its lookup
  // cache. This header used to declare a separate `EntityCategoryLookupResolver`
  // interface that callers reached by casting `RRuleGameRulesImpl*`; the binary
  // has only the `RRuleGameRules` vtable.

  /**
   * Address: 0x005552F0 (FUN_005552F0, Moho::ParseEntityCategory)
   *
   * IDA signature:
   * Moho::EntityCategory* __userpurge Moho::ParseEntityCategory@<eax>(
   *     Moho::EntityCategorySet* categoryLookup, Moho::EntityCategory* out, const char* expr);
   *
   * What it does:
   * Parses a comma-separated category expression against a game-rules category
   * lookup table. Each comma clause intersects its space-separated terms; every
   * non-empty clause is then unioned into `out`. `categoryLookup` is the opaque
   * `RRuleGameRulesImpl::mEntityCategoryLookup` handle (+0xC4); `out` is an
   * uninitialized category set built in place and returned for chaining.
   */
  EntityCategorySet*
  ParseEntityCategory(const void* categoryLookup, EntityCategorySet* out, const char* categoryExpression);
} // namespace moho
