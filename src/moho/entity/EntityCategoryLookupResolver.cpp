#include "EntityCategoryLookupResolver.h"

#include "moho/sim/RRuleGameRules.h"

#include <algorithm>
#include <atomic>
#include <cstring>

#include "legacy/containers/String.h"
#include "moho/console/CConCommand.h"
#include "moho/containers/BVIntSet.h"

namespace
{
  void IntersectCategoryWordRanges(moho::EntityCategorySet& lhs, const moho::EntityCategorySet& rhs)
  {
    lhs.mBits.IntersectWith(&rhs.mBits);
  }



  [[nodiscard]] bool
  NextSegmentToken(const char*& cursor, const char delimiter, const char*& tokenStart, const char*& tokenEnd) noexcept
  {
    if (!cursor) {
      tokenStart = nullptr;
      tokenEnd = nullptr;
      return false;
    }

    while (*cursor == delimiter) {
      ++cursor;
    }

    if (*cursor == '\0') {
      tokenStart = nullptr;
      tokenEnd = nullptr;
      cursor = nullptr;
      return false;
    }

    tokenStart = cursor;
    ++cursor;
    while (*cursor != '\0' && *cursor != delimiter) {
      ++cursor;
    }
    tokenEnd = cursor;

    if (*cursor != '\0') {
      ++cursor;
    }

    return true;
  }

  [[nodiscard]] bool NextBoundedToken(
    const char*& cursor, const char* const end, const char delimiter, const char*& tokenStart, const char*& tokenEnd
  ) noexcept
  {
    if (!cursor || !end || cursor >= end) {
      tokenStart = nullptr;
      tokenEnd = nullptr;
      return false;
    }

    while (cursor < end && *cursor == delimiter) {
      ++cursor;
    }

    if (cursor >= end) {
      tokenStart = nullptr;
      tokenEnd = nullptr;
      return false;
    }

    tokenStart = cursor;
    ++cursor;
    while (cursor < end && *cursor != delimiter) {
      ++cursor;
    }
    tokenEnd = cursor;

    if (cursor < end) {
      ++cursor;
    }

    return true;
  }

  /// One remembered lookup (sim_CategoryLookupCache). `text` holds the name, so a pointer that
  /// now names something else, such as a reused buffer, misses.
  struct SCategoryCacheSlot
  {
    const char* name = nullptr;
    const moho::EntityCategoryLookupTable* table = nullptr;
    std::uint32_t generation = 0;
    std::size_t mapSize = 0;
    const moho::EntityCategorySet* result = nullptr;
    char text[32] = {};
  };

  constexpr std::size_t kCategoryCacheSlots = 128;

  // Per thread, so the sim's workers and the UI never share a slot; plain storage, so a lookup
  // allocates nothing.
  thread_local SCategoryCacheSlot tCategoryCache[kCategoryCacheSlots];

  std::atomic<std::uint32_t> gCategoryTableGeneration{1u};

  [[nodiscard]] std::size_t CategoryCacheSlotOf(const char* const name, const void* const table) noexcept
  {
    const std::uint64_t key = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(name)) ^
                              (static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(table)) << 7u);
    return static_cast<std::size_t>((key * 0x9E3779B97F4A7C15ull) >> 57u) & (kCategoryCacheSlots - 1u);
  }
} // namespace

namespace moho
{
  bool sim_CategoryLookupCache = true;
  TConVar<bool> gTConVar_sim_CategoryLookupCache(
    "sim_CategoryLookupCache",
    "Category lookups by name remember their results per thread (same results, no tree walk).",
    &sim_CategoryLookupCache
  );

  void NoteEntityCategoryTableBuilt() noexcept
  {
    gCategoryTableGeneration.fetch_add(1u, std::memory_order_relaxed);
  }


  /**
   * Address: 0x0052B1E0 (FUN_0052B1E0)
   *
   * IDA signature:
   * char* __thiscall sub_52B1E0(_DWORD* this, char* source);
   *
   * What it does:
   * Looks up category text in RRuleGameRulesImpl category map and returns
   * either mapped range or fallback range stored in lookup table.
   */
  const EntityCategorySet* EntityCategoryLookupResolver::GetEntityCategory(const char* categoryName) const
  {
    // `RRuleGameRulesImpl` is the only class the binary dispatches slot 22 on,
    // and it does not derive from this synthetic interface, so reaching its
    // `mEntityCategoryLookup` (+0xC4, asserted in RRuleGameRules.h) still needs
    // the cast -- but to the real class, not to a padded stand-in for it.
    const auto* const rules = reinterpret_cast<const RRuleGameRulesImpl*>(this);
    if (!rules->mEntityCategoryLookup) {
      static const EntityCategorySet kEmpty{};
      return &kEmpty;
    }

    const EntityCategoryLookupTable& lookup = *rules->mEntityCategoryLookup;
    if (!categoryName) {
      return &lookup.mCategoryFallback;
    }

    if (!sim_CategoryLookupCache) {
      return lookup.FindOrFallback(fa::string(categoryName));
    }

    // Engine addition (sim_CategoryLookupCache): a hit is the same name text, against the same
    // table, built in the same generation and holding the same number of names, so the tree
    // walk would find the same set. Categories are only added while blueprints load, which
    // changes the size; the sets found are the table's own and are never moved.
    SCategoryCacheSlot& slot = tCategoryCache[CategoryCacheSlotOf(categoryName, &lookup)];
    const std::uint32_t generation = gCategoryTableGeneration.load(std::memory_order_relaxed);
    const std::size_t mapSize = lookup.mCategoryMap.size();
    if (slot.name == categoryName && slot.table == &lookup && slot.generation == generation &&
        slot.mapSize == mapSize && std::strcmp(slot.text, categoryName) == 0) {
      return slot.result;
    }

    const EntityCategorySet* const result = lookup.FindOrFallback(fa::string(categoryName));
    const std::size_t length = std::strlen(categoryName);
    if (length < sizeof(slot.text)) {
      std::memcpy(slot.text, categoryName, length + 1u);
      slot.name = categoryName;
      slot.table = &lookup;
      slot.generation = generation;
      slot.mapSize = mapSize;
      slot.result = result;
    }
    return result;
  }

  /**
   * Address: 0x005552F0 (FUN_005552F0, Moho::ParseEntityCategory)
   *
   * IDA signature:
   * Moho::EntityCategory* __userpurge Moho::ParseEntityCategory@<eax>(
   *     Moho::EntityCategorySet* categoryLookup, Moho::EntityCategory* out, const char* expr);
   *
   * What it does:
   * Real parse body behind the `RRuleGameRulesImpl::ParseEntityCategory`
   * (0x0052B280) thin virtual wrapper. Tokenizes `categoryExpression` on ','
   * into clauses; each clause is further tokenized on ' ' into terms. Every
   * resolved term looks up its precomputed category-word range in the lookup
   * table map; the first term in a clause seeds the clause accumulator and each
   * further term intersects into it. Every non-empty clause is then unioned
   * (via `EntityCategory::Add`, which ordinal-remaps bits) into `out`. `out` is
   * built in place, seeded to empty with the table's word-universe handle, and
   * returned for chaining.
   */
  EntityCategorySet*
  ParseEntityCategory(const void* const categoryLookup, EntityCategorySet* const out, const char* const categoryExpression)
  {
    const auto* const lookupTable = static_cast<const EntityCategoryLookupTable*>(categoryLookup);

    // Binary seeds the out set to empty using the table's word-universe handle
    // (the decompiler labels the +0x38 lane `mHelper.mRules`).
    out->ResetToEmpty(EntityCategoryHelper{lookupTable->mRules});

    if (!categoryExpression) {
      return out;
    }

    const char* clauseCursor = categoryExpression;
    const char* clauseStart = nullptr;
    const char* clauseEnd = nullptr;
    while (NextSegmentToken(clauseCursor, ',', clauseStart, clauseEnd)) {
      EntityCategorySet clauseAccum;
      clauseAccum.ResetToEmpty(EntityCategoryHelper{lookupTable->mRules});
      bool hasResolvedClauseTerm = false;

      const char* termCursor = clauseStart;
      const char* termStart = nullptr;
      const char* termEnd = nullptr;
      while (NextBoundedToken(termCursor, clauseEnd, ' ', termStart, termEnd)) {
        const fa::string termToken(termStart, termEnd);
        const EntityCategorySet* const range = lookupTable->TryFind(termToken);
        if (range == nullptr) {
          continue;
        }

        if (!hasResolvedClauseTerm) {
          clauseAccum = *range;
          hasResolvedClauseTerm = true;
        } else {
          IntersectCategoryWordRanges(clauseAccum, *range);
        }
      }

      // Fold the fully-intersected clause into the result. In the binary this
      // is `EntityCategory::Add(out /*result@ebx*/, &clauseAccum /*source@ecx*/)`,
      // which ordinal-remaps every set bit of the clause into `out`.
      (void)EntityCategory::Add(out, &clauseAccum);
    }

    return out;
  }
} // namespace moho
