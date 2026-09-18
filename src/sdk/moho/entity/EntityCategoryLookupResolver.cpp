#include "EntityCategoryLookupResolver.h"

#include "moho/sim/RRuleGameRules.h"

#include <algorithm>
#include <cstring>

#include "legacy/containers/String.h"
#include "moho/containers/BVIntSet.h"

namespace
{
  void IntersectCategoryWordRanges(moho::CategoryWordRangeView& lhs, const moho::CategoryWordRangeView& rhs)
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
} // namespace

namespace moho
{


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
  const CategoryWordRangeView* EntityCategoryLookupResolver::GetEntityCategory(const char* categoryName) const
  {
    // `RRuleGameRulesImpl` is the only class the binary dispatches slot 22 on,
    // and it does not derive from this synthetic interface, so reaching its
    // `mEntityCategoryLookup` (+0xC4, asserted in RRuleGameRules.h) still needs
    // the cast -- but to the real class, not to a padded stand-in for it.
    const auto* const rules = reinterpret_cast<const RRuleGameRulesImpl*>(this);
    if (!rules->mEntityCategoryLookup) {
      static const CategoryWordRangeView kEmpty{};
      return &kEmpty;
    }

    const EntityCategoryLookupTable& lookup = *rules->mEntityCategoryLookup;
    if (!categoryName) {
      return &lookup.mCategoryFallback;
    }

    return lookup.FindOrFallback(msvc8::string(categoryName));
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
  CategoryWordRangeView*
  ParseEntityCategory(const void* const categoryLookup, CategoryWordRangeView* const out, const char* const categoryExpression)
  {
    const auto* const lookupTable = static_cast<const EntityCategoryLookupTable*>(categoryLookup);

    // Binary seeds the out set to empty using the table's word-universe handle
    // (the decompiler labels the +0x38 lane `mHelper.mRules`).
    out->ResetToEmpty(lookupTable->mWordUniverseHandle);

    if (!categoryExpression) {
      return out;
    }

    const char* clauseCursor = categoryExpression;
    const char* clauseStart = nullptr;
    const char* clauseEnd = nullptr;
    while (NextSegmentToken(clauseCursor, ',', clauseStart, clauseEnd)) {
      CategoryWordRangeView clauseAccum;
      clauseAccum.ResetToEmpty(lookupTable->mWordUniverseHandle);
      bool hasResolvedClauseTerm = false;

      const char* termCursor = clauseStart;
      const char* termStart = nullptr;
      const char* termEnd = nullptr;
      while (NextBoundedToken(termCursor, clauseEnd, ' ', termStart, termEnd)) {
        const msvc8::string termToken(termStart, termEnd);
        const CategoryWordRangeView* const range = lookupTable->TryFind(termToken);
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
