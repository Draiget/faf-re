#include "EntityCategoryLookupResolver.h"

#include <algorithm>
#include <cstring>

#include "legacy/containers/String.h"
#include "legacy/containers/Tree.h"
#include "moho/containers/BVIntSet.h"

namespace
{
  void IntersectCategoryWordRanges(moho::CategoryWordRangeView& lhs, const moho::CategoryWordRangeView& rhs)
  {
    lhs.mBits.IntersectWith(&rhs.mBits);
  }

  void UnionCategoryWordRanges(moho::CategoryWordRangeView& lhs, const moho::CategoryWordRangeView& rhs)
  {
    if (rhs.Empty()) {
      return;
    }
    if (lhs.Empty()) {
      lhs = rhs;
      return;
    }

    lhs.mBits.AddAllFrom(&rhs.mBits);
  }

  struct CategoryNameMapNodeView : msvc8::Tree<CategoryNameMapNodeView>
  {
    std::uint8_t color;
    std::uint8_t reserved0D;
    std::uint8_t reserved0E;
    std::uint8_t reserved0F;
    msvc8::string key;
    std::uint8_t pad_2C_2F[0x04];
    moho::CategoryWordRangeView value;
    std::uint8_t nodeState;
    std::uint8_t isNil;
  };

  static_assert(offsetof(CategoryNameMapNodeView, key) == 0x10, "CategoryNameMapNodeView::key offset must be 0x10");
  static_assert(offsetof(CategoryNameMapNodeView, value) == 0x30, "CategoryNameMapNodeView::value offset must be 0x30");
  static_assert(offsetof(CategoryNameMapNodeView, isNil) == 0x59, "CategoryNameMapNodeView::isNil offset must be 0x59");

  struct CategoryNameMapView
  {
    std::uint32_t unknown00;
    CategoryNameMapNodeView* head;
    std::uint32_t size;
    std::uint32_t unknown0C;
  };

  static_assert(sizeof(CategoryNameMapView) == 0x10, "CategoryNameMapView size must be 0x10");
  static_assert(offsetof(CategoryNameMapView, head) == 0x04, "CategoryNameMapView::head offset must be 0x04");

  struct EntityCategoryLookupTableView
  {
    CategoryNameMapView categoryMap;              // +0x00
    moho::CategoryWordRangeView categoryFallback; // +0x10
    std::uint32_t wordUniverseHandle;             // +0x38
  };

  static_assert(
    offsetof(EntityCategoryLookupTableView, categoryMap) == 0x00,
    "EntityCategoryLookupTableView::categoryMap offset must be 0x00"
  );
  static_assert(
    offsetof(EntityCategoryLookupTableView, categoryFallback) == 0x10,
    "EntityCategoryLookupTableView::categoryFallback offset must be 0x10"
  );
  static_assert(
    offsetof(EntityCategoryLookupTableView, wordUniverseHandle) == 0x38,
    "EntityCategoryLookupTableView::wordUniverseHandle offset must be 0x38"
  );

  struct RRuleGameRulesCategoryStorageView
  {
    std::uint8_t pad_0000_00C4[0x0C4];
    EntityCategoryLookupTableView* categoryLookup;
  };

  static_assert(
    offsetof(RRuleGameRulesCategoryStorageView, categoryLookup) == 0x0C4,
    "RRuleGameRulesCategoryStorageView::categoryLookup offset must be 0x0C4"
  );

  [[nodiscard]] const char* GetStringData(const msvc8::string& str) noexcept
  {
    return (str.myRes < 0x10u) ? &str.bx.buf[0] : str.bx.ptr;
  }

  [[nodiscard]] int CompareStringLexicographically(
    const char* lhs, const std::uint32_t lhsLength, const char* rhs, const std::uint32_t rhsLength
  ) noexcept
  {
    if (!lhs) {
      lhs = "";
    }
    if (!rhs) {
      rhs = "";
    }

    const std::uint32_t minLength = std::min(lhsLength, rhsLength);
    if (minLength > 0u) {
      const int cmp = std::memcmp(lhs, rhs, static_cast<std::size_t>(minLength));
      if (cmp != 0) {
        return cmp;
      }
    }

    if (lhsLength < rhsLength) {
      return -1;
    }
    if (lhsLength > rhsLength) {
      return 1;
    }
    return 0;
  }

  [[nodiscard]] int CompareNodeKeyAgainstQuery(const CategoryNameMapNodeView& node, const msvc8::string& query) noexcept
  {
    return CompareStringLexicographically(GetStringData(node.key), node.key.mySize, GetStringData(query), query.mySize);
  }

  /**
   * Address: 0x00556970 (FUN_00556970)
   *
   * What it does:
   * Tree lower_bound over category-name map using lexical string compare.
   */
  [[nodiscard]] const CategoryNameMapNodeView*
  FindCategoryLowerBound(const CategoryNameMapView& map, const msvc8::string& key) noexcept
  {
    return msvc8::lower_bound_node<CategoryNameMapNodeView, &CategoryNameMapNodeView::isNil>(
      map.head, key, [](const CategoryNameMapNodeView& node, const msvc8::string& query) {
      return CompareNodeKeyAgainstQuery(node, query) < 0;
    }
    );
  }

  /**
   * Address: 0x00556220 (FUN_00556220)
   *
   * What it does:
   * Resolves exact category-name match in map, or returns map end sentinel.
   */
  [[nodiscard]] const CategoryNameMapNodeView*
  FindCategoryNodeOrHead(const CategoryNameMapView& map, const msvc8::string& key) noexcept
  {
    return msvc8::find_equal_or_head_node<CategoryNameMapNodeView, &CategoryNameMapNodeView::isNil>(
      map.head, key, [](const CategoryNameMapNodeView& node, const msvc8::string& query) {
      return CompareNodeKeyAgainstQuery(node, query) < 0;
    }
    );
  }

  struct CategoryMapWithDefaultRuntimeView
  {
    CategoryNameMapView mMap;              // +0x00
    moho::CategoryWordRangeView mDefault;  // +0x10
  };

  static_assert(
    offsetof(CategoryMapWithDefaultRuntimeView, mMap) == 0x00,
    "CategoryMapWithDefaultRuntimeView::mMap offset must be 0x00"
  );
  static_assert(
    offsetof(CategoryMapWithDefaultRuntimeView, mDefault) == 0x10,
    "CategoryMapWithDefaultRuntimeView::mDefault offset must be 0x10"
  );

  /**
   * Address: 0x00555290 (FUN_00555290)
   *
   * What it does:
   * Returns the mapped category range for `key`, or `nullptr` when the key is
   * absent.
   */
  [[maybe_unused]] [[nodiscard]] moho::CategoryWordRangeView* FindCategoryValueOrNull(
    CategoryMapWithDefaultRuntimeView* const mapRuntime,
    const msvc8::string& key
  ) noexcept
  {
    if (!mapRuntime) {
      return nullptr;
    }

    const CategoryNameMapNodeView* const node = FindCategoryNodeOrHead(mapRuntime->mMap, key);
    if (!node || node == mapRuntime->mMap.head) {
      return nullptr;
    }

    return const_cast<moho::CategoryWordRangeView*>(&node->value);
  }

  /**
   * Address: 0x005552C0 (FUN_005552C0)
   *
   * What it does:
   * Returns the mapped category range for `key`, or the runtime default range
   * when the key is absent.
   */
  [[maybe_unused]] [[nodiscard]] moho::CategoryWordRangeView* FindCategoryValueOrDefault(
    CategoryMapWithDefaultRuntimeView* const mapRuntime,
    const msvc8::string& key
  ) noexcept
  {
    if (!mapRuntime) {
      return nullptr;
    }

    const CategoryNameMapNodeView* const node = FindCategoryNodeOrHead(mapRuntime->mMap, key);
    if (!node || node == mapRuntime->mMap.head) {
      return &mapRuntime->mDefault;
    }

    return const_cast<moho::CategoryWordRangeView*>(&node->value);
  }

  /**
   * Address: 0x0052CC30 (FUN_0052CC30)
   *
   * What it does:
   * Advances one category-name map node pointer to its in-order successor
   * using the map's legacy sentinel-node layout.
   */
  [[maybe_unused]] void AdvanceCategoryNameMapNodeSuccessor(CategoryNameMapNodeView** const cursor) noexcept
  {
    CategoryNameMapNodeView* node = *cursor;
    if (node->isNil != 0u) {
      return;
    }

    CategoryNameMapNodeView* right = node->right;
    if (right->isNil != 0u) {
      CategoryNameMapNodeView* parent = node->parent;
      while (parent->isNil == 0u) {
        if (*cursor != parent->right) {
          break;
        }
        *cursor = parent;
        parent = parent->parent;
      }
      *cursor = parent;
      return;
    }

    CategoryNameMapNodeView* left = right->left;
    while (left->isNil == 0u) {
      right = left;
      left = left->left;
    }
    *cursor = right;
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
    const auto* const rules = reinterpret_cast<const RRuleGameRulesCategoryStorageView*>(this);
    if (!rules->categoryLookup) {
      static const CategoryWordRangeView kEmpty{};
      return &kEmpty;
    }

    const EntityCategoryLookupTableView& lookup = *rules->categoryLookup;
    if (!categoryName || !lookup.categoryMap.head) {
      return &lookup.categoryFallback;
    }

    const msvc8::string query(categoryName);
    const CategoryNameMapNodeView* const node = FindCategoryNodeOrHead(lookup.categoryMap, query);
    if (!node || node == lookup.categoryMap.head) {
      return &lookup.categoryFallback;
    }

    return &node->value;
  }

  /**
   * Address: 0x0052B280 (FUN_0052B280)
   *
   * IDA signature:
   * int __thiscall sub_52B280(_DWORD* this, int out, int source);
   *
   * What it does:
   * Parses comma-separated category clauses; each clause intersects space-
   * separated terms, then unions all clauses into a resulting category set.
   */
  CategoryWordRangeView EntityCategoryLookupResolver::ParseEntityCategory(const char* categoryExpression) const
  {
    const auto* const rules = reinterpret_cast<const RRuleGameRulesCategoryStorageView*>(this);
    CategoryWordRangeView parsed;
    if (!rules->categoryLookup) {
      parsed.ResetToEmpty(0u);
      return parsed;
    }

    const EntityCategoryLookupTableView& lookup = *rules->categoryLookup;

    parsed.ResetToEmpty(lookup.wordUniverseHandle);
    if (!categoryExpression || !*categoryExpression) {
      return parsed;
    }

    const char* clauseCursor = categoryExpression;
    const char* clauseStart = nullptr;
    const char* clauseEnd = nullptr;
    while (NextSegmentToken(clauseCursor, ',', clauseStart, clauseEnd)) {
      CategoryWordRangeView clauseAccum;
      clauseAccum.ResetToEmpty(lookup.wordUniverseHandle);
      bool hasResolvedClauseTerm = false;

      const char* termCursor = clauseStart;
      const char* termStart = nullptr;
      const char* termEnd = nullptr;
      while (NextBoundedToken(termCursor, clauseEnd, ' ', termStart, termEnd)) {
        const msvc8::string termToken(termStart, termEnd);
        const CategoryNameMapNodeView* const node = FindCategoryNodeOrHead(lookup.categoryMap, termToken);
        if (!node || node == lookup.categoryMap.head) {
          continue;
        }

        if (!hasResolvedClauseTerm) {
          clauseAccum = node->value;
          hasResolvedClauseTerm = true;
        } else {
          IntersectCategoryWordRanges(clauseAccum, node->value);
        }
      }

      if (hasResolvedClauseTerm) {
        UnionCategoryWordRanges(parsed, clauseAccum);
      }
    }

    return parsed;
  }
} // namespace moho
