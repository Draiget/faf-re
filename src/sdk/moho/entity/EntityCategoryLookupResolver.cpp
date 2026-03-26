#include "EntityCategoryLookupResolver.h"

#include <algorithm>
#include <cstring>
#include <new>
#include <utility>

#include "legacy/containers/String.h"
#include "legacy/containers/Tree.h"
#include "moho/containers/BVIntSet.h"

namespace
{
  constexpr std::size_t kInlineWordCapacity = 2u;

  void SaveInlineCapacityHeader(moho::CategoryWordRangeView& range) noexcept
  {
    // Mirrors FastVectorN::SaveInlineCapacity_ layout contract used by BVIntSet.
    *reinterpret_cast<std::uint32_t**>(&range.mWordsInlineStorage[0]) = &range.mWordsInlineStorage[kInlineWordCapacity];
  }

  [[nodiscard]] moho::BVIntSet& AsWordBitset(moho::CategoryWordRangeView& range) noexcept
  {
    static_assert(
      offsetof(moho::CategoryWordRangeView, mStartWordIndex) == 0x08,
      "CategoryWordRangeView::mStartWordIndex offset must be 0x08"
    );
    static_assert(sizeof(moho::BVIntSet) == 0x20, "BVIntSet size must be 0x20");
    return *reinterpret_cast<moho::BVIntSet*>(&range.mStartWordIndex);
  }

  [[nodiscard]] const moho::BVIntSet& AsWordBitset(const moho::CategoryWordRangeView& range) noexcept
  {
    static_assert(
      offsetof(moho::CategoryWordRangeView, mStartWordIndex) == 0x08,
      "CategoryWordRangeView::mStartWordIndex offset must be 0x08"
    );
    static_assert(sizeof(moho::BVIntSet) == 0x20, "BVIntSet size must be 0x20");
    return *reinterpret_cast<const moho::BVIntSet*>(&range.mStartWordIndex);
  }

  void ResetInlineWordStorage(moho::CategoryWordRangeView& range) noexcept
  {
    range.mWordsInlineBase = &range.mWordsInlineStorage[0];
    range.mWordsBegin = range.mWordsInlineBase;
    range.mWordsEnd = range.mWordsInlineBase;
    range.mWordsCapacityEnd = range.mWordsInlineBase + kInlineWordCapacity;
    SaveInlineCapacityHeader(range);
  }

  void ReleaseWordStorage(moho::CategoryWordRangeView& range) noexcept
  {
    if (range.mWordsBegin != nullptr && range.mWordsBegin != range.mWordsInlineBase) {
      delete[] range.mWordsBegin;
    }
    ResetInlineWordStorage(range);
  }

  void EnsureWordCapacity(moho::CategoryWordRangeView& range, const std::size_t requestedWordCapacity)
  {
    const std::size_t currentWordCapacity = static_cast<std::size_t>(range.mWordsCapacityEnd - range.mWordsBegin);
    if (currentWordCapacity >= requestedWordCapacity) {
      return;
    }

    auto* const newWords = new std::uint32_t[requestedWordCapacity];
    const std::size_t currentWordCount = range.WordCount();
    if (currentWordCount > 0u) {
      std::copy(range.cbegin(), range.cend(), newWords);
    }

    if (range.mWordsBegin == range.mWordsInlineBase) {
      // Preserve inline-capacity header before leaving inline storage.
      SaveInlineCapacityHeader(range);
    }

    if (range.mWordsBegin != range.mWordsInlineBase) {
      delete[] range.mWordsBegin;
    }

    range.mWordsBegin = newWords;
    range.mWordsEnd = newWords + currentWordCount;
    range.mWordsCapacityEnd = newWords + requestedWordCapacity;
  }

  void ResizeWordCount(moho::CategoryWordRangeView& range, const std::size_t wordCount)
  {
    EnsureWordCapacity(range, wordCount);
    range.mWordsEnd = range.mWordsBegin + wordCount;
  }

  void CopyCategoryWordRange(moho::CategoryWordRangeView& dst, const moho::CategoryWordRangeView& src)
  {
    dst.mWordUniverseHandle = src.mWordUniverseHandle;
    dst.mReserved04 = src.mReserved04;
    dst.mStartWordIndex = src.mStartWordIndex;
    dst.mReserved0C = src.mReserved0C;

    const std::size_t wordCount = src.WordCount();
    ResizeWordCount(dst, wordCount);
    if (wordCount > 0u) {
      std::copy(src.cbegin(), src.cend(), dst.begin());
    }
  }

  void IntersectCategoryWordRanges(moho::CategoryWordRangeView& lhs, const moho::CategoryWordRangeView& rhs)
  {
    AsWordBitset(lhs).IntersectWith(&AsWordBitset(rhs));
  }

  void UnionCategoryWordRanges(moho::CategoryWordRangeView& lhs, const moho::CategoryWordRangeView& rhs)
  {
    if (rhs.Empty()) {
      return;
    }
    if (lhs.Empty()) {
      CopyCategoryWordRange(lhs, rhs);
      return;
    }

    AsWordBitset(lhs).AddAllFrom(&AsWordBitset(rhs));
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
  CategoryWordRangeView::CategoryWordRangeView() noexcept
    : mWordUniverseHandle(0u)
    , mReserved04(0u)
    , mStartWordIndex(0u)
    , mReserved0C(0u)
    , mWordsBegin(nullptr)
    , mWordsEnd(nullptr)
    , mWordsCapacityEnd(nullptr)
    , mWordsInlineBase(nullptr)
    , mWordsInlineStorage{0u, 0u}
  {
    ResetInlineWordStorage(*this);
  }

  CategoryWordRangeView::CategoryWordRangeView(const CategoryWordRangeView& other)
    : CategoryWordRangeView()
  {
    CopyCategoryWordRange(*this, other);
  }

  CategoryWordRangeView& CategoryWordRangeView::operator=(const CategoryWordRangeView& other)
  {
    if (this == &other) {
      return *this;
    }

    CopyCategoryWordRange(*this, other);
    return *this;
  }

  CategoryWordRangeView::CategoryWordRangeView(CategoryWordRangeView&& other) noexcept
    : CategoryWordRangeView()
  {
    *this = std::move(other);
  }

  CategoryWordRangeView& CategoryWordRangeView::operator=(CategoryWordRangeView&& other) noexcept
  {
    if (this == &other) {
      return *this;
    }

    ReleaseWordStorage(*this);

    mWordUniverseHandle = other.mWordUniverseHandle;
    mReserved04 = other.mReserved04;
    mStartWordIndex = other.mStartWordIndex;
    mReserved0C = other.mReserved0C;

    if (other.mWordsBegin == other.mWordsInlineBase) {
      const std::size_t wordCount = other.WordCount();
      ResetInlineWordStorage(*this);
      if (wordCount > 0u) {
        std::copy(other.cbegin(), other.cend(), begin());
      }
      mWordsEnd = mWordsBegin + wordCount;
    } else {
      mWordsInlineBase = &mWordsInlineStorage[0];
      mWordsBegin = other.mWordsBegin;
      mWordsEnd = other.mWordsEnd;
      mWordsCapacityEnd = other.mWordsCapacityEnd;

      ResetInlineWordStorage(other);
      other.mWordUniverseHandle = 0u;
      other.mReserved04 = 0u;
      other.mStartWordIndex = 0u;
      other.mReserved0C = 0u;
      other.mWordsInlineStorage[0] = 0u;
      other.mWordsInlineStorage[1] = 0u;
    }

    return *this;
  }

  CategoryWordRangeView::~CategoryWordRangeView()
  {
    ReleaseWordStorage(*this);
  }

  void CategoryWordRangeView::ResetToEmpty(const std::uint32_t universeHandle) noexcept
  {
    mWordUniverseHandle = universeHandle;
    mReserved04 = 0u;
    mStartWordIndex = 0u;
    mReserved0C = 0u;
    ReleaseWordStorage(*this);
  }

  std::size_t CategoryWordRangeView::WordCount() const noexcept
  {
    if (!mWordsBegin || !mWordsEnd || mWordsEnd < mWordsBegin) {
      return 0u;
    }
    return static_cast<std::size_t>(mWordsEnd - mWordsBegin);
  }

  bool CategoryWordRangeView::Empty() const noexcept
  {
    return WordCount() == 0u;
  }

  const std::uint32_t* CategoryWordRangeView::WordData() const noexcept
  {
    return mWordsBegin;
  }

  std::uint32_t* CategoryWordRangeView::WordData() noexcept
  {
    return mWordsBegin;
  }

  CategoryWordRangeView::iterator CategoryWordRangeView::begin() noexcept
  {
    return mWordsBegin;
  }

  CategoryWordRangeView::iterator CategoryWordRangeView::end() noexcept
  {
    return mWordsEnd;
  }

  CategoryWordRangeView::const_iterator CategoryWordRangeView::begin() const noexcept
  {
    return mWordsBegin;
  }

  CategoryWordRangeView::const_iterator CategoryWordRangeView::end() const noexcept
  {
    return mWordsEnd;
  }

  CategoryWordRangeView::const_iterator CategoryWordRangeView::cbegin() const noexcept
  {
    return begin();
  }

  CategoryWordRangeView::const_iterator CategoryWordRangeView::cend() const noexcept
  {
    return end();
  }

  CategoryWordRangeView::const_iterator
  CategoryWordRangeView::FindWord(const std::uint32_t absoluteWordIndex) const noexcept
  {
    if (absoluteWordIndex < mStartWordIndex) {
      return cend();
    }

    const std::size_t localWordIndex = static_cast<std::size_t>(absoluteWordIndex - mStartWordIndex);
    if (localWordIndex >= WordCount()) {
      return cend();
    }

    return cbegin() + localWordIndex;
  }

  bool CategoryWordRangeView::ContainsBit(const std::uint32_t categoryBitIndex) const noexcept
  {
    const CategoryWordRangeView::const_iterator wordIt = FindWord(categoryBitIndex >> 5u);
    if (wordIt == cend()) {
      return false;
    }

    return (((*wordIt) >> (categoryBitIndex & 0x1Fu)) & 1u) != 0u;
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
          CopyCategoryWordRange(clauseAccum, node->value);
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
