#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <type_traits>
#include <utility>

#include "moho/containers/BVIntSet.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  /**
   * Generic value-set container modeled directly on the binary 0x28-byte
   * payload used by the engine for category/entity set storage.
   *
   * Layout (1:1 with binary at every specialization):
   *   +0x00  U mUniverse;        // 4-byte typed universe handle
   *   +0x04  uint32 mReserved04; // gap (binary always-zero observed)
   *   +0x08  BVIntSet mBits;     // word-bitset payload (size 0x20)
   *
   * The `T` template parameter is a value-type marker only; it does not
   * appear in the layout. The `U` parameter must be a 4-byte trivially
   * copyable type that names the universe lane (e.g. EntityCategoryHelper,
   * EntIdUniverse, uint32_t).
   *
   * Convenience accessors below mirror the legacy CategoryWordRangeView API
   * so all category/word-range call sites operate on a single canonical type.
   */
  template <class T, class U>
  struct BVSet
  {
    static_assert(sizeof(U) == 4u, "BVSet<T,U>::U must be exactly 4 bytes to preserve binary layout.");

    using iterator = std::uint32_t*;
    using const_iterator = const std::uint32_t*;

    static gpg::RType* sType;

    U mUniverse{};               // +0x00
    std::uint32_t mReserved04{}; // +0x04 (binary-facing gap)
    BVIntSet mBits{};            // +0x08 (size 0x20)

    BVSet() noexcept = default;

    BVSet(const BVSet& other) : mUniverse(other.mUniverse), mReserved04(other.mReserved04), mBits(other.mBits) {}

    BVSet& operator=(const BVSet& other)
    {
      if (this != &other) {
        mUniverse = other.mUniverse;
        mReserved04 = other.mReserved04;
        mBits = other.mBits;
      }
      return *this;
    }

    BVSet(BVSet&& other) noexcept
      : mUniverse(other.mUniverse), mReserved04(other.mReserved04), mBits(other.mBits)
    {
      other.mUniverse = U{};
      other.mReserved04 = 0u;
    }

    BVSet& operator=(BVSet&& other) noexcept
    {
      if (this != &other) {
        mUniverse = other.mUniverse;
        mReserved04 = other.mReserved04;
        mBits = other.mBits;
        other.mUniverse = U{};
        other.mReserved04 = 0u;
      }
      return *this;
    }

    ~BVSet() = default;

    [[nodiscard]] const BVIntSet& Bits() const noexcept { return mBits; }
    [[nodiscard]] BVIntSet& Bits() noexcept { return mBits; }

    /**
     * Iterates every set value in `mBits` and invokes `fn(value)` for each.
     * Mirrors the legacy `BVSet::ForEachValue` API used across recovered
     * sim/UI code that walks selection/category sets.
     */
    template <class F>
    void ForEachValue(F&& fn) const
    {
      const unsigned int sentinel = mBits.Max();
      for (unsigned int value = mBits.GetNext(std::numeric_limits<unsigned int>::max()); value != sentinel;
           value = mBits.GetNext(value)) {
        fn(value);
      }
    }

    // ---- legacy CategoryWordRangeView API surface (delegated to mBits) ----

    void ResetToEmpty(const U& universe) noexcept
    {
      mUniverse = universe;
      mReserved04 = 0u;
      mBits = BVIntSet{};
    }

    // Convenience overload for the common case where the universe is supplied
    // as a raw 4-byte word (e.g. `lookup.wordUniverseHandle`). Reinterprets
    // the bits as the typed `U` lane via the static-size guarantee above.
    template <class V = U, std::enable_if_t<!std::is_same_v<V, std::uint32_t>, int> = 0>
    void ResetToEmpty(const std::uint32_t universeBits) noexcept
    {
      static_assert(std::is_trivially_copyable_v<U>, "BVSet<T,U>::U must be trivially copyable.");
      std::memcpy(&mUniverse, &universeBits, sizeof(U));
      mReserved04 = 0u;
      mBits = BVIntSet{};
    }

    [[nodiscard]] std::size_t WordCount() const noexcept
    {
      const auto* const begin = mBits.mWords.start_;
      const auto* const end = mBits.mWords.end_;
      if (!begin || !end || end < begin) {
        return 0u;
      }
      return static_cast<std::size_t>(end - begin);
    }

    [[nodiscard]] bool Empty() const noexcept { return WordCount() == 0u; }

    [[nodiscard]] const std::uint32_t* WordData() const noexcept { return mBits.mWords.start_; }
    [[nodiscard]] std::uint32_t* WordData() noexcept { return mBits.mWords.start_; }

    [[nodiscard]] iterator begin() noexcept { return mBits.mWords.start_; }
    [[nodiscard]] iterator end() noexcept { return mBits.mWords.end_; }
    [[nodiscard]] const_iterator begin() const noexcept { return mBits.mWords.start_; }
    [[nodiscard]] const_iterator end() const noexcept { return mBits.mWords.end_; }
    [[nodiscard]] const_iterator cbegin() const noexcept { return mBits.mWords.start_; }
    [[nodiscard]] const_iterator cend() const noexcept { return mBits.mWords.end_; }

    [[nodiscard]] const_iterator FindWord(const std::uint32_t absoluteWordIndex) const noexcept
    {
      if (absoluteWordIndex < mBits.mFirstWordIndex) {
        return cend();
      }

      const std::size_t localWordIndex =
        static_cast<std::size_t>(absoluteWordIndex - mBits.mFirstWordIndex);
      if (localWordIndex >= WordCount()) {
        return cend();
      }

      return cbegin() + localWordIndex;
    }

    [[nodiscard]] bool ContainsBit(const std::uint32_t categoryBitIndex) const noexcept
    {
      const const_iterator wordIt = FindWord(categoryBitIndex >> 5u);
      if (wordIt == cend()) {
        return false;
      }
      return (((*wordIt) >> (categoryBitIndex & 0x1Fu)) & 1u) != 0u;
    }
  };

  template <class T, class U>
  gpg::RType* BVSet<T, U>::sType = nullptr;

  using BVSetWord32 = BVSet<std::uint32_t, std::uint32_t>;
  static_assert(offsetof(BVSetWord32, mUniverse) == 0x00, "BVSet::mUniverse offset must be 0x00");
  static_assert(offsetof(BVSetWord32, mReserved04) == 0x04, "BVSet::mReserved04 offset must be 0x04");
  static_assert(offsetof(BVSetWord32, mBits) == 0x08, "BVSet::mBits offset must be 0x08");
  static_assert(sizeof(BVSetWord32) == 0x28, "BVSet size must be 0x28");
} // namespace moho
