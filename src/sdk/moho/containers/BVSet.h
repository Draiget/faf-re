#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>

#include "moho/containers/BVIntSet.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  struct BVSetBitsHeader
  {
    std::uint32_t universeStart;
    std::uint32_t universeCount;
    BVIntSet bits;
  };
  static_assert(sizeof(BVSetBitsHeader) == 0x28, "BVSetBitsHeader size must be 0x28");

  template <class T, class U>
  struct BVSet
  {
    static gpg::RType* sType;

    // Universe metadata for compressed-ID sets (nullable in transit paths).
    BVSetBitsHeader* mBitsHeader{nullptr}; // +0x00
    // Reserved metadata/flags word (binary-facing, semantics still unresolved).
    std::uint32_t mFlags{0}; // +0x04
    // Packed bit storage for selected IDs.
    BVIntSet mBits; // +0x08

    [[nodiscard]] const BVIntSet& Bits() const noexcept
    {
      return mBits;
    }
    [[nodiscard]] BVIntSet& Bits() noexcept
    {
      return mBits;
    }

    template <class F>
    void ForEachValue(F&& fn) const
    {
      const unsigned int sentinel = mBits.Max();
      for (unsigned int value = mBits.GetNext(std::numeric_limits<unsigned int>::max()); value != sentinel;
           value = mBits.GetNext(value)) {
        fn(value);
      }
    }
  };

  template <class T, class U>
  gpg::RType* BVSet<T, U>::sType = nullptr;

  using BVSetWord32 = BVSet<std::uint32_t, std::uint32_t>;
  static_assert(offsetof(BVSetWord32, mBits) == 0x8, "BVSet::mBits offset must be 0x8");
  static_assert(sizeof(BVSetWord32) == 0x28, "BVSet size must be 0x28");
} // namespace moho
