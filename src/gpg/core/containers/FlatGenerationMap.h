#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace gpg::core
{
  /**
   * Engine addition: a map from 32-bit keys to small values for scratch data
   * that is filled and thrown away many times, such as one search's records.
   *
   * Open addressing with linear probing over one array, Fibonacci hashing (a
   * multiply and a shift, no division), and kept at most half full. Clear()
   * does not touch the array: it bumps the generation, and only slots of the
   * current generation count as filled. The array is only walked again when
   * the generation wraps.
   *
   * Values are stored in the slots, so a value's address changes when the map
   * grows; store a pointer to keep an object in place.
   */
  template <class TValue>
  class FlatGenerationMap
  {
  public:
    /// Slot count of a default-constructed map, as a power of two (1024 slots).
    static constexpr unsigned kDefaultCapacityLog2 = 10;
    /// Largest starting size: the slot index must fit 32 bits on x86 as well.
    static constexpr unsigned kMaxCapacityLog2 = 31;

    /** Starts with 2^capacityLog2 slots (1 to kMaxCapacityLog2). */
    explicit FlatGenerationMap(const unsigned capacityLog2 = kDefaultCapacityLog2)
      : mSlots(std::size_t{1} << capacityLog2)
      , mMask((std::size_t{1} << capacityLog2) - 1)
      , mShift(kHashBits - capacityLog2)
    {
      assert(capacityLog2 >= 1 && capacityLog2 <= kMaxCapacityLog2);
    }

    /** The value stored for `key` since the last Clear(), or null. */
    [[nodiscard]] TValue* Find(const std::uint32_t key) noexcept
    {
      // Terminates: the map is never more than half full, so an empty slot follows.
      for (std::size_t i = Bucket(key);; i = Next(i)) {
        Slot& slot = mSlots[i];
        if (slot.generation != mGeneration) {
          return nullptr;
        }
        if (slot.key == key) {
          return &slot.value;
        }
      }
    }

    /** Stores `value` for `key`, which must not be in the map. */
    TValue& Insert(const std::uint32_t key, const TValue& value)
    {
      assert(Find(key) == nullptr && "FlatGenerationMap::Insert: the key is already in the map");
      if ((mCount + 1) * kSlotsPerEntry > mSlots.size()) {
        Grow();
      }
      ++mCount;
      return Place(key, value);
    }

    /** Empties the map in O(1): slots of older generations read as empty. */
    void Clear() noexcept
    {
      mCount = 0;
      if (++mGeneration == kEmptyGeneration) {
        // Wrapped: stamps from 2^32 generations ago would read as current again.
        for (Slot& slot : mSlots) {
          slot.generation = kEmptyGeneration;
        }
        mGeneration = kFirstGeneration;
      }
    }

  private:
    /// Width of the hash the slot index is taken from (the top bits of a 64-bit product).
    static constexpr unsigned kHashBits = 64;
    /// 2^64 / golden ratio, odd: Fibonacci hashing spreads consecutive keys (neighbouring
    /// cells) across the whole table.
    static constexpr std::uint64_t kFibonacciMultiplier = 0x9E3779B97F4A7C15ull;
    /// At least this many slots per stored entry, i.e. at most half full, which keeps
    /// linear-probe runs short and guarantees Find() meets an empty slot.
    static constexpr std::size_t kSlotsPerEntry = 2;
    /// A slot's generation before anything is placed in it; never a live generation.
    static constexpr std::uint32_t kEmptyGeneration = 0;
    static constexpr std::uint32_t kFirstGeneration = 1;

    struct Slot
    {
      std::uint32_t key = 0;
      std::uint32_t generation = kEmptyGeneration; // filled only when it equals the map's
      TValue value{};
    };

    [[nodiscard]] std::size_t Bucket(const std::uint32_t key) const noexcept
    {
      return static_cast<std::size_t>((key * kFibonacciMultiplier) >> mShift);
    }

    [[nodiscard]] std::size_t Next(const std::size_t index) const noexcept { return (index + 1) & mMask; }

    TValue& Place(const std::uint32_t key, const TValue& value) noexcept
    {
      std::size_t i = Bucket(key);
      while (mSlots[i].generation == mGeneration) {
        i = Next(i);
      }
      mSlots[i].key = key;
      mSlots[i].generation = mGeneration;
      mSlots[i].value = value;
      return mSlots[i].value;
    }

    /** Doubles the slot array and places the current generation's entries again. */
    void Grow()
    {
      std::vector<Slot> previous = std::exchange(mSlots, std::vector<Slot>(mSlots.size() * 2));
      mMask = mSlots.size() - 1;
      --mShift;
      for (const Slot& slot : previous) {
        if (slot.generation == mGeneration) {
          (void)Place(slot.key, slot.value);
        }
      }
    }

    std::vector<Slot> mSlots;
    std::size_t mMask;
    unsigned mShift;
    std::uint32_t mGeneration = kFirstGeneration;
    std::size_t mCount = 0;
  };
} // namespace gpg::core
