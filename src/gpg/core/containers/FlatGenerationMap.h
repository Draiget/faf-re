#pragma once

#include <cstddef>
#include <cstdint>
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
    /** Starts with 2^capacityLog2 slots. */
    explicit FlatGenerationMap(const unsigned capacityLog2 = 10)
      : mSlots(std::size_t{1} << capacityLog2)
      , mMask((std::size_t{1} << capacityLog2) - 1)
      , mShift(64 - capacityLog2)
    {
    }

    /** The value stored for `key` since the last Clear(), or null. */
    [[nodiscard]] TValue* Find(const std::uint32_t key) noexcept
    {
      for (std::size_t i = Bucket(key);; i = (i + 1) & mMask) {
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
      if ((mCount + 1) * 2 > mSlots.size()) {
        Grow();
      }
      ++mCount;
      return Place(key, value);
    }

    void Clear() noexcept
    {
      mCount = 0;
      if (++mGeneration == 0) {
        for (Slot& slot : mSlots) {
          slot.generation = 0;
        }
        mGeneration = 1;
      }
    }

  private:
    struct Slot
    {
      std::uint32_t key = 0;
      std::uint32_t generation = 0; // filled only when it equals the map's
      TValue value{};
    };

    [[nodiscard]] std::size_t Bucket(const std::uint32_t key) const noexcept
    {
      return static_cast<std::size_t>((key * 0x9E3779B97F4A7C15ull) >> mShift);
    }

    TValue& Place(const std::uint32_t key, const TValue& value) noexcept
    {
      std::size_t i = Bucket(key);
      while (mSlots[i].generation == mGeneration) {
        i = (i + 1) & mMask;
      }
      mSlots[i].key = key;
      mSlots[i].generation = mGeneration;
      mSlots[i].value = value;
      return mSlots[i].value;
    }

    void Grow()
    {
      std::vector<Slot> old(mSlots.size() * 2);
      old.swap(mSlots);
      mMask = mSlots.size() - 1;
      --mShift;
      for (const Slot& slot : old) {
        if (slot.generation == mGeneration) {
          (void)Place(slot.key, slot.value);
        }
      }
    }

    std::vector<Slot> mSlots;
    std::size_t mMask;
    unsigned mShift;
    std::uint32_t mGeneration = 1;
    std::size_t mCount = 0;
  };
} // namespace gpg::core
