#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  /**
   * Engine addition: a hash index over a write archive's tracked pointers, in place of the binary's ordered
   * `mObjRefs` tree. A keyframe saves hundreds of thousands of pointers, and looking each one up in the tree took
   * 46% of a save on replay 26915859. The tree's order only picks which unclaimed pointer `EndSection` reports first,
   * and a pointer's number comes from the count of pointers before it, so an archive writes the same values.
   *
   * An entry stays where it is once inserted, as `WriteRawPointer` keeps its record across the nested writes.
   */
  class TrackedPointerIndex
  {
  public:
    struct Entry
    {
      RRef key;
      WriteArchive::TrackedPointerRecord record;
    };

    TrackedPointerIndex()
      : mSlots(kInitialSlots, 0u)
    {}

    [[nodiscard]] Entry* Find(const RRef& key) noexcept
    {
      const std::size_t mask = mSlots.size() - 1u;
      for (std::size_t slot = Hash(key) & mask;; slot = (slot + 1u) & mask) {
        const std::uint32_t stored = mSlots[slot];
        if (stored == 0u) {
          return nullptr;
        }
        Entry& entry = At(stored - 1u);
        if (entry.key.mObj == key.mObj && entry.key.mType == key.mType) {
          return &entry;
        }
      }
    }

    /** `key` must not be in the index. */
    Entry& Insert(const RRef& key, const WriteArchive::TrackedPointerRecord& record)
    {
      if ((mCount + 1u) * 2u > mSlots.size()) {
        Grow();
      }
      if ((mCount >> kChunkBits) == mChunks.size()) {
        mChunks.push_back(std::make_unique<Entry[]>(std::size_t{1} << kChunkBits));
      }
      Entry& entry = At(mCount);
      entry.key = key;
      entry.record = record;
      ++mCount;
      Place(key, mCount);
      return entry;
    }

    [[nodiscard]] std::size_t Size() const noexcept
    {
      return mCount;
    }

    [[nodiscard]] Entry& At(const std::uint32_t index) noexcept
    {
      return mChunks[index >> kChunkBits][index & ((1u << kChunkBits) - 1u)];
    }

    void Clear()
    {
      mChunks.clear();
      mSlots.assign(kInitialSlots, 0u);
      mCount = 0u;
    }

  private:
    static constexpr std::size_t kInitialSlots = std::size_t{1} << 16;
    static constexpr std::uint32_t kChunkBits = 14u;

    [[nodiscard]] static std::size_t Hash(const RRef& key) noexcept
    {
      const std::uint64_t object = reinterpret_cast<std::uintptr_t>(key.mObj);
      const std::uint64_t type = reinterpret_cast<std::uintptr_t>(key.mType);
      const std::uint64_t mixed = (object ^ (type << 21u)) * 0x9E3779B97F4A7C15ull;
      return static_cast<std::size_t>(mixed >> 20u);
    }

    /** `stored` is the entry's position plus one, as 0 marks an empty slot. */
    void Place(const RRef& key, const std::uint32_t stored) noexcept
    {
      const std::size_t mask = mSlots.size() - 1u;
      std::size_t slot = Hash(key) & mask;
      while (mSlots[slot] != 0u) {
        slot = (slot + 1u) & mask;
      }
      mSlots[slot] = stored;
    }

    void Grow()
    {
      mSlots.assign(mSlots.size() * 2u, 0u);
      for (std::uint32_t index = 0u; index < mCount; ++index) {
        Place(At(index).key, index + 1u);
      }
    }

    std::vector<std::unique_ptr<Entry[]>> mChunks;
    std::vector<std::uint32_t> mSlots;
    std::uint32_t mCount = 0u;
  };
} // namespace gpg
