#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/containers/BVIntSet.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  struct SimSubRes3
  {
    // Copied by 0x00403CB0 into SimSubRes2 history ring.
    int32_t mValue; // +0x00
    int32_t mReserved04;
    gpg::core::FastVectorN<int32_t, 2> mValues; // +0x08
  };
  static_assert(offsetof(SimSubRes3, mValue) == 0x00, "SimSubRes3::mValue offset must be 0x00");
  static_assert(offsetof(SimSubRes3, mReserved04) == 0x04, "SimSubRes3::mReserved04 offset must be 0x04");
  static_assert(offsetof(SimSubRes3, mValues) == 0x08, "SimSubRes3::mValues offset must be 0x08");
  static_assert(sizeof(SimSubRes3) == 0x20, "SimSubRes3 size must be 0x20");

  struct SimSubRes2
  {
    SimSubRes3 mData[100]; // +0x0000..+0x0C7F
    int32_t mStart;        // +0x0C80
    int32_t mEnd;          // +0x0C84

    /**
     * Address: 0x00403CB0 (FUN_00403CB0, struct_sim_subres3::struct_sim_subres3)
     *
     * What it does:
     * Copies one BVIntSet snapshot into the tail slot and advances `mEnd` modulo 100.
     */
    void PushSnapshot(const BVIntSet& snapshot);

    /**
     * Address: 0x00403D20 (FUN_00403D20, sub_403D20)
     *
     * What it does:
     * Releases heap storage from the oldest slot (if any) and advances `mStart` modulo 100.
     */
    void PopOldest();

    /**
     * Address: 0x00403E70 (FUN_00403E70, struct_CyclicBuffer100_BVIntSet::struct_CyclicBuffer100_BVIntSet)
     *
     * What it does:
     * Drains all active history slots and resets the ring indices to empty state.
     */
    void Reset();
  };
  static_assert(offsetof(SimSubRes2, mData) == 0x0000, "SimSubRes2::mData offset must be 0x0000");
  static_assert(offsetof(SimSubRes2, mStart) == 0x0C80, "SimSubRes2::mStart offset must be 0x0C80");
  static_assert(offsetof(SimSubRes2, mEnd) == 0x0C84, "SimSubRes2::mEnd offset must be 0x0C84");
  static_assert(sizeof(SimSubRes2) == 0xC88, "SimSubRes2 size must be 0xC88");

  class IdPool
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00403920 (FUN_00403920, Moho::IdPool::IdPool)
     *
     * What it does:
     * Initializes the released-id bitset and the 100-slot recycle history ring.
     */
    IdPool();

    /**
     * Address: 0x004039F0 (FUN_004039F0, sub_4039F0)
     *
     * What it does:
     * Queues one released low-id bit into the current recycle-history tail bucket.
     */
    void QueueReleasedLowId(unsigned int lowId);

    /**
     * Address: 0x00403A30 (FUN_00403A30, Moho::IdPool::Update)
     *
     * What it does:
     * Advances the 100-slot recycle ring, merges the oldest slot into released ids,
     * and backtracks the next-low-id cursor when necessary.
     */
    void Update();

    // 0x00684480 uses this as sequential low-id allocator in the `(*v3)++` branch.
    int32_t mNextLowId; // +0x00
    int32_t mReserved04;
    BVIntSet mReleasedLows; // +0x08
    SimSubRes2 mSubRes2;    // +0x28

    /**
     * Address: 0x00404390 (FUN_00404390, Moho::IdPool::MemberDeserialize)
     *
     * What it does:
     * Reads the next low-id cursor and released-id set from archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00404410 (FUN_00404410, Moho::IdPool::MemberSerialize)
     *
     * What it does:
     * Compacts the released-id set with the recycle ring and writes it to archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };
  static_assert(offsetof(IdPool, mNextLowId) == 0x00, "IdPool::mNextLowId offset must be 0x00");
  static_assert(offsetof(IdPool, mReserved04) == 0x04, "IdPool::mReserved04 offset must be 0x04");
  static_assert(offsetof(IdPool, mReleasedLows) == 0x08, "IdPool::mReleasedLows offset must be 0x08");
  static_assert(offsetof(IdPool, mSubRes2) == 0x28, "IdPool::mSubRes2 offset must be 0x28");
  static_assert(sizeof(IdPool) == 0xCB0, "IdPool size must be 0xCB0");
} // namespace moho
