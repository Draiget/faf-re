#include "moho/sim/IdPool.h"

#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"

using namespace moho;

gpg::RType* IdPool::sType = nullptr;

namespace
{
  constexpr int kHistoryCapacity = 100;

  static_assert(
    offsetof(SimSubRes3, mValue) == offsetof(BVIntSet, mFirstWordIndex), "SimSubRes3/BVIntSet offset mismatch"
  );
  static_assert(
    offsetof(SimSubRes3, mReserved04) == offsetof(BVIntSet, mReservedMetaWord), "SimSubRes3/BVIntSet offset mismatch"
  );
  static_assert(offsetof(SimSubRes3, mValues) == offsetof(BVIntSet, mWords), "SimSubRes3/BVIntSet offset mismatch");
  static_assert(sizeof(SimSubRes3) == sizeof(BVIntSet), "SimSubRes3/BVIntSet size mismatch");

  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  [[nodiscard]] BVIntSet& AsBitSet(SimSubRes3& slot) noexcept
  {
    return *reinterpret_cast<BVIntSet*>(&slot);
  }

  [[nodiscard]] const BVIntSet& AsBitSet(const SimSubRes3& slot) noexcept
  {
    return *reinterpret_cast<const BVIntSet*>(&slot);
  }

  [[nodiscard]] gpg::RType* CachedBVIntSetType()
  {
    gpg::RType* type = BVIntSet::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(BVIntSet));
      BVIntSet::sType = type;
    }
    GPG_ASSERT(type != nullptr);
    return type;
  }

  /**
   * Address: 0x00403720 (FUN_00403720, sub_403720)
   *
   * What it does:
   * Returns `{set, value}` when `value` is currently set; otherwise advances to
   * the next set bit and returns that index pair.
   */
  [[nodiscard]] BVIntSetIndex ResolveExistingOrNextIndex(BVIntSet& set, unsigned int value)
  {
    if (!set.Contains(value)) {
      value = set.GetNext(value);
    }
    return MakeBVIntSetIndex(&set, value);
  }
} // namespace

/**
 * Address: 0x00403CB0 (FUN_00403CB0, struct_sim_subres3::struct_sim_subres3)
 *
 * What it does:
 * Copies one BVIntSet snapshot into the tail slot and advances `mEnd` modulo 100.
 */
void SimSubRes2::PushSnapshot(const BVIntSet& snapshot)
{
  BVIntSet& destination = AsBitSet(mData[mEnd]);
  destination.mFirstWordIndex = snapshot.mFirstWordIndex;
  destination.mWords.ResetFrom(snapshot.mWords);
  mEnd = (mEnd + 1) % kHistoryCapacity;
}

/**
 * Address: 0x00403D20 (FUN_00403D20, sub_403D20)
 *
 * What it does:
 * Releases heap storage from the oldest slot (if any) and advances `mStart` modulo 100.
 */
void SimSubRes2::PopOldest()
{
  mData[mStart].mValues.ResetStorageToInline();
  mStart = (mStart + 1) % kHistoryCapacity;
}

/**
 * Address: 0x00403E70 (FUN_00403E70, struct_CyclicBuffer100_BVIntSet::struct_CyclicBuffer100_BVIntSet)
 *
 * What it does:
 * Drains all active history slots and resets the ring indices to empty state.
 */
void SimSubRes2::Reset()
{
  while (mStart != mEnd) {
    PopOldest();
  }

  mStart = 0;
  mEnd = 0;
}

/**
 * Address: 0x00403920 (FUN_00403920, Moho::IdPool::IdPool)
 *
 * What it does:
 * Initializes the released-id bitset and seeds the recycle-history ring.
 */
IdPool::IdPool()
  : mNextLowId(0)
  , mReserved04(0)
  , mReleasedLows()
  , mSubRes2()
{
  const BVIntSet emptySnapshot{};
  mSubRes2.PushSnapshot(emptySnapshot);
}

/**
 * Address: 0x004039F0 (FUN_004039F0, sub_4039F0)
 *
 * What it does:
 * Queues one released low-id bit into the current recycle-history tail bucket.
 */
void IdPool::QueueReleasedLowId(const unsigned int lowId)
{
  const int bucketIndex = (mSubRes2.mEnd + (kHistoryCapacity - 1)) % kHistoryCapacity;
  (void)AsBitSet(mSubRes2.mData[bucketIndex]).Add(lowId);
}

/**
 * Address: 0x00403A30 (FUN_00403A30, Moho::IdPool::Update)
 *
 * What it does:
 * Advances the 100-slot recycle ring, merges the oldest slot into released ids,
 * and backtracks the next-low-id cursor when necessary.
 */
void IdPool::Update()
{
  const int nextEnd = (mSubRes2.mEnd + 1) % kHistoryCapacity;
  if (nextEnd == mSubRes2.mStart) {
    BVIntSet& oldestSet = AsBitSet(mSubRes2.mData[mSubRes2.mStart]);
    if (!oldestSet.mWords.Empty()) {
      const unsigned int lower = oldestSet.GetNext(std::numeric_limits<unsigned int>::max());
      const unsigned int upper = oldestSet.Max();
      mReleasedLows.AddFrom(&oldestSet, lower, upper);

      unsigned int nextLowId = static_cast<unsigned int>(mNextLowId);
      while (nextLowId > 0u && mReleasedLows.Contains(nextLowId - 1u)) {
        --nextLowId;
      }

      if (nextLowId != static_cast<unsigned int>(mNextLowId)) {
        const BVIntSetIndex lowerIndex = ResolveExistingOrNextIndex(mReleasedLows, nextLowId);
        const BVIntSetIndex upperIndex = MakeBVIntSetIndex(&mReleasedLows, mReleasedLows.Max());
        mReleasedLows.ClearRange(lowerIndex, upperIndex);
        mNextLowId = static_cast<std::int32_t>(nextLowId);
      }
    }

    mSubRes2.PopOldest();
  }

  const BVIntSet emptySnapshot{};
  mSubRes2.PushSnapshot(emptySnapshot);
}

/**
 * Address: 0x00404390 (FUN_00404390, Moho::IdPool::MemberDeserialize)
 *
 * What it does:
 * Reads the next low-id cursor and released-id set from archive.
 */
void IdPool::MemberDeserialize(gpg::ReadArchive* const archive)
{
  std::uint32_t nextLowId = 0;
  archive->ReadUInt(&nextLowId);
  mNextLowId = static_cast<std::int32_t>(nextLowId);

  archive->Read(CachedBVIntSetType(), &mReleasedLows, NullOwnerRef());
}

/**
 * Address: 0x00404410 (FUN_00404410, Moho::IdPool::MemberSerialize)
 *
 * What it does:
 * Compacts the released-id set with the recycle ring and writes it to archive.
 */
void IdPool::MemberSerialize(gpg::WriteArchive* const archive) const
{
  BVIntSet compactedReleased = mReleasedLows;

  for (int index = mSubRes2.mStart; index != mSubRes2.mEnd; index = (index + 1) % kHistoryCapacity) {
    const BVIntSet& slot = AsBitSet(mSubRes2.mData[index]);
    const unsigned int slotMax = slot.Max();
    const unsigned int firstReleased = slot.GetNext(std::numeric_limits<unsigned int>::max());
    compactedReleased.AddFrom(&slot, firstReleased, slotMax);
  }

  std::uint32_t nextLowId = static_cast<std::uint32_t>(mNextLowId);
  if (mNextLowId > 0) {
    while (nextLowId > 0 && compactedReleased.Contains(nextLowId - 1u)) {
      --nextLowId;
    }
  }

  const unsigned int clearUpper = compactedReleased.Max();
  const unsigned int clearLower =
    compactedReleased.Contains(nextLowId) ? nextLowId : compactedReleased.GetNext(nextLowId);
  const BVIntSetIndex lower{&compactedReleased, clearLower};
  const BVIntSetIndex upper{&compactedReleased, clearUpper};
  compactedReleased.ClearRange(lower, upper);

  archive->WriteInt(static_cast<int>(nextLowId));
  archive->Write(CachedBVIntSetType(), &compactedReleased, NullOwnerRef());
}
