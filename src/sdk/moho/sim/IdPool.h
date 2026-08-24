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

  /**
   * `IdPool` requires 8-byte alignment in the shipped binary, even though every
   * member declared below is individually 4-byte (or smaller) aligned. Evidence,
   * converging from four independent sites:
   *   - `CEntityDb::mIdPoolTree`'s node (`msvc8::map<std::uint32_t, IdPool>`,
   *     `EntityDb.h`) places `IdPool` at node+0x18, one 4-byte word after the
   *     node's `key`+0x10..0x14 -- i.e. a forced pad word between key and
   *     payload that only 8-byte alignment on the payload explains
   *     (`FUN_006881C0`, the `map<uint,IdPool>::_Buynode` emission, writes the
   *     key at `node+0x10` and copy-constructs the pool at `node+0x18`).
   *   - The already-recovered `IdPoolMapLaneCopyView` (`IdPool.cpp`) independently
   *     derived the same `{key@0x00, reserved@0x04, IdPool@0x08}` shape from
   *     `FUN_00686D10`/`FUN_00688A10`'s map-lane copy bodies.
   *   - `Moho::CDecalBuffer` (`CDecalBuffer.h`) carries a hand-inserted
   *     `mReserved04` pad dword between its 4-byte `Sim*` and `IdPool mPool` --
   *     without an alignment requirement on `IdPool` the compiler would place
   *     `mPool` at +0x04 with no pad needed, so that manual pad is itself
   *     evidence of the same requirement, worked around instead of modelled.
   *   - `sizeof(IdPool) == 0xCB0` is already a multiple of 8, and every existing
   *     embedding (`CommandManager::mIdPool`@0x00, `CDecalBuffer::mPool`@0x08,
   *     `CCommandDbRuntimeView::pool`@0x10) sits at an offset that is *also* a
   *     multiple of 8, so this alignment is free everywhere `IdPool` is already
   *     embedded -- it changes no existing `offsetof`/`sizeof` assertion.
   */
  class alignas(8) IdPool
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
  static_assert(alignof(IdPool) == 8, "IdPool alignment must be 8");
} // namespace moho
