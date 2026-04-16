#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/render/CDecalTypes.h"
#include "moho/sim/IdPool.h"
#include "Wm3Vector2.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class Sim;
  class CArmyImpl;
  class CDecalHandle;

  struct CDecalStartTickMapStorage
  {
    void* allocatorCookie;
    void* head;
    std::uint32_t size;
  };
  static_assert(sizeof(CDecalStartTickMapStorage) == 0x0C, "CDecalStartTickMapStorage size must be 0x0C");

  class CDecalBuffer
  {
  public:
    static gpg::RType* sType;

    /**
     * What it does:
     * Returns cached reflection descriptor for `CDecalBuffer`.
     */
    [[nodiscard]]
    static gpg::RType* StaticGetClass();

  public:
    /**
       * Address: 0x00779170 (FUN_00779170)
     *
     * What it does:
     * Initializes decal runtime storage (id pool, handle list, start-tick buckets).
     */
    CDecalBuffer();

    /**
       * Address: 0x00779170 (FUN_00779170)
     *
     * What it does:
     * Initializes decal runtime storage bound to a Sim owner.
     */
    explicit CDecalBuffer(Sim* sim);

    /**
     * Address: 0x00779270 (FUN_00779270)
     *
     * What it does:
     * Destroys live decal handles and releases container backing storage.
     */
    ~CDecalBuffer();

    /**
     * Address: 0x00779710 (FUN_00779710)
     *
     * What it does:
     * Advances decal lifetime queues and performs per-tick decal cleanup.
     */
    void CleanupTick();

    /**
     * Address: 0x007793D0 (FUN_007793D0, Moho::CDecalBuffer::CreateHandle)
     *
     * What it does:
     * Creates one script-visible decal handle, links it into active tracking,
     * and initializes per-army visibility flags for the new decal.
     */
    [[nodiscard]]
    CDecalHandle* CreateHandle(const SDecalInfo& info);

    /**
     * Address: 0x00779680 (FUN_00779680, sub_779680)
     *
     * What it does:
     * Removes one handle from active tracking, queues object-id retirement, and deletes the handle.
     */
    void DestroyHandle(CDecalHandle* handle);

    /**
     * Address: 0x00779BB0 (FUN_00779BB0, Moho::CDecalBuffer::SwapVectors)
     *
     * What it does:
     * Swaps runtime storage pointers for both decal publish vectors:
     * visible decals and pending hide object-id lanes.
     */
    void SwapVectors(msvc8::vector<SDecalInfo>* addDecals, msvc8::vector<std::uint32_t>* removeDecals);

  private:
    /**
     * What it does:
     * Delegates one recycle-window tick to `IdPool::Update`.
     */
    void AdvanceIdPoolWindow();

    /**
     * Address: 0x00779040 (FUN_00779040, sub_779040)
     *
     * What it does:
     * Tests whether an observer army may currently detect a decal owned by `sourceArmy`.
     */
    [[nodiscard]]
    bool IsDecalVisibleForArmy(const CArmyImpl* sourceArmy, const SDecalInfo& info, CArmyImpl* observerArmy) const;

    /**
     * Address: 0x00778730 (FUN_00778730, sub_778730)
     *
     * What it does:
     * Computes world-space XZ AABB bounds for a rotated decal quad.
     */
    static void ProjectDecalToBoundsXZ(const SDecalInfo& info, Wm3::Vec2f& outMax, Wm3::Vec2f& outMin);

  public:
    Sim* mSim;                                          // +0x0000
    std::uint32_t mReserved04;                          // +0x0004
    IdPool mPool;                                       // +0x0008
    CDecalHandleList mHandleListHead;                   // +0x0CB8
    CDecalStartTickMapStorage mStartTickBuckets;        // +0x0CC0
    msvc8::vector<SDecalInfo> mVisibleDecals;           // +0x0CCC
    msvc8::vector<std::uint32_t> mPendingHideObjectIds; // +0x0CDC
    std::uint32_t mPendingHideObjectIdsAux;             // +0x0CEC
  };

  static_assert(offsetof(CDecalBuffer, mSim) == 0x0000, "CDecalBuffer::mSim offset must be 0x0000");
  static_assert(offsetof(CDecalBuffer, mPool) == 0x0008, "CDecalBuffer::mPool offset must be 0x0008");
  static_assert(
    offsetof(CDecalBuffer, mHandleListHead) == 0x0CB8, "CDecalBuffer::mHandleListHead offset must be 0x0CB8"
  );
  static_assert(
    offsetof(CDecalBuffer, mStartTickBuckets) == 0x0CC0, "CDecalBuffer::mStartTickBuckets offset must be 0x0CC0"
  );
  static_assert(offsetof(CDecalBuffer, mVisibleDecals) == 0x0CCC, "CDecalBuffer::mVisibleDecals offset must be 0x0CCC");
  static_assert(
    offsetof(CDecalBuffer, mPendingHideObjectIds) == 0x0CDC, "CDecalBuffer::mPendingHideObjectIds offset must be 0x0CDC"
  );
  static_assert(
    offsetof(CDecalBuffer, mPendingHideObjectIdsAux) == 0x0CEC,
    "CDecalBuffer::mPendingHideObjectIdsAux offset must be 0x0CEC"
  );
  static_assert(sizeof(CDecalBuffer) == 0xCF0, "CDecalBuffer size must be 0xCF0");
} // namespace moho
