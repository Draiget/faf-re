#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/sim/IdPool.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

namespace moho
{
  class Sim;
  class CArmyImpl;
  class CDecalHandle;

  struct SDecalInfo
  {
    // +0x00..+0x0B
    Wm3::Vec3f worldOrigin;
    // +0x0C..+0x17
    Wm3::Vec3f worldSize;
    // +0x18
    float rotationRadians;
    // +0x1C..+0x5B
    std::uint8_t reserved1C[0x40];
    // +0x5C
    std::uint8_t requiresRecon;
    // +0x5D..+0x63
    std::uint8_t reserved5D[0x07];
    // +0x64
    std::uint32_t startTick;
    // +0x68..+0x83
    std::uint8_t reserved68[0x1C];
    // +0x84
    std::uint32_t scriptObjectId;
    // +0x88
    std::uint32_t sourceArmyIndex;
    // +0x8C..+0x8F
    std::uint8_t reserved8C[0x04];
  };
  static_assert(offsetof(SDecalInfo, worldOrigin) == 0x00, "SDecalInfo::worldOrigin offset must be 0x00");
  static_assert(offsetof(SDecalInfo, worldSize) == 0x0C, "SDecalInfo::worldSize offset must be 0x0C");
  static_assert(offsetof(SDecalInfo, rotationRadians) == 0x18, "SDecalInfo::rotationRadians offset must be 0x18");
  static_assert(offsetof(SDecalInfo, requiresRecon) == 0x5C, "SDecalInfo::requiresRecon offset must be 0x5C");
  static_assert(offsetof(SDecalInfo, startTick) == 0x64, "SDecalInfo::startTick offset must be 0x64");
  static_assert(offsetof(SDecalInfo, scriptObjectId) == 0x84, "SDecalInfo::scriptObjectId offset must be 0x84");
  static_assert(offsetof(SDecalInfo, sourceArmyIndex) == 0x88, "SDecalInfo::sourceArmyIndex offset must be 0x88");
  static_assert(sizeof(SDecalInfo) == 0x90, "SDecalInfo size must be 0x90");

  struct CDecalHandleListNode
  {
    CDecalHandleListNode* next;
    CDecalHandleListNode* prev;
  };
  static_assert(sizeof(CDecalHandleListNode) == 0x08, "CDecalHandleListNode size must be 0x08");

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

  private:
    /**
     * Address: 0x00779680 (FUN_00779680, sub_779680)
     *
     * What it does:
     * Removes one handle from active tracking, queues object-id retirement, and deletes the handle.
     */
    void DestroyHandle(CDecalHandle* handle);

    /**
     * Address: 0x00403A30 (FUN_00403A30, sub_403A30)
     * Address: 0x00403D20 (FUN_00403D20, sub_403D20)
     *
     * What it does:
     * Advances the IdPool rolling recycle window by one tick, including oldest-slot pop.
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
    CDecalHandleListNode mHandleListHead;               // +0x0CB8
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
