#include "moho/render/CDecalBuffer.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <typeinfo>
#include <utility>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/render/CDecalHandle.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"

using namespace moho;

gpg::RType* CDecalBuffer::sType = nullptr;

namespace
{
  struct DecalBucketNode
  {
    DecalBucketNode* left;
    DecalBucketNode* parent;
    DecalBucketNode* right;
    CDecalHandle* handle;
    std::uint8_t color;
    std::uint8_t isNil;
    std::uint8_t reserved12[2];
  };
  static_assert(sizeof(DecalBucketNode) == 0x14, "DecalBucketNode size must be 0x14");

  struct DecalMapNode
  {
    DecalMapNode* left;
    DecalMapNode* parent;
    DecalMapNode* right;
    std::uint32_t startTick;
    void* bucketAllocatorCookie;
    DecalBucketNode* bucketHead;
    std::uint32_t bucketSize;
    std::uint8_t color;
    std::uint8_t isNil;
    std::uint8_t reserved1E[2];
  };
  static_assert(sizeof(DecalMapNode) == 0x20, "DecalMapNode size must be 0x20");

  struct DecalBucketTreeStorage
  {
    void* allocatorCookie;  // +0x00
    DecalBucketNode* head;  // +0x04
    std::uint32_t size;     // +0x08
  };
  static_assert(sizeof(DecalBucketTreeStorage) == 0x0C, "DecalBucketTreeStorage size must be 0x0C");

  /**
   * Address: 0x0077C6F0 (FUN_0077C6F0)
   *
   * What it does:
   * Releases one heap node through the global scalar delete lane.
   */
  [[maybe_unused]] void DeleteDecalRuntimeNodeLaneA(void* const node)
  {
    ::operator delete(node);
  }

  /**
   * Address: 0x0077CF50 (FUN_0077CF50)
   *
   * What it does:
   * Secondary wrapper for the same scalar delete lane.
   */
  [[maybe_unused]] void DeleteDecalRuntimeNodeLaneB(void* const node)
  {
    ::operator delete(node);
  }

  void DestroyBucketTreeNodes(DecalBucketNode* node, const DecalBucketNode* const head);
  void DestroyMapNodes(DecalMapNode* node, const DecalMapNode* const head);

  struct DecalMapFindOrInsertResult
  {
    DecalMapNode* node;
    bool inserted;
  };

  // Forward declarations for the start-tick map / decal-bucket RB-tree
  // rotate, successor-advance, insert and erase family (mutually referenced
  // across the map/bucket tree split below).
  DecalMapNode* RetreatStartTickMapIterator(
    const std::uint32_t /*unused*/, DecalMapNode** const iteratorLane
  ) noexcept;
  DecalMapNode* AdvanceMapNodeToSuccessor(
    const std::uint32_t /*unused*/, DecalMapNode** const iteratorLane
  ) noexcept;
  [[nodiscard]] DecalMapNode* LinkMapNodeAndRebalance(
    DecalMapNode* const where, CDecalStartTickMapStorage* const mapThis, const bool addLeft, const std::uint32_t startTick
  );
  struct DecalMapTreeRuntimeView
  {
    std::uint32_t lane00; // +0x00
    DecalMapNode* head;   // +0x04
  };
  static_assert(sizeof(DecalMapTreeRuntimeView) == 0x08, "DecalMapTreeRuntimeView size must be 0x08");

  struct DecalBucketTreeRuntimeView
  {
    std::uint32_t lane00;
    DecalBucketNode* head;
  };
  static_assert(sizeof(DecalBucketTreeRuntimeView) == 0x08, "DecalBucketTreeRuntimeView size must be 0x08");

  struct DecalBucketBoundPairRuntime
  {
    DecalBucketNode* lowerBound;
    DecalBucketNode* upperBound;
  };
  static_assert(sizeof(DecalBucketBoundPairRuntime) == 0x08, "DecalBucketBoundPairRuntime size must be 0x08");

  struct DecalBucketFindOrInsertResult
  {
    DecalBucketNode* node;
    bool inserted;
  };

  struct DwordByteLanePairRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint8_t lane04;  // +0x04
  };
  static_assert(offsetof(DwordByteLanePairRuntimeView, lane04) == 0x04, "DwordByteLanePairRuntimeView::lane04 offset must be 0x04");

  /**
   * Address: 0x0077B830 (FUN_0077B830)
   *
   * What it does:
   * Writes one `{dword, byte}` lane from scalar source slots.
   */
  [[maybe_unused]] DwordByteLanePairRuntimeView* WriteDwordByteLanePair(
    DwordByteLanePairRuntimeView* const outValue,
    const std::uint32_t* const dwordSource,
    const std::uint8_t* const byteSource
  ) noexcept
  {
    outValue->lane00 = *dwordSource;
    outValue->lane04 = *byteSource;
    return outValue;
  }

  [[nodiscard]] std::uint32_t* StoreDwordLane(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0077B910 (FUN_0077B910)
   *
   * What it does:
   * Stores one scalar dword lane into output and returns the output slot.
   */
  [[maybe_unused]] std::uint32_t* StoreDecalDwordLanePrimary(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordLane(outValue, value);
  }

  /**
   * Address: 0x0077C720 (FUN_0077C720)
   *
   * What it does:
   * Stores one scalar dword lane into output and returns the output slot.
   */
  [[maybe_unused]] std::uint32_t* StoreDecalDwordLaneSecondary(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordLane(outValue, value);
  }

  /**
   * Address: 0x0077C790 (FUN_0077C790)
   *
   * What it does:
   * Clears one dword output lane to zero.
   */
  [[maybe_unused]] std::uint32_t* ClearDecalDwordLane(std::uint32_t* const outValue) noexcept
  {
    return StoreDwordLane(outValue, 0u);
  }

  /**
   * Address: 0x0077C7B0 (FUN_0077C7B0)
   *
   * What it does:
   * Stores one scalar dword lane into output and returns the output slot.
   */
  [[maybe_unused]] std::uint32_t* StoreDecalDwordLaneTertiary(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordLane(outValue, value);
  }

  /**
   * Address: 0x0077C7E0 (FUN_0077C7E0)
   *
   * What it does:
   * Stores one scalar dword lane into output and returns the output slot.
   */
  [[maybe_unused]] std::uint32_t* StoreDecalDwordLaneQuaternary(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordLane(outValue, value);
  }

  /**
   * Address: 0x0077C910 (FUN_0077C910)
   *
   * What it does:
   * Stores one scalar dword lane into output and returns the output slot.
   */
  [[maybe_unused]] std::uint32_t* StoreDecalDwordLaneQuinary(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordLane(outValue, value);
  }

  /**
   * Address: 0x0077A0A0 (FUN_0077A0A0)
   *
   * What it does:
   * Appends one visible decal payload into the pending publish vector.
   */
  void AppendVisibleDecal(msvc8::vector<SDecalInfo>& visibleDecals, const SDecalInfo& decalInfo)
  {
    visibleDecals.push_back(decalInfo);
  }

  [[nodiscard]]
  std::uint32_t AllocateDecalObjectId(IdPool& pool)
  {
    if (pool.mReleasedLows.mWords.Empty()) {
      const std::uint32_t nextId = static_cast<std::uint32_t>(pool.mNextLowId);
      ++pool.mNextLowId;
      return nextId;
    }

    const std::uint32_t recycled = pool.mReleasedLows.GetNext(std::numeric_limits<std::uint32_t>::max());
    pool.mReleasedLows.Remove(recycled);
    return recycled;
  }

  [[nodiscard]]
  std::size_t ResolveArmyCount(CArmyImpl* const* const armiesBegin, CArmyImpl* const* const armiesEnd) noexcept
  {
    if (!armiesBegin || !armiesEnd || armiesEnd < armiesBegin) {
      return 0u;
    }
    return static_cast<std::size_t>(armiesEnd - armiesBegin);
  }

  void SetArmyVisibilityFlag(CDecalHandle& handle, const std::size_t armyIndex) noexcept
  {
    if (armyIndex < 32u) {
      handle.mArmyVisibilityFlags |= (1u << static_cast<std::uint32_t>(armyIndex));
    }
  }

  void PropagateVisibilityToObserverAllies(
    CDecalHandle& handle,
    CArmyImpl* const* const armiesBegin,
    const std::size_t armyCount,
    const std::size_t observerIndex
  )
  {
    for (std::size_t allyIndex = observerIndex; allyIndex < armyCount; ++allyIndex) {
      CArmyImpl* const allyArmy = armiesBegin[allyIndex];
      if (allyArmy && allyArmy->Allies.Contains(static_cast<std::uint32_t>(observerIndex))) {
        SetArmyVisibilityFlag(handle, allyIndex);
      }
    }
  }
} // namespace

gpg::RType* CDecalBuffer::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CDecalBuffer));
  }
  return sType;
}

/**
 * Address: 0x00779170 (FUN_00779170)
 *
 * What it does:
 * Initializes decal runtime storage (id pool, handle list, start-tick buckets).
 */
CDecalBuffer::CDecalBuffer()
  : CDecalBuffer(nullptr)
{}

/**
    * Alias of FUN_00779170 (non-canonical helper lane).
 *
 * What it does:
 * Initializes decal runtime storage bound to a Sim owner.
 */
CDecalBuffer::CDecalBuffer(Sim* const sim)
  : mSim(sim)
  , mReserved04(0)
  , mPool()
  , mHandleListHead{}
  , mStartTickBuckets{}
  , mVisibleDecals()
  , mPendingHideObjectIds()
  , mPendingHideObjectIdsAux(0)
{
  mHandleListHead.ListResetLinks();

  // The map's constructor seats its own sentinel head and zeroes the size;
  // the binary open-codes both here.
}

/**
 * Address: 0x00779270 (FUN_00779270)
 *
 * What it does:
 * Destroys live decal handles and releases container backing storage.
 */
CDecalBuffer::~CDecalBuffer()
{
  auto* const listHeadNode = static_cast<CDecalHandleListNode*>(&mHandleListHead);
  while (mHandleListHead.mNext != listHeadNode) {
    CDecalHandleListNode* const node = mHandleListHead.mNext;
    CDecalHandle* const handle = CDecalHandle::FromListNode(node);
    delete handle;
  }

  // Each bucket set and the outer map release their own nodes; the binary
  // open-codes that teardown, including freeing the sentinel head, which is
  // the container's destructor here.
  mStartTickBuckets.clear();
  mHandleListHead.ListResetLinks();
}

/**
 * Address: 0x00779BB0 (FUN_00779BB0, Moho::CDecalBuffer::SwapVectors)
 *
 * What it does:
 * Swaps runtime storage pointers for both decal publish vectors:
 * visible decals and pending hide object-id lanes.
 */
void CDecalBuffer::SwapVectors(msvc8::vector<SDecalInfo>* const addDecals, msvc8::vector<std::uint32_t>* const removeDecals)
{
  // Exchanging all three lanes pairwise is vector::swap.
  mVisibleDecals.swap(*addDecals);
  mPendingHideObjectIds.swap(*removeDecals);
}

/**
 * Address: 0x007793D0 (FUN_007793D0, Moho::CDecalBuffer::CreateHandle)
 *
 * What it does:
 * Creates one script-visible decal handle, links it into active tracking,
 * inserts it into its start-tick bucket (`FindOrCreateStartTickBucket` +
 * `FindOrInsertBucketNode`, gated on `mStartTick != 0` exactly as the
 * binary gates its `sub_77A250`/`sub_77A930` call pair), and initializes
 * per-army visibility flags for the new decal.
 */
CDecalHandle* CDecalBuffer::CreateHandle(const SDecalInfo& info)
{
  if (!mSim) {
    return nullptr;
  }

  const std::uint32_t objectId = AllocateDecalObjectId(mPool);

  CDecalHandle* const handle = new CDecalHandle(mSim->mLuaState, objectId, info, mSim->mCurTick);
  if (handle == nullptr) {
    return nullptr;
  }

  handle->mListNode.ListLinkBefore(&mHandleListHead);

  if (handle->mInfo.mStartTick != 0u) {
    mStartTickBuckets[handle->mInfo.mStartTick].insert(handle);
  }

  CArmyImpl** const armiesBegin = mSim->mArmiesList.begin();
  CArmyImpl** const armiesEnd = mSim->mArmiesList.end();
  const std::size_t armyCount = ResolveArmyCount(armiesBegin, armiesEnd);

  CArmyImpl* sourceArmy = nullptr;
  if (handle->mInfo.mArmy < armyCount) {
    sourceArmy = armiesBegin[handle->mInfo.mArmy];
  }

  if (sourceArmy != nullptr && handle->mInfo.mIsSplat != 0u) {
    const bool sourceIsCivilian = sourceArmy->IsCivilian != 0u;
    for (std::size_t i = 0; i < armyCount; ++i) {
      if (sourceArmy->Allies.Contains(static_cast<std::uint32_t>(i)) || !sourceIsCivilian) {
        SetArmyVisibilityFlag(*handle, i);
      }
    }
    return handle;
  }

  for (std::size_t i = 0; i < armyCount; ++i) {
    if (i < 32u && ((handle->mArmyVisibilityFlags & (1u << static_cast<std::uint32_t>(i))) != 0u)) {
      continue;
    }

    CArmyImpl* const observerArmy = armiesBegin[i];
    if (!observerArmy || observerArmy->IsCivilian != 0u) {
      continue;
    }

    if (sourceArmy && !IsDecalVisibleForArmy(sourceArmy, handle->mInfo, observerArmy)) {
      continue;
    }

    PropagateVisibilityToObserverAllies(*handle, armiesBegin, armyCount, i);
  }

  return handle;
}

/**
 * Address: 0x00779D70 (FUN_00779D70)
 *
 * IDA signature:
 * void __stdcall sub_779D70(Moho::CDecalBuffer *buf, gpg::ReadArchive *ar);
 *
 * What it does:
 * Reads the owned decal-handle stream written by `WriteDecalHandles`. Each
 * archive read yields one owned `CDecalHandle*`; a null pointer terminates
 * the stream. Every handle is tail-linked into `mHandleListHead` (the binary
 * open-codes `ListUnlink` + self-link + link-before at 0x00779DB6..0x00779DD7)
 * and, when its start tick is non-zero, re-registered in its start-tick
 * bucket through the same `FindOrCreateStartTickBucket`/`FindOrInsertBucketNode`
 * pair `CreateHandle` uses (0x00779DF7 / 0x00779E03).
 *
 * The owner reference is re-zeroed before every read, matching the binary
 * clearing `mObj`/`mType` at 0x00779D88 and again at 0x00779E13.
 */
void CDecalBuffer::ReadDecalHandles(gpg::ReadArchive* const ar)
{
  for (;;) {
    gpg::RRef ownerRef{};
    CDecalHandle* handle = nullptr;
    (void)ar->ReadPointerOwned_CDecalHandle(&handle, &ownerRef);
    if (handle == nullptr) {
      return;
    }

    handle->mListNode.ListLinkBefore(&mHandleListHead);

    if (handle->mInfo.mStartTick != 0u) {
      mStartTickBuckets[handle->mInfo.mStartTick].insert(handle);
    }
  }
}

/**
 * Address: 0x00779680 (FUN_00779680, sub_779680)
 *
 * What it does:
 * Removes one handle from its start-tick bucket, queues object-id
 * retirement, and deletes the handle. `FindOrCreateStartTickBucket` +
 * `EraseBucketNodesByKey` reproduce the binary's `sub_77A250`/`sub_77A9F0`
 * call pair, gated on `mStartTick != 0` exactly as the binary gates it
 * (decals with no start tick were never inserted into the bucket tree by
 * `CreateHandle` in the first place). CreateHandle's own insert-side wiring
 * into the same start-tick bucket tree (`mStartTickBuckets[...].insert(handle)`,
 * see `CreateHandle` above) is already done -- `FUN_0077A930`/`FUN_0077CE50`
 * are both recovered, cited on `legacy/containers/RbTree.h`'s canonical
 * insert member for this map/set instantiation.
 */
void CDecalBuffer::DestroyHandle(CDecalHandle* const handleOpaque)
{
  if (!handleOpaque) {
    return;
  }

  if (handleOpaque->mInfo.mStartTick != 0u) {
    mStartTickBuckets[handleOpaque->mInfo.mStartTick].erase(handleOpaque);
  }

  if (handleOpaque->mVisibleInFocus != 0u) {
    mPendingHideObjectIds.push_back(handleOpaque->mInfo.mObj);
  }

  mPool.QueueReleasedLowId(handleOpaque->mInfo.mObj);

  delete handleOpaque;
}

/**
 * What it does:
 * Delegates one recycle-window tick to `IdPool::Update`.
 */
void CDecalBuffer::AdvanceIdPoolWindow()
{
  mPool.Update();
}

/**
 * Address: 0x00778730 (FUN_00778730, sub_778730)
 *
 * What it does:
 * Computes world-space XZ AABB bounds for a rotated decal quad.
 */
void CDecalBuffer::ProjectDecalToBoundsXZ(const SDecalInfo& info, Wm3::Vec2f& outMax, Wm3::Vec2f& outMin)
{
  const float c = std::cos(info.mRot.y);
  const float s = std::sin(info.mRot.y);

  const float xAxisX = info.mSize.x * c;
  const float xAxisZ = info.mSize.x * s;
  const float zAxisX = -(info.mSize.z * s);
  const float zAxisZ = info.mSize.z * c;

  const float minXOffset = std::min({0.0f, xAxisX, zAxisX, xAxisX + zAxisX});
  const float minZOffset = std::min({0.0f, xAxisZ, zAxisZ, xAxisZ + zAxisZ});
  const float maxXOffset = std::max({0.0f, xAxisX, zAxisX, xAxisX + zAxisX});
  const float maxZOffset = std::max({0.0f, xAxisZ, zAxisZ, xAxisZ + zAxisZ});

  outMin.x = info.mPos.x + minXOffset;
  outMin.y = info.mPos.z + minZOffset;
  outMax.x = info.mPos.x + maxXOffset;
  outMax.y = info.mPos.z + maxZOffset;
}

/**
 * Address: 0x00779040 (FUN_00779040, sub_779040)
 *
 * What it does:
 * Tests whether an observer army may currently detect a decal owned by `sourceArmy`.
 */
bool CDecalBuffer::IsDecalVisibleForArmy(
  const CArmyImpl* const sourceArmy, const SDecalInfo& info, CArmyImpl* const observerArmy
) const
{
  if (!observerArmy) {
    return false;
  }

  if (sourceArmy && observerArmy->Allies.Contains(static_cast<std::uint32_t>(sourceArmy->ArmyId))) {
    return true;
  }

  Wm3::Vec2f maxBounds{};
  Wm3::Vec2f minBounds{};
  ProjectDecalToBoundsXZ(info, maxBounds, minBounds);

  const moho::Rect2<int> queryRect{
    static_cast<int>(std::floor(minBounds.x)),
    static_cast<int>(std::floor(minBounds.y)),
    static_cast<int>(std::ceil(maxBounds.x)),
    static_cast<int>(std::ceil(maxBounds.y)),
  };

  const CAiReconDBImpl* const reconDb = observerArmy->GetReconDB();
  if (!reconDb) {
    return false;
  }

  return reconDb->ReconCanDetect(queryRect, info.mPos.y, 8) != 0;
}

/**
 * Address: 0x00779710 (FUN_00779710)
 *
 * What it does:
 * Advances decal lifetime queues and performs per-tick decal cleanup.
 */
void CDecalBuffer::CleanupTick()
{
  if (!mSim) {
    AdvanceIdPoolWindow();
    return;
  }

  const std::uint32_t curTick = mSim->mCurTick;

  // Pass 1: expire handles whose start tick has elapsed.
  const auto* const listHeadNode = static_cast<const CDecalHandleListNode*>(&mHandleListHead);
  for (CDecalHandleListNode* node = mHandleListHead.mNext; node != listHeadNode;) {
    CDecalHandleListNode* const next = node->mNext;
    CDecalHandle* const handle = CDecalHandle::FromListNode(node);
    if (handle->mInfo.mStartTick != 0u && handle->mInfo.mStartTick <= curTick) {
      handle->mInfo.mStartTick = 0u;
      DestroyHandle(handle);
    }
    node = next;
  }

  CArmyImpl** const armiesBegin = mSim->mArmiesList.begin();
  CArmyImpl** const armiesEnd = mSim->mArmiesList.end();
  const std::size_t armyCount = armiesBegin ? static_cast<std::size_t>(armiesEnd - armiesBegin) : 0u;

  if (armyCount != 0u) {
    const std::uint32_t rotatingArmyIndex = curTick % static_cast<std::uint32_t>(armyCount);
    CArmyImpl* const rotatingArmy = armiesBegin[rotatingArmyIndex];

    if (rotatingArmy && rotatingArmy->IsCivilian == 0u) {
      const std::int32_t focusArmy = mSim->mSyncFilter.focusArmy;
      const std::uint32_t rotatingArmyMask = rotatingArmyIndex < 32u ? (1u << rotatingArmyIndex) : 0u;

      for (CDecalHandleListNode* node = mHandleListHead.mNext; node != listHeadNode; node = node->mNext) {
        CDecalHandle* const handle = CDecalHandle::FromListNode(node);

        if (rotatingArmyMask != 0u && (handle->mArmyVisibilityFlags & rotatingArmyMask) == 0u) {
          const bool bypassRecon = handle->mInfo.mIsSplat == 0u;
          const bool graceWindow = handle->mInfo.mStartTick != 0u && (handle->mCreatedAtTick + 10u > curTick);

          if (bypassRecon || graceWindow) {
            CArmyImpl* sourceArmy = nullptr;
            if (handle->mInfo.mArmy < armyCount) {
              sourceArmy = armiesBegin[handle->mInfo.mArmy];
            }

            if (!sourceArmy || IsDecalVisibleForArmy(sourceArmy, handle->mInfo, rotatingArmy)) {
              for (std::size_t i = 0; i < armyCount; ++i) {
                CArmyImpl* const army = armiesBegin[i];
                if (!army) {
                  continue;
                }

                if (army->Allies.Contains(rotatingArmyIndex)) {
                  const std::uint32_t armyIndex = static_cast<std::uint32_t>(army->ArmyId);
                  if (armyIndex < 32u) {
                    handle->mArmyVisibilityFlags |= (1u << armyIndex);
                  }
                }
              }
            }
          }
        }

        bool shouldBeVisible = focusArmy == -1;
        if (!shouldBeVisible && focusArmy >= 0 && focusArmy < 32) {
          shouldBeVisible = (handle->mArmyVisibilityFlags & (1u << focusArmy)) != 0u;
        }

        if (shouldBeVisible) {
          if (handle->mVisibleInFocus == 0u) {
            AppendVisibleDecal(mVisibleDecals, handle->mInfo);
            handle->mVisibleInFocus = 1u;
          }
        } else if (handle->mVisibleInFocus != 0u) {
          mPendingHideObjectIds.push_back(handle->mInfo.mObj);
          handle->mVisibleInFocus = 0u;
        }
      }
    }
  }

  AdvanceIdPoolWindow();
}
