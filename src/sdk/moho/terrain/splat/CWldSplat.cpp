#include "moho/terrain/splat/CWldSplat.h"

#include <algorithm>
#include <cstring>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "moho/render/CDecalGroup.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DTextureBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/STIMap.h"

namespace
{
  struct CWldTerrainResRuntimeView
  {
    void* mVftable;
    moho::STIMap* mMap;
  };

  static_assert(sizeof(CWldTerrainResRuntimeView) == 0x08, "CWldTerrainResRuntimeView size must be 0x08");
  static_assert(
    offsetof(CWldTerrainResRuntimeView, mMap) == 0x04,
    "CWldTerrainResRuntimeView::mMap offset must be 0x04"
  );

  [[nodiscard]] const CWldTerrainResRuntimeView*
  AsCWldTerrainResRuntimeView(const moho::IWldTerrainRes* const terrainRes) noexcept
  {
    return reinterpret_cast<const CWldTerrainResRuntimeView*>(terrainRes);
  }

  [[nodiscard]] const moho::DecalGroupLookupNode* FindLookupNodeByKey(
    const moho::DecalGroupLookupTree& lookupTree, const std::uint32_t key
  ) noexcept
  {
    const moho::DecalGroupLookupNode* const head = lookupTree.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    const moho::DecalGroupLookupNode* best = head;
    const moho::DecalGroupLookupNode* cursor = head->mParent;
    while (cursor != nullptr && cursor->mIsNil == 0u) {
      if (cursor->mKey >= key) {
        best = cursor;
        cursor = cursor->mLeft;
      } else {
        cursor = cursor->mRight;
      }
    }

    if (best == head || key < best->mKey) {
      return head;
    }

    return best;
  }

  [[nodiscard]] moho::DecalGroupLookupNode* FindLookupNodeByKeyMutable(
    moho::DecalGroupLookupTree& lookupTree, const std::uint32_t key
  ) noexcept
  {
    moho::DecalGroupLookupNode* const head = lookupTree.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    moho::DecalGroupLookupNode* cursor = head->mParent;
    while (cursor != nullptr && cursor->mIsNil == 0u) {
      if (key < cursor->mKey) {
        cursor = cursor->mLeft;
      } else if (key > cursor->mKey) {
        cursor = cursor->mRight;
      } else {
        return cursor;
      }
    }

    return head;
  }

  [[nodiscard]] moho::DecalGroupLookupNode*
  FindLookupTreeMinimumNode(moho::DecalGroupLookupNode* node, moho::DecalGroupLookupNode* const head) noexcept
  {
    while (node != nullptr && node != head && node->mIsNil == 0u && node->mLeft != nullptr && node->mLeft != head
           && node->mLeft->mIsNil == 0u) {
      node = node->mLeft;
    }
    return node;
  }

  [[nodiscard]] moho::DecalGroupLookupNode*
  FindLookupTreeMaximumNode(moho::DecalGroupLookupNode* node, moho::DecalGroupLookupNode* const head) noexcept
  {
    while (node != nullptr && node != head && node->mIsNil == 0u && node->mRight != nullptr && node->mRight != head
           && node->mRight->mIsNil == 0u) {
      node = node->mRight;
    }
    return node;
  }

  void RefreshLookupHeadExtents(moho::DecalGroupLookupTree& lookupTree) noexcept
  {
    moho::DecalGroupLookupNode* const head = lookupTree.mHead;
    if (head == nullptr) {
      return;
    }

    if (lookupTree.mNodeCount == 0u || head->mParent == nullptr || head->mParent == head || head->mParent->mIsNil != 0u) {
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      lookupTree.mNodeCount = 0u;
      return;
    }

    head->mLeft = FindLookupTreeMinimumNode(head->mParent, head);
    head->mRight = FindLookupTreeMaximumNode(head->mParent, head);
  }

  [[nodiscard]] moho::DecalGroupLookupNode* CreateLookupNode(
    moho::DecalGroupLookupNode* const head, moho::DecalGroupLookupNode* const parent, const std::uint32_t key
  )
  {
    auto* const node = new moho::DecalGroupLookupNode{};
    node->mLeft = head;
    node->mParent = parent;
    node->mRight = head;
    node->mKey = key;
    node->mGroupIndex = 0;
    node->mColor = 0u;
    node->mIsNil = 0u;
    node->mPad16_17[0] = 0u;
    node->mPad16_17[1] = 0u;
    return node;
  }

  void ReplaceLookupNode(
    moho::DecalGroupLookupTree& lookupTree, moho::DecalGroupLookupNode* node, moho::DecalGroupLookupNode* replacement
  ) noexcept
  {
    moho::DecalGroupLookupNode* const head = lookupTree.mHead;
    if (head == nullptr || node == nullptr) {
      return;
    }

    if (node->mParent == head) {
      head->mParent = replacement;
    } else if (node == node->mParent->mLeft) {
      node->mParent->mLeft = replacement;
    } else {
      node->mParent->mRight = replacement;
    }

    if (replacement != nullptr && replacement != head) {
      replacement->mParent = node->mParent;
    }
  }

  /**
   * Address: 0x00879120 (FUN_00879120)
   *
   * What it does:
   * Resolves one lookup-node value lane for `key`; inserts a new key node
   * when the key is absent and returns the inserted value slot.
   */
  [[nodiscard]] std::uint32_t* ResolveLookupValueSlotForKey(
    moho::DecalGroupLookupTree& lookupTree, const std::uint32_t key
  )
  {
    moho::DecalGroupLookupNode* const head = lookupTree.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    moho::DecalGroupLookupNode* parent = head;
    moho::DecalGroupLookupNode* cursor = head->mParent;
    while (cursor != nullptr && cursor->mIsNil == 0u) {
      parent = cursor;
      if (key < cursor->mKey) {
        cursor = cursor->mLeft;
      } else if (key > cursor->mKey) {
        cursor = cursor->mRight;
      } else {
        return reinterpret_cast<std::uint32_t*>(&cursor->mGroupIndex);
      }
    }

    moho::DecalGroupLookupNode* const inserted = CreateLookupNode(head, parent, key);
    if (parent == head) {
      head->mParent = inserted;
      head->mLeft = inserted;
      head->mRight = inserted;
    } else if (key < parent->mKey) {
      parent->mLeft = inserted;
      if (head->mLeft == head || key < head->mLeft->mKey) {
        head->mLeft = inserted;
      }
    } else {
      parent->mRight = inserted;
      if (head->mRight == head || key > head->mRight->mKey) {
        head->mRight = inserted;
      }
    }

    ++lookupTree.mNodeCount;
    return reinterpret_cast<std::uint32_t*>(&inserted->mGroupIndex);
  }

  /**
   * Address: 0x00879510 (FUN_00879510)
   *
   * What it does:
   * Erases one key range from the manager lookup tree and returns the number
   * of removed nodes (0 or 1 for this unique-key lookup lane).
   */
  std::int32_t EraseLookupEntriesByKey(
    moho::DecalGroupLookupTree& lookupTree, const std::int32_t* const keyLane
  )
  {
    const std::uint32_t key = keyLane != nullptr ? static_cast<std::uint32_t>(*keyLane) : 0u;

    moho::DecalGroupLookupNode* const head = lookupTree.mHead;
    if (head == nullptr || lookupTree.mNodeCount == 0u) {
      return 0;
    }

    moho::DecalGroupLookupNode* const target = FindLookupNodeByKeyMutable(lookupTree, key);
    if (target == nullptr || target == head || target->mIsNil != 0u || target->mKey != key) {
      return 0;
    }

    if (target->mLeft == nullptr || target->mLeft->mIsNil != 0u) {
      ReplaceLookupNode(lookupTree, target, target->mRight);
    } else if (target->mRight == nullptr || target->mRight->mIsNil != 0u) {
      ReplaceLookupNode(lookupTree, target, target->mLeft);
    } else {
      moho::DecalGroupLookupNode* const successor = FindLookupTreeMinimumNode(target->mRight, head);
      if (successor != nullptr && successor->mParent != target) {
        ReplaceLookupNode(lookupTree, successor, successor->mRight);
        successor->mRight = target->mRight;
        if (successor->mRight != nullptr && successor->mRight != head) {
          successor->mRight->mParent = successor;
        }
      }

      if (successor != nullptr) {
        ReplaceLookupNode(lookupTree, target, successor);
        successor->mLeft = target->mLeft;
        if (successor->mLeft != nullptr && successor->mLeft != head) {
          successor->mLeft->mParent = successor;
        }
      }
    }

    delete target;
    if (lookupTree.mNodeCount > 0u) {
      --lookupTree.mNodeCount;
    }
    RefreshLookupHeadExtents(lookupTree);
    return 1;
  }

  [[nodiscard]] moho::SpatialDB_MeshInstance*
  AsDecalManagerSpatialDbRuntime(moho::CDecalManager* const manager) noexcept
  {
    return reinterpret_cast<moho::SpatialDB_MeshInstance*>(manager->mSpatialDbOwnerStorage);
  }

  /**
   * Address: 0x0087CF80 (FUN_0087CF80, sub_87CF80)
   *
   * What it does:
   * Dispatches one decal-index removal lane across `[groupBegin,groupEnd)` and
   * stores the processed index in `outValue`.
   */
  [[nodiscard]] std::int32_t* DispatchRemoveDecalIndexToGroupRange(
    std::int32_t* const outValue,
    moho::CDecalGroup** groupBegin,
    moho::CDecalGroup** groupEnd,
    const std::int32_t decalIndex
  ) noexcept
  {
    if (groupBegin != groupEnd) {
      do {
        (*groupBegin)->RemoveFromGroup(decalIndex);
        ++groupBegin;
      } while (groupBegin != groupEnd);
    }

    *outValue = decalIndex;
    return outValue;
  }

  [[nodiscard]] std::int32_t
  ErasePrimaryDecalLookupEntriesByKey(moho::DecalGroupLookupTree& lookupTree, const std::int32_t key);

  /**
   * Address: 0x008779B0 (FUN_008779B0)
   *
   * What it does:
   * Removes one active decal from groups/vector/lookup lanes, deletes the
   * decal, reindexes remaining entries, and returns the next vector slot.
   */
  [[nodiscard]] moho::CWldTerrainDecal**
  RemoveDecalFromManagerAndReturnNextSlot(moho::CDecalManager& manager, moho::CWldTerrainDecal* const decal)
  {
    if (decal == nullptr) {
      return nullptr;
    }

    auto& groupView = msvc8::AsVectorRuntimeView(manager.mDecalGroups);
    std::int32_t removedDecalIndexLane = 0;
    (void)DispatchRemoveDecalIndexToGroupRange(
      &removedDecalIndexLane,
      groupView.begin,
      groupView.end,
      decal->mIndex
    );
    (void)ErasePrimaryDecalLookupEntriesByKey(manager.mDecalGroupLookupByDecalIndex, decal->mIndex);

    auto& decalsView = msvc8::AsVectorRuntimeView(manager.mDecals);
    moho::CWldTerrainDecal** found = decalsView.begin;
    while (found != decalsView.end) {
      if (*found == decal) {
        break;
      }
      ++found;
    }

    if (found == decalsView.end) {
      return decalsView.end;
    }

    const std::ptrdiff_t trailingCount = decalsView.end - (found + 1);
    if (trailingCount > 0) {
      const std::size_t bytesToMove = static_cast<std::size_t>(trailingCount) * sizeof(moho::CWldTerrainDecal*);
      (void)::memmove_s(found, bytesToMove, found + 1, bytesToMove);
    }
    --decalsView.end;

    delete decal;

    for (moho::CWldTerrainDecal** it = decalsView.begin; it != decalsView.end; ++it) {
      moho::CWldTerrainDecal* const activeDecal = *it;
      if (activeDecal != nullptr) {
        activeDecal->mVecIndex = static_cast<std::uint32_t>(it - decalsView.begin);
      }
    }

    manager.mDidSomething = 1u;
    return found;
  }

  [[nodiscard]] float MoveAlphaTowardZero(const float value, const float step) noexcept
  {
    float upperCandidate = value + step;
    if (upperCandidate > 0.0f) {
      upperCandidate = 0.0f;
    }

    const float lowerCandidate = value - step;
    if (lowerCandidate > upperCandidate) {
      return lowerCandidate;
    }

    return upperCandidate;
  }

  [[nodiscard]] std::int32_t SortUserEntityPointerRange(gpg::fastvector<moho::UserEntity*>& entities)
  {
    auto& view = gpg::AsFastVectorRuntimeView<moho::UserEntity*>(&entities);
    if (view.begin != nullptr && view.end != nullptr && (view.end - view.begin) > 1) {
      std::sort(view.begin, view.end);
    }

    if (view.begin == nullptr || view.end == nullptr) {
      return 0;
    }

    return static_cast<std::int32_t>(view.end - view.begin);
  }

  [[nodiscard]] moho::DecalGroupLookupNode* CreateLookupHeadSentinel()
  {
    auto* const head = new moho::DecalGroupLookupNode{};
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mKey = 0u;
    head->mGroupIndex = 0;
    head->mColor = 0u;
    head->mIsNil = 1u;
    head->mPad16_17[0] = 0u;
    head->mPad16_17[1] = 0u;
    return head;
  }

  void InitializeLookupTree(moho::DecalGroupLookupTree& lookupTree)
  {
    lookupTree.mUnknown00 = 0u;
    lookupTree.mHead = CreateLookupHeadSentinel();
    lookupTree.mNodeCount = 0u;
    lookupTree.mUnknown0C = 0u;
  }

  void DeleteLookupSubtree(
    moho::DecalGroupLookupNode* const node,
    const moho::DecalGroupLookupNode* const head
  )
  {
    if (node == nullptr || node == head || node->mIsNil != 0u) {
      return;
    }

    DeleteLookupSubtree(node->mLeft, head);
    DeleteLookupSubtree(node->mRight, head);
    delete node;
  }

  /**
   * Address: 0x00878D30 (FUN_00878D30)
   *
   * What it does:
   * Releases one keyed lookup tree (`+0x1C` lane), deletes its sentinel, and
   * resets the tree header to `{head=null,count=0}`.
   */
  std::int32_t ResetDecalLookupTreePrimary(moho::DecalGroupLookupTree& lookupTree)
  {
    if (lookupTree.mHead != nullptr) {
      DeleteLookupSubtree(lookupTree.mHead->mParent, lookupTree.mHead);
      delete lookupTree.mHead;
    }
    lookupTree.mHead = nullptr;
    lookupTree.mNodeCount = 0u;
    return 0;
  }

  /**
   * Address: 0x00878D60 (FUN_00878D60)
   *
   * What it does:
   * Releases one keyed lookup tree (`+0x38` lane), deletes its sentinel, and
   * resets the tree header to `{head=null,count=0}`.
   */
  std::int32_t ResetDecalLookupTreeSecondary(moho::DecalGroupLookupTree& lookupTree)
  {
    if (lookupTree.mHead != nullptr) {
      DeleteLookupSubtree(lookupTree.mHead->mParent, lookupTree.mHead);
      delete lookupTree.mHead;
    }
    lookupTree.mHead = nullptr;
    lookupTree.mNodeCount = 0u;
    return 0;
  }

  /**
   * Address: 0x008791E0 (FUN_008791E0)
   *
   * What it does:
   * Erases one keyed entry range from the primary decal lookup tree and
   * returns the number of removed entries.
   */
  std::int32_t ErasePrimaryDecalLookupEntriesByKey(
    moho::DecalGroupLookupTree& lookupTree,
    const std::int32_t key
  )
  {
    return EraseLookupEntriesByKey(lookupTree, &key);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00877250 (FUN_00877250, ??0IDecalManager@Moho@@QAE@XZ)
   * Address: 0x00878D20 (FUN_00878D20, IDecalManager ctor lane)
   *
   * What it does:
   * Initializes one decal-manager base interface object.
   */
  IDecalManager::IDecalManager() = default;

  /**
   * Address: 0x00877A60 (FUN_00877A60, Moho::CDecalManager::CDecalManager)
   *
   * What it does:
   * Initializes decal vectors, keyed lookup sentinels, and embedded spatial
   * db storage for the owning terrain map.
   */
  CDecalManager::CDecalManager(IWldTerrainRes* const terrainRes)
    : IDecalManager()
    , mDecalCount(0u)
    , mNumDecals(0u)
    , mUnknown0C_0F{0u, 0u, 0u, 0u}
    , mDecals()
    , mDecalGroupLookupByDecalIndex{}
    , mDecalGroups()
    , mDecalGroupLookupBySplatIndex{}
    , mSplats()
    , mSpatialDbOwnerStorage{}
    , mWldTerrain(terrainRes)
    , mUnknownE8_10F{}
    , mDidSomething(0u)
    , mPad111_113{0u, 0u, 0u}
  {
    InitializeLookupTree(mDecalGroupLookupByDecalIndex);
    InitializeLookupTree(mDecalGroupLookupBySplatIndex);

    SpatialDB_MeshInstance* const spatialDb = AsDecalManagerSpatialDbRuntime(this);
    spatialDb->InitializeStorage();

    if (mWldTerrain == nullptr) {
      return;
    }

    const STIMap* const map = AsCWldTerrainResRuntimeView(mWldTerrain)->mMap;
    if (map == nullptr || map->mHeightField.get() == nullptr) {
      return;
    }

    const CHeightField* const heightField = map->mHeightField.get();
    spatialDb->ResizeStorageForMap(heightField->width - 1, heightField->height - 1);
  }

  /**
   * Address: 0x00877B70 (FUN_00877B70, Moho::CDecalManager::~CDecalManager)
   *
   * What it does:
   * Deletes active decals/groups/splats, clears both keyed lookup trees, and
   * tears down embedded spatial-db registration storage.
   */
  CDecalManager::~CDecalManager()
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);
    for (CWldTerrainDecal** it = decalsView.begin; it != decalsView.end; ++it) {
      if (*it != nullptr) {
        delete *it;
      }
    }

    auto& groupsView = msvc8::AsVectorRuntimeView(mDecalGroups);
    for (CDecalGroup** it = groupsView.begin; it != groupsView.end; ++it) {
      if (*it != nullptr) {
        delete *it;
      }
    }

    auto& splatsView = msvc8::AsVectorRuntimeView(mSplats);
    for (CWldSplat** it = splatsView.begin; it != splatsView.end; ++it) {
      if (*it != nullptr) {
        delete *it;
      }
    }

    AsDecalManagerSpatialDbRuntime(this)->DestroyStorage();

    if (splatsView.begin != nullptr) {
      ::operator delete(splatsView.begin);
    }
    splatsView.begin = nullptr;
    splatsView.end = nullptr;
    splatsView.capacityEnd = nullptr;

    (void)ResetDecalLookupTreeSecondary(mDecalGroupLookupBySplatIndex);

    if (groupsView.begin != nullptr) {
      ::operator delete(groupsView.begin);
    }
    groupsView.begin = nullptr;
    groupsView.end = nullptr;
    groupsView.capacityEnd = nullptr;

    (void)ResetDecalLookupTreePrimary(mDecalGroupLookupByDecalIndex);

    if (decalsView.begin != nullptr) {
      ::operator delete(decalsView.begin);
    }
    decalsView.begin = nullptr;
    decalsView.end = nullptr;
    decalsView.capacityEnd = nullptr;
  }

  /**
   * Address: 0x00877FF0 (FUN_00877FF0, Moho::CDecalManager::Func5)
   *
   * What it does:
   * Looks up one decal-index key in the decal-group lookup tree and returns
   * the mapped group index, or `0` when the key is absent.
   */
  std::int32_t CDecalManager::FindGroupByDecalIndex(const std::uint32_t decalIndex) const
  {
    const DecalGroupLookupNode* const node = FindLookupNodeByKey(mDecalGroupLookupByDecalIndex, decalIndex);
    if (node == nullptr || node == mDecalGroupLookupByDecalIndex.mHead) {
      return 0;
    }

    return node->mGroupIndex;
  }

  /**
   * Address: 0x00878250 (FUN_00878250, Moho::CDecalManager::DestroyDecal)
   *
   * What it does:
   * Removes one decal from group memberships and manager storage, destroys
   * the decal object, and compacts vector-index lanes.
   */
  void CDecalManager::DestroyDecal(CWldTerrainDecal* const decal)
  {
    if (decal == nullptr) {
      return;
    }

    const auto& groupsView = msvc8::AsVectorRuntimeView(mDecalGroups);
    for (CDecalGroup** groupIt = groupsView.begin; groupIt != groupsView.end; ++groupIt) {
      CDecalGroup* const group = *groupIt;
      if (group != nullptr) {
        group->RemoveFromGroup(decal->mIndex);
      }
    }

    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);
    CWldTerrainDecal** found = decalsView.begin;
    while (found != decalsView.end) {
      if (*found == decal) {
        break;
      }
      ++found;
    }
    if (found == decalsView.end) {
      return;
    }

    CWldTerrainDecal* const removedDecal = *found;
    const std::ptrdiff_t trailingCount = decalsView.end - (found + 1);
    if (trailingCount > 0) {
      const std::size_t bytesToMove = static_cast<std::size_t>(trailingCount) * sizeof(CWldTerrainDecal*);
      (void)::memmove_s(found, bytesToMove, found + 1, bytesToMove);
    }
    --decalsView.end;

    delete removedDecal;

    for (CWldTerrainDecal** decalIt = decalsView.begin; decalIt != decalsView.end; ++decalIt) {
      CWldTerrainDecal* const activeDecal = *decalIt;
      if (activeDecal != nullptr) {
        activeDecal->mVecIndex = static_cast<std::uint32_t>(decalIt - decalsView.begin);
      }
    }

    mDidSomething = 1u;
  }

  /**
   * Address: 0x008782A0 (FUN_008782A0, Moho::CDecalManager::Func10)
   *
   * What it does:
   * Looks up one splat/decal-index key in the secondary lookup tree and
   * returns the mapped group index, or `0` when the key is absent.
   */
  std::int32_t CDecalManager::FindGroupBySplatIndex(const std::uint32_t splatIndex) const
  {
    const DecalGroupLookupNode* const node = FindLookupNodeByKey(mDecalGroupLookupBySplatIndex, splatIndex);
    if (node == nullptr || node == mDecalGroupLookupBySplatIndex.mHead) {
      return 0;
    }

    return node->mGroupIndex;
  }

  /**
   * Address: 0x00878A40 (FUN_00878A40, Moho::CDecalManager::RemoveDecals)
   *
   * What it does:
   * Scans all active decals for each requested runtime handle and marks
   * matching decals for deferred removal.
   */
  void CDecalManager::RemoveDecals(const msvc8::vector<std::int32_t>& decalHandles)
  {
    const auto& handleView = msvc8::AsVectorRuntimeView(decalHandles);
    for (const std::int32_t* handleIt = handleView.begin; handleIt != handleView.end; ++handleIt) {
      const auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);
      for (CWldTerrainDecal** decalIt = decalsView.begin; decalIt != decalsView.end; ++decalIt) {
        CWldTerrainDecal* const decal = *decalIt;
        if (decal->mRuntimeHandle == *handleIt) {
          decal->mRemoveTick = 1;
          break;
        }
      }
    }
  }

  /**
   * Address: 0x008776D0 (FUN_008776D0, Moho::CDecalManager::Reindex)
   *
   * What it does:
   * Refreshes each decal's `mVecIndex` lane to match the current `mDecals`
   * vector order.
   */
  void CDecalManager::Reindex()
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);
    for (CWldTerrainDecal** decalIt = decalsView.begin; decalIt != decalsView.end; ++decalIt) {
      CWldTerrainDecal* const decal = *decalIt;
      decal->mVecIndex = static_cast<std::uint32_t>(decalIt - decalsView.begin);
    }
  }

  /**
   * Address: 0x00878590 (FUN_00878590, Moho::CDecalManager::Func17)
   *
   * What it does:
   * Finds one decal in `mDecals`, moves it to the front while preserving
   * relative order of earlier entries, then reindexes the decal lane.
   */
  void CDecalManager::MoveDecalToFront(CWldTerrainDecal* const decal)
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);

    CWldTerrainDecal** found = decalsView.begin;
    while (found != decalsView.end) {
      if (*found == decal) {
        break;
      }
      ++found;
    }

    if (found == decalsView.end) {
      return;
    }

    if (found != decalsView.begin) {
      do {
        CWldTerrainDecal* const previous = *(found - 1);
        *found = previous;
        --found;
      } while (found != decalsView.begin);
    }

    *found = decal;
    Reindex();
  }

  /**
   * Address: 0x008785D0 (FUN_008785D0, Moho::CDecalManager::Func18)
   *
   * What it does:
   * Finds one decal in `mDecals`, swaps it with the next entry when it is
   * not the last element, then reindexes when the decal exists.
   */
  void CDecalManager::MoveDecalTowardBack(CWldTerrainDecal* const decal)
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);

    CWldTerrainDecal** found = decalsView.begin;
    while (found != decalsView.end) {
      if (*found == decal) {
        break;
      }
      ++found;
    }

    if (found == decalsView.end) {
      return;
    }

    CWldTerrainDecal** const next = found + 1;
    if (next != decalsView.end) {
      *found = *next;
      *next = decal;
    }

    Reindex();
  }

  /**
   * Address: 0x00878610 (FUN_00878610, Moho::CDecalManager::Func19)
   *
   * What it does:
   * Finds one decal in `mDecals`, swaps it with the previous entry when it
   * is not the first element, then reindexes when a swap is applied.
   */
  void CDecalManager::MoveDecalTowardFront(CWldTerrainDecal* const decal)
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);

    CWldTerrainDecal** found = decalsView.begin;
    while (found != decalsView.end) {
      if (*found == decal) {
        break;
      }
      ++found;
    }

    if (found != decalsView.end && found != decalsView.begin) {
      *found = *(found - 1);
      *(found - 1) = decal;
      Reindex();
    }
  }

  /**
   * Address: 0x00878020 (FUN_00878020, Moho::CDecalManager::NewDecal)
   *
   * What it does:
   * Allocates one terrain decal for the requested runtime index, marks the
   * manager dirty, and forwards to `LoadDecal`.
   */
  CWldTerrainDecal* CDecalManager::NewDecal(const std::int32_t decalIndex)
  {
    CWldTerrainDecal* const decal = new CWldTerrainDecal(AsDecalManagerSpatialDbRuntime(this), mWldTerrain);
    decal->mIndex = decalIndex;
    mDidSomething = 1u;
    return LoadDecal(decal);
  }

  /**
   * Address: 0x008780A0 (FUN_008780A0, Moho::CDecalManager::LoadDecal)
   *
   * What it does:
   * Loads one existing decal (or allocates a new one), appends it to active
   * manager storage, and updates the decal-index lookup lane.
   */
  CWldTerrainDecal* CDecalManager::LoadDecal(CWldTerrainDecal* decal)
  {
    CWldTerrainDecal* loaded = decal;
    if (loaded == nullptr) {
      loaded = new CWldTerrainDecal(AsDecalManagerSpatialDbRuntime(this), mWldTerrain);
      loaded->mIndex = static_cast<std::int32_t>(mDecalCount);
      ++mDecalCount;
    }

    const auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);
    const std::uint32_t vectorIndex =
      decalsView.begin != nullptr ? static_cast<std::uint32_t>(decalsView.end - decalsView.begin) : 0u;
    loaded->mVecIndex = vectorIndex;

    mDecals.push_back(loaded);

    std::uint32_t* const valueLane =
      ResolveLookupValueSlotForKey(mDecalGroupLookupByDecalIndex, static_cast<std::uint32_t>(loaded->mIndex));
    if (valueLane != nullptr) {
      *valueLane = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(loaded));
    }

    mDidSomething = 1u;
    return loaded;
  }

  /**
   * Address: 0x00878460 (FUN_00878460, Moho::CDecalManager::DestroyDecalGroup)
   *
   * What it does:
   * Removes one decal-group mapping, erases the group from manager storage,
   * then deletes the group object.
   */
  std::int32_t CDecalManager::DestroyDecalGroup(CDecalGroup* group)
  {
    if (group == nullptr) {
      return 0;
    }

    std::int32_t* const groupIndexLane = group->GetIndex();
    const std::int32_t removedFromLookup = EraseLookupEntriesByKey(mDecalGroupLookupBySplatIndex, groupIndexLane);

    auto& groupsView = msvc8::AsVectorRuntimeView(mDecalGroups);
    CDecalGroup** found = groupsView.begin;
    while (found != groupsView.end) {
      if (*found == group) {
        break;
      }
      ++found;
    }

    if (found != groupsView.end) {
      const std::ptrdiff_t trailingCount = groupsView.end - (found + 1);
      if (trailingCount > 0) {
        const std::size_t bytesToMove = static_cast<std::size_t>(trailingCount) * sizeof(CDecalGroup*);
        (void)::memmove_s(found, bytesToMove, found + 1, bytesToMove);
      }
      --groupsView.end;
    }

    delete group;
    return removedFromLookup;
  }

  /**
   * Address: 0x00878530 (FUN_00878530, Moho::CDecalManager::AddSplat)
   *
   * What it does:
   * Moves one existing decal pointer to the end of the active decal vector
   * and reindexes after the move.
   */
  void CDecalManager::AddSplat(CWldTerrainDecal* const decal)
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);
    CWldTerrainDecal** found = decalsView.begin;
    while (found != decalsView.end) {
      if (*found == decal) {
        break;
      }
      ++found;
    }

    if (found == decalsView.end) {
      return;
    }

    const std::ptrdiff_t trailingCount = decalsView.end - (found + 1);
    if (trailingCount > 0) {
      const std::size_t bytesToMove = static_cast<std::size_t>(trailingCount) * sizeof(CWldTerrainDecal*);
      (void)::memmove_s(found, bytesToMove, found + 1, bytesToMove);
    }
    --decalsView.end;

    mDecals.push_back(decal);
    Reindex();
  }

  /**
   * Address: 0x00878A90 (FUN_00878A90, Moho::CDecalManager::ProcessRemovals)
   *
   * What it does:
   * Fades scheduled decals/splats toward zero alpha and erases fully faded
   * entries from manager storage.
   */
  void CDecalManager::ProcessRemovals(const std::int32_t tick)
  {
    auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);
    CWldTerrainDecal** decalIt = decalsView.begin;
    while (decalIt != decalsView.end) {
      CWldTerrainDecal* const decal = *decalIt;
      if (decal != nullptr && decal->mRemoveTick > 0 && tick > decal->mRemoveTick) {
        decal->mCurrentAlpha = MoveAlphaTowardZero(decal->mCurrentAlpha, 0.2f);
        if (decal->mCurrentAlpha == 0.0f) {
          decalIt = RemoveDecalFromManagerAndReturnNextSlot(*this, decal);
          continue;
        }
      }
      ++decalIt;
    }

    auto& splatsView = msvc8::AsVectorRuntimeView(mSplats);
    CWldSplat** splatIt = splatsView.begin;
    while (splatIt != splatsView.end) {
      CWldSplat* const splat = *splatIt;
      if (splat != nullptr && splat->mRemoveTick > 0 && tick > splat->mRemoveTick) {
        splat->mCurrentAlpha = MoveAlphaTowardZero(splat->mCurrentAlpha, 0.03f);
        if (splat->mCurrentAlpha == 0.0f) {
          delete splat;
          const std::ptrdiff_t trailingCount = splatsView.end - (splatIt + 1);
          if (trailingCount > 0) {
            const std::size_t bytesToMove = static_cast<std::size_t>(trailingCount) * sizeof(CWldSplat*);
            (void)::memmove_s(splatIt, bytesToMove, splatIt + 1, bytesToMove);
          }
          --splatsView.end;
          continue;
        }
      }

      ++splatIt;
    }
  }

  /**
   * Address: 0x00878BE0 (FUN_00878BE0, Moho::CDecalManager::EntitiesInView)
   *
   * What it does:
   * Collects one camera-visible entity lane from the manager spatial-db
   * registration and sorts the collected pointer range.
   */
  std::int32_t CDecalManager::EntitiesInView(
    GeomCamera3* const camera,
    gpg::fastvector<UserEntity*>& entities,
    const bool ignoreDecalLod
  )
  {
    auto* const spatialDb = AsDecalManagerSpatialDbRuntime(this);
    if (ignoreDecalLod) {
      spatialDb->CollectInVolume(entities, static_cast<EEntityType>(0x0800u), &camera->solid2);
    } else {
      spatialDb->CollectInView(camera, entities, static_cast<EEntityType>(0x0800u));
    }

    return SortUserEntityPointerRange(entities);
  }

  /**
   * Address: 0x00878C40 (FUN_00878C40, Moho::CDecalManager::PropsInView)
   *
   * What it does:
   * Collects one camera-visible prop lane from the manager spatial-db
   * registration and sorts the collected pointer range.
   */
  std::int32_t CDecalManager::PropsInView(
    GeomCamera3* const camera,
    gpg::fastvector<UserEntity*>& props,
    const bool ignoreDecalLod
  )
  {
    auto* const spatialDb = AsDecalManagerSpatialDbRuntime(this);
    if (ignoreDecalLod) {
      spatialDb->CollectInVolume(props, static_cast<EEntityType>(0x0200u), &camera->solid2);
    } else {
      spatialDb->CollectInView(camera, props, static_cast<EEntityType>(0x0200u));
    }

    return SortUserEntityPointerRange(props);
  }

  /**
   * Address: 0x0089DF70 (FUN_0089DF70, Moho::CWldSplat::CWldSplat)
   *
   * What it does:
   * Seeds the splat's base decal state and leaves the batch-texture lane
   * empty until a name is assigned.
   */
  CWldSplat::CWldSplat(SpatialDB_MeshInstance* const spatialDbOwner, IWldTerrainRes* const terrainRes)
    : CWldTerrainDecal(spatialDbOwner, terrainRes)
    , mTex()
  {}

  /**
   * Address: 0x0089DFE0 (FUN_0089DFE0, Moho::CWldSplat::dtr)
   * Address: 0x0089E010 (FUN_0089E010, Moho::CWldSplat::~CWldSplat)
   *
   * What it does:
   * Releases the retained batch texture and then tears down the terrain
   * decal base lanes.
   */
  CWldSplat::~CWldSplat() = default;

  /**
   * Address: 0x0089E2C0 (FUN_0089E2C0, Moho::CWldSplat::SetName)
   *
   * What it does:
   * Stores the splat name, resolves the texture from disk when non-empty,
   * and keeps the previous texture lane intact when the name is empty.
   */
  void CWldSplat::SetName(const msvc8::string& name, const int slot)
  {
    (void)slot;

    mNames[0] = name;
    if (mNames[0].empty()) {
      return;
    }

    mTex = CD3DBatchTexture::FromFile(mNames[0].c_str(), 0u);
  }

  /**
   * Address: 0x0089E090 (FUN_0089E090, Moho::CWldSplat::Update)
   *
   * What it does:
   * Advances the base decal state and refreshes the splat vertex positions.
   */
  void CWldSplat::Update()
  {
    CWldTerrainDecal::Update();
    UpdateVertices();
  }

  /**
   * Address: 0x0089E0B0 (FUN_0089E0B0, Moho::CWldSplat::UpdateVertices)
   *
   * What it does:
   * Projects the unit quad into world space and samples terrain elevation
   * for each corner.
   */
  void CWldSplat::UpdateVertices()
  {
    const auto* const terrainView = AsCWldTerrainResRuntimeView(mTerrainRes);
    const STIMap* const map = terrainView->mMap;
    const CHeightField* const heightField = map->mHeightField.get();

    const Wm3::Vec2f localCorners[4]{
      {0.0f, 0.0f},
      {1.0f, 0.0f},
      {1.0f, 1.0f},
      {0.0f, 1.0f},
    };

    for (std::size_t index = 0; index < 4; ++index) {
      const Wm3::Vec2f corner = ComputeCorner(localCorners[index]);
      SplatVertex& vertex = mSplatVertices[index];
      vertex.mPosition.x = corner.x;
      vertex.mPosition.z = corner.y;
      vertex.mPosition.y = heightField->GetElevation(vertex.mPosition.x, vertex.mPosition.z);
    }
  }

  /**
   * Address: 0x0089E1F0 (FUN_0089E1F0, Moho::CWldSplat::UpdateBatchTexture)
   *
   * What it does:
   * Adds the retained batch texture to the atlas and writes the returned UV
   * rectangle into the splat quad.
   */
  void CWldSplat::UpdateBatchTexture(CD3DTextureBatcher* const batcher)
  {
    if (mTex) {
      const gpg::Rect2f* const uvRect = batcher->AddTexture(mTex);
      if (uvRect != nullptr) {
        mSplatVertices[0].mTexCoord.x = uvRect->x0;
        mSplatVertices[0].mTexCoord.y = uvRect->z0;
        mSplatVertices[1].mTexCoord.x = uvRect->x1;
        mSplatVertices[1].mTexCoord.y = uvRect->z0;
        mSplatVertices[2].mTexCoord.x = uvRect->x1;
        mSplatVertices[2].mTexCoord.y = uvRect->z1;
        mSplatVertices[3].mTexCoord.x = uvRect->x0;
        mSplatVertices[3].mTexCoord.y = uvRect->z1;
      }
    }
  }

  /**
   * Address: 0x0089E2B0 (FUN_0089E2B0, Moho::CWldSplat::GetSplatVertices)
   *
   * What it does:
   * Returns the first vertex lane for the splat quad.
   */
  CWldSplat::SplatVertex* CWldSplat::GetSplatVertices() noexcept
  {
    return mSplatVertices;
  }

  /**
   * Address: 0x00878190 (FUN_00878190, Moho::CDecalManager::NewSplat)
   *
   * What it does:
   * Allocates one `CWldSplat`, seeds it from this manager's spatial-db owner
   * and terrain resource lanes, and appends it to `mSplats`.
   */
  CWldSplat* CDecalManager::NewSplat()
  {
    auto* const spatialDbOwner = AsDecalManagerSpatialDbRuntime(this);
    CWldSplat* const splat = new CWldSplat(spatialDbOwner, mWldTerrain);
    mSplats.push_back(splat);
    return splat;
  }

  /**
   * Address: 0x008784C0 (FUN_008784C0, Moho::CDecalManager::NewSplatAt)
   *
   * What it does:
   * Creates one splat, assigns type/name/default transform lanes, updates the
   * splat runtime state, and reports success.
   */
  bool CDecalManager::NewSplatAt(
    const Wm3::Vec3f& position,
    const EWldTerrainDecalType type,
    const msvc8::string& name
  )
  {
    CWldSplat* const splat = NewSplat();
    splat->mType = type;
    splat->SetName(name, 0);
    splat->mScale.x = 1.0f;
    splat->mScale.y = 1.0f;
    splat->mScale.z = 1.0f;
    splat->mPosition = position;
    splat->mOrientation.x = 0.0f;
    splat->mOrientation.y = 0.0f;
    splat->mOrientation.z = 0.0f;
    splat->Update();
    return true;
  }

  /**
   * Address: 0x00877E40 (FUN_00877E40, Moho::CDecalManager::Save)
   *
   * What it does:
   * Writes manager decal counts, serializes active decals, then serializes
   * all decal groups to the binary writer.
   */
  void CDecalManager::Save(gpg::BinaryWriter& writer)
  {
    writer.Write(mDecalCount);
    writer.Write(mNumDecals);

    const auto& decalsView = msvc8::AsVectorRuntimeView(mDecals);

    std::uint32_t activeDecalCount = 0u;
    for (CWldTerrainDecal** decalIt = decalsView.begin; decalIt != decalsView.end; ++decalIt) {
      CWldTerrainDecal* const decal = *decalIt;
      if (decal != nullptr && decal->mUnknownA0 == 0u) {
        ++activeDecalCount;
      }
    }
    writer.Write(activeDecalCount);

    for (CWldTerrainDecal** decalIt = decalsView.begin; decalIt != decalsView.end; ++decalIt) {
      CWldTerrainDecal* const decal = *decalIt;
      if (decal != nullptr && decal->mUnknownA0 == 0u) {
        decal->DecalSave(writer);
      }
    }

    const auto& groupsView = msvc8::AsVectorRuntimeView(mDecalGroups);
    const std::uint32_t groupCount =
      groupsView.begin != nullptr ? static_cast<std::uint32_t>(groupsView.end - groupsView.begin) : 0u;
    writer.Write(groupCount);

    for (CDecalGroup** groupIt = groupsView.begin; groupIt != groupsView.end; ++groupIt) {
      CDecalGroup* const group = *groupIt;
      if (group != nullptr) {
        group->WriteToStream(writer);
      }
    }
  }

} // namespace moho
