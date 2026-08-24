#include "moho/terrain/splat/CWldSplat.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <new>
#include <set>
#include <vector>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "legacy/algorithms/Sort.h"
#include "moho/entity/UserEntity.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/CDecalGroup.h"
#include "moho/render/CDecalTypes.h"
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

  /// True when a decal texture reference already names an absolute location -
  /// a UNC share, a drive-qualified path, or a rooted one - and so must be used
  /// exactly as the sim spelled it.
  [[nodiscard]] bool IsAbsoluteTextureReference(const char* const path) noexcept
  {
    if (path == nullptr || *path == '\0') {
      return false;
    }
    if (moho::FILE_HasUNC(path)) {
      return true;
    }

    const char root = moho::FILE_HasDrive(path) ? path[2] : path[0];
    return root == '/' || root == '\\';
  }

  /**
   * Address: 0x008786BF..0x00878786 (inside FUN_00878650)
   *
   * What it does:
   * Expands one `SDecalInfo` texture lane into the resource path the decal
   * loads from. Absolute references are taken verbatim; a bare name is looked
   * up as a `.dds` under the shared splat or decal folder. An empty lane stays
   * empty, which is how the decal path tells "leave this slot alone" apart from
   * "load this texture".
   */
  [[nodiscard]] msvc8::string ResolveDecalTexturePath(const msvc8::string& texture, const bool isSplat)
  {
    msvc8::string resolved;
    if (texture.empty()) {
      return resolved;
    }

    if (IsAbsoluteTextureReference(texture.c_str())) {
      resolved.assign(texture, 0, msvc8::string::npos);
      return resolved;
    }

    const char* const folder = isSplat ? "/env/common/splats/" : "/env/common/decals/";
    resolved.assign(folder, std::strlen(folder));
    (void)resolved.append(texture.view());
    (void)resolved.append(".dds", 4);
    return resolved;
  }

  /// The transform lanes every incoming decal record carries, in the order the
  /// binary writes them (0x008787AA..0x008787E5).
  void ApplyDecalRecordTransform(moho::CWldTerrainDecal& decal, const moho::SDecalInfo& record) noexcept
  {
    decal.mScale = record.mSize;
    decal.mPosition = record.mPos;
    decal.mOrientation = record.mRot;
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

    auto& groups = manager.mDecalGroups;
    std::int32_t removedDecalIndexLane = 0;
    (void)DispatchRemoveDecalIndexToGroupRange(
      &removedDecalIndexLane,
      groups.begin(),
      groups.end(),
      decal->mIndex
    );
    (void)ErasePrimaryDecalLookupEntriesByKey(manager.mDecalGroupLookupByDecalIndex, decal->mIndex);

    auto& decals = manager.mDecals;
    auto* const found = std::find(decals.begin(), decals.end(), decal);
    if (found == decals.end()) {
      return decals.end();
    }

    // The binary's memmove-tail-down + `--mLast` is vector::erase(it), which
    // likewise returns the slot the following element moved into.
    auto* const next = decals.erase(found);

    delete decal;

    for (auto* it = decals.begin(); it != decals.end(); ++it) {
      moho::CWldTerrainDecal* const activeDecal = *it;
      if (activeDecal != nullptr) {
        activeDecal->mVecIndex = static_cast<std::uint32_t>(it - decals.begin());
      }
    }

    manager.mDidSomething = 1u;
    return next;
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

  /**
   * Address: 0x0087E850 (FUN_0087E850), 0x0087E5B0 (FUN_0087E5B0),
   * 0x0087E5F0 (FUN_0087E5F0) -- `msvc8::sort<UserEntity*, Compare>`'s
   * `adjust_heap`/`make_heap`/`sort_heap` heapsort-fallback instantiation.
   * Cited in full on `legacy/algorithms/Sort.h`'s canonical templates.
   *
   * What it does:
   * Sorts one collected `UserEntity*` range (entities or props gathered by
   * `EntitiesInView`/`PropsInView`) into decal-draw order. The binary orders
   * by each entity's spatial-db registration id
   * (`UserEntity::mSpatialDbEntry.mEntryId`, an unsigned compare at node
   * offset `+0x14`) rather than by pointer identity, so this has to be
   * `msvc8::sort` with an explicit comparator, not a bare `std::sort` on the
   * pointers themselves.
   */
  [[nodiscard]] std::int32_t SortUserEntityPointerRange(gpg::fastvector<moho::UserEntity*>& entities)
  {
    if (entities.size() > 1u) {
      msvc8::sort(
        entities.begin(),
        entities.end(),
        [](const moho::UserEntity* const lhs, const moho::UserEntity* const rhs) noexcept {
          return static_cast<std::uint32_t>(lhs->mSpatialDbEntry.mEntryId)
               < static_cast<std::uint32_t>(rhs->mSpatialDbEntry.mEntryId);
        }
      );
    }

    return static_cast<std::int32_t>(entities.size());
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
   * In-order successor step for the decal-group lookup tree, matching the
   * MSVC8 `std::_Tree::_Inc` traversal the STL range-erase emission open-codes.
   * A raw pointer walk is retained here because this is the exact successor
   * mechanics the binary reproduces; higher-level range helpers cannot express
   * the sentinel-anchored parent climb without changing node visitation order.
   */
  [[nodiscard]] moho::DecalGroupLookupNode*
  AdvanceLookupNodeToInOrderSuccessor(moho::DecalGroupLookupNode* node) noexcept
  {
    if (node->mIsNil != 0u) {
      return node;
    }

    if (node->mRight->mIsNil != 0u) {
      // No right subtree: climb to the first ancestor whose left branch we came from.
      moho::DecalGroupLookupNode* ancestor = node->mParent;
      while (ancestor->mIsNil == 0u && node == ancestor->mRight) {
        node = ancestor;
        ancestor = ancestor->mParent;
      }
      return ancestor;
    }

    // Right subtree exists: successor is its left-most descendant.
    node = node->mRight;
    for (moho::DecalGroupLookupNode* left = node->mLeft; left->mIsNil == 0u; left = node->mLeft) {
      node = left;
    }
    return node;
  }

  /**
   * Address: 0x00879C30 (FUN_00879C30, sub_879C30)
   * Mangled: MSVC8 `std::_Tree<...>::erase(iterator first, iterator last)`
   *          emission for the primary decal-index lookup map.
   *
   * IDA signature:
   * _DWORD *__userpurge sub_879C30@<eax>(int this@<edi>, _DWORD *out,
   *                                      _DWORD *first, _DWORD *last);
   *
   * What it does:
   * Erases the half-open node range `[first,last)` from the decal-group lookup
   * tree. When the range spans the whole tree (`first` is the minimum and
   * `last` is the head sentinel) it destroys the entire body in one recursive
   * sweep and re-links the sentinel to the empty state, keeping the head node
   * alive for reuse. Otherwise it erases node-by-node in in-order sequence.
   * Returns the node one past the erased range (`out`).
   */
  moho::DecalGroupLookupNode* ClearDecalLookupTree(
    moho::DecalGroupLookupTree& tree,
    moho::DecalGroupLookupNode* first,
    moho::DecalGroupLookupNode* last
  )
  {
    moho::DecalGroupLookupNode* const head = tree.mHead;

    // Fast path: erasing every element ([_Lmost, _Head)) collapses to one
    // recursive subtree destroy plus a sentinel re-link (head is retained).
    if (first == head->mLeft && last == head) {
      DeleteLookupSubtree(head->mParent, head);
      head->mParent = head;
      tree.mNodeCount = 0u;
      head->mLeft = head;
      head->mRight = head;
      return head->mLeft;
    }

    // General range erase: remove each node in [first,last) individually,
    // advancing to the in-order successor before the node is unlinked/freed.
    moho::DecalGroupLookupNode* cursor = first;
    while (cursor != last) {
      moho::DecalGroupLookupNode* const doomed = cursor;
      cursor = AdvanceLookupNodeToInOrderSuccessor(cursor);
      // Unique-key map: erasing the specific node equals erasing by its key.
      const std::int32_t doomedKey = static_cast<std::int32_t>(doomed->mKey);
      (void)EraseLookupEntriesByKey(tree, &doomedKey);
    }

    return last;
  }

  /**
   * Address: 0x00878D30 (FUN_00878D30)
   *
   * What it does:
   * Releases one keyed lookup tree (`+0x1C` lane): clears every node via the
   * `_Tree::erase` range emission (which keeps and re-links the sentinel),
   * deletes the now-empty sentinel, and resets the header to
   * `{head=null,count=0}`.
   */
  std::int32_t ResetDecalLookupTreePrimary(moho::DecalGroupLookupTree& lookupTree)
  {
    if (lookupTree.mHead != nullptr) {
      (void)ClearDecalLookupTree(lookupTree, lookupTree.mHead->mLeft, lookupTree.mHead);
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
   * Releases one keyed lookup tree (`+0x38` lane): clears every node via the
   * `_Tree::erase` range emission (which keeps and re-links the sentinel),
   * deletes the now-empty sentinel, and resets the header to
   * `{head=null,count=0}`. The secondary tree shares the unified
   * `ClearDecalLookupTree` helper with the primary lane (the binary emits a
   * per-map instantiation, sub_87A080, folded here onto the generic body).
   */
  std::int32_t ResetDecalLookupTreeSecondary(moho::DecalGroupLookupTree& lookupTree)
  {
    if (lookupTree.mHead != nullptr) {
      (void)ClearDecalLookupTree(lookupTree, lookupTree.mHead->mLeft, lookupTree.mHead);
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
    , mLodThresholds{}
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
   * Address: 0x00878D90 (FUN_00878D90, Moho::CDecalManager::operator new)
   * Mangled: ??2CDecalManager@Moho@@QAE@@Z
   *
   * IDA signature:
   * Moho::CDecalManager *__cdecl Moho::CDecalManager::operator new(Moho::CWldTerrainRes *a1);
   *
   * What it does:
   * Class-static allocating factory. Requests 0x114 bytes (== sizeof(CDecalManager))
   * from the global throwing operator new; if the block is null returns nullptr,
   * otherwise placement-constructs a CDecalManager owning `terrainRes` and returns
   * it. The placement-new form re-emits the matching operator delete on ctor throw,
   * reproducing the binary's SEH cleanup funclet.
   */
  CDecalManager* CDecalManager::Create(IWldTerrainRes* const terrainRes)
  {
    void* const storage = ::operator new(0x114u);
    if (storage == nullptr) {
      return nullptr;
    }

    return new (storage) CDecalManager(terrainRes);
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
    for (CWldTerrainDecal* const decal : mDecals) {
      delete decal;
    }

    for (CDecalGroup* const group : mDecalGroups) {
      delete group;
    }

    for (CWldSplat* const splat : mSplats) {
      delete splat;
    }

    AsDecalManagerSpatialDbRuntime(this)->DestroyStorage();

    // Each `= {}` is VC8's `_Tidy()`: free the block and null the three lanes.
    // The binary interleaves them with the two lookup-tree teardowns in this
    // exact order.
    mSplats = {};
    (void)ResetDecalLookupTreeSecondary(mDecalGroupLookupBySplatIndex);

    mDecalGroups = {};
    (void)ResetDecalLookupTreePrimary(mDecalGroupLookupByDecalIndex);

    mDecals = {};
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

    for (CDecalGroup* const group : mDecalGroups) {
      if (group != nullptr) {
        group->RemoveFromGroup(decal->mIndex);
      }
    }

    auto* const found = std::find(mDecals.begin(), mDecals.end(), decal);
    if (found == mDecals.end()) {
      return;
    }

    CWldTerrainDecal* const removedDecal = *found;
    (void)mDecals.erase(found);

    delete removedDecal;

    for (auto* decalIt = mDecals.begin(); decalIt != mDecals.end(); ++decalIt) {
      CWldTerrainDecal* const activeDecal = *decalIt;
      if (activeDecal != nullptr) {
        activeDecal->mVecIndex = static_cast<std::uint32_t>(decalIt - mDecals.begin());
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
   * Address: 0x00878650 (FUN_00878650, Moho::CDecalManager::AddDecals)
   * Slot: 22 (`??_7CDecalManager@Moho@@6B@` + 0x58)
   *
   * IDA signature:
   * std::vector *__thiscall Moho::CDecalManager::Func20(Moho::CDecalManager *this, std::vector *a2);
   *
   * What it does:
   * Materializes one sync packet's worth of sim-authored decals. A splat record
   * gets a fresh `CWldSplat` and is always albedo; any other record resolves its
   * type name against `CWldTerrainDecal::sTypeDesc` first and is dropped (with a
   * warning) when the name is unknown, or silently when it resolves to the
   * undefined slot. Both paths copy the transform, refresh the decal, apply the
   * resolved texture names, carry the handle / fade deadline / army / fidelity
   * lanes across, and settle the cutoff LOD - taking the record's when it is
   * positive and asking the decal to compute one otherwise.
   */
  void CDecalManager::AddDecals(const msvc8::vector<SDecalInfo>& decals)
  {
    for (const SDecalInfo* record = decals.begin(); record != decals.end(); ++record) {
      const bool isSplat = record->mIsSplat != 0u;

      // Both name lanes are resolved up front, exactly as the binary does, so a
      // record dropped by the type lookup below still pays for the expansion.
      const msvc8::string resolvedNames[2] = {
        ResolveDecalTexturePath(record->mTexName1, isSplat),
        ResolveDecalTexturePath(record->mTexName2, isSplat),
      };

      CWldTerrainDecal* decal = nullptr;
      if (isSplat) {
        decal = NewSplat();
        ApplyDecalRecordTransform(*decal, *record);
        decal->Update();
        decal->mType = WldTerrainDecalType_Albedo;
        decal->SetName(resolvedNames[0], 0);
      } else {
        const EWldTerrainDecalType type = CWldTerrainDecal::LookupDecalType(record->mType);
        if (type == WldTerrainDecalType_Undefined) {
          continue;
        }

        decal = LoadDecal(nullptr);
        ApplyDecalRecordTransform(*decal, *record);
        decal->Update();
        decal->mType = type;
        for (int slot = 0; slot < 2; ++slot) {
          if (!resolvedNames[slot].empty()) {
            decal->SetName(resolvedNames[slot], slot);
          }
        }
      }

      decal->mRuntimeHandle = static_cast<std::int32_t>(record->mObj);
      decal->mRemoveTick = static_cast<std::int32_t>(record->mStartTick);
      decal->mArmy = static_cast<std::int32_t>(record->mArmy);
      decal->mFidelity = static_cast<std::int32_t>(record->mFidelity);

      // A record that carries its own cutoff wins; otherwise the decal works one
      // out from its own footprint. Either way the spatial-db dissolve key is
      // rekeyed, which is what `SetCutoffLOD` exists for.
      decal->SetCutoffLOD(record->mLODParam > 0.0f ? record->mLODParam : decal->ComputeCutoffLOD(-1.0f));
    }
  }

  /**
   * Address: 0x00878A40 (FUN_00878A40, Moho::CDecalManager::RemoveDecals)
   * Slot: 23 (`??_7CDecalManager@Moho@@6B@` + 0x5C)
   *
   * What it does:
   * Scans all active decals for each requested runtime handle and marks
   * matching decals for deferred removal.
   */
  void CDecalManager::RemoveDecals(const msvc8::vector<std::int32_t>& decalHandles)
  {
    for (const std::int32_t handle : decalHandles) {
      for (CWldTerrainDecal* const decal : mDecals) {
        if (decal->mRuntimeHandle == handle) {
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
    for (auto* decalIt = mDecals.begin(); decalIt != mDecals.end(); ++decalIt) {
      CWldTerrainDecal* const decal = *decalIt;
      decal->mVecIndex = static_cast<std::uint32_t>(decalIt - mDecals.begin());
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
    auto* found = std::find(mDecals.begin(), mDecals.end(), decal);
    if (found == mDecals.end()) {
      return;
    }

    // Shift [begin, found) right by one and drop `decal` at the front.
    std::rotate(mDecals.begin(), found, found + 1);
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
    auto* const found = std::find(mDecals.begin(), mDecals.end(), decal);
    if (found == mDecals.end()) {
      return;
    }

    auto* const next = found + 1;
    if (next != mDecals.end()) {
      std::iter_swap(found, next);
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
    auto* const found = std::find(mDecals.begin(), mDecals.end(), decal);
    if (found != mDecals.end() && found != mDecals.begin()) {
      std::iter_swap(found, found - 1);
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
   * Address: 0x0087A830 (FUN_0087A830, msvc8::vector<Moho::CWldTerrainDecal*>::_Insert_n)
   *
   * IDA signature:
   * char *__userpurge sub_87A830@<eax>(int *value@<eax>, int vec, char *pos);
   *
   * What it does:
   * Engine-instantiated body of `msvc8::vector<Moho::CWldTerrainDecal*>::_Insert_n`.
   * Inserts `insertCount` copies of `fillValue` at `insertPosition`; on sufficient
   * capacity shifts the live tail right by `insertCount` and fills the gap, else
   * 1.5x-grows the buffer (head-move / gap-fill / tail-move / free-old). Backs the
   * `push_back(decal)` slow-path append used by CDecalManager::LoadDecal / NewSplat
   * for the mDecals vector; the body lives in `msvc8::vector<T>::insert`
   * (legacy/containers/Vector.h) and this per-T free helper is the source-level
   * by-name invocation that keeps the emitted symbol.
   */
  void InsertNCopiesCWldTerrainDecalPtrVector(
    msvc8::vector<CWldTerrainDecal*>& storage,
    CWldTerrainDecal** const insertPosition,
    const unsigned int insertCount,
    CWldTerrainDecal* const fillValue)
  {
    if (insertCount == 0u) {
      return;
    }

    const auto offset = static_cast<std::size_t>(insertPosition - storage.begin());
    storage.insert(storage.begin() + offset, static_cast<std::size_t>(insertCount), fillValue);
  }

  /**
   * Address: 0x008780A0 (Moho::CDecalManager decal-append lane, inlined push_back in LoadDecal/NewSplat)
   * Address: 0x00879070 (FUN_00879070, std::vector<Moho::CWldTerrainDecal*>::push_back
   * — identical check-capacity/grow-or-append shape, a separate per-call-site
   * emission of the same operation; reached from CDecalManager::AddSplat's
   * `AppendDecal(mDecals, decal)` call in this file)
   *
   * What it does:
   * Appends one `CWldTerrainDecal*` into the manager's `mDecals` vector, mirroring
   * the MSVC8 inlined `push_back` shape used by the binary: when the reserved
   * capacity is exhausted the append reaches the canonical
   * `vector<CWldTerrainDecal*>::_Insert_n` slow-path
   * (`InsertNCopiesCWldTerrainDecalPtrVector`, FUN_0087A830); otherwise a fast-path
   * in-place store.
   */
  void AppendDecal(msvc8::vector<CWldTerrainDecal*>& storage, CWldTerrainDecal* const value)
  {
    if (storage.size() == storage.capacity()) {
      InsertNCopiesCWldTerrainDecalPtrVector(storage, storage.end(), 1u, value);
    } else {
      storage.push_back(value);
    }
  }

  /**
   * Address: 0x0087B1C0 (FUN_0087B1C0, msvc8::vector<Moho::CDecalGroup*>::_Insert_n)
   *
   * What it does:
   * Canonical `_Insert_n` slow-path for the mDecalGroups vector; the body lives
   * in `msvc8::vector<T>::insert` (legacy/containers/Vector.h) and this per-T
   * free helper is the source-level by-name invocation that keeps the emitted
   * symbol.
   */
  void InsertNCopiesCDecalGroupPtrVector(
    msvc8::vector<CDecalGroup*>& storage,
    CDecalGroup** const insertPosition,
    const unsigned int insertCount,
    CDecalGroup* const fillValue)
  {
    if (insertCount == 0u) {
      return;
    }

    const auto offset = static_cast<std::size_t>(insertPosition - storage.begin());
    storage.insert(storage.begin() + offset, static_cast<std::size_t>(insertCount), fillValue);
  }

  /**
   * What it does:
   * Appends one `CDecalGroup*` into the manager's `mDecalGroups` vector,
   * mirroring the MSVC8 inlined `push_back` shape used by the binary: when the
   * reserved capacity is exhausted the append reaches the canonical
   * `vector<CDecalGroup*>::_Insert_n` slow-path
   * (`InsertNCopiesCDecalGroupPtrVector`); otherwise a fast-path in-place store.
   */
  void AppendDecalGroup(msvc8::vector<CDecalGroup*>& storage, CDecalGroup* const value)
  {
    if (storage.size() == storage.capacity()) {
      InsertNCopiesCDecalGroupPtrVector(storage, storage.end(), 1u, value);
    } else {
      storage.push_back(value);
    }
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

    loaded->mVecIndex = static_cast<std::uint32_t>(mDecals.size());

    AppendDecal(mDecals, loaded);

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

    auto* const found = std::find(mDecalGroups.begin(), mDecalGroups.end(), group);
    if (found != mDecalGroups.end()) {
      (void)mDecalGroups.erase(found);
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
    auto* const found = std::find(mDecals.begin(), mDecals.end(), decal);
    if (found == mDecals.end()) {
      return;
    }

    (void)mDecals.erase(found);
    AppendDecal(mDecals, decal);
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
    auto* decalIt = mDecals.begin();
    while (decalIt != mDecals.end()) {
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

    auto* splatIt = mSplats.begin();
    while (splatIt != mSplats.end()) {
      CWldSplat* const splat = *splatIt;
      if (splat != nullptr && splat->mRemoveTick > 0 && tick > splat->mRemoveTick) {
        splat->mCurrentAlpha = MoveAlphaTowardZero(splat->mCurrentAlpha, 0.03f);
        if (splat->mCurrentAlpha == 0.0f) {
          delete splat;
          splatIt = mSplats.erase(splatIt);
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
   * Address: 0x00878CB0 (FUN_00878CB0, Moho::CDecalManager::Func26)
   *
   * What it does: see the header - plain field read, no side effects.
   */
  bool CDecalManager::HasPendingChanges() const
  {
    return mDidSomething != 0;
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
   * Address: 0x0087BB40 (FUN_0087BB40, msvc8::vector<Moho::CWldSplat*>::_Insert_n)
   *
   * IDA signature:
   * char *__userpurge sub_87BB40@<eax>(int *value@<eax>, int vec, char *pos);
   *
   * What it does:
   * Engine-instantiated body of `msvc8::vector<Moho::CWldSplat*>::_Insert_n`.
   * Inserts `insertCount` copies of `fillValue` at `insertPosition`; on sufficient
   * capacity shifts the live tail right by `insertCount` and fills the gap, else
   * 1.5x-grows the buffer (head-move / gap-fill / tail-move / free-old). Backs the
   * `push_back(splat)` slow-path append used by CDecalManager::NewSplat for the
   * mSplats vector; the body lives in `msvc8::vector<T>::insert`
   * (legacy/containers/Vector.h) and this per-T free helper is the source-level
   * by-name invocation that keeps the emitted symbol. Byte-identical to the
   * mDecals sibling FUN_0087A830 (both 4-byte pointer instantiations).
   */
  void InsertNCopiesCWldSplatPtrVector(
    msvc8::vector<CWldSplat*>& storage,
    CWldSplat** const insertPosition,
    const unsigned int insertCount,
    CWldSplat* const fillValue)
  {
    if (insertCount == 0u) {
      return;
    }

    const auto offset = static_cast<std::size_t>(insertPosition - storage.begin());
    storage.insert(storage.begin() + offset, static_cast<std::size_t>(insertCount), fillValue);
  }

  /**
   * Address: 0x00878190 (Moho::CDecalManager splat-append lane, inlined push_back in NewSplat)
   *
   * What it does:
   * Appends one `CWldSplat*` into the manager's `mSplats` vector, mirroring the
   * MSVC8 inlined `push_back` shape used by the binary: when the reserved capacity
   * is exhausted the append reaches the canonical
   * `vector<CWldSplat*>::_Insert_n` slow-path
   * (`InsertNCopiesCWldSplatPtrVector`, FUN_0087BB40); otherwise a fast-path
   * in-place store.
   */
  void AppendSplat(msvc8::vector<CWldSplat*>& storage, CWldSplat* const value)
  {
    if (storage.size() == storage.capacity()) {
      InsertNCopiesCWldSplatPtrVector(storage, storage.end(), 1u, value);
    } else {
      storage.push_back(value);
    }
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
    AppendSplat(mSplats, splat);
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

    std::uint32_t activeDecalCount = 0u;
    for (CWldTerrainDecal* const decal : mDecals) {
      if (decal != nullptr && decal->mUnknownA0 == 0u) {
        ++activeDecalCount;
      }
    }
    writer.Write(activeDecalCount);

    for (CWldTerrainDecal* const decal : mDecals) {
      if (decal != nullptr && decal->mUnknownA0 == 0u) {
        decal->DecalSave(writer);
      }
    }

    writer.Write(static_cast<std::uint32_t>(mDecalGroups.size()));

    for (CDecalGroup* const group : mDecalGroups) {
      if (group != nullptr) {
        group->WriteToStream(writer);
      }
    }
  }

  /**
   * Address: 0x008782D0 (FUN_008782D0, Moho::CDecalManager::LoadDecalGroup)
   *
   * What it does:
   * Get-or-create decal group: when `group` is null, allocates a new
   * CDecalGroup(mNumDecals++) and assigns it a default "Group_<index>" name;
   * then appends the group to mDecalGroups and registers its index in the
   * splat-index lookup lane. Returns the group.
   */
  CDecalGroup* CDecalManager::LoadDecalGroup(CDecalGroup* group)
  {
    if (group == nullptr) {
      group = new CDecalGroup(static_cast<std::int32_t>(mNumDecals));
      ++mNumDecals;

      char nameBuffer[32];
      (void)std::snprintf(nameBuffer, sizeof(nameBuffer), "Group_%d", *group->GetIndex());
      *group->GetName() = nameBuffer;
    }

    AppendDecalGroup(mDecalGroups, group);

    std::uint32_t* const valueLane =
      ResolveLookupValueSlotForKey(mDecalGroupLookupBySplatIndex, static_cast<std::uint32_t>(*group->GetIndex()));
    if (valueLane != nullptr) {
      *valueLane = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(group));
    }

    return group;
  }

  /**
   * Address: 0x00877730 (FUN_00877730, Moho::CDecalManager::RebuildLodHistogram)
   *
   * What it does:
   * Rebuilds the decal-area decile LOD histogram (mLodThresholds[0..9]) from the
   * scale-area (mScale.z * mScale.x) of every decal. Zeroes the array, then walks
   * every decal collecting the DISTINCT areas (a set dedups; the vector keeps
   * them in first-seen order). On a non-empty distinct set, sets [0]=0 and, for i
   * in 1..9, nth-selects the decile element at index floor(count * i * 0.1) and
   * stores it at [i].
   */
  void CDecalManager::RebuildLodHistogram()
  {
    for (float& threshold : mLodThresholds) {
      threshold = 0.0f;
    }

    if (mDecals.empty()) {
      return;
    }

    // The binary keeps a std::set<float> purely for dedup and a std::vector<float>
    // of the distinct areas in first-seen order; a decal's area is stored only the
    // first time it is seen (insert reports "no existing equal element").
    //
    // Address: 0x0087D510 (FUN_0087D510, the MSVC8 `_Tree_val<...>::_Alloc::
    // allocate` emission for this set's 0x14-byte node: `max_size` folds to
    // `0xFFFFFFFF / 0x14 = 0xCCCCCCC`, and an over-large request throws
    // `std::bad_alloc` through `_CxxThrowException` before falling through to
    // `operator new(count*0x14)`.) This std::set<float> local is what
    // instantiates it; two sibling `_Buynode` node-initializers share the
    // same allocator call: 0x0087C990 (the no-argument overload used once,
    // when this local is default-constructed, to build the empty tree's
    // self-linked sentinel: `{left=parent=right=0, color=1, isnil=0}`, later
    // self-linked by the tree ctor) and 0x0087C060 (the value-carrying
    // overload used by `seenAreas.insert(area)` below to buy each real node:
    // `{left, parent, right = the three link args, value = *area, color =
    // 0}`). Both are plain MSVC8 `std::set<float>` template emissions with no
    // CDecalManager-specific behavior of their own.
    std::set<float> seenAreas;
    std::vector<float> distinctAreas;

    for (CWldTerrainDecal* const decal : mDecals) {
      const float area = decal->mScale.z * decal->mScale.x;
      if (seenAreas.insert(area).second) {
        distinctAreas.push_back(area);
      }
    }

    if (distinctAreas.empty()) {
      return;
    }

    const std::size_t count = distinctAreas.size();
    mLodThresholds[0] = 0.0f;
    for (int decile = 1; decile < 10; ++decile) {
      const std::size_t index =
        static_cast<std::size_t>(static_cast<float>(count) * (static_cast<float>(decile) * 0.1f));
      // Addresses 0x0087D750/0x0087DC80/0x0087E390 are this std::nth_element's
      // own MSVC8 STL-internal partition/median-of-3/insertion-sort trio for
      // the float distinctAreas element -- already reproduced by this call.
      std::nth_element(distinctAreas.begin(), distinctAreas.begin() + index, distinctAreas.end());
      mLodThresholds[decile] = distinctAreas[index];
    }
  }

  /**
   * Address: 0x00877CB0 (FUN_00877CB0, Moho::CDecalManager::Func1)
   *
   * What it does:
   * Reads one entry out of the decal-area decile histogram RebuildLodHistogram
   * fills in, clamping the index to the ten entries the table actually holds.
   */
  float CDecalManager::GetLodThreshold(const std::int32_t lodIndex) const
  {
    constexpr std::int32_t kLastLodIndex = 9;
    const std::int32_t clamped = std::clamp(lodIndex, 0, kLastLodIndex);
    return mLodThresholds[clamped];
  }

  /**
   * Address: 0x00877CD0 (FUN_00877CD0, Moho::CDecalManager::Load)
   *
   * What it does:
   * Inverse of Save: reads mDecalCount/mNumDecals, then a decal count with each
   * decal deserialized (new CWldTerrainDecal + DecalLoad + LoadDecal); then a
   * group count with each group deserialized (new CDecalGroup + ReadFromStream +
   * LoadDecalGroup); reindexes every decal's mVecIndex, then rebuilds the LOD
   * histogram.
   */
  void CDecalManager::Load(gpg::BinaryReader& reader, const unsigned int version)
  {
    reader.Read(reinterpret_cast<char*>(&mDecalCount), sizeof(mDecalCount));
    reader.Read(reinterpret_cast<char*>(&mNumDecals), sizeof(mNumDecals));

    std::uint32_t decalCount = 0;
    reader.Read(reinterpret_cast<char*>(&decalCount), sizeof(decalCount));
    for (; decalCount != 0u; --decalCount) {
      auto* const decal = new CWldTerrainDecal(AsDecalManagerSpatialDbRuntime(this), mWldTerrain);
      decal->DecalLoad(reader);
      (void)LoadDecal(decal);
    }

    std::uint32_t groupCount = 0;
    reader.Read(reinterpret_cast<char*>(&groupCount), sizeof(groupCount));
    for (; groupCount != 0u; --groupCount) {
      auto* const group = new CDecalGroup(0);
      group->ReadFromStream(reader, static_cast<int>(version));
      (void)LoadDecalGroup(group);
    }

    Reindex();

    RebuildLodHistogram();
  }

} // namespace moho
