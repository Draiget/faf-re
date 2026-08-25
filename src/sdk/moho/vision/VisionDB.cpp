#include "moho/vision/VisionDB.h"

#include <cmath>
#include <stdexcept>

#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "Wm3IntrBox2Circle2.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x006610E0 (FUN_006610E0, nullsub_3)
   *
   * What it does:
   * Preserves one legacy list-node callback lane used by VisionDB pool setup/teardown.
   */
  void VisionDbPoolNoOpListCallback(void* /*self*/) {}

  struct VisionDbIntrusiveListNodeRuntime
  {
    VisionDbIntrusiveListNodeRuntime* next; // +0x00
    VisionDbIntrusiveListNodeRuntime* prev; // +0x04
  };

  struct VisionDbIntrusiveListStateRuntime
  {
    std::uint32_t listCookie;              // +0x00
    VisionDbIntrusiveListNodeRuntime* head; // +0x04
    std::uint32_t size;                    // +0x08
  };

  static_assert(
    sizeof(VisionDbIntrusiveListStateRuntime) == 0x0C,
    "VisionDbIntrusiveListStateRuntime size must be 0x0C"
  );

  /**
   * Address: 0x0081B9C0 (FUN_0081B9C0)
   *
   * What it does:
   * Clears one intrusive list while preserving its sentinel node.
   */
  VisionDbIntrusiveListNodeRuntime* VisionDbClearListNodesKeepingSentinel(
    VisionDbIntrusiveListStateRuntime* const listState
  ) noexcept
  {
    if (listState == nullptr || listState->head == nullptr) {
      return nullptr;
    }

    VisionDbIntrusiveListNodeRuntime* const head = listState->head;
    VisionDbIntrusiveListNodeRuntime* node = head->next;
    head->next = head;
    head->prev = head;
    listState->size = 0;

    while (node != head) {
      VisionDbIntrusiveListNodeRuntime* const next = node->next;
      ::operator delete(node);
      node = next;
    }

    return head;
  }

  /**
   * Address: 0x0081B790 (FUN_0081B790)
   *
   * What it does:
   * Allocates one 12-byte intrusive-list sentinel lane and self-links its
   * `prev/next` pointers.
   */
  [[nodiscard]] VisionDbIntrusiveListNodeRuntime* VisionDbAllocateSelfLinkedListSentinel12()
  {
    auto* const rawNode = static_cast<std::uint8_t*>(gpg::core::legacy::AllocateChecked12ByteLane(1u));
    if (rawNode == nullptr) {
      return nullptr;
    }

    auto* const node = reinterpret_cast<VisionDbIntrusiveListNodeRuntime*>(rawNode);
    node->next = node;
    node->prev = node;
    return node;
  }

  void ResetVisionEntry(
    VisionDB::Pool::Entry* const entry,
    const VisionDB::Pool::EntryCircle& previousCircle,
    const VisionDB::Pool::EntryCircle& currentCircle,
    const bool isReal
  )
  {
    if (entry == nullptr) {
      return;
    }

    entry->mParent = nullptr;
    entry->mContained = nullptr;
    entry->mNext = nullptr;
    entry->mIsReal = isReal ? 1u : 0u;
    entry->mVis = 0u;
    entry->mPad0E = 0u;
    entry->mPrevCircle = previousCircle;
    entry->mCurCircle = currentCircle;
  }

  [[nodiscard]] bool CircleFullyContains(
    const VisionDB::Pool::EntryCircle& outer,
    const VisionDB::Pool::EntryCircle& inner
  ) noexcept
  {
    if (inner.radius > outer.radius) {
      return false;
    }

    const float dx = inner.x - outer.x;
    const float dy = inner.y - outer.y;
    const float radiusDelta = outer.radius - inner.radius;
    return (radiusDelta * radiusDelta) >= ((dx * dx) + (dy * dy));
  }

  [[nodiscard]] bool EntryFullyContains(
    const VisionDB::Pool::PooledNode* const outer,
    const VisionDB::Pool::PooledNode* const inner
  ) noexcept
  {
    if (outer == nullptr || inner == nullptr) {
      return false;
    }

    return CircleFullyContains(outer->mPrevCircle, inner->mPrevCircle)
      && CircleFullyContains(outer->mCurCircle, inner->mCurCircle);
  }

  void EntryAddToChain(VisionDB::Pool::PooledNode* chain, VisionDB::Pool::PooledNode* append) noexcept
  {
    if (chain == nullptr || append == nullptr) {
      return;
    }

    while (chain->mNext != nullptr) {
      chain = chain->mNext;
    }

    chain->mNext = append;
    append->mParent = chain->mParent;
  }

  void EntryRemoveFromChain(VisionDB::Pool::PooledNode* const root, VisionDB::Pool::PooledNode* const entry) noexcept
  {
    if (root == nullptr || entry == nullptr) {
      return;
    }

    VisionDB::Pool::PooledNode* result = root->mContained;
    if (result == entry) {
      result = result->mNext;
      root->mContained = result;
    } else if (result != nullptr) {
      while (result->mNext != nullptr && result->mNext != entry) {
        result = result->mNext;
      }
      if (result->mNext == entry) {
        result->mNext = result->mNext->mNext;
      }
    }

    VisionDB::Pool::PooledNode* const children = entry->mContained;
    if (children != nullptr) {
      VisionDB::Pool::PooledNode* const rootContained = root->mContained;
      if (rootContained != nullptr) {
        if (rootContained->mNext != nullptr) {
          EntryAddToChain(rootContained->mNext, children);
        } else {
          rootContained->mNext = children;
          children->mParent = rootContained->mParent;
        }
      } else {
        root->mContained = children;
        children->mParent = root;
      }

      for (VisionDB::Pool::PooledNode* child = children; child != nullptr; child = child->mNext) {
        child->mParent = root;
      }
    }

    entry->mParent = nullptr;
    entry->mContained = nullptr;
    entry->mNext = nullptr;
  }

  /**
   * Address: 0x0081B310 (FUN_0081B310, Moho::VisionDB::Entry::PutInChain)
   *
   * What it does:
   * Descends into the deepest containing child for `entry` and links it into
   * that owner's contained-chain.
   */
  void EntryPutInChain(VisionDB::Pool::PooledNode* entry, VisionDB::Pool::PooledNode* root) noexcept
  {
    if (entry == nullptr || root == nullptr) {
      return;
    }

    while (EntryFullyContains(root, entry)) {
      VisionDB::Pool::PooledNode* containingChild = nullptr;
      for (VisionDB::Pool::PooledNode* child = root->mContained; child != nullptr; child = child->mNext) {
        if (EntryFullyContains(child, entry)) {
          containingChild = child;
          break;
        }
      }

      if (containingChild == nullptr) {
        break;
      }
      root = containingChild;
    }

    if (VisionDB::Pool::PooledNode* const contained = root->mContained; contained != nullptr) {
      if (contained->mNext != nullptr) {
        EntryAddToChain(contained->mNext, entry);
      } else {
        contained->mNext = entry;
        entry->mParent = contained->mParent;
      }
    } else {
      root->mContained = entry;
      entry->mParent = root;
    }
  }
} // namespace

/**
 * Address: 0x0081ACA0 (FUN_0081ACA0)
 * Mangled: ??0Pool@VisionDB@Moho@@QAE@@Z
 *
 * What it does:
 * Allocates and self-links zone/free-node list sentinels.
 */
VisionDB::Pool::Pool()
{
  mEntriesHead = reinterpret_cast<ZoneBlockEntry*>(VisionDbAllocateSelfLinkedListSentinel12());
  if (mEntriesHead != nullptr) {
    mEntriesHead->blockBase = nullptr;
  }
  mEntriesSize = 0;

  mEntryPoolHead = reinterpret_cast<FreeNodeEntry*>(VisionDbAllocateSelfLinkedListSentinel12());
  if (mEntryPoolHead != nullptr) {
    mEntryPoolHead->node = nullptr;
  }
  mEntryPoolSize = 0;
}

/**
 * Address: 0x0081AD20 (FUN_0081AD20)
 * Address: 0x103E3CA0
 *
 * What it does:
 * Releases pooled-node blocks, clears both intrusive lists, and frees sentinels.
 */
void VisionDB::Pool::Clear()
{
  VisionDbPoolNoOpListCallback(this);
  FreeZoneBlocks(mEntriesHead);

  if (mEntryPoolHead != nullptr) {
    auto* const entryPoolState = reinterpret_cast<VisionDbIntrusiveListStateRuntime*>(&mEntryPoolListState);
    (void)VisionDbClearListNodesKeepingSentinel(entryPoolState);
    ::operator delete(mEntryPoolHead);
    mEntryPoolHead = nullptr;
  }

  if (mEntriesHead != nullptr) {
    auto* const entriesState = reinterpret_cast<VisionDbIntrusiveListStateRuntime*>(&mEntriesListState);
    (void)VisionDbClearListNodesKeepingSentinel(entriesState);
    ::operator delete(mEntriesHead);
    mEntriesHead = nullptr;
  }
}

/**
 * Address: 0x0081AD00 (FUN_0081AD00)
 * Address: 0x103E3C80
 *
 * What it does:
 * Invokes `Clear()` and optionally deletes the object (scalar deleting dtor).
 */
VisionDB::Pool::~Pool()
{
  Clear();
}

/**
 * Address: 0x0081AA00 (FUN_0081AA00)
 *
 * What it does:
 * Obtains one entry from the reusable pool, allocating and seeding a 500-entry
 * block when the free-list is empty.
 */
VisionDB::Pool::Entry*
VisionDB::Pool::NewEntry(const EntryCircle& previousCircle, const EntryCircle& currentCircle, const bool isReal)
{
  VisionDbPoolNoOpListCallback(this);

  if (mEntryPoolSize == 0) {
    constexpr std::uint32_t kEntryBlockCount = 500;
    const std::size_t blockBytes = sizeof(std::uint32_t) + sizeof(Entry) * kEntryBlockCount;
    auto* const rawBlock = static_cast<std::uint8_t*>(::operator new[](blockBytes));
    auto* const entryCountLane = reinterpret_cast<std::uint32_t*>(rawBlock);
    *entryCountLane = kEntryBlockCount;

    auto* const entryBlock = reinterpret_cast<Entry*>(rawBlock + sizeof(std::uint32_t));
    for (std::uint32_t index = 0; index < kEntryBlockCount; ++index) {
      ResetVisionEntry(&entryBlock[index], EntryCircle{}, EntryCircle{}, false);
    }

    auto* const blockNode = new ZoneBlockEntry();
    blockNode->blockBase = entryBlock;
    blockNode->ListLinkBefore(mEntriesHead);
    ++mEntriesSize;

    for (std::uint32_t index = 0; index < kEntryBlockCount; ++index) {
      // Address: 0x0081BA00 (FUN_0081BA00) -- std::list<Entry*>::_Buynode
      // for this pool's free list (IDA's own type inference: `_List_nod_
      // VisionDB_Entry::_Node`), matching FreeNodeEntry's real 12-byte
      // {_Next,_Prev,_Myval=Entry*} layout exactly.
      auto* const freeEntry = new FreeNodeEntry();
      freeEntry->node = &entryBlock[index];
      freeEntry->ListLinkBefore(mEntryPoolHead);
      // Address: 0x0081BA40 (FUN_0081BA40) -- the sibling `_Incsize`,
      // checked against the Dinkumware 0x3FFFFFFF cap and throwing
      // std::length_error("list<T> too long") on overflow.
      if (mEntryPoolSize == 0x3FFFFFFFu) {
        throw std::length_error("list<T> too long");
      }
      ++mEntryPoolSize;
    }
  }

  if (mEntryPoolHead == nullptr || mEntryPoolHead->mNext == mEntryPoolHead) {
    return nullptr;
  }

  auto* const freeEntry = static_cast<FreeNodeEntry*>(mEntryPoolHead->mNext);
  Entry* const entry = freeEntry->node;
  freeEntry->ListUnlink();
  ::operator delete(freeEntry);
  --mEntryPoolSize;

  ResetVisionEntry(entry, previousCircle, currentCircle, isReal);
  return entry;
}

void VisionDB::Pool::FreeZoneBlocks(ZoneBlockEntry* head)
{
  if (!head) {
    return;
  }

  for (ZoneBlockEntry* it = static_cast<ZoneBlockEntry*>(head->mNext); it != head;
       it = static_cast<ZoneBlockEntry*>(it->mNext)) {
    if (!it->blockBase) {
      continue;
    }

    // The block is allocated as: [count dword][count * Entry].
    auto* rawBlock = reinterpret_cast<std::uint32_t*>(it->blockBase) - 1;
    ::operator delete[](rawBlock);
    it->blockBase = nullptr;
  }
}

/**
 * Address: 0x0081AE10 (FUN_0081AE10)
 *
 * What it does:
 * Stores owner and pooled-node pointers for this handle.
 */
VisionDB::Handle*
VisionDB::Handle::Init(Handle* self, const std::uintptr_t pooledNodePtr, const std::uintptr_t ownerPtr)
{
  if (!self) {
    return nullptr;
  }

  self->mDB = ownerPtr;
  self->mNode = pooledNodePtr;
  return self;
}

/**
 * Address: 0x0081A8C0 (FUN_0081A8C0)
 * Address: 0x103E38B0
 *
 * What it does:
 * Appends a sibling chain to the tail of another sibling chain.
 */
void VisionDB::Handle::AttachSiblingChain(Pool::PooledNode* tailChain, Pool::PooledNode* chainHead)
{
  if (!tailChain || !chainHead) {
    return;
  }

  while (tailChain->mNext != nullptr) {
    tailChain = tailChain->mNext;
  }

  tailChain->mNext = chainHead;
  chainHead->mParent = tailChain->mParent;
}

/**
 * Address: 0x0081A8E0 (FUN_0081A8E0)
 * Address: 0x103E38D0
 *
 * What it does:
 * Unlinks a pooled node from its owner chain and reparents children.
 */
void VisionDB::Handle::UnlinkFromOwnerTree(OwnerChainView* ownerChain, Pool::PooledNode* node)
{
  if (!node || !ownerChain) {
    return;
  }

  Pool::PooledNode*& rootSlot = ownerChain->mRoot;
  Pool::PooledNode* cursor = rootSlot;

  if (cursor == node) {
    rootSlot = cursor->mNext;
  } else if (cursor) {
    while (cursor->mNext) {
      if (cursor->mNext == node) {
        cursor->mNext = cursor->mNext->mNext;
        break;
      }
      cursor = cursor->mNext;
    }
  }

  if (node->mContained) {
    Pool::PooledNode* const ownerRoot = rootSlot;
    if (ownerRoot) {
      if (ownerRoot->mNext) {
        AttachSiblingChain(ownerRoot->mNext, node->mContained);
      } else {
        ownerRoot->mNext = node->mContained;
        node->mContained->mParent = ownerRoot->mParent;
      }
    } else {
      rootSlot = node->mContained;
      node->mContained->mParent = ownerChain;
    }

    for (Pool::PooledNode* child = node->mContained; child; child = child->mNext) {
      child->mParent = ownerChain;
    }
  }

  node->mParent = nullptr;
  node->mContained = nullptr;
  node->mNext = nullptr;
}

/**
 * Address: 0x0081ABF0 (FUN_0081ABF0)
 * Address: 0x103E3B70
 *
 * What it does:
 * Clears one pooled node and pushes it back to the pool free-list.
 */
void VisionDB::Handle::ReturnNodeToFreeList(Pool* ownerPool, Pool::PooledNode* node)
{
  if (!node || !ownerPool || !ownerPool->mEntryPoolHead) {
    return;
  }

  ResetVisionEntry(node, Pool::EntryCircle{}, Pool::EntryCircle{}, false);

  auto* const entry = static_cast<Pool::FreeNodeEntry*>(::operator new(sizeof(Pool::FreeNodeEntry)));
  entry->node = node;
  entry->ListLinkBefore(ownerPool->mEntryPoolHead);

  ++ownerPool->mEntryPoolSize;
}

/**
 * Address: 0x0081AE60 (FUN_0081AE60)
 *
 * What it does:
 * Runs the non-deleting handle teardown lane shared by the deleting-dtor
 * wrapper: unlink the pooled node from the owner chain and return it to the
 * owning VisionDB pool.
 */
void VisionDB::Handle::ReleasePooledNodeToOwnerPool()
{
  auto* const owner = reinterpret_cast<VisionDB*>(mDB);
  auto* const pooledNode = reinterpret_cast<Pool::PooledNode*>(mNode);
  auto* const ownerChain = static_cast<OwnerChainView*>(pooledNode->mParent);
  UnlinkFromOwnerTree(ownerChain, pooledNode);
  ReturnNodeToFreeList(&owner->pool_, pooledNode);
}

/**
 * Address: 0x0081AE20 (FUN_0081AE20)
 * Address: 0x103E3DA0
 *
 * What it does:
 * Unlinks the pooled node from its owner chain and returns it to the pool free-list.
 */
VisionDB::Handle::~Handle()
{
  ReleasePooledNodeToOwnerPool();
}

/**
 * Address: 0x0081AE90 (FUN_0081AE90, sub_81AE90)
 *
 * What it does:
 * Initializes one vision DB instance by constructing its pool lane and
 * clearing the root-node pointer.
 */
VisionDB::VisionDB()
  : pool_()
  , rootNode_(nullptr)
{}

namespace
{
  /**
   * Helper used by both `Init` quadtree expansion and `GenerateQuadTree`:
   * appends a freshly-allocated child node to the tail of the parent's
   * `mContained` chain. Mirrors the binary insertion pattern at FUN_0081B080.
   */
  void AppendChildToParent(VisionDB::Pool::PooledNode* const parent, VisionDB::Pool::PooledNode* const child) noexcept
  {
    if (parent->mContained == nullptr) {
      parent->mContained = child;
      child->mParent = parent;
      return;
    }

    VisionDB::Pool::PooledNode* const head = parent->mContained;
    if (head->mNext != nullptr) {
      EntryAddToChain(head->mNext, child);
    } else {
      head->mNext = child;
      child->mParent = head->mParent;
    }
  }
} // namespace

/**
 * Address: 0x0081AF00 (FUN_0081AF00, Moho::VisionDB::Init)
 *
 * What it does:
 * Allocates the root pooled-node entry covering a circle whose center is
 * `(width/2, height/2)` and bounding radius `2*sqrt((width/2)^2 + (height/2)^2)`,
 * stores the root in `rootNode_`, and recursively subdivides the area via
 * `GenerateQuadTree` starting at level 0 with maxLevel 1.
 */
void VisionDB::Init(const float width, const float height)
{
  rootNode_ = nullptr;

  const Wm3::Vector2f halfSize{width * 0.5f, height * 0.5f};
  const float halfDiag = std::sqrt((halfSize.x * halfSize.x) + (halfSize.y * halfSize.y));

  // Root node covers the full area; the binary stores doubled radius.
  Pool::EntryCircle rootCircle{};
  rootCircle.x = halfSize.x;
  rootCircle.y = halfSize.y;
  rootCircle.radius = halfDiag * 2.0f;

  Pool::PooledNode* const rootEntry = pool_.NewEntry(rootCircle, rootCircle, false);
  rootNode_ = rootEntry;

  GenerateQuadTree(rootEntry, halfSize, 0, 1);
}

/**
 * Address: 0x0081B080 (FUN_0081B080, Moho::VisionDB::GenerateQuadTree)
 *
 * What it does:
 * Recursively subdivides `parent` into four quadrant child nodes (NW, SW, NE,
 * SE) when `level < maxLevel`. Each child covers a half-size sub-rectangle
 * centered at the corresponding quadrant offset from the parent's stored
 * circle center, with bounding-circle radius equal to the half-diagonal of
 * the new sub-rectangle. New nodes are linked into the parent's `mContained`
 * chain via `AppendChildToParent`, then recursively subdivided themselves.
 */
void VisionDB::GenerateQuadTree(
  Pool::PooledNode* const parent,
  const Wm3::Vector2f& size,
  const int level,
  const int maxLevel)
{
  if (level >= maxLevel) {
    return;
  }

  const Wm3::Vector2f halfSize{size.x * 0.5f, size.y * 0.5f};
  const float halfDiag = std::sqrt((halfSize.x * halfSize.x) + (halfSize.y * halfSize.y));
  const float parentX = parent->mPrevCircle.x;
  const float parentY = parent->mPrevCircle.y;
  const int nextLevel = level + 1;

  Pool::EntryCircle childCircle{};
  childCircle.radius = halfDiag;

  // NW quadrant: (-halfSize.x, -halfSize.y)
  childCircle.x = parentX - halfSize.x;
  childCircle.y = parentY - halfSize.y;
  Pool::PooledNode* const nw = pool_.NewEntry(childCircle, childCircle, false);
  AppendChildToParent(parent, nw);
  GenerateQuadTree(nw, halfSize, nextLevel, maxLevel);

  // SW quadrant: (-halfSize.x, +halfSize.y)
  childCircle.x = parentX - halfSize.x;
  childCircle.y = parentY + halfSize.y;
  Pool::PooledNode* const sw = pool_.NewEntry(childCircle, childCircle, false);
  AppendChildToParent(parent, sw);
  GenerateQuadTree(sw, halfSize, nextLevel, maxLevel);

  // NE quadrant: (+halfSize.x, -halfSize.y)
  childCircle.x = parentX + halfSize.x;
  childCircle.y = parentY - halfSize.y;
  Pool::PooledNode* const ne = pool_.NewEntry(childCircle, childCircle, false);
  AppendChildToParent(parent, ne);
  GenerateQuadTree(ne, halfSize, nextLevel, maxLevel);

  // SE quadrant: (+halfSize.x, +halfSize.y)
  childCircle.x = parentX + halfSize.x;
  childCircle.y = parentY + halfSize.y;
  Pool::PooledNode* const se = pool_.NewEntry(childCircle, childCircle, false);
  AppendChildToParent(parent, se);
  GenerateQuadTree(se, halfSize, nextLevel, maxLevel);
}

/**
 * Address: 0x0081AFD0 (FUN_0081AFD0, Moho::VisionDB::NewHandle)
 *
 * What it does:
 * Allocates one tracked vision handle using previous/current 2D positions
 * and inserts its pooled node under the root vision entry.
 */
VisionDB::Handle* VisionDB::NewHandle(const Wm3::Vector2f& current, const Wm3::Vector2f& previous)
{
  Pool::EntryCircle prevCircle{};
  prevCircle.x = previous.x;
  prevCircle.y = previous.y;
  prevCircle.radius = 0.0f;

  Pool::EntryCircle curCircle{};
  curCircle.x = current.x;
  curCircle.y = current.y;
  curCircle.radius = 0.0f;

  Pool::PooledNode* const entry = pool_.NewEntry(prevCircle, curCircle, true);
  if (entry == nullptr) {
    return nullptr;
  }

  EntryPutInChain(entry, rootNode_);

  Handle* const handle = new Handle();
  handle->mDB = reinterpret_cast<std::uintptr_t>(this);
  handle->mNode = reinterpret_cast<std::uintptr_t>(entry);
  return handle;
}

/**
 * Address: 0x0081AEB0 (FUN_0081AEB0)
 * Address: 0x103E3E30
 *
 * What it does:
 * Clears the root pointer then tears down `Pool`.
 */
VisionDB::~VisionDB()
{
  rootNode_ = nullptr;
}

/**
 * Address: 0x008B83B0 (FUN_008B83B0, Moho::VisionDB::Handle::Update)
 *
 * What it does:
 * Refreshes this handle's previous/current circles and visibility bit,
 * then reparents into the vision tree when containment no longer holds.
 */
void VisionDB::Handle::Update(
  const Wm3::Vector2f& next,
  const Wm3::Vector2f& previous,
  const float radius,
  const bool visible
)
{
  auto* const node = reinterpret_cast<Pool::PooledNode*>(mNode);
  auto* const db = reinterpret_cast<VisionDB*>(mDB);
  if (node == nullptr || db == nullptr) {
    return;
  }

  node->mVis = visible ? 1u : 0u;
  node->mPrevCircle.x = previous.x;
  node->mPrevCircle.y = previous.y;
  node->mPrevCircle.radius = radius;
  node->mCurCircle.x = next.x;
  node->mCurCircle.y = next.y;
  node->mCurCircle.radius = radius;

  auto* const parent = reinterpret_cast<Pool::PooledNode*>(node->mParent);
  if (parent == nullptr || EntryFullyContains(parent, node)) {
    return;
  }

  EntryRemoveFromChain(parent, node);
  EntryPutInChain(node, db->rootNode_);
}

/**
 * Address: 0x0081B490 (FUN_0081B490, Moho::VisionDB::Entry::TryAdd)
 *
 * IDA signature:
 * void __stdcall Moho::VisionDB::struct1::TryAdd(gpg::fastvector_Circle2f *accum,
 *         Moho::VisionDB::Entry *a2, const Wm3::Box3f *box, float amt);
 *
 * What it does:
 * Interpolates one vision entry's circle between its previous and current
 * samples, tests the result against the query box, and either accumulates the
 * circle (real + visible leaf) or walks the entry's contained sibling chain.
 *
 * Field displacements taken from the shipped body:
 *   +0x04 mContained (0x0081B585), +0x08 mNext (0x0081B5A2),
 *   +0x0C mIsReal (0x0081B546),    +0x0D mVis (0x0081B54C),
 *   +0x10/+0x14/+0x18 mPrevCircle  (0x0081B4BC/0x0081B4C1/0x0081B4ED),
 *   +0x1C/+0x20/+0x24 mCurCircle   (0x0081B4C6/0x0081B4CB/0x0081B4DC).
 */
void VisionDB::TryAdd(
  gpg::fastvector<Wm3::Circle2f>& accumulator,
  Pool::Entry* const entry,
  const Wm3::Box2f& box,
  const float interpolant
) const
{
  const Pool::EntryCircle& previous = entry->mPrevCircle;
  const Pool::EntryCircle& current = entry->mCurCircle;

  const Wm3::Circle2f sampled{
    Wm3::Vector2f{
      previous.x + ((current.x - previous.x) * interpolant),
      previous.y + ((current.y - previous.y) * interpolant)
    },
    ((current.radius - previous.radius) * interpolant) + previous.radius
  };

  // `Wm3::IntrBox2Circle2f` keeps references to both operands, so `box` and
  // `sampled` must outlive it - matching the two stack temporaries the binary
  // builds at 0x0081B4F2/0x0081B504 before the ctor call at 0x0081B52C.
  Wm3::IntrBox2Circle2f overlap{box, sampled};
  if (!overlap.Test()) {
    return;
  }

  if (entry->mIsReal != 0u && entry->mVis != 0u) {
    accumulator.push_back(sampled);
    return;
  }

  for (Pool::Entry* child = entry->mContained; child != nullptr; child = child->mNext) {
    TryAdd(accumulator, child, box, interpolant);
  }
}
