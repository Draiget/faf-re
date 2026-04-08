#include "moho/vision/VisionDB.h"

using namespace moho;

namespace
{
  template <class Entry>
  void ClearRingAndDeleteHead(Entry*& head, std::uint32_t& count) noexcept
  {
    if (!head) {
      return;
    }

    Entry* node = static_cast<Entry*>(head->mNext);
    head->mNext = head;
    head->mPrev = head;
    count = 0;

    while (node != head) {
      Entry* next = static_cast<Entry*>(node->mNext);
      ::operator delete(node);
      node = next;
    }

    ::operator delete(head);
    head = nullptr;
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
  mEntriesHead = new ZoneBlockEntry();
  mEntriesSize = 0;

  mEntryPoolHead = new FreeNodeEntry();
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
  FreeZoneBlocks(mEntriesHead);

  ClearRingAndDeleteHead(mEntryPoolHead, mEntryPoolSize);
  ClearRingAndDeleteHead(mEntriesHead, mEntriesSize);
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
      auto* const freeEntry = new FreeNodeEntry();
      freeEntry->node = &entryBlock[index];
      freeEntry->ListLinkBefore(mEntryPoolHead);
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
 * Address: 0x0081AE20 (FUN_0081AE20)
 * Address: 0x103E3DA0
 *
 * What it does:
 * Unlinks the pooled node from its owner chain and returns it to the pool free-list.
 */
VisionDB::Handle::~Handle()
{
  auto* const pooledNode = reinterpret_cast<Pool::PooledNode*>(mNode);
  auto* const owner = reinterpret_cast<VisionDB*>(mDB);
  if (pooledNode && owner) {
    auto* const ownerChain = static_cast<OwnerChainView*>(pooledNode->mParent);
    UnlinkFromOwnerTree(ownerChain, pooledNode);
    ReturnNodeToFreeList(&owner->pool_, pooledNode);
  }

  mDB = 0;
  mNode = 0;
}

VisionDB::VisionDB()
  : pool_()
  , rootNode_(nullptr)
{}

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
