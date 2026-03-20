// Auto-generated from IDA VFTABLE/RTTI scan.
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
  zoneBlocksHead_ = new ZoneBlockEntry();
  zoneBlockCount_ = 0;

  freeNodeHead_ = new FreeNodeEntry();
  freeNodeCount_ = 0;
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
  FreeZoneBlocks(zoneBlocksHead_);

  ClearRingAndDeleteHead(freeNodeHead_, freeNodeCount_);
  ClearRingAndDeleteHead(zoneBlocksHead_, zoneBlockCount_);
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

    // The block is allocated via operator new as: [count dword][count * PooledNode].
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

  self->ownerPtr_ = ownerPtr;
  self->pooledNodePtr_ = pooledNodePtr;
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

  while (tailChain->nextSibling != nullptr) {
    tailChain = tailChain->nextSibling;
  }

  tailChain->nextSibling = chainHead;
  chainHead->ownerOrChain = tailChain->ownerOrChain;
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

  Pool::PooledNode*& rootSlot = ownerChain->rootNode;
  Pool::PooledNode* cursor = rootSlot;

  if (cursor == node) {
    rootSlot = cursor->nextSibling;
  } else if (cursor) {
    while (cursor->nextSibling) {
      if (cursor->nextSibling == node) {
        cursor->nextSibling = cursor->nextSibling->nextSibling;
        break;
      }
      cursor = cursor->nextSibling;
    }
  }

  if (node->firstChild) {
    Pool::PooledNode* const ownerRoot = rootSlot;
    if (ownerRoot) {
      if (ownerRoot->nextSibling) {
        AttachSiblingChain(ownerRoot->nextSibling, node->firstChild);
      } else {
        ownerRoot->nextSibling = node->firstChild;
        node->firstChild->ownerOrChain = ownerRoot->ownerOrChain;
      }
    } else {
      rootSlot = node->firstChild;
      node->firstChild->ownerOrChain = ownerChain;
    }

    for (Pool::PooledNode* child = node->firstChild; child; child = child->nextSibling) {
      child->ownerOrChain = ownerChain;
    }
  }

  node->ownerOrChain = nullptr;
  node->firstChild = nullptr;
  node->nextSibling = nullptr;
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
  if (!node || !ownerPool || !ownerPool->freeNodeHead_) {
    return;
  }

  node->ownerOrChain = nullptr;
  node->firstChild = nullptr;
  node->nextSibling = nullptr;
  node->typeFlag = 0;
  node->markFlag = 0;

  auto* const entry = static_cast<Pool::FreeNodeEntry*>(::operator new(sizeof(Pool::FreeNodeEntry)));
  entry->node = node;
  entry->ListLinkBefore(ownerPool->freeNodeHead_);

  ++ownerPool->freeNodeCount_;
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
  auto* const pooledNode = reinterpret_cast<Pool::PooledNode*>(pooledNodePtr_);
  auto* const owner = reinterpret_cast<VisionDB*>(ownerPtr_);
  if (pooledNode && owner) {
    auto* const ownerChain = static_cast<OwnerChainView*>(pooledNode->ownerOrChain);
    UnlinkFromOwnerTree(ownerChain, pooledNode);
    ReturnNodeToFreeList(&owner->pool_, pooledNode);
  }

  ownerPtr_ = 0;
  pooledNodePtr_ = 0;
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
