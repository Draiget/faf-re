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
   * Address: 0x0077CD00 (FUN_0077CD00)
   *
   * What it does:
   * Allocates one decal-bucket RB-tree node lane with null links/payload and
   * default marker bytes (`color=black`, `isNil=0`).
   */
  [[nodiscard]] DecalBucketNode* AllocateDecalBucketNode()
  {
    auto* const node = static_cast<DecalBucketNode*>(::operator new(sizeof(DecalBucketNode)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->handle = nullptr;
    node->color = 1u;
    node->isNil = 0u;
    node->reserved12[0] = 0u;
    node->reserved12[1] = 0u;
    return node;
  }

  /**
   * Address: 0x0077C5B0 (FUN_0077C5B0)
   *
   * What it does:
   * Initializes one compact bucket-tree storage lane by allocating the head
   * sentinel node, wiring self-links, and clearing the element count.
   */
  [[maybe_unused]] DecalBucketNode* InitializeDecalBucketTreeHeadNode(DecalBucketTreeStorage* const storage)
  {
    DecalBucketNode* const head = AllocateDecalBucketNode();
    storage->head = head;
    head->isNil = 1u;
    head->parent = head;
    head->left = head;
    head->right = head;
    storage->size = 0u;
    return head;
  }

  /**
   * Address: 0x0077A8B0 (FUN_0077A8B0)
   *
   * What it does:
   * Initializes one compact decal-bucket tree-storage lane by allocating a
   * sentinel head node, wiring self-links, clearing count, and returning the
   * storage pointer.
   */
  [[maybe_unused]] DecalBucketTreeStorage* InitializeDecalBucketTreeStorageAndReturnStorageA(
    DecalBucketTreeStorage* const storage
  )
  {
    DecalBucketNode* const head = AllocateDecalBucketNode();
    storage->head = head;
    head->isNil = 1u;
    head->parent = head;
    head->left = head;
    head->right = head;
    storage->size = 0u;
    return storage;
  }

  /**
   * Address: 0x0077B4C0 (FUN_0077B4C0)
   *
   * What it does:
   * Sibling alias for the same compact decal-bucket tree-storage sentinel lane;
   * returns the input storage pointer.
   */
  [[maybe_unused]] DecalBucketTreeStorage* InitializeDecalBucketTreeStorageAndReturnStorageB(
    DecalBucketTreeStorage* const storage
  )
  {
    DecalBucketNode* const head = AllocateDecalBucketNode();
    storage->head = head;
    head->isNil = 1u;
    head->parent = head;
    head->left = head;
    head->right = head;
    storage->size = 0u;
    return storage;
  }

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

  [[nodiscard]]
  DecalMapNode* AllocateMapHeadNode()
  {
    auto* const node = static_cast<DecalMapNode*>(::operator new(sizeof(DecalMapNode)));
    node->left = node;
    node->parent = node;
    node->right = node;
    node->startTick = 0;
    node->bucketAllocatorCookie = nullptr;
    node->bucketHead = nullptr;
    node->bucketSize = 0;
    node->color = 1;
    node->isNil = 1;
    node->reserved1E[0] = 0;
    node->reserved1E[1] = 0;
    return node;
  }

  /**
   * Address: 0x0077B0B0 (FUN_0077B0B0)
   *
   * What it does:
   * Rotates one start-tick map node's right child up into its slot,
   * re-parenting the moved subtree and patching the header's root link when
   * `node` was the root. Sentinel-backed RB-tree layout (`isNil` at
   * `+0x1D`).
   */
  DecalMapNode* RotateMapNodeLeft(DecalMapNode* const node, CDecalStartTickMapStorage* const tree) noexcept
  {
    DecalMapNode* const pivot = node->right;
    node->right = pivot->left;
    if (pivot->left->isNil == 0u) {
      pivot->left->parent = node;
    }
    pivot->parent = node->parent;

    auto* const head = static_cast<DecalMapNode*>(tree->head);
    if (node == head->parent) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->left = node;
    node->parent = pivot;
    return pivot;
  }

  /**
   * Address: 0x0077B160 (FUN_0077B160)
   *
   * What it does:
   * Mirror of `RotateMapNodeLeft`: rotates one start-tick map node's left
   * child up into its slot.
   */
  DecalMapNode* RotateMapNodeRight(DecalMapNode* const node, CDecalStartTickMapStorage* const tree) noexcept
  {
    DecalMapNode* const pivot = node->left;
    node->left = pivot->right;
    if (pivot->right->isNil == 0u) {
      pivot->right->parent = node;
    }
    pivot->parent = node->parent;

    auto* const head = static_cast<DecalMapNode*>(tree->head);
    if (node == head->parent) {
      head->parent = pivot;
    } else if (node == node->parent->right) {
      node->parent->right = pivot;
    } else {
      node->parent->left = pivot;
    }

    pivot->right = node;
    node->parent = pivot;
    return pivot;
  }

  /**
   * Address: 0x0077CAE0 (FUN_0077CAE0)
   * Address: 0x0077DC40 (FUN_0077DC40, the single-element
   *   `allocator<DecalMapNode>::allocate` lane it calls with count=1)
   *
   * What it does:
   * Allocates one start-tick map value node, links it with both children
   * pointing at the sentinel `head` and `parent` set to the attach point,
   * marks it red/non-nil, and default-constructs its embedded bucket-tree
   * storage as a fresh empty tree via `InitializeDecalBucketTreeHeadNode`.
   *
   * The binary builds this node's embedded bucket by copy-constructing from
   * a temporary empty `DecalBucketTreeStorage` that its caller (`FUN_0077A250`)
   * builds and tears down around the insert - 2005-era unoptimized-debug-STL
   * codegen for materializing the `value_type` before linking. This recovery
   * reaches the same observable end state (a freshly allocated, empty,
   * correctly self-linked bucket tree) directly, without replicating the
   * redundant temporary. `FUN_0077DC40`'s overflow-checked array-new guard
   * (`0xFFFFFFFF / count < 0x20`) is unreachable at its only call site
   * (`count` is always 1) and is not reproduced here, matching the sibling
   * `AllocateDecalBucketNode`/`AllocateMapHeadNode` allocators in this file.
   */
  [[nodiscard]] DecalMapNode* AllocateDecalMapValueNode(
    const std::uint32_t startTick, DecalMapNode* const head, DecalMapNode* const parent
  )
  {
    auto* const node = static_cast<DecalMapNode*>(::operator new(sizeof(DecalMapNode)));
    node->left = head;
    node->parent = parent;
    node->right = head;
    node->startTick = startTick;
    node->bucketAllocatorCookie = nullptr;
    node->bucketHead = nullptr;
    node->bucketSize = 0u;
    (void)InitializeDecalBucketTreeHeadNode(reinterpret_cast<DecalBucketTreeStorage*>(&node->bucketAllocatorCookie));
    node->color = 0u;
    node->isNil = 0u;
    node->reserved1E[0] = 0u;
    node->reserved1E[1] = 0u;
    return node;
  }

  /**
   * Address: 0x0077BE80 (FUN_0077BE80)
   *
   * What it does:
   * Links a freshly constructed start-tick map value node under `where`
   * (updating the header's cached leftmost/rightmost/root links) then
   * repairs the red-red violation upwards and reblackens the root - MSVC8
   * `_Tree::_Insert` specialized for the sentinel-backed DecalMapNode layout
   * (`isNil` at `+0x1D`, `color` at `+0x1C`). Rejects the insert when the
   * tree already holds the MSVC8 `_Tree::max_size() - 1` element count.
   */
  [[nodiscard]] DecalMapNode* LinkMapNodeAndRebalance(
    DecalMapNode* const where, CDecalStartTickMapStorage* const mapThis, const bool addLeft, const std::uint32_t startTick
  )
  {
    if (mapThis->size >= 0xFFFFFFEu) {
      throw std::length_error("map/set<T> too long");
    }

    auto* const head = static_cast<DecalMapNode*>(mapThis->head);
    DecalMapNode* const fresh = AllocateDecalMapValueNode(startTick, head, where);
    ++mapThis->size;

    if (where == head) {
      head->parent = fresh;
      head->left = fresh;
      head->right = fresh;
    } else if (addLeft) {
      where->left = fresh;
      if (where == head->left) {
        head->left = fresh;
      }
    } else {
      where->right = fresh;
      if (where == head->right) {
        head->right = fresh;
      }
    }

    for (DecalMapNode* n = fresh; n->parent->color == 0u;) {
      DecalMapNode* const parent = n->parent;
      DecalMapNode* const grand = parent->parent;

      if (parent == grand->left) {
        DecalMapNode* const uncle = grand->right;
        if (uncle->color == 0u) {
          parent->color = 1u;
          uncle->color = 1u;
          grand->color = 0u;
          n = grand;
        } else {
          if (n == parent->right) {
            n = parent;
            (void)RotateMapNodeLeft(n, mapThis);
          }
          n->parent->color = 1u;
          n->parent->parent->color = 0u;
          (void)RotateMapNodeRight(n->parent->parent, mapThis);
        }
      } else {
        DecalMapNode* const uncle = grand->left;
        if (uncle->color == 0u) {
          parent->color = 1u;
          uncle->color = 1u;
          grand->color = 0u;
          n = grand;
        } else {
          if (n == parent->left) {
            n = parent;
            (void)RotateMapNodeRight(n, mapThis);
          }
          n->parent->color = 1u;
          n->parent->parent->color = 0u;
          (void)RotateMapNodeLeft(n->parent->parent, mapThis);
        }
      }
    }

    head->parent->color = 1u;
    return fresh;
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
  [[nodiscard]] DecalMapFindOrInsertResult FindStartTickBucketNode(
    CDecalStartTickMapStorage* const mapThis, const std::uint32_t startTick
  );
  [[nodiscard]] DecalBucketNode* DescendBucketLeftChainRuntime(DecalBucketNode* node) noexcept;
  [[nodiscard]] DecalBucketNode* DescendBucketRightChainRuntime(DecalBucketNode* node) noexcept;
  DecalBucketNode* AdvanceBucketNodeToSuccessor(DecalBucketNode** const iteratorLane) noexcept;
  DecalBucketNode* EraseBucketNode(DecalBucketTreeStorage* const tree, DecalBucketNode* const erased);

  /**
   * Address: 0x0077C690 (FUN_0077C690)
   *
   * What it does:
   * Allocates one compact bucket-tree node and writes `{left,parent,right}`
   * links plus `{handle,color,isNil}` payload/state lanes.
   */
  [[nodiscard]] DecalBucketNode* AllocateClonedDecalBucketNode(
    DecalBucketNode* const left,
    DecalBucketNode* const parent,
    DecalBucketNode* const right,
    CDecalHandle* const handle,
    const std::uint8_t color
  )
  {
    auto* const node = static_cast<DecalBucketNode*>(::operator new(sizeof(DecalBucketNode)));
    if (node != nullptr) {
      node->left = left;
      node->parent = parent;
      node->right = right;
      node->handle = handle;
      node->color = color;
      node->isNil = 0u;
      node->reserved12[0] = 0u;
      node->reserved12[1] = 0u;
    }
    return node;
  }

  /**
   * Address: 0x0077D090 (FUN_0077D090)
   *
   * What it does:
   * Recursively clones one compact bucket-tree subtree into `destination`,
   * wiring each clone under `parentNode` and preserving payload lanes.
   */
  [[maybe_unused]] [[nodiscard]] DecalBucketNode* CloneDecalBucketSubtreeRecursive(
    DecalBucketTreeStorage* const destination,
    const DecalBucketNode* const sourceNode,
    DecalBucketNode* const parentNode
  )
  {
    DecalBucketNode* cloneOrHead = destination->head;
    if (sourceNode->isNil == 0u) {
      try {
        DecalBucketNode* const cloneNode = AllocateClonedDecalBucketNode(
          destination->head,
          parentNode,
          destination->head,
          sourceNode->handle,
          sourceNode->color
        );
        cloneOrHead = cloneNode;
        cloneNode->left = CloneDecalBucketSubtreeRecursive(destination, sourceNode->left, cloneNode);
        cloneNode->right = CloneDecalBucketSubtreeRecursive(destination, sourceNode->right, cloneNode);
      } catch (...) {
        DestroyBucketTreeNodes(cloneOrHead, destination->head);
        throw;
      }
    }
    return cloneOrHead;
  }

  /**
   * Address: 0x0077CBB0 (FUN_0077CBB0)
   *
   * What it does:
   * Clones one compact bucket-tree root/header from `source` into
   * `destination`, then recomputes destination leftmost/rightmost caches.
   */
  [[maybe_unused]] [[nodiscard]] DecalBucketNode* CopyDecalBucketTreeHeaderAndExtrema(
    DecalBucketTreeStorage* const destination,
    const DecalBucketTreeStorage* const source
  )
  {
    DecalBucketNode* const destinationHead = destination->head;
    destinationHead->parent = CloneDecalBucketSubtreeRecursive(destination, source->head->parent, destinationHead);
    destination->size = source->size;

    DecalBucketNode* const root = destinationHead->parent;
    if (root->isNil != 0u) {
      destinationHead->left = destinationHead;
      destinationHead->right = destinationHead;
      return root;
    }

    DecalBucketNode* leftmost = root;
    while (leftmost->left->isNil == 0u) {
      leftmost = leftmost->left;
    }
    destinationHead->left = leftmost;

    DecalBucketNode* rightParent = root;
    DecalBucketNode* result = rightParent->right;
    while (result->isNil == 0u) {
      rightParent = result;
      result = result->right;
    }
    destinationHead->right = rightParent;
    return result;
  }

  /**
   * Address: 0x0077C1E0 (FUN_0077C1E0)
   *
   * What it does:
   * Copy-constructs one compact bucket-tree storage lane by creating a fresh
   * sentinel head and cloning source contents into destination.
   */
  [[maybe_unused]] [[nodiscard]] DecalBucketTreeStorage* CopyConstructDecalBucketTreeStorage(
    DecalBucketTreeStorage* const destination,
    const DecalBucketTreeStorage* const source
  )
  {
    DecalBucketNode* const head = AllocateDecalBucketNode();
    destination->head = head;
    head->isNil = 1u;
    head->parent = head;
    head->left = head;
    head->right = head;
    destination->size = 0u;

    try {
      (void)CopyDecalBucketTreeHeaderAndExtrema(destination, source);
    } catch (...) {
      DestroyBucketTreeNodes(head->parent, head);
      ::operator delete(head);
      destination->head = nullptr;
      destination->size = 0u;
      throw;
    }

    return destination;
  }

  /**
   * Address: 0x0077E280 (FUN_0077E280)
   *
   * What it does:
   * Assigns one compact bucket-tree storage lane by erasing destination
   * contents and cloning the full source tree when `destination != source`.
   */
  [[maybe_unused]] [[nodiscard]] DecalBucketTreeStorage* AssignDecalBucketTreeStorage(
    DecalBucketTreeStorage* const destination,
    const DecalBucketTreeStorage* const source
  )
  {
    if (destination != source) {
      DecalBucketNode* const head = destination->head;
      DestroyBucketTreeNodes(head->parent, head);
      head->parent = head;
      destination->size = 0u;
      head->left = head;
      head->right = head;
      (void)CopyDecalBucketTreeHeaderAndExtrema(destination, source);
    }
    return destination;
  }

  /**
   * Address: 0x0077BCD0 (FUN_0077BCD0)
   *
   * What it does:
   * Finds the start-tick map node keyed by `startTick`, inserting a fresh
   * node (with an empty bucket-tree storage payload) when no exact match
   * exists. MSVC8 `_Tree::insert_unique` specialized for the sentinel-backed
   * DecalMapNode layout (`isNil` at `+0x1D`): descends recording the last
   * left-branch taken, then confirms uniqueness against the in-order
   * predecessor before linking a fresh node via `LinkMapNodeAndRebalance`.
   */
  [[nodiscard]] DecalMapFindOrInsertResult FindStartTickBucketNode(
    CDecalStartTickMapStorage* const mapThis, const std::uint32_t startTick
  )
  {
    auto* const head = static_cast<DecalMapNode*>(mapThis->head);

    DecalMapNode* where = head;
    bool addLeft = true;
    for (DecalMapNode* node = head->parent; node->isNil == 0u;) {
      where = node;
      addLeft = startTick < node->startTick;
      node = addLeft ? node->left : node->right;
    }

    DecalMapNode* probe = where;
    if (addLeft) {
      if (where == head->left) {
        DecalMapNode* const inserted = LinkMapNodeAndRebalance(where, mapThis, true, startTick);
        return {inserted, true};
      }
      DecalMapNode* iteratorSlot = where;
      (void)RetreatStartTickMapIterator(0u, &iteratorSlot);
      probe = iteratorSlot;
    }

    if (probe->startTick >= startTick) {
      return {probe, false};
    }
    DecalMapNode* const inserted = LinkMapNodeAndRebalance(where, mapThis, addLeft, startTick);
    return {inserted, true};
  }

  /**
   * Address: 0x0077D160 (FUN_0077D160)
   *
   * What it does:
   * Moves one start-tick map iterator lane backward in the sentinel-backed
   * RB-tree (`isNil` at `+0x1D`).
   */
  DecalMapNode* RetreatStartTickMapIterator(
    const std::uint32_t /*unused*/,
    DecalMapNode** const iteratorLane
  ) noexcept
  {
    if (iteratorLane == nullptr || *iteratorLane == nullptr) {
      return nullptr;
    }

    DecalMapNode* const node = *iteratorLane;
    if (node->isNil != 0u) {
      DecalMapNode* const right = node->right;
      *iteratorLane = right;
      return right;
    }

    DecalMapNode* left = node->left;
    if (left->isNil != 0u) {
      DecalMapNode* parent = node->parent;
      while (parent->isNil == 0u) {
        if (*iteratorLane != parent->left) {
          break;
        }
        *iteratorLane = parent;
        parent = parent->parent;
      }

      if ((*iteratorLane)->isNil == 0u) {
        *iteratorLane = parent;
      }
      return parent;
    }

    DecalMapNode* right = left->right;
    while (right->isNil == 0u) {
      left = right;
      right = right->right;
    }

    *iteratorLane = left;
    return right;
  }

  /**
   * Address: 0x0077C7A0 (FUN_0077C7A0)
   *
   * What it does:
   * Register-shape adapter that retreats one start-tick iterator lane and
   * returns the iterator-slot pointer.
   */
  [[maybe_unused]] DecalMapNode** RetreatStartTickMapIteratorAdapterA(
    const std::uint32_t laneTag,
    DecalMapNode** const iteratorLane
  ) noexcept
  {
    (void)RetreatStartTickMapIterator(laneTag, iteratorLane);
    return iteratorLane;
  }

  /**
   * Address: 0x0077CE30 (FUN_0077CE30)
   *
   * What it does:
   * Secondary register-shape adapter for the same iterator-retreat lane.
   */
  [[maybe_unused]] DecalMapNode** RetreatStartTickMapIteratorAdapterB(
    const std::uint32_t laneTag,
    DecalMapNode** const iteratorLane
  ) noexcept
  {
    (void)RetreatStartTickMapIterator(laneTag, iteratorLane);
    return iteratorLane;
  }

  /**
   * Address: 0x0077CE50 (FUN_0077CE50)
   *
   * What it does:
   * Moves one start-tick map iterator lane forward to its in-order
   * successor in the sentinel-backed RB-tree (`isNil` at `+0x1D`) - the
   * successor-direction mirror of `RetreatStartTickMapIterator`.
   */
  DecalMapNode* AdvanceMapNodeToSuccessor(
    const std::uint32_t /*unused*/, DecalMapNode** const iteratorLane
  ) noexcept
  {
    DecalMapNode* result = *iteratorLane;
    if (result->isNil != 0u) {
      return result;
    }

    DecalMapNode* const right = result->right;
    if (right->isNil != 0u) {
      for (result = result->parent; result->isNil == 0u; result = result->parent) {
        if (*iteratorLane != result->right) {
          break;
        }
        *iteratorLane = result;
      }
      *iteratorLane = result;
    } else {
      DecalMapNode* cursor = right->left;
      result = cursor;
      DecalMapNode* lastNonNil = right;
      while (cursor->isNil == 0u) {
        lastNonNil = cursor;
        cursor = cursor->left;
        result = cursor;
      }
      *iteratorLane = lastNonNil;
    }
    return result;
  }

  /**
   * Address: 0x0077AF40 (FUN_0077AF40)
   *
   * What it does:
   * Hinted unique insert (MSVC8 `_Tree::insert(const_iterator, const
   * value_type&)`) for the start-tick map: checks whether `hint` is
   * adjacent to `begin()`/`end()`/its immediate neighbor for an O(1)
   * hint-based insert, falling back to the full descend-based find-or-insert
   * (`FindStartTickBucketNode`) only on a hint miss.
   */
  [[nodiscard]] DecalMapNode* ResolveStartTickInsertPosition(
    CDecalStartTickMapStorage* const mapThis, const std::uint32_t startTick, DecalMapNode* const hint
  )
  {
    auto* const head = static_cast<DecalMapNode*>(mapThis->head);

    if (mapThis->size == 0u) {
      return LinkMapNodeAndRebalance(head, mapThis, true, startTick);
    }

    if (hint == head->left) {
      if (startTick < hint->startTick) {
        return LinkMapNodeAndRebalance(hint, mapThis, true, startTick);
      }
    } else if (hint == head) {
      if (head->right->startTick < startTick) {
        return LinkMapNodeAndRebalance(head->right, mapThis, false, startTick);
      }
    } else if (startTick < hint->startTick) {
      DecalMapNode* before = hint;
      (void)RetreatStartTickMapIterator(0u, &before);
      if (before->startTick < startTick) {
        return before->right->isNil != 0u ? LinkMapNodeAndRebalance(before, mapThis, false, startTick)
                                           : LinkMapNodeAndRebalance(hint, mapThis, true, startTick);
      }
    } else if (hint->startTick < startTick) {
      DecalMapNode* after = hint;
      (void)AdvanceMapNodeToSuccessor(0u, &after);
      if (after->isNil != 0u || startTick < after->startTick) {
        return hint->right->isNil != 0u ? LinkMapNodeAndRebalance(hint, mapThis, false, startTick)
                                         : LinkMapNodeAndRebalance(after, mapThis, true, startTick);
      }
    }

    return FindStartTickBucketNode(mapThis, startTick).node;
  }

  /**
   * Address: 0x0077B100 (FUN_0077B100)
   *
   * What it does:
   * Walks one map-node right chain from `node->right` and returns the last
   * non-sentinel lane reached.
   */
  [[maybe_unused]] [[nodiscard]] DecalMapNode* DescendMapRightChainRuntime(DecalMapNode* node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    for (DecalMapNode* cursor = node->right; cursor != nullptr && cursor->isNil == 0u; cursor = cursor->right) {
      node = cursor;
    }
    return node;
  }

  /**
   * Address: 0x0077B120 (FUN_0077B120)
   *
   * What it does:
   * Walks one map-node left chain from `node->left` and returns the last
   * non-sentinel lane reached.
   */
  [[maybe_unused]] [[nodiscard]] DecalMapNode* DescendMapLeftChainRuntime(DecalMapNode* node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    DecalMapNode* cursor = node->left;
    if (cursor != nullptr && cursor->isNil == 0u) {
      do {
        node = cursor;
        cursor = cursor->left;
      } while (cursor->isNil == 0u);
    }
    return node;
  }

  struct DecalMapTreeRuntimeView
  {
    std::uint32_t lane00; // +0x00
    DecalMapNode* head;   // +0x04
  };
  static_assert(sizeof(DecalMapTreeRuntimeView) == 0x08, "DecalMapTreeRuntimeView size must be 0x08");

  /**
   * Address: 0x0077B070 (FUN_0077B070)
   *
   * What it does:
   * Resolves map lower-bound candidate for `startTick >= key` and writes the
   * result node to one output slot.
   */
  [[maybe_unused]] DecalMapNode** FindStartTickLowerBoundNodeToSlot(
    DecalMapNode** const outSlot,
    const DecalMapTreeRuntimeView* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    DecalMapNode* candidate = tree->head;
    for (DecalMapNode* probe = candidate->parent; probe->isNil == 0u;) {
      if (probe->startTick >= *key) {
        candidate = probe;
        probe = probe->left;
      } else {
        probe = probe->right;
      }
    }

    *outSlot = candidate;
    return outSlot;
  }

  /**
   * Address: 0x0077C020 (FUN_0077C020)
   *
   * What it does:
   * Returns map lower-bound candidate for `startTick >= key` from one
   * sentinel-backed start-tick tree lane.
   */
  [[maybe_unused]] DecalMapNode* FindStartTickLowerBoundNode(
    const DecalMapTreeRuntimeView* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    DecalMapNode* candidate = tree->head;
    for (DecalMapNode* probe = candidate->parent; probe->isNil == 0u;) {
      if (probe->startTick >= *key) {
        candidate = probe;
        probe = probe->left;
      } else {
        probe = probe->right;
      }
    }

    return candidate;
  }

  /**
   * Address: 0x0077A250 (FUN_0077A250, Moho::CDecalBuffer start-tick
   *   `operator[]`-equivalent)
   *
   * What it does:
   * Finds the bucket-tree storage for `startTick`, default-constructing an
   * empty one and inserting it when no exact match exists - MSVC8
   * `std::map<uint32_t, DecalBucketTreeStorage>::operator[]`.
   */
  [[nodiscard]] DecalBucketTreeStorage* FindOrCreateStartTickBucket(
    CDecalStartTickMapStorage* const mapThis, const std::uint32_t startTick
  )
  {
    auto* const head = static_cast<DecalMapNode*>(mapThis->head);
    const DecalMapTreeRuntimeView view{0u, head};
    DecalMapNode* candidate = FindStartTickLowerBoundNode(&view, &startTick);

    if (candidate == head || startTick < candidate->startTick) {
      candidate = ResolveStartTickInsertPosition(mapThis, startTick, candidate);
    }

    return reinterpret_cast<DecalBucketTreeStorage*>(&candidate->bucketAllocatorCookie);
  }

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

  /**
   * Address: 0x0077C550 (FUN_0077C550)
   *
   * What it does:
   * Resolves bucket-tree lower-bound candidate for `nodeKey >= key` and
   * writes it into one output slot.
   */
  [[maybe_unused]] DecalBucketNode** FindDecalBucketLowerBoundNodeToSlot(
    DecalBucketNode** const outSlot,
    const DecalBucketTreeRuntimeView* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    DecalBucketNode* candidate = tree->head;
    for (DecalBucketNode* probe = candidate->parent; probe->isNil == 0u;) {
      const std::uint32_t probeKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(probe->handle));
      if (probeKey >= *key) {
        candidate = probe;
        probe = probe->left;
      } else {
        probe = probe->right;
      }
    }

    *outSlot = candidate;
    return outSlot;
  }

  /**
   * Address: 0x0077C580 (FUN_0077C580)
   *
   * What it does:
   * Resolves bucket-tree upper-bound candidate for `nodeKey > key` and
   * writes it into one output slot.
   */
  [[maybe_unused]] DecalBucketNode** FindDecalBucketUpperBoundNodeToSlot(
    DecalBucketNode** const outSlot,
    const DecalBucketTreeRuntimeView* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    DecalBucketNode* candidate = tree->head;
    for (DecalBucketNode* probe = candidate->parent; probe->isNil == 0u;) {
      const std::uint32_t probeKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(probe->handle));
      if (*key >= probeKey) {
        probe = probe->right;
      } else {
        candidate = probe;
        probe = probe->left;
      }
    }

    *outSlot = candidate;
    return outSlot;
  }

  /**
   * Address: 0x0077B5B0 (FUN_0077B5B0)
   *
   * What it does:
   * Computes `{lowerBound,upperBound}` candidates for one bucket-key lookup
   * in the sentinel-backed decal bucket tree.
   */
  [[maybe_unused]] DecalBucketBoundPairRuntime* FindDecalBucketBoundsByKeyRuntime(
    DecalBucketBoundPairRuntime* const outBounds,
    const DecalBucketTreeRuntimeView* const tree,
    const std::uint32_t* const keyLane
  ) noexcept
  {
    if (outBounds == nullptr || tree == nullptr || tree->head == nullptr || keyLane == nullptr) {
      return outBounds;
    }

    const std::uint32_t key = *keyLane;

    DecalBucketNode* upperCandidate = tree->head;
    for (DecalBucketNode* probe = upperCandidate->parent; probe->isNil == 0u;) {
      const std::uint32_t probeKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(probe->handle));
      if (key >= probeKey) {
        probe = probe->right;
      } else {
        upperCandidate = probe;
        probe = probe->left;
      }
    }

    DecalBucketNode* lowerCandidate = tree->head;
    for (DecalBucketNode* probe = lowerCandidate->parent; probe->isNil == 0u;) {
      const std::uint32_t probeKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(probe->handle));
      if (probeKey >= key) {
        lowerCandidate = probe;
        probe = probe->left;
      } else {
        probe = probe->right;
      }
    }

    outBounds->lowerBound = lowerCandidate;
    outBounds->upperBound = upperCandidate;
    return outBounds;
  }

  /**
   * Address: 0x0077CC90 (FUN_0077CC90)
   *
   * What it does:
   * Walks one bucket-node right chain from `node->right` and returns the last
   * non-sentinel lane reached.
   */
  [[nodiscard]] DecalBucketNode* DescendBucketRightChainRuntime(DecalBucketNode* node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    for (DecalBucketNode* cursor = node->right; cursor != nullptr && cursor->isNil == 0u; cursor = cursor->right) {
      node = cursor;
    }
    return node;
  }

  /**
   * Address: 0x0077CCB0 (FUN_0077CCB0)
   *
   * What it does:
   * Walks one bucket-node left chain from `node->left` and returns the last
   * non-sentinel lane reached.
   */
  [[nodiscard]] DecalBucketNode* DescendBucketLeftChainRuntime(DecalBucketNode* node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    DecalBucketNode* cursor = node->left;
    if (cursor != nullptr && cursor->isNil == 0u) {
      do {
        node = cursor;
        cursor = cursor->left;
      } while (cursor->isNil == 0u);
    }
    return node;
  }

  /**
   * Address: 0x0077C5E0 (FUN_0077C5E0)
   *
   * What it does:
   * Rotates one decal-bucket node's right child up into its slot,
   * re-parenting the moved subtree and patching the header's root link when
   * `node` was the root. Sentinel-backed RB-tree layout (`isNil` at
   * `+0x11`).
   */
  DecalBucketNode* RotateBucketNodeLeft(DecalBucketNode* const node, DecalBucketTreeStorage* const tree) noexcept
  {
    DecalBucketNode* const pivot = node->right;
    node->right = pivot->left;
    if (pivot->left->isNil == 0u) {
      pivot->left->parent = node;
    }
    pivot->parent = node->parent;

    DecalBucketNode* const head = tree->head;
    if (node == head->parent) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->left = node;
    node->parent = pivot;
    return pivot;
  }

  /**
   * Address: 0x0077C640 (FUN_0077C640)
   *
   * What it does:
   * Mirror of `RotateBucketNodeLeft`: rotates one decal-bucket node's left
   * child up into its slot.
   */
  DecalBucketNode* RotateBucketNodeRight(DecalBucketNode* const node, DecalBucketTreeStorage* const tree) noexcept
  {
    DecalBucketNode* const pivot = node->left;
    node->left = pivot->right;
    if (pivot->right->isNil == 0u) {
      pivot->right->parent = node;
    }
    pivot->parent = node->parent;

    DecalBucketNode* const head = tree->head;
    if (node == head->parent) {
      head->parent = pivot;
    } else if (node == node->parent->right) {
      node->parent->right = pivot;
    } else {
      node->parent->left = pivot;
    }

    pivot->right = node;
    node->parent = pivot;
    return pivot;
  }

  /**
   * Address: 0x0077C740 (FUN_0077C740)
   *
   * What it does:
   * Moves one decal-bucket iterator lane forward to its in-order successor
   * in the sentinel-backed RB-tree (`isNil` at `+0x11`).
   */
  DecalBucketNode* AdvanceBucketNodeToSuccessor(DecalBucketNode** const iteratorLane) noexcept
  {
    DecalBucketNode* result = *iteratorLane;
    if (result->isNil != 0u) {
      return result;
    }

    DecalBucketNode* const right = result->right;
    if (right->isNil != 0u) {
      for (result = result->parent; result->isNil == 0u; result = result->parent) {
        if (*iteratorLane != result->right) {
          break;
        }
        *iteratorLane = result;
      }
      *iteratorLane = result;
    } else {
      DecalBucketNode* cursor = right->left;
      result = cursor;
      DecalBucketNode* lastNonNil = right;
      while (cursor->isNil == 0u) {
        lastNonNil = cursor;
        cursor = cursor->left;
        result = cursor;
      }
      *iteratorLane = lastNonNil;
    }
    return result;
  }

  /**
   * Address: 0x0077C270 (FUN_0077C270)
   *
   * What it does:
   * Unlinks and destroys `erased` from the decal-bucket RB-tree, returning
   * its in-order successor. Transplants the successor into the erased
   * node's slot when both subtrees exist, then repairs the black-height
   * deficit from the stitched-up child upwards - MSVC8 `_Tree::erase`
   * specialized for the sentinel-backed DecalBucketNode layout (`isNil` at
   * `+0x11`, `color` at `+0x10`).
   *
   * Throws `std::out_of_range` when `erased` is the header sentinel
   * (matches the binary's "invalid map/set<T> iterator" guard).
   */
  DecalBucketNode* EraseBucketNode(DecalBucketTreeStorage* const tree, DecalBucketNode* const erased)
  {
    if (erased->isNil != 0u) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    DecalBucketNode* iteratorSlot = erased;
    DecalBucketNode* const next = AdvanceBucketNodeToSuccessor(&iteratorSlot);

    DecalBucketNode* lifted = erased;
    DecalBucketNode* fix = nullptr;
    DecalBucketNode* fixParent = nullptr;

    if (erased->left->isNil != 0u) {
      fix = erased->right;
    } else if (erased->right->isNil != 0u) {
      fix = erased->left;
    } else {
      lifted = next;
      fix = lifted->right;
    }

    DecalBucketNode* const head = tree->head;

    if (lifted == erased) {
      fixParent = erased->parent;
      if (fix->isNil == 0u) {
        fix->parent = fixParent;
      }

      if (head->parent == erased) {
        head->parent = fix;
      } else if (fixParent->left == erased) {
        fixParent->left = fix;
      } else {
        fixParent->right = fix;
      }

      if (head->left == erased) {
        head->left = fix->isNil != 0u ? fixParent : DescendBucketLeftChainRuntime(fix);
      }
      if (head->right == erased) {
        head->right = fix->isNil != 0u ? fixParent : DescendBucketRightChainRuntime(fix);
      }
    } else {
      erased->left->parent = lifted;
      lifted->left = erased->left;

      if (lifted == erased->right) {
        fixParent = lifted;
      } else {
        fixParent = lifted->parent;
        if (fix->isNil == 0u) {
          fix->parent = fixParent;
        }
        fixParent->left = fix;
        lifted->right = erased->right;
        erased->right->parent = lifted;
      }

      if (head->parent == erased) {
        head->parent = lifted;
      } else if (erased->parent->left == erased) {
        erased->parent->left = lifted;
      } else {
        erased->parent->right = lifted;
      }

      lifted->parent = erased->parent;
      std::swap(lifted->color, erased->color);
    }

    if (erased->color == 1u) {
      DecalBucketNode* fixCursor = fix;
      DecalBucketNode* fixParentCursor = fixParent;
      while (fixCursor != head->parent && fixCursor->color == 1u) {
        if (fixCursor == fixParentCursor->left) {
          DecalBucketNode* sibling = fixParentCursor->right;
          if (sibling->color == 0u) {
            sibling->color = 1u;
            fixParentCursor->color = 0u;
            (void)RotateBucketNodeLeft(fixParentCursor, tree);
            sibling = fixParentCursor->right;
          }

          if (sibling->isNil != 0u) {
            fixCursor = fixParentCursor;
            fixParentCursor = fixCursor->parent;
          } else if (sibling->left->color == 1u && sibling->right->color == 1u) {
            sibling->color = 0u;
            fixCursor = fixParentCursor;
            fixParentCursor = fixCursor->parent;
          } else {
            if (sibling->right->color == 1u) {
              sibling->left->color = 1u;
              sibling->color = 0u;
              (void)RotateBucketNodeRight(sibling, tree);
              sibling = fixParentCursor->right;
            }
            sibling->color = fixParentCursor->color;
            fixParentCursor->color = 1u;
            sibling->right->color = 1u;
            (void)RotateBucketNodeLeft(fixParentCursor, tree);
            fixCursor = head->parent;
            break;
          }
        } else {
          DecalBucketNode* sibling = fixParentCursor->left;
          if (sibling->color == 0u) {
            sibling->color = 1u;
            fixParentCursor->color = 0u;
            (void)RotateBucketNodeRight(fixParentCursor, tree);
            sibling = fixParentCursor->left;
          }

          if (sibling->isNil != 0u) {
            fixCursor = fixParentCursor;
            fixParentCursor = fixCursor->parent;
          } else if (sibling->right->color == 1u && sibling->left->color == 1u) {
            sibling->color = 0u;
            fixCursor = fixParentCursor;
            fixParentCursor = fixCursor->parent;
          } else {
            if (sibling->left->color == 1u) {
              sibling->right->color = 1u;
              sibling->color = 0u;
              (void)RotateBucketNodeLeft(sibling, tree);
              sibling = fixParentCursor->left;
            }
            sibling->color = fixParentCursor->color;
            fixParentCursor->color = 1u;
            sibling->left->color = 1u;
            (void)RotateBucketNodeRight(fixParentCursor, tree);
            fixCursor = head->parent;
            break;
          }
        }
      }
      fixCursor->color = 1u;
    }

    ::operator delete(erased);
    if (tree->size != 0u) {
      --tree->size;
    }
    return next;
  }

  /**
   * Address: 0x0077B4F0 (FUN_0077B4F0)
   *
   * What it does:
   * Erases `[first, last)` from the decal-bucket RB-tree. Takes the O(1)
   * whole-tree fast path (recursive subtree destroy + sentinel reset) when
   * erasing the full range; otherwise advances to each node's successor
   * before erasing it, so the walk stays valid across the erase.
   */
  DecalBucketNode* EraseBucketNodeRange(
    DecalBucketTreeStorage* const tree,
    DecalBucketNode** const outPosition,
    DecalBucketNode* const first,
    DecalBucketNode* const last
  )
  {
    DecalBucketNode* const head = tree->head;
    DecalBucketNode* cursor = first;

    if (first == head->left && last == head) {
      DestroyBucketTreeNodes(head->parent, head);
      head->parent = head;
      tree->size = 0u;
      head->left = head;
      head->right = head;
      *outPosition = head;
      return *outPosition;
    }

    if (first != last) {
      do {
        DecalBucketNode* const erasing = cursor;
        (void)AdvanceBucketNodeToSuccessor(&cursor);
        (void)EraseBucketNode(tree, erasing);
      } while (cursor != last);
    }

    *outPosition = cursor;
    return *outPosition;
  }

  /**
   * Address: 0x0077A9F0 (FUN_0077A9F0)
   *
   * What it does:
   * Erases every decal-bucket node keyed by `key` (`equal_range` then
   * range-erase) and returns the number of nodes removed.
   */
  [[nodiscard]] std::uint32_t EraseBucketNodesByKey(DecalBucketTreeStorage* const tree, const CDecalHandle* const key)
  {
    const DecalBucketTreeRuntimeView view{0u, tree->head};
    const std::uint32_t keyValue = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(key));

    DecalBucketBoundPairRuntime bounds{};
    (void)FindDecalBucketBoundsByKeyRuntime(&bounds, &view, &keyValue);

    std::uint32_t erasedCount = 0u;
    DecalBucketNode* cursor = bounds.lowerBound;
    for (; cursor != bounds.upperBound; (void)AdvanceBucketNodeToSuccessor(&cursor)) {
      ++erasedCount;
    }

    DecalBucketNode* outPosition = nullptr;
    (void)EraseBucketNodeRange(tree, &outPosition, bounds.lowerBound, bounds.upperBound);
    return erasedCount;
  }

  /**
   * Address: 0x0077CD80 (FUN_0077CD80)
   *
   * What it does:
   * Moves one decal-bucket iterator lane backward to its in-order
   * predecessor in the sentinel-backed RB-tree (`isNil` at `+0x11`) - the
   * predecessor-direction mirror of `AdvanceBucketNodeToSuccessor`.
   */
  DecalBucketNode* RetreatBucketNodeIterator(DecalBucketNode** const iteratorLane) noexcept
  {
    DecalBucketNode* const node = *iteratorLane;
    if (node->isNil != 0u) {
      DecalBucketNode* const right = node->right;
      *iteratorLane = right;
      return right;
    }

    DecalBucketNode* left = node->left;
    if (left->isNil != 0u) {
      DecalBucketNode* parent = node->parent;
      while (parent->isNil == 0u) {
        if (*iteratorLane != parent->left) {
          break;
        }
        *iteratorLane = parent;
        parent = parent->parent;
      }

      if ((*iteratorLane)->isNil == 0u) {
        *iteratorLane = parent;
      }
      return parent;
    }

    DecalBucketNode* right = left->right;
    while (right->isNil == 0u) {
      left = right;
      right = right->right;
    }

    *iteratorLane = left;
    return right;
  }

  /**
   * Address: 0x0077B600 (FUN_0077B600)
   *
   * What it does:
   * Links a freshly constructed decal-bucket node under `where` (updating
   * the header's cached leftmost/rightmost/root links) then repairs the
   * red-red violation upwards and reblackens the root - MSVC8
   * `_Tree::_Insert` specialized for the sentinel-backed DecalBucketNode
   * layout (`isNil` at `+0x11`, `color` at `+0x10`). Twin of
   * `LinkMapNodeAndRebalance` for the bucket tree; rejects the insert at
   * the binary's own (smaller) bucket-tree `max_size() - 1` bound.
   */
  [[nodiscard]] DecalBucketNode* LinkBucketNodeAndRebalance(
    DecalBucketNode* const where, DecalBucketTreeStorage* const tree, const bool addLeft, CDecalHandle* const handle
  )
  {
    if (tree->size >= 0x3FFFFFFEu) {
      throw std::length_error("map/set<T> too long");
    }

    DecalBucketNode* const head = tree->head;
    DecalBucketNode* const fresh = AllocateClonedDecalBucketNode(head, where, head, handle, 0u);
    ++tree->size;

    if (where == head) {
      head->parent = fresh;
      head->left = fresh;
      head->right = fresh;
    } else if (addLeft) {
      where->left = fresh;
      if (where == head->left) {
        head->left = fresh;
      }
    } else {
      where->right = fresh;
      if (where == head->right) {
        head->right = fresh;
      }
    }

    for (DecalBucketNode* n = fresh; n->parent->color == 0u;) {
      DecalBucketNode* const parent = n->parent;
      DecalBucketNode* const grand = parent->parent;

      if (parent == grand->left) {
        DecalBucketNode* const uncle = grand->right;
        if (uncle->color == 0u) {
          parent->color = 1u;
          uncle->color = 1u;
          grand->color = 0u;
          n = grand;
        } else {
          if (n == parent->right) {
            n = parent;
            (void)RotateBucketNodeLeft(n, tree);
          }
          n->parent->color = 1u;
          n->parent->parent->color = 0u;
          (void)RotateBucketNodeRight(n->parent->parent, tree);
        }
      } else {
        DecalBucketNode* const uncle = grand->left;
        if (uncle->color == 0u) {
          parent->color = 1u;
          uncle->color = 1u;
          grand->color = 0u;
          n = grand;
        } else {
          if (n == parent->left) {
            n = parent;
            (void)RotateBucketNodeRight(n, tree);
          }
          n->parent->color = 1u;
          n->parent->parent->color = 0u;
          (void)RotateBucketNodeLeft(n->parent->parent, tree);
        }
      }
    }

    head->parent->color = 1u;
    return fresh;
  }

  struct DecalBucketFindOrInsertResult
  {
    DecalBucketNode* node;
    bool inserted;
  };

  /**
   * Address: 0x0077A930 (FUN_0077A930)
   *
   * What it does:
   * Finds the decal-bucket node keyed by `handle`, inserting a fresh node
   * when no exact match exists - MSVC8 `_Tree::insert_unique` specialized
   * for the sentinel-backed DecalBucketNode layout (`isNil` at `+0x11`).
   * Twin of `FindStartTickBucketNode` for the bucket tree; the bucket key
   * is the handle pointer's own bit pattern (matches the already-recovered
   * `FindDecalBucketBoundsByKeyRuntime`/lower/upper-bound helpers in this
   * file).
   */
  [[nodiscard]] DecalBucketFindOrInsertResult FindOrInsertBucketNode(
    DecalBucketTreeStorage* const tree, CDecalHandle* const handle
  )
  {
    DecalBucketNode* const head = tree->head;
    const std::uint32_t key = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(handle));

    DecalBucketNode* where = head;
    bool addLeft = true;
    for (DecalBucketNode* node = head->parent; node->isNil == 0u;) {
      where = node;
      const std::uint32_t nodeKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(node->handle));
      addLeft = key < nodeKey;
      node = addLeft ? node->left : node->right;
    }

    DecalBucketNode* probe = where;
    if (addLeft) {
      if (where == head->left) {
        DecalBucketNode* const inserted = LinkBucketNodeAndRebalance(where, tree, true, handle);
        return {inserted, true};
      }
      DecalBucketNode* iteratorSlot = where;
      (void)RetreatBucketNodeIterator(&iteratorSlot);
      probe = iteratorSlot;
    }

    const std::uint32_t probeKey = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(probe->handle));
    if (probeKey >= key) {
      return {probe, false};
    }
    DecalBucketNode* const inserted = LinkBucketNodeAndRebalance(where, tree, addLeft, handle);
    return {inserted, true};
  }

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

  void DestroyBucketTreeNodes(DecalBucketNode* node, const DecalBucketNode* const head)
  {
    if (!node || node == head) {
      return;
    }

    DestroyBucketTreeNodes(node->left, head);
    DestroyBucketTreeNodes(node->right, head);
    ::operator delete(node);
  }

  /**
   * Address: 0x00779B80 (FUN_00779B80, sub_779B80)
   *
   * What it does:
   * Releases one decal-bucket RB-tree storage lane by erasing all nodes,
   * deleting the head sentinel, and zeroing `{head,size}`.
   */
  std::int32_t ReleaseDecalBucketTreeStorage(DecalBucketTreeStorage* const storage)
  {
    if (storage == nullptr) {
      return 0;
    }

    DecalBucketNode* const head = storage->head;
    if (head != nullptr) {
      DestroyBucketTreeNodes(head->left, head);
      ::operator delete(head);
    }

    storage->head = nullptr;
    storage->size = 0u;
    return 0;
  }

  /**
   * Address: 0x00779240 (FUN_00779240, sub_779240)
   *
   * What it does:
   * Releases one start-tick map RB-tree storage lane by erasing all map nodes,
   * deleting the head sentinel, and zeroing `{head,size}`.
   */
  std::int32_t ReleaseDecalStartTickMapStorage(CDecalStartTickMapStorage* const storage)
  {
    if (storage == nullptr) {
      return 0;
    }

    auto* const head = static_cast<DecalMapNode*>(storage->head);
    if (head != nullptr) {
      DestroyMapNodes(head->left, head);
      ::operator delete(head);
    }

    storage->head = nullptr;
    storage->size = 0u;
    return 0;
  }

  /**
   * Address: 0x0077B7D0 (FUN_0077B7D0)
   *
   * What it does:
   * Alias wrapper for the decal-bucket RB-tree storage teardown lane.
   */
  std::int32_t DestroyDecalBucketTreeStorage(DecalBucketTreeStorage* const storage)
  {
    return ReleaseDecalBucketTreeStorage(storage);
  }

  /**
   * Address: 0x0077AC30 (FUN_0077AC30)
   *
   * What it does:
   * Alias wrapper for the start-tick map RB-tree storage teardown lane.
   */
  std::int32_t DestroyStartTickMapStorage(CDecalStartTickMapStorage* const storage)
  {
    return ReleaseDecalStartTickMapStorage(storage);
  }

  void DestroyBucketHead(DecalBucketNode* const head)
  {
    DecalBucketTreeStorage storage{};
    storage.allocatorCookie = nullptr;
    storage.head = head;
    storage.size = 0u;
    (void)DestroyDecalBucketTreeStorage(&storage);
  }

  void DestroyMapNodes(DecalMapNode* node, const DecalMapNode* const head)
  {
    if (!node || node == head) {
      return;
    }

    DestroyMapNodes(node->left, head);
    DestroyMapNodes(node->right, head);
    DestroyBucketHead(node->bucketHead);
    ::operator delete(node);
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

  mStartTickBuckets.allocatorCookie = nullptr;
  mStartTickBuckets.head = AllocateMapHeadNode();
  mStartTickBuckets.size = 0;
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

  auto* const mapHead = static_cast<DecalMapNode*>(mStartTickBuckets.head);
  if (mapHead) {
    (void)DestroyStartTickMapStorage(&mStartTickBuckets);
  }

  mStartTickBuckets.head = nullptr;
  mStartTickBuckets.size = 0;
  mStartTickBuckets.allocatorCookie = nullptr;
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
  auto& visibleView = msvc8::AsVectorRuntimeView(mVisibleDecals);
  auto& addView = msvc8::AsVectorRuntimeView(*addDecals);

  std::swap(visibleView.begin, addView.begin);
  std::swap(visibleView.end, addView.end);
  std::swap(visibleView.capacityEnd, addView.capacityEnd);

  auto& pendingHideView = msvc8::AsVectorRuntimeView(mPendingHideObjectIds);
  auto& removeView = msvc8::AsVectorRuntimeView(*removeDecals);

  std::swap(pendingHideView.begin, removeView.begin);
  std::swap(pendingHideView.end, removeView.end);
  std::swap(pendingHideView.capacityEnd, removeView.capacityEnd);
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
    DecalBucketTreeStorage* const bucket = FindOrCreateStartTickBucket(&mStartTickBuckets, handle->mInfo.mStartTick);
    (void)FindOrInsertBucketNode(bucket, handle);
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
      DecalBucketTreeStorage* const bucket = FindOrCreateStartTickBucket(&mStartTickBuckets, handle->mInfo.mStartTick);
      (void)FindOrInsertBucketNode(bucket, handle);
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
 * into the same start-tick bucket tree is deferred (needs `FUN_0077A930`
 * and its own dependency closure).
 */
void CDecalBuffer::DestroyHandle(CDecalHandle* const handleOpaque)
{
  if (!handleOpaque) {
    return;
  }

  if (handleOpaque->mInfo.mStartTick != 0u) {
    DecalBucketTreeStorage* const bucket =
      FindOrCreateStartTickBucket(&mStartTickBuckets, handleOpaque->mInfo.mStartTick);
    (void)EraseBucketNodesByKey(bucket, handleOpaque);
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
