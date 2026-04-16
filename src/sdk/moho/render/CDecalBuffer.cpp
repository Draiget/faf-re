#include "moho/render/CDecalBuffer.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <typeinfo>

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

  void DestroyBucketTreeNodes(DecalBucketNode* node, const DecalBucketNode* const head);
  void DestroyMapNodes(DecalMapNode* node, const DecalMapNode* const head);

  /**
   * Address: 0x0077C690 (FUN_0077C690)
   *
   * What it does:
   * Allocates one compact bucket-tree node and writes `{left,parent,right}`
   * links plus `{handle,color,isNil}` payload/state lanes.
   */
  [[maybe_unused]] [[nodiscard]] DecalBucketNode* AllocateClonedDecalBucketNode(
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
   * Finds the lower-bound start-tick bucket node for a given decal start tick
   * using the sentinel-backed RB-tree layout.
   */
  [[maybe_unused]] [[nodiscard]] DecalMapNode* FindStartTickBucketNode(
    DecalMapNode* const head, const std::uint32_t startTick
  ) noexcept
  {
    if (head == nullptr) {
      return nullptr;
    }

    DecalMapNode* candidate = head;
    for (DecalMapNode* node = head->parent; node != nullptr && node->isNil == 0u;) {
      candidate = node;
      if (startTick < node->startTick) {
        node = node->left;
      } else {
        node = node->right;
      }
    }

    return candidate;
  }

  /**
   * Address: 0x0077D160 (FUN_0077D160)
   *
   * What it does:
   * Moves one start-tick map iterator lane backward in the sentinel-backed
   * RB-tree (`isNil` at `+0x1D`).
   */
  [[maybe_unused]] DecalMapNode* RetreatStartTickMapIterator(
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
  [[maybe_unused]] [[nodiscard]] DecalBucketNode* DescendBucketRightChainRuntime(DecalBucketNode* node) noexcept
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
  [[maybe_unused]] [[nodiscard]] DecalBucketNode* DescendBucketLeftChainRuntime(DecalBucketNode* node) noexcept
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
 * Creates one script-visible decal handle, links it into active tracking, and
 * initializes per-army visibility flags for the new decal.
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
 * Address: 0x00779680 (FUN_00779680, sub_779680)
 *
 * What it does:
 * Removes one handle from active tracking, queues object-id retirement, and deletes the handle.
 */
void CDecalBuffer::DestroyHandle(CDecalHandle* const handleOpaque)
{
  if (!handleOpaque) {
    return;
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
