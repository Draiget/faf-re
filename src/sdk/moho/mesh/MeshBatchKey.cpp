#include "MeshBatchKey.h"

#include <algorithm>
#include <cstring>
#include <new>
#include <stdexcept>

namespace moho
{
  namespace
  {
    constexpr std::uint8_t kNodeRed = 0;
    constexpr std::uint8_t kNodeBlack = 1;
    constexpr std::uint8_t kSentinelNodeFlag = 1;
    constexpr std::uint32_t kMeshBatchTreeMaxSize = 0x07FFFFFEu;
    constexpr std::size_t kMeshBatchVectorMaxElements = 0x3FFFFFFFu;

    [[nodiscard]] bool IsSentinelNode(const MeshBatchBucketNode* const node)
    {
      return node == nullptr || node->isSentinel == kSentinelNodeFlag;
    }

    [[nodiscard]] bool MeshBatchKeyEqual(const MeshBatchKey& lhs, const MeshBatchKey& rhs)
    {
      return !MeshBatchKeyLess(lhs, rhs) && !MeshBatchKeyLess(rhs, lhs);
    }

    /**
     * Address: 0x007E41A0 (FUN_007E41A0)
     *
     * What it does:
     * Clones one instance-pointer vector payload into freshly allocated storage.
     */
    [[nodiscard]] MeshBatchInstanceVector CloneMeshBatchInstanceVector(const MeshBatchInstanceVector& source)
    {
      MeshBatchInstanceVector cloned{};
      cloned.proxy = nullptr;

      if (!source.first || source.first == source.last) {
        return cloned;
      }

      const std::size_t count = static_cast<std::size_t>(source.last - source.first);
      if (count > kMeshBatchVectorMaxElements) {
        throw std::bad_alloc();
      }

      auto* const allocated = static_cast<MeshInstance**>(::operator new(sizeof(MeshInstance*) * count));
      std::copy(source.first, source.last, allocated);

      cloned.first = allocated;
      cloned.last = allocated + count;
      cloned.end = allocated + count;
      return cloned;
    }

    /**
     * Address: 0x007E2A30 (FUN_007E2A30)
     *
     * What it does:
     * Clears one mesh-batch instance-pointer vector by resetting `last` to
     * `first` while preserving allocated storage.
     */
    [[maybe_unused]] void ClearMeshBatchInstanceVectorRange(MeshBatchInstanceVector& vector) noexcept
    {
      if (vector.first != vector.last) {
        vector.last = vector.first;
      }
    }

    /**
     * Address: 0x007DA100 (FUN_007DA100)
     *
     * What it does:
     * Relocates one suffix pointer range from `source` into `destination`,
     * updates the vector `last` lane, and writes the destination iterator to
     * caller output storage.
     */
    [[maybe_unused]] MeshInstance*** RelocateMeshBatchInstancePointerRangeAndStoreIterator(
      MeshBatchInstanceVector& vector,
      MeshInstance*** const outIterator,
      MeshInstance** const destination,
      MeshInstance** const source
    ) noexcept
    {
      if (destination != source) {
        const std::ptrdiff_t elementCount = vector.last - source;
        MeshInstance** const destinationEnd = destination + elementCount;
        if (elementCount > 0) {
          std::memmove(
            destination,
            source,
            static_cast<std::size_t>(elementCount) * sizeof(MeshInstance*)
          );
        }
        vector.last = destinationEnd;
      }

      *outIterator = destination;
      return outIterator;
    }

    /**
     * Address: 0x007E3110 (FUN_007E3110)
     *
     * What it does:
     * Register-shape adapter for mesh-batch instance-pointer range relocation.
     */
    [[maybe_unused]] MeshInstance*** RelocateMeshBatchInstancePointerRangeAndStoreIteratorAdapter(
      MeshBatchInstanceVector& vector,
      MeshInstance*** const outIterator,
      MeshInstance** const destination,
      MeshInstance** const source
    ) noexcept
    {
      return RelocateMeshBatchInstancePointerRangeAndStoreIterator(vector, outIterator, destination, source);
    }

    /**
     * Address: 0x007E4BC0 (FUN_007E4BC0)
     * Address: 0x007E5070 (FUN_007E5070)
     * Address: 0x007E5740 (FUN_007E5740)
     *
     * What it does:
     * Allocates and initializes one RB-tree node and copies bucket value payload.
     */
    [[nodiscard]] MeshBatchBucketNode* CreateMeshBatchBucketNode(
      MeshBatchBucketNode* const parent, MeshBatchBucketNode* const head, const MeshBatchBucket& bucket
    )
    {
      auto* const node = new MeshBatchBucketNode{};
      node->left = head;
      node->parent = parent;
      node->right = head;
      node->color = kNodeRed;
      node->isSentinel = 0;
      node->bucket.key = bucket.key;
      try {
        node->bucket.instances = CloneMeshBatchInstanceVector(bucket.instances);
      } catch (...) {
        delete node;
        throw;
      }
      return node;
    }

    /**
     * Address: 0x007E4AC0 (FUN_007E4AC0)
     *
     * What it does:
     * Performs one left-rotation around `node` in the mesh-bucket RB-tree.
     */
    void RotateMeshBatchTreeLeft(MeshBatchBucketNode* const node, MeshBatchBucketTree& tree)
    {
      MeshBatchBucketNode* const pivot = node->right;
      node->right = pivot->left;
      if (!IsSentinelNode(pivot->left)) {
        pivot->left->parent = node;
      }

      pivot->parent = node->parent;
      MeshBatchBucketNode* const head = tree.head;
      if (node == head->parent) {
        head->parent = pivot;
      } else {
        MeshBatchBucketNode* const parent = node->parent;
        if (node == parent->left) {
          parent->left = pivot;
        } else {
          parent->right = pivot;
        }
      }

      pivot->left = node;
      node->parent = pivot;
    }

    /**
     * Address: 0x007E4B30 (FUN_007E4B30)
     *
     * What it does:
     * Performs one right-rotation around `node` in the mesh-bucket RB-tree.
     */
    void RotateMeshBatchTreeRight(MeshBatchBucketNode* const node, MeshBatchBucketTree& tree)
    {
      MeshBatchBucketNode* const pivot = node->left;
      node->left = pivot->right;
      if (!IsSentinelNode(pivot->right)) {
        pivot->right->parent = node;
      }

      pivot->parent = node->parent;
      MeshBatchBucketNode* const head = tree.head;
      if (node == head->parent) {
        head->parent = pivot;
      } else {
        MeshBatchBucketNode* const parent = node->parent;
        if (node == parent->right) {
          parent->right = pivot;
        } else {
          parent->left = pivot;
        }
      }

      pivot->right = node;
      node->parent = pivot;
    }

    /**
     * Address: 0x007E3F10 (FUN_007E3F10)
     *
     * What it does:
     * Rebalances the RB-tree after linking one red node.
     */
    void RebalanceAfterInsert(MeshBatchBucketTree& tree, MeshBatchBucketNode* node)
    {
      MeshBatchBucketNode* const head = tree.head;
      while (!IsSentinelNode(node->parent) && node->parent->color == kNodeRed) {
        MeshBatchBucketNode* const parent = node->parent;
        MeshBatchBucketNode* const grandParent = parent->parent;

        if (parent == grandParent->left) {
          MeshBatchBucketNode* const uncle = grandParent->right;
          if (!IsSentinelNode(uncle) && uncle->color == kNodeRed) {
            parent->color = kNodeBlack;
            uncle->color = kNodeBlack;
            grandParent->color = kNodeRed;
            node = grandParent;
          } else {
            if (node == parent->right) {
              node = parent;
              RotateMeshBatchTreeLeft(node, tree);
            }

            node->parent->color = kNodeBlack;
            node->parent->parent->color = kNodeRed;
            RotateMeshBatchTreeRight(node->parent->parent, tree);
          }
        } else {
          MeshBatchBucketNode* const uncle = grandParent->left;
          if (!IsSentinelNode(uncle) && uncle->color == kNodeRed) {
            parent->color = kNodeBlack;
            uncle->color = kNodeBlack;
            grandParent->color = kNodeRed;
            node = grandParent;
          } else {
            if (node == parent->left) {
              node = parent;
              RotateMeshBatchTreeRight(node, tree);
            }

            node->parent->color = kNodeBlack;
            node->parent->parent->color = kNodeRed;
            RotateMeshBatchTreeLeft(node->parent->parent, tree);
          }
        }
      }

      if (!IsSentinelNode(head->parent)) {
        head->parent->color = kNodeBlack;
      }
    }

    void LinkInsertedNode(
      MeshBatchBucketTree& tree,
      MeshBatchBucketNode* const parent,
      MeshBatchBucketNode* const insertedNode,
      const bool insertLeft
    )
    {
      MeshBatchBucketNode* const head = tree.head;
      if (parent == head) {
        head->parent = insertedNode;
        head->left = insertedNode;
        head->right = insertedNode;
        return;
      }

      if (insertLeft) {
        parent->left = insertedNode;
        if (parent == head->left) {
          head->left = insertedNode;
        }
        return;
      }

      parent->right = insertedNode;
      if (parent == head->right) {
        head->right = insertedNode;
      }
    }
  } // namespace

  /**
   * Address: 0x007DB060 (FUN_007DB060)
   *
   * What it does:
   * Initializes RTTI/vtable identity for one mesh-batch key object.
   */
  MeshBatchKey::MeshBatchKey() = default;

  /**
   * Address: 0x007DB0B0 (FUN_007DB0B0)
   *
   * What it does:
   * Releases one mesh-batch key object when called as deleting destructor.
   */
  MeshBatchKey::~MeshBatchKey() = default;

  MeshBatchBucket::MeshBatchBucket()
    : key()
    , instances{nullptr, nullptr, nullptr, nullptr}
  {}

  /**
   * Address: 0x007E36C0 (FUN_007E36C0, ??0MeshBatchBucket@Moho@@QAE@ABU01@@Z)
   *
   * What it does:
   * Copy-constructs one mesh-batch bucket key and clones the owned
   * instance-pointer vector payload.
   */
  MeshBatchBucket::MeshBatchBucket(const MeshBatchBucket& other)
    : key(other.key)
    , instances(CloneMeshBatchInstanceVector(other.instances))
  {}

  /**
   * Address: 0x007E35B0 (FUN_007E35B0)
   *
   * What it does:
   * Returns whether `second` compares less than `first` in mesh-batch key order.
   */
  bool MeshBatchKeyIsSecondLessThanFirst(const MeshBatchKey& first, const MeshBatchKey& second)
  {
    if (second.mSortKey == first.mSortKey) {
      const std::uint8_t secondStatic = second.mIsStaticPose;
      const std::uint8_t firstStatic = first.mIsStaticPose;
      if (secondStatic == firstStatic) {
        return second.mLodIndexKey < first.mLodIndexKey;
      }

      if (secondStatic || firstStatic == 0U) {
        return false;
      }
    } else if (first.mSortKey <= second.mSortKey) {
      return false;
    }

    return true;
  }

  bool MeshBatchKeyLess(const MeshBatchKey& lhs, const MeshBatchKey& rhs)
  {
    return MeshBatchKeyIsSecondLessThanFirst(rhs, lhs);
  }

  bool MeshBatchKeyHasHigherPriority(const MeshBatchKey& lhs, const MeshBatchKey& rhs)
  {
    return MeshBatchKeyIsSecondLessThanFirst(lhs, rhs);
  }

  /**
   * Address: 0x007E40C0 (FUN_007E40C0)
   *
   * What it does:
   * Returns the first node not ordered before `key` in the batch-bucket RB-tree.
   */
  MeshBatchBucketNode* MeshBatchBucketTreeLowerBound(const MeshBatchBucketTree& tree, const MeshBatchKey& key)
  {
    MeshBatchBucketNode* const head = tree.head;
    if (!head) {
      return nullptr;
    }

    MeshBatchBucketNode* candidate = head;
    for (MeshBatchBucketNode* node = head->parent; !IsSentinelNode(node);) {
      if (MeshBatchKeyLess(node->bucket.key, key)) {
        node = node->right;
      } else {
        candidate = node;
        node = node->left;
      }
    }

    return candidate;
  }

  /**
   * Address: 0x007E4FA0 (FUN_007E4FA0)
   *
   * What it does:
   * Moves one mesh-bucket RB-tree iterator lane backward.
   */
  [[maybe_unused]] MeshBatchBucketNode* RetreatMeshBatchBucketIterator(
    const std::uint32_t /*unused*/,
    MeshBatchBucketNode** const iteratorLane
  )
  {
    if (iteratorLane == nullptr || *iteratorLane == nullptr) {
      return nullptr;
    }

    MeshBatchBucketNode* const node = *iteratorLane;
    if (IsSentinelNode(node)) {
      MeshBatchBucketNode* const right = node->right;
      *iteratorLane = right;
      return right;
    }

    MeshBatchBucketNode* left = node->left;
    if (IsSentinelNode(left)) {
      MeshBatchBucketNode* parent = node->parent;
      while (!IsSentinelNode(parent)) {
        if (*iteratorLane != parent->left) {
          break;
        }
        *iteratorLane = parent;
        parent = parent->parent;
      }

      if (!IsSentinelNode(*iteratorLane)) {
        *iteratorLane = parent;
      }
      return parent;
    }

    MeshBatchBucketNode* right = left->right;
    while (!IsSentinelNode(right)) {
      left = right;
      right = right->right;
    }

    *iteratorLane = left;
    return right;
  }

  /**
   * Address: 0x007E3CF0 (FUN_007E3CF0)
   *
   * What it does:
   * Inserts one unique key bucket into the RB-tree and reports whether insertion happened.
   */
  MeshBatchBucketLookupResult MeshBatchBucketTreeInsertUnique(MeshBatchBucketTree& tree, const MeshBatchBucket& bucket)
  {
    MeshBatchBucketLookupResult result{};
    result.node = nullptr;
    result.inserted = 0;

    MeshBatchBucketNode* const head = tree.head;
    if (!head) {
      return result;
    }

    MeshBatchBucketNode* parent = head;
    MeshBatchBucketNode* node = head->parent;
    bool insertLeft = true;

    while (!IsSentinelNode(node)) {
      parent = node;
      if (MeshBatchKeyLess(bucket.key, node->bucket.key)) {
        insertLeft = true;
        node = node->left;
        continue;
      }

      if (MeshBatchKeyLess(node->bucket.key, bucket.key)) {
        insertLeft = false;
        node = node->right;
        continue;
      }

      result.node = node;
      return result;
    }

    if (tree.size >= kMeshBatchTreeMaxSize) {
      throw std::length_error("map/set<T> too long");
    }

    MeshBatchBucketNode* const insertedNode = CreateMeshBatchBucketNode(parent, head, bucket);
    LinkInsertedNode(tree, parent, insertedNode, insertLeft);
    ++tree.size;
    RebalanceAfterInsert(tree, insertedNode);

    result.node = insertedNode;
    result.inserted = 1;
    return result;
  }

  /**
   * Address: 0x007E2C60 (FUN_007E2C60)
   *
   * What it does:
   * Finds or creates the instance-vector bucket associated with one mesh-batch key.
   */
  MeshBatchInstanceVector* MeshBatchBucketTreeFindOrCreateInstances(const MeshBatchKey& key, MeshBatchBucketTree& tree)
  {
    MeshBatchBucketNode* const head = tree.head;
    if (!head) {
      return nullptr;
    }

    MeshBatchBucketNode* const candidate = MeshBatchBucketTreeLowerBound(tree, key);
    if (candidate && candidate != head && MeshBatchKeyEqual(candidate->bucket.key, key)) {
      return &candidate->bucket.instances;
    }

    MeshBatchBucket bucket{};
    bucket.key = key;
    bucket.instances.proxy = nullptr;
    bucket.instances.first = nullptr;
    bucket.instances.last = nullptr;
    bucket.instances.end = nullptr;

    const MeshBatchBucketLookupResult lookup = MeshBatchBucketTreeInsertUnique(tree, bucket);
    return lookup.node ? &lookup.node->bucket.instances : nullptr;
  }
} // namespace moho
