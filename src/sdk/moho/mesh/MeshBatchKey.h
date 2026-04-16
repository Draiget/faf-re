#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  class MeshInstance;

  struct MeshBatchInstanceVector
  {
    void* proxy;          // +0x00
    MeshInstance** first; // +0x04
    MeshInstance** last;  // +0x08
    MeshInstance** end;   // +0x0C
  };

  class MeshBatchKey
  {
  public:
    /**
     * Address: 0x007DB060 (FUN_007DB060)
     *
     * What it does:
     * Initializes RTTI/vtable identity for one mesh-batch key object.
     */
    MeshBatchKey();

    /**
     * Address: 0x007DB0B0 (FUN_007DB0B0)
     *
     * What it does:
     * Releases one mesh-batch key object when called as deleting destructor.
     */
    virtual ~MeshBatchKey();

  public:
    std::uint8_t mIsStaticPose; // +0x04
    std::uint8_t pad_05_07[0x03];
    std::int32_t mLodIndexKey; // +0x08
    float mSortKey;            // +0x0C
  };

  struct MeshBatchBucket
  {
    /**
     * Local source compatibility constructor for default-constructed bucket lanes.
     */
    MeshBatchBucket();

    /**
     * Address: 0x007E36C0 (FUN_007E36C0, ??0MeshBatchBucket@Moho@@QAE@ABU01@@Z)
     *
     * What it does:
     * Copy-constructs one mesh-batch bucket by cloning key lanes and
     * duplicating the owned instance-pointer vector payload.
     */
    MeshBatchBucket(const MeshBatchBucket& other);

    MeshBatchKey key;                  // +0x00
    MeshBatchInstanceVector instances; // +0x10
  };

  struct MeshBatchBucketNode
  {
    MeshBatchBucketNode* left;   // +0x00
    MeshBatchBucketNode* parent; // +0x04
    MeshBatchBucketNode* right;  // +0x08
    MeshBatchBucket bucket;      // +0x0C
    std::uint8_t color;          // +0x2C (RB-tree color)
    std::uint8_t isSentinel;     // +0x2D (nil/header marker)
    std::uint8_t pad_2E_2F[0x02];
  };

  struct MeshBatchBucketLookupResult
  {
    MeshBatchBucketNode* node; // +0x00
    std::uint8_t inserted;     // +0x04
    std::uint8_t pad_05_07[0x03];
  };

  struct MeshBatchBucketTree
  {
    void* proxy;               // +0x00
    MeshBatchBucketNode* head; // +0x04 (RB-tree sentinel/header node)
    std::uint32_t size;        // +0x08
  };

  /**
   * Address: 0x007E35B0 (FUN_007E35B0)
   *
   * What it does:
   * Returns whether `second` compares less than `first` in mesh-batch key order.
   */
  [[nodiscard]] bool MeshBatchKeyIsSecondLessThanFirst(const MeshBatchKey& first, const MeshBatchKey& second);

  [[nodiscard]] bool MeshBatchKeyLess(const MeshBatchKey& lhs, const MeshBatchKey& rhs);
  [[nodiscard]] bool MeshBatchKeyHasHigherPriority(const MeshBatchKey& lhs, const MeshBatchKey& rhs);

  /**
   * Address: 0x007E40C0 (FUN_007E40C0)
   *
   * What it does:
   * Returns the first node not ordered before `key` in the batch-bucket RB-tree.
   */
  [[nodiscard]] MeshBatchBucketNode*
  MeshBatchBucketTreeLowerBound(const MeshBatchBucketTree& tree, const MeshBatchKey& key);

  /**
   * Address: 0x007E3CF0 (FUN_007E3CF0)
   *
   * What it does:
   * Inserts one unique key bucket into the RB-tree and reports whether insertion happened.
   */
  [[nodiscard]] MeshBatchBucketLookupResult
  MeshBatchBucketTreeInsertUnique(MeshBatchBucketTree& tree, const MeshBatchBucket& bucket);

  /**
   * Address: 0x007E2C60 (FUN_007E2C60)
   *
   * What it does:
   * Finds or creates the instance-vector bucket associated with one mesh-batch key.
   */
  [[nodiscard]] MeshBatchInstanceVector*
  MeshBatchBucketTreeFindOrCreateInstances(const MeshBatchKey& key, MeshBatchBucketTree& tree);

  static_assert(offsetof(MeshBatchKey, mIsStaticPose) == 0x04, "MeshBatchKey::mIsStaticPose offset must be 0x04");
  static_assert(offsetof(MeshBatchKey, mLodIndexKey) == 0x08, "MeshBatchKey::mLodIndexKey offset must be 0x08");
  static_assert(offsetof(MeshBatchKey, mSortKey) == 0x0C, "MeshBatchKey::mSortKey offset must be 0x0C");
  static_assert(sizeof(MeshBatchKey) == 0x10, "MeshBatchKey size must be 0x10");

  static_assert(offsetof(MeshBatchBucket, key) == 0x00, "MeshBatchBucket::key offset must be 0x00");
  static_assert(offsetof(MeshBatchBucket, instances) == 0x10, "MeshBatchBucket::instances offset must be 0x10");
  static_assert(sizeof(MeshBatchBucket) == 0x20, "MeshBatchBucket size must be 0x20");

  static_assert(offsetof(MeshBatchInstanceVector, proxy) == 0x00, "MeshBatchInstanceVector::proxy offset must be 0x00");
  static_assert(offsetof(MeshBatchInstanceVector, first) == 0x04, "MeshBatchInstanceVector::first offset must be 0x04");
  static_assert(offsetof(MeshBatchInstanceVector, last) == 0x08, "MeshBatchInstanceVector::last offset must be 0x08");
  static_assert(offsetof(MeshBatchInstanceVector, end) == 0x0C, "MeshBatchInstanceVector::end offset must be 0x0C");
  static_assert(sizeof(MeshBatchInstanceVector) == 0x10, "MeshBatchInstanceVector size must be 0x10");

  static_assert(offsetof(MeshBatchBucketNode, left) == 0x00, "MeshBatchBucketNode::left offset must be 0x00");
  static_assert(offsetof(MeshBatchBucketNode, bucket) == 0x0C, "MeshBatchBucketNode::bucket offset must be 0x0C");
  static_assert(offsetof(MeshBatchBucketNode, color) == 0x2C, "MeshBatchBucketNode::color offset must be 0x2C");
  static_assert(
    offsetof(MeshBatchBucketNode, isSentinel) == 0x2D, "MeshBatchBucketNode::isSentinel offset must be 0x2D"
  );
  static_assert(sizeof(MeshBatchBucketNode) == 0x30, "MeshBatchBucketNode size must be 0x30");

  static_assert(
    offsetof(MeshBatchBucketLookupResult, node) == 0x00, "MeshBatchBucketLookupResult::node offset must be 0x00"
  );
  static_assert(
    offsetof(MeshBatchBucketLookupResult, inserted) == 0x04, "MeshBatchBucketLookupResult::inserted offset must be 0x04"
  );
  static_assert(sizeof(MeshBatchBucketLookupResult) == 0x08, "MeshBatchBucketLookupResult size must be 0x08");

  static_assert(offsetof(MeshBatchBucketTree, proxy) == 0x00, "MeshBatchBucketTree::proxy offset must be 0x00");
  static_assert(offsetof(MeshBatchBucketTree, head) == 0x04, "MeshBatchBucketTree::head offset must be 0x04");
  static_assert(offsetof(MeshBatchBucketTree, size) == 0x08, "MeshBatchBucketTree::size offset must be 0x08");
  static_assert(sizeof(MeshBatchBucketTree) == 0x0C, "MeshBatchBucketTree size must be 0x0C");
} // namespace moho
