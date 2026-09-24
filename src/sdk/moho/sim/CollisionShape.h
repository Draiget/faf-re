#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3AxisAlignedBox3.h"

namespace moho
{
  class CColPrimitiveBase;
  class CollisionShapeBase;
  struct EntityOccupationManager;

  /**
   * One rectangle of 4x4 collision cells, as `func_AABoxToRect` (0x004FCBE0)
   * quantizes an AABB. RTTI: `Moho::CollisionDBRect`, the innermost base of
   * every entity's `CollisionShape<Entity>` subobject.
   */
  struct CollisionDBRect
  {
    std::uint16_t mStartX;
    std::uint16_t mStartZ;
    std::uint16_t mWidth;
    std::uint16_t mHeight;

    /**
     * Address: 0x004FCA10 (FUN_004FCA10, Moho::CollisionDBRect::NotEqual)
     *
     * What it does:
     * Returns `true` when any collision-rect lane differs from `other`.
     */
    [[nodiscard]] bool NotEqual(const CollisionDBRect& other) const noexcept;
  };
  static_assert(sizeof(CollisionDBRect) == 0x08, "CollisionDBRect size must be 0x08");

  /**
   * One pooled bucket-chain node of `EntityOccupationManager`: a shape is
   * linked into every bucket its rect covers, one node per cell.
   */
  struct EntityCollisionCellNode
  {
    EntityCollisionCellNode* next; // +0x00
    CollisionShapeBase* owner;     // +0x04
  };
  static_assert(sizeof(EntityCollisionCellNode) == 0x08, "EntityCollisionCellNode size must be 0x08");
  static_assert(offsetof(EntityCollisionCellNode, next) == 0x00, "EntityCollisionCellNode::next offset must be 0x00");
  static_assert(offsetof(EntityCollisionCellNode, owner) == 0x04, "EntityCollisionCellNode::owner offset must be 0x04");

  /**
   * RTTI: `Moho::CollisionShapeBase`, derived from `CollisionDBRect` at offset 0.
   * Its rect is the set of grid buckets the shape is currently linked into.
   *
   * `mMarked` is the gather flag the occupancy queries set while collecting
   * and clear afterwards (byte `cmp`/`mov` at +0x0C, e.g. 0x004FD2DF/0x004FD2E5);
   * `mBucketFlags` carries the `EEntityType` bits that choose the bucket array
   * (0x100 units, 0x200 props, 0xC00 entities/projectiles) and filter queries.
   */
  class CollisionShapeBase : public CollisionDBRect
  {
  public:
    /**
     * What it does:
     * Empty rect, not yet linked. Inlined into every `Entity` constructor
     * (0x006779E0, 0x00678160, ...), which is where the grid comes from.
     */
    CollisionShapeBase(EntityOccupationManager* const grid, const std::uint32_t bucketFlags) noexcept
      : CollisionDBRect{0u, 0u, 0u, 0u}
      , mSpatialGrid(grid)
      , mMarked(0u)
      , mPad0D{}
      , mBucketFlags(bucketFlags)
    {}

    /**
     * What it does:
     * Unlinks the shape from every bucket it covers; `~Entity` (0x006785D0)
     * reaches `Remove` (0x004FD490) through this, after `~CTask` and the
     * dirty-list unlink.
     */
    ~CollisionShapeBase();

    CollisionShapeBase(const CollisionShapeBase&) = delete;
    CollisionShapeBase& operator=(const CollisionShapeBase&) = delete;

    /**
     * Address: 0x004FD420 (FUN_004FD420)
     *
     * What it does:
     * Grows the node pool to `mWidth * mHeight` free nodes, then links one node
     * into each covered bucket, row by row.
     */
    void Add();

    /**
     * Address: 0x004FD490 (FUN_004FD490)
     *
     * What it does:
     * Unlinks this shape's node from each covered bucket, row by row.
     */
    void Remove();

    /**
     * Address: 0x004FD590 (FUN_004FD590)
     *
     * What it does:
     * Quantizes `bounds` and, when the rect changed, relinks under the new one.
     */
    void UpdateRect(const Wm3::AxisAlignedBox3f& bounds);

    /**
     * Address: 0x004FD4F0 (FUN_004FD4F0)
     *
     * What it does:
     * Same, from `primitive->GetBoundingBox()`; a null primitive means the
     * empty rect, which unlinks the shape everywhere.
     */
    void UpdateRect(const CColPrimitiveBase* primitive);

  public:
    EntityOccupationManager* mSpatialGrid; // +0x08
    std::uint8_t mMarked;                  // +0x0C
    std::uint8_t mPad0D[3];                // +0x0D
    std::uint32_t mBucketFlags;            // +0x10

  private:
    void RelinkTo(const CollisionDBRect& rect);
  };
  static_assert(sizeof(CollisionShapeBase) == 0x14, "CollisionShapeBase size must be 0x14");
  static_assert(offsetof(CollisionShapeBase, mSpatialGrid) == 0x08, "CollisionShapeBase::mSpatialGrid offset must be 0x08");
  static_assert(offsetof(CollisionShapeBase, mMarked) == 0x0C, "CollisionShapeBase::mMarked offset must be 0x0C");
  static_assert(offsetof(CollisionShapeBase, mBucketFlags) == 0x10, "CollisionShapeBase::mBucketFlags offset must be 0x10");

  /**
   * RTTI: `Moho::CollisionShape<Moho::Entity>`, a base of `Entity` at +0x4C
   * (+0x54 in `Unit`, whose `Entity` sits at +0x08). The bucket nodes store
   * `CollisionShapeBase*`; every gather steps back to the owner with
   * `add reg, -4Ch` (e.g. 0x00722E30, 0x0075B0E3), which is `GetOwner()`.
   */
  template <class T>
  class CollisionShape : public CollisionShapeBase
  {
  public:
    using CollisionShapeBase::CollisionShapeBase;

    [[nodiscard]] T* GetOwner() noexcept
    {
      return static_cast<T*>(this);
    }

    [[nodiscard]] static T* OwnerOf(CollisionShapeBase* const shape) noexcept
    {
      return shape ? static_cast<T*>(static_cast<CollisionShape*>(shape)) : nullptr;
    }
  };
} // namespace moho
