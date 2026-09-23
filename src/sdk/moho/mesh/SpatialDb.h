#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/Rect2.h"
#include "Wm3AxisAlignedBox3.h"

namespace moho
{
  enum EEntityType : std::uint32_t;

  class UserEntity;
  class CGeomSolid3;
  struct GeomCamera3;
  struct Vector4f;
  struct SphereBoundsProbe;

  struct SpatialShardData;

  template <class T>
  struct SpatialShardArray
  {
    void* mDebugProxy; // +0x00
    T** mBegin;        // +0x04
    T** mEnd;          // +0x08
    T** mCapacity;     // +0x0C
  };

  static_assert(sizeof(SpatialShardArray<void>) == 0x10, "SpatialShardArray size must be 0x10");

  struct SpatialShard
  {
    SpatialShard* mParent;                     // +0x00
    gpg::Rect2i mAreaRect;                     // +0x04
    std::int32_t mLevel;                       // +0x14
    std::int32_t mUnitCount;                   // +0x18
    std::int32_t mProjectileCount;             // +0x1C
    std::int32_t mPropCount;                   // +0x20
    std::int32_t mEntityCount;                 // +0x24
    Wm3::AxisAlignedBox3f mBounds;             // +0x28
    SpatialShardArray<SpatialShard> mShards;   // +0x40
    SpatialShardArray<SpatialShardData> mData; // +0x50

    /**
     * Address: 0x005011A0 (FUN_005011A0, Moho::SpatialShard::SpatialShard)
     *
     * What it does:
     * Builds one shard node (or one leaf-data lane set) for the recursive 4x4
     * spatial partition tree.
     */
    SpatialShard(std::int32_t level, SpatialShard* parent, const gpg::Rect2i& areaRect);

    /**
     * Address: 0x00501370 (FUN_00501370, Moho::SpatialShard::~SpatialShard)
     *
     * What it does:
     * Releases recursively-owned child shards or leaf-data lanes and clears
     * shard pointer arrays.
     */
    ~SpatialShard();

    /**
     * Address: 0x00501490 (FUN_00501490, Moho::SpatialShard::CountType)
     *
     * What it does:
     * Returns true when this shard has no entities for the requested type mask.
     */
    [[nodiscard]] bool CountType(EEntityType type) const;

    /**
     * Address: 0x00501710 (FUN_00501710, Moho::SpatialShard::DecrementCount)
     *
     * What it does:
     * Decrements one requested entity-lane counter on this shard and all
     * ancestors.
     */
    static void DecrementCount(SpatialShard* shard, EEntityType type);

    /**
     * Address: 0x00501500 (FUN_00501500, Moho::SpatialShard::RecalculateBounds)
     *
     * What it does:
     * Rebuilds this shard bounds from the 16 child lanes and propagates
     * recalculation up the parent chain.
     */
    void RecalculateBounds();
  };

  static_assert(sizeof(SpatialShard) == 0x60, "SpatialShard size must be 0x60");
  static_assert(offsetof(SpatialShard, mLevel) == 0x14, "SpatialShard::mLevel offset must be 0x14");
  static_assert(offsetof(SpatialShard, mBounds) == 0x28, "SpatialShard::mBounds offset must be 0x28");
  static_assert(offsetof(SpatialShard, mShards) == 0x40, "SpatialShard::mShards offset must be 0x40");
  static_assert(offsetof(SpatialShard, mData) == 0x50, "SpatialShard::mData offset must be 0x50");

  struct SpatialMapNode
  {
    SpatialMapNode* mLeft;      // +0x00
    SpatialMapNode* mParent;    // +0x04
    SpatialMapNode* mRight;     // +0x08
    Wm3::AxisAlignedBox3f mBox; // +0x0C
    std::uint32_t mEntityType;     // +0x24
    SpatialShardData* mShardData;  // +0x28
    float mFadeOut;                // +0x2C
    void* mOwner;                  // +0x30
    std::uint8_t mColor;           // +0x34
    std::uint8_t mIsNil;           // +0x35
    std::uint8_t mPad_36_37[0x02];
  };

  static_assert(sizeof(SpatialMapNode) == 0x38, "SpatialMapNode size must be 0x38");
  static_assert(offsetof(SpatialMapNode, mBox) == 0x0C, "SpatialMapNode::mBox offset must be 0x0C");
  static_assert(offsetof(SpatialMapNode, mEntityType) == 0x24, "SpatialMapNode::mEntityType offset must be 0x24");
  static_assert(offsetof(SpatialMapNode, mShardData) == 0x28, "SpatialMapNode::mShardData offset must be 0x28");
  static_assert(offsetof(SpatialMapNode, mFadeOut) == 0x2C, "SpatialMapNode::mFadeOut offset must be 0x2C");
  static_assert(offsetof(SpatialMapNode, mOwner) == 0x30, "SpatialMapNode::mOwner offset must be 0x30");
  static_assert(offsetof(SpatialMapNode, mIsNil) == 0x35, "SpatialMapNode::mIsNil offset must be 0x35");

  struct SpatialMapTree
  {
    void* mAllocatorCookie; // +0x00
    SpatialMapNode* mHead;  // +0x04
    std::int32_t mSize;     // +0x08
  };

  static_assert(sizeof(SpatialMapTree) == 0x0C, "SpatialMapTree size must be 0x0C");

  struct SpatialShardData
  {
    SpatialShard* mShard;       // +0x00
    std::uint8_t mPad_04_13[0x10];
    std::int32_t mTimeSinceRecalc; // +0x14
    Wm3::AxisAlignedBox3f mBounds; // +0x18
    SpatialMapTree mMapUnits;      // +0x30
    SpatialMapTree mMapProjectiles; // +0x3C
    SpatialMapTree mMapProps;      // +0x48
    SpatialMapTree mMapEntities;   // +0x54

    /**
     * Address: 0x00500F60 (FUN_00500F60, Moho::SpatialShardData::SpatialShardData)
     *
     * What it does:
     * Initializes one leaf-data lane container and allocates sentinel map
     * heads for unit/projectile/prop/entity trees.
     */
    explicit SpatialShardData(SpatialShard* ownerShard);

    /**
     * The database embeds one of these as its inline root lane and fills it in
     * its own constructor body (0x00501D80), rather than through a member
     * initializer -- there is no owning shard to name at that point. This
     * leaves the members untouched, exactly as the binary does.
     */
    SpatialShardData() = default;

    /**
     * Address: 0x005017E0 (FUN_005017E0, Moho::SpatialShardData::~SpatialShardData)
     *
     * What it does:
     * Destroys all map nodes in unit/projectile/prop/entity trees and releases
     * their sentinel heads.
     */
    ~SpatialShardData();

    /**
     * Address: 0x00502780 (FUN_00502780, Moho::SpatialShardData::CollectFromData)
     *
     * What it does:
     * Appends all entity pointers from selected leaf maps to destination.
     */
    static void CollectFromData(EEntityType type, gpg::fastvector<UserEntity*>& destination, SpatialShardData* data);

    /**
     * Address: 0x00501070 (FUN_00501070, Moho::SpatialShardData::HasType)
     *
     * What it does:
     * Returns true when this leaf-data lane has no entities for the requested
     * type mask.
     */
    [[nodiscard]] static bool HasType(const SpatialShardData* data, EEntityType type);

    /**
     * Address: 0x005023B0 (FUN_005023B0, Moho::SpatialShardData::RecalculateBounds)
     *
     * What it does:
     * Rebuilds leaf-map aggregate bounds and updates owner shard bounds.
     */
    void RecalculateBounds();

    /**
     * Address: 0x00503BB0 (FUN_00503BB0, Moho::SpatialShardData::Collect)
     *
     * What it does:
     * Recursively collects selected entities from every shard/data lane.
     */
    static void Collect(SpatialShard* shard, EEntityType type, gpg::fastvector<UserEntity*>& destination);

    /**
     * Address: 0x00503C00 (FUN_00503C00, Moho::SpatialShardData::CollectInBox)
     *
     * What it does:
     * Recursively collects selected entities that intersect one AABB query.
     */
    static void CollectInBox(
      SpatialShard* shard,
      EEntityType type,
      const Wm3::AxisAlignedBox3f& bounds,
      gpg::fastvector<UserEntity*>& destination
    );

    /**
     * Address: 0x00502950 (FUN_00502950, Moho::SpatialShardData::CollectInBoxFromData)
     *
     * What it does:
     * Collects selected leaf-map entities intersecting one AABB query.
     */
    void CollectInBoxFromData(
      const Wm3::AxisAlignedBox3f& bounds,
      EEntityType type,
      gpg::fastvector<UserEntity*>& destination
    );

    /**
     * Address: 0x00503DB0 (FUN_00503DB0, Moho::SpatialShardData::CollectInVolume)
     *
     * What it does:
     * Recursively collects selected entities that intersect one convex volume.
     */
    static void CollectInVolume(
      SpatialShard* shard,
      EEntityType type,
      CGeomSolid3* volume,
      gpg::fastvector<UserEntity*>& destination
    );

    /**
     * Address: 0x00503490 (FUN_00503490, Moho::SpatialShardData::CollectInVolumeFromData)
     *
     * What it does:
     * Collects selected leaf-map entities intersecting one convex volume.
     */
    void CollectInVolumeFromData(gpg::fastvector<UserEntity*>& destination, EEntityType type, CGeomSolid3* volume);

    /**
     * Address: 0x00503D40 (FUN_00503D40, Moho::SpatialShardData::CollectInSphere)
     *
     * What it does:
     * Recursively collects selected entities that intersect one bounding
     * sphere — walks the 4x4 child shard array, recursing into non-leaf
     * children and dispatching to the per-leaf `CollectInSphereFromData`
     * helper at the bottom level.
     */
    [[nodiscard]] static bool CollectInSphere(
      SpatialShard* shard,
      EEntityType type,
      const SphereBoundsProbe& probe,
      gpg::fastvector<UserEntity*>& destination
    );

    /**
     * Address: 0x005030C0 (FUN_005030C0, Moho::SpatialShardData::CollectInSphereFromData)
     *
     * What it does:
     * Collects entities from this leaf shard-data lane that intersect one
     * bounding sphere. Skips the lane when the shard reports no entities of
     * the requested type or when the sphere does not touch the lane's AABB.
     * Refreshes the cached bounds if their staleness counter is over the
     * limit, then for each enabled entity-type bucket walks the associated
     * tree appending owners whose node-box either intersects the sphere or
     * is fully contained by it.
     */
    [[nodiscard]] bool CollectInSphereFromData(
      EEntityType type,
      const SphereBoundsProbe& probe,
      gpg::fastvector<UserEntity*>& destination
    );

    /**
     * Address: 0x00502340 (FUN_00502340, Moho::SpatialShardData::RemoveNode)
     *
     * What it does:
     * Removes one map node from the matching type lane and decrements shard
     * counters up the parent chain.
     */
    void RemoveNode(SpatialMapNode* node);

    /**
     * Address: 0x00503730 (FUN_00503730, Moho::SpatialShardData::FindInVolumeFromData)
     *
     * What it does:
     * Collects leaf-lane entities intersecting one volume with fade-threshold
     * early-out driven by support selector and viewport plane lanes.
     */
    static void FindInVolumeFromData(
      const Vector4f& fadePlane,
      const Wm3::Vector3f& supportSelector,
      SpatialShardData* data,
      EEntityType type,
      CGeomSolid3* volume,
      gpg::fastvector<UserEntity*>& destination
    );

    /**
     * Address: 0x00503E30 (FUN_00503E30, Moho::SpatialShardData::FindInVolume)
     *
     * What it does:
     * Recursively collects entities intersecting one volume using view/fade
     * cull inputs for leaf-lane filtering.
     */
    static void FindInVolume(
      SpatialShard* shard,
      EEntityType type,
      CGeomSolid3* volume,
      const Wm3::Vector3f& supportSelector,
      const Vector4f& fadePlane,
      gpg::fastvector<UserEntity*>& destination
    );
  };

  static_assert(sizeof(SpatialShardData) == 0x60, "SpatialShardData size must be 0x60");
  static_assert(offsetof(SpatialShardData, mTimeSinceRecalc) == 0x14, "SpatialShardData::mTimeSinceRecalc offset must be 0x14");
  static_assert(offsetof(SpatialShardData, mBounds) == 0x18, "SpatialShardData::mBounds offset must be 0x18");
  static_assert(offsetof(SpatialShardData, mMapUnits) == 0x30, "SpatialShardData::mMapUnits offset must be 0x30");
  static_assert(offsetof(SpatialShardData, mMapProjectiles) == 0x3C, "SpatialShardData::mMapProjectiles offset must be 0x3C");
  static_assert(offsetof(SpatialShardData, mMapProps) == 0x48, "SpatialShardData::mMapProps offset must be 0x48");
  static_assert(offsetof(SpatialShardData, mMapEntities) == 0x54, "SpatialShardData::mMapEntities offset must be 0x54");

  /**
   * The spatial database: a recursive 4x4 shard partition over the playable
   * area plus a fade-ordered overflow map. 0x90 bytes.
   *
   * This was a class template in the 2007 source and the binary still proves
   * it -- `MeshInstance`'s constructor mangles as
   * `??0MeshInstance@Moho@@QAE@PAV?$SpatialDB@VMeshInstance@Moho@@@1@H...`,
   * whose first parameter decodes to `Moho::SpatialDB<Moho::MeshInstance>*`.
   *
   * Two instantiations exist: `SpatialDB<MeshInstance>`, owned inline by
   * `MeshRenderer` at +0xAC, and `SpatialDB<UserEntity>`, owned inline by
   * `CWldSession` at +0x50. Their bodies differ only in pointer types, so
   * `/OPT:ICF` folded each pair onto one address -- which is why the export
   * names only one of them, and why this was previously recovered as a single
   * flat `SpatialDB_MeshInstance` that had to serve as both the database and
   * the per-object handle.
   *
   * `SpatialDB()` is 0x00501D80 and `~SpatialDB()` is 0x00501E50; the progress
   * db records the former under the class's own constructor name. They were
   * previously spelled as explicit `InitializeStorage()` / `DestroyStorage()`
   * calls at every owner, which is hand-written member construction.
   */
  template <class T>
  struct SpatialDB
  {
    SpatialShardArray<SpatialShard> mShards; // +0x00
    SpatialShardData mShardData;             // +0x10
    std::int32_t mMapWidth;                  // +0x70
    std::int32_t mMapHeight;                 // +0x74
    std::int32_t mShardWidth;                // +0x78
    std::int32_t mShardHeight;               // +0x7C
    std::int32_t mShardLevel;                // +0x80
    SpatialMapTree mMapTree;                 // +0x84

    /** Address: 0x00501D80 -- builds the root shard lanes and the map tree. */
    SpatialDB();

    /** Address: 0x00501E50 -- releases every shard lane and map node. */
    ~SpatialDB();

    SpatialDB(const SpatialDB&) = delete;
    SpatialDB& operator=(const SpatialDB&) = delete;

    /** Alias of 0x00501F50 -- rebuilds the top-level shards for a map size. */
    void ResizeForMap(std::int32_t width, std::int32_t height);

    // The collect destination is still typed `UserEntity*` even for
    // `SpatialDB<MeshInstance>`, where the slots are really `MeshInstance*`.
    // Typing it `T*` cascades into eight `SpatialShardData` helpers, so it is
    // a separate step; the payload stays erased at the node (`mOwner`) until
    // then.
    /** Address: 0x00503F80 */
    std::int32_t Collect(gpg::fastvector<UserEntity*>& dest, EEntityType type);
    /** Address: 0x00504040 */
    std::int32_t CollectInBox(gpg::fastvector<UserEntity*>& dest, const Wm3::AxisAlignedBox3f& bounds);
    /** Address: 0x005040E0 */
    std::int32_t CollectInSphere(gpg::fastvector<UserEntity*>& dest, EEntityType type, const SphereBoundsProbe& probe);
    /** Address: 0x00504130 */
    std::int32_t CollectInVolume(gpg::fastvector<UserEntity*>& dest, EEntityType type, CGeomSolid3* volume);
    /** Address: 0x00504180 */
    std::int32_t CollectAllInVolume(
      gpg::fastvector<UserEntity*>& dest,
      CGeomSolid3* volume,
      const Wm3::Vector3f& supportSelector,
      const Vector4f& fadePlane
    );
    /** Address: 0x005041E0 */
    std::int32_t CollectInView(GeomCamera3* camera, gpg::fastvector<UserEntity*>& dest, EEntityType type);
  };

  /**
   * One object's registration in a `SpatialDB<T>` -- two words, embedded by
   * value in every participant (`MeshInstance` +0x0C, `UserEntity` +0x10,
   * `ShoreCell` +0x38, `CWldTerrainDecal` +0x0C, `WaveGenerator` +0x08).
   *
   * Field evidence from `Register` (0x00501A80) and its teardown (0x00501BC0):
   *
   *   - `mDb` (+0x00) is the database registered into. `Register` publishes it
   *     with `mov [edi], esi`, `esi` being the storage root the caller passed
   *     -- `CWldSession + 0x50` for entities.
   *   - `mNode` (+0x04) is the node the insert produced, not an index.
   *     `Register` stores it with `mov [edi+4], edx`, and the teardown
   *     dereferences it immediately: `mov eax, [edi+4]; mov esi, [eax+0x28]`,
   *     +0x28 being `SpatialMapNode::mShardData`. Typing it `std::int32_t` is
   *     why consumers had to launder it through casts.
   *
   * Both entry points guard on `mDb != nullptr` and the teardown zeroes it, so
   * unregistering twice is a no-op by construction.
   */
  template <class T>
  struct SpatialDBEntry
  {
    SpatialDB<T>* mDb;     // +0x00
    SpatialMapNode* mNode; // +0x04

    /** Address: 0x00501A80 -- rebinds this entry, unregistering any previous. */
    void Register(SpatialDB<T>* db, T* owner, std::int32_t routingMask);

    /** Address: 0x00501B00 -- updates the dissolve cutoff on this entry's node. */
    void UpdateDissolveCutoff(float cutoff);

    /** Address: 0x00501C10 -- republishes bounds, re-seating the node if needed. */
    void UpdateBounds(const Wm3::AxisAlignedBox3f& bounds);

    /** Drops local state without touching a database already torn down. */
    void ClearRegistration() noexcept;

    /** Address: 0x00501BC0 -- removes the node and clears `mDb`. */
    ~SpatialDBEntry();
  };

  static_assert(sizeof(SpatialDBEntry<UserEntity>) == 0x08, "SpatialDBEntry size must be 0x08");
} // namespace moho
