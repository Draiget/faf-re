#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/Rect2.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/Vector.h"
#include "Wm3AxisAlignedBox3.h"

namespace moho
{
  enum EEntityType : std::uint32_t;

  class UserEntity;
  class CGeomSolid3;
  struct GeomCamera3;
  struct Vector4f;
  struct SphereBoundsProbe;

  template <class T> struct SpatialShardData;

  /**
   * One object's record in a spatial map -- the value a map node carries at
   * +0x0C. The node is 0x38: three links, this 0x28 entry, then the colour and
   * nil bytes at +0x34/+0x35 (every tree body in 0x005043B0..0x00505F40 reads
   * `_Isnil` at +0x35).
   *
   *   - `mBox` is the world box the owner last published (`UpdateBounds`,
   *     0x00501C10, copies six dwords into node+0x0C).
   *   - `mEntityType` is the routing mask `Register` was given; it picks the
   *     leaf map (0x100 unit, 0x400 projectile, 0x200 prop, anything else the
   *     generic lane) in `Insert` 0x00502200 and `RemoveNode` 0x00502340.
   *   - `mShardData` is the leaf lane holding the entry, null while it sits in
   *     the database's overflow map. `Insert` stores it through the fresh
   *     iterator; `Unregister` 0x00501BC0 branches on it.
   *   - `mFadeOut` is the dissolve cutoff and the map's sort key (see
   *     `SpatialEntryLess`); `UpdateDissolveCutoff` 0x00501B00 re-inserts the
   *     entry with a new one.
   *   - `mOwner` is the object that registered; every collect pushes it.
   */
  template <class T>
  struct SpatialEntry
  {
    Wm3::AxisAlignedBox3f mBox;      // +0x00
    std::uint32_t mEntityType;       // +0x18
    SpatialShardData<T>* mShardData; // +0x1C
    float mFadeOut;                  // +0x20
    T* mOwner;                       // +0x24
  };

  static_assert(sizeof(SpatialEntry<UserEntity>) == 0x28, "SpatialEntry<T> size must be 0x28");
  static_assert(offsetof(SpatialEntry<UserEntity>, mEntityType) == 0x18, "SpatialEntry<T>::mEntityType offset must be 0x18");
  static_assert(offsetof(SpatialEntry<UserEntity>, mShardData) == 0x1C, "SpatialEntry<T>::mShardData offset must be 0x1C");
  static_assert(offsetof(SpatialEntry<UserEntity>, mFadeOut) == 0x20, "SpatialEntry<T>::mFadeOut offset must be 0x20");
  static_assert(offsetof(SpatialEntry<UserEntity>, mOwner) == 0x24, "SpatialEntry<T>::mOwner offset must be 0x24");

  /**
   * The spatial map's ordering: entries that never fade (`mFadeOut <= 0`)
   * first, in ascending order, then the fading ones by descending cutoff.
   *
   * That order is what lets the view collect stop early.
   * `SpatialShardData<T>::FindInVolumeFromData` (0x00503730) walks a map
   * front to back and breaks at the first fading entry whose cutoff the view
   * already reaches -- every entry after it fades out sooner.
   *
   * Decoded from the compare MSVC inlined into the tree's insert (0x00504990)
   * and hinted insert (0x00504A10): `0 < lhs` selects the first arm, and in it
   * `rhs <= 0` answers false; otherwise `0 < rhs` answers true.
   */
  template <class T>
  struct SpatialEntryLess
  {
    [[nodiscard]] bool operator()(const SpatialEntry<T>& lhs, const SpatialEntry<T>& rhs) const noexcept
    {
      if (lhs.mFadeOut > 0.0f) {
        return rhs.mFadeOut > 0.0f && lhs.mFadeOut > rhs.mFadeOut;
      }
      return rhs.mFadeOut > 0.0f || lhs.mFadeOut < rhs.mFadeOut;
    }
  };

  /**
   * The spatial database's map type: a VC8 multiset of entries in fade order.
   * Its insert/erase/destroy bodies are the tree's own and are cited on
   * `msvc8::multiset` and `msvc8::detail::rb_tree`.
   */
  template <class T>
  using SpatialMap = msvc8::multiset<SpatialEntry<T>, SpatialEntryLess<T>>;

  static_assert(sizeof(SpatialMap<UserEntity>) == 0x0C, "SpatialMap<T> size must be 0x0C");

  template <class T>
  struct SpatialShard
  {
    SpatialShard<T>* mParent;                   // +0x00
    gpg::Rect2i mAreaRect;                      // +0x04
    std::int32_t mLevel;                        // +0x14
    std::int32_t mUnitCount;                    // +0x18
    std::int32_t mProjectileCount;              // +0x1C
    std::int32_t mPropCount;                    // +0x20
    std::int32_t mEntityCount;                  // +0x24
    Wm3::AxisAlignedBox3f mBounds;              // +0x28
    msvc8::vector<SpatialShard<T>*> mShards;    // +0x40, the 4x4 children while mLevel > 0
    msvc8::vector<SpatialShardData<T>*> mData;  // +0x50, the 4x4 leaf lanes once mLevel <= 0

    /**
     * Address: 0x005011A0 (FUN_005011A0, Moho::SpatialShard<T>::SpatialShard)
     *
     * What it does:
     * Builds one shard node (or one leaf-data lane set) for the recursive 4x4
     * spatial partition tree.
     */
    SpatialShard(std::int32_t level, SpatialShard<T>* parent, const gpg::Rect2i& areaRect);

    /**
     * Address: 0x00501370 (FUN_00501370, Moho::SpatialShard<T>::~SpatialShard)
     *
     * What it does:
     * Deletes the owned child shards or leaf-data lanes and clears whichever
     * vector held them; both vectors then release their storage as members.
     */
    ~SpatialShard();

    SpatialShard(const SpatialShard&) = delete;
    SpatialShard& operator=(const SpatialShard&) = delete;

    /**
     * Address: 0x00501490 (FUN_00501490, Moho::SpatialShard<T>::CountType)
     *
     * What it does:
     * Returns true when this shard has no entities for the requested type mask.
     */
    [[nodiscard]] bool CountType(EEntityType type) const;

    /**
     * Address: 0x00501710 (FUN_00501710, Moho::SpatialShard<T>::DecrementCount)
     *
     * What it does:
     * Decrements one requested entity-lane counter on this shard and all
     * ancestors.
     */
    static void DecrementCount(SpatialShard<T>* shard, EEntityType type);

    /**
     * Address: 0x00501500 (FUN_00501500, Moho::SpatialShard<T>::RecalculateBounds)
     *
     * What it does:
     * Rebuilds this shard bounds from the 16 child lanes and propagates
     * recalculation up the parent chain.
     */
    void RecalculateBounds();
  };

  static_assert(sizeof(SpatialShard<UserEntity>) == 0x60, "SpatialShard<T> size must be 0x60");
  static_assert(offsetof(SpatialShard<UserEntity>, mLevel) == 0x14, "SpatialShard<T>::mLevel offset must be 0x14");
  static_assert(offsetof(SpatialShard<UserEntity>, mBounds) == 0x28, "SpatialShard<T>::mBounds offset must be 0x28");
  static_assert(offsetof(SpatialShard<UserEntity>, mShards) == 0x40, "SpatialShard<T>::mShards offset must be 0x40");
  static_assert(offsetof(SpatialShard<UserEntity>, mData) == 0x50, "SpatialShard<T>::mData offset must be 0x50");

  template <class T>
  struct SpatialShardData
  {
    using iterator = typename SpatialMap<T>::iterator;

    SpatialShard<T>* mShard;       // +0x00

    /**
     * +0x04..+0x13. Four dwords the constructor at 0x00500F60 stores zero into
     * individually, so a member was declared here -- this is not compiler
     * padding. Nothing else in the subsystem touches it: not the destructor at
     * 0x005017E0, not HasType (which answers per-type queries from the map
     * sizes at +0x38/+0x44/+0x50/+0x5C), not RecalculateBounds, and not any of
     * the collect or find bodies. Both constructors that build one of these
     * leave it at zero -- the database at 0x00501D80 for its inline lane, and
     * the shard at 0x005011A0 for each of its 16 leaf lanes.
     *
     * The sibling SpatialShard carries a gpg::Rect2i at this exact offset and
     * width, followed by a dword at +0x14, so an identical header is the
     * natural reading. It stays unnamed because the shard *assigns* its rect
     * while this zeroes, and no reader exists to settle the difference.
     */
    std::uint8_t mUnknown_04_13[0x10];
    std::int32_t mTimeSinceRecalc; // +0x14
    Wm3::AxisAlignedBox3f mBounds; // +0x18
    SpatialMap<T> mMapUnits;       // +0x30
    SpatialMap<T> mMapProjectiles; // +0x3C
    SpatialMap<T> mMapProps;       // +0x48
    SpatialMap<T> mMapEntities;    // +0x54

    /**
     * Address: 0x00500F60 (FUN_00500F60, Moho::SpatialShardData<T>::SpatialShardData)
     *
     * What it does:
     * Names the owning shard, zeroes the header and staleness counter and
     * seeds the bounds inverted; the four maps construct their own heads.
     */
    explicit SpatialShardData(SpatialShard<T>* ownerShard);

    /**
     * Address: 0x005017E0 (FUN_005017E0, Moho::SpatialShardData<T>::~SpatialShardData)
     *
     * What it does:
     * Member destruction only: the four maps' `~_Tree`, entities first,
     * inlined into this body.
     */
    ~SpatialShardData();

    SpatialShardData(const SpatialShardData&) = delete;
    SpatialShardData& operator=(const SpatialShardData&) = delete;

    /**
     * Address: 0x00502200 (FUN_00502200)
     *
     * What it does:
     * Inserts one entry into the map its routing mask selects, widens this
     * lane's bounds, stores this lane into the entry through the new iterator,
     * and propagates the bounds and the type count up the shard chain.
     */
    iterator Insert(const SpatialEntry<T>& entry);

    /**
     * Address: 0x00502780 (FUN_00502780, Moho::SpatialShardData<T>::CollectFromData)
     *
     * What it does:
     * Appends all entity pointers from selected leaf maps to destination.
     */
    static void CollectFromData(EEntityType type, gpg::fastvector<T*>& destination, SpatialShardData<T>* data);

    /**
     * Address: 0x00501070 (FUN_00501070, Moho::SpatialShardData<T>::HasType)
     *
     * What it does:
     * Returns true when this leaf-data lane has no entities for the requested
     * type mask.
     */
    [[nodiscard]] static bool HasType(const SpatialShardData<T>* data, EEntityType type);

    /**
     * Address: 0x005023B0 (FUN_005023B0, Moho::SpatialShardData<T>::RecalculateBounds)
     *
     * What it does:
     * Rebuilds leaf-map aggregate bounds and updates owner shard bounds.
     */
    void RecalculateBounds();

    /**
     * Address: 0x00503BB0 (FUN_00503BB0, Moho::SpatialShardData<T>::Collect)
     *
     * What it does:
     * Recursively collects selected entities from every shard/data lane.
     */
    static void Collect(SpatialShard<T>* shard, EEntityType type, gpg::fastvector<T*>& destination);

    /**
     * Address: 0x00503C00 (FUN_00503C00, Moho::SpatialShardData<T>::CollectInBox)
     *
     * What it does:
     * Recursively collects selected entities that intersect one AABB query.
     */
    static void CollectInBox(
      SpatialShard<T>* shard,
      EEntityType type,
      const Wm3::AxisAlignedBox3f& bounds,
      gpg::fastvector<T*>& destination
    );

    /**
     * Address: 0x00502950 (FUN_00502950, Moho::SpatialShardData<T>::CollectInBoxFromData)
     *
     * What it does:
     * Collects selected leaf-map entities intersecting one AABB query.
     */
    void CollectInBoxFromData(
      const Wm3::AxisAlignedBox3f& bounds,
      EEntityType type,
      gpg::fastvector<T*>& destination
    );

    /**
     * Address: 0x00503DB0 (FUN_00503DB0, Moho::SpatialShardData<T>::CollectInVolume)
     *
     * What it does:
     * Recursively collects selected entities that intersect one convex volume.
     */
    static void CollectInVolume(
      SpatialShard<T>* shard,
      EEntityType type,
      CGeomSolid3* volume,
      gpg::fastvector<T*>& destination
    );

    /**
     * Address: 0x00503490 (FUN_00503490, Moho::SpatialShardData<T>::CollectInVolumeFromData)
     *
     * What it does:
     * Collects selected leaf-map entities intersecting one convex volume.
     */
    void CollectInVolumeFromData(gpg::fastvector<T*>& destination, EEntityType type, CGeomSolid3* volume);

    /**
     * Address: 0x00503D40 (FUN_00503D40, Moho::SpatialShardData<T>::CollectInSphere)
     *
     * What it does:
     * Recursively collects selected entities that intersect one bounding
     * sphere — walks the 4x4 child shard array, recursing into non-leaf
     * children and dispatching to the per-leaf `CollectInSphereFromData`
     * helper at the bottom level.
     */
    [[nodiscard]] static bool CollectInSphere(
      SpatialShard<T>* shard,
      EEntityType type,
      const SphereBoundsProbe& probe,
      gpg::fastvector<T*>& destination
    );

    /**
     * Address: 0x005030C0 (FUN_005030C0, Moho::SpatialShardData<T>::CollectInSphereFromData)
     *
     * What it does:
     * Collects entities from this leaf shard-data lane that intersect one
     * bounding sphere. Skips the lane when the shard reports no entities of
     * the requested type or when the sphere does not touch the lane's AABB.
     * Refreshes the cached bounds if their staleness counter is over the
     * limit, then for each enabled entity-type bucket walks the associated
     * map appending owners whose box either intersects the sphere or is
     * fully contained by it.
     */
    [[nodiscard]] bool CollectInSphereFromData(
      EEntityType type,
      const SphereBoundsProbe& probe,
      gpg::fastvector<T*>& destination
    );

    /**
     * Address: 0x00502340 (FUN_00502340, Moho::SpatialShardData<T>::RemoveNode)
     *
     * What it does:
     * Erases one entry from the map its routing mask selects and decrements
     * shard counters up the parent chain.
     */
    void RemoveNode(iterator node);

    /**
     * Address: 0x00503730 (FUN_00503730, Moho::SpatialShardData<T>::FindInVolumeFromData)
     *
     * What it does:
     * Collects leaf-lane entities intersecting one volume with fade-threshold
     * early-out driven by support selector and viewport plane lanes.
     */
    static void FindInVolumeFromData(
      const Vector4f& fadePlane,
      const Wm3::Vector3f& supportSelector,
      SpatialShardData<T>* data,
      EEntityType type,
      CGeomSolid3* volume,
      gpg::fastvector<T*>& destination
    );

    /**
     * Address: 0x00503E30 (FUN_00503E30, Moho::SpatialShardData<T>::FindInVolume)
     *
     * What it does:
     * Recursively collects entities intersecting one volume using view/fade
     * cull inputs for leaf-lane filtering.
     */
    static void FindInVolume(
      SpatialShard<T>* shard,
      EEntityType type,
      CGeomSolid3* volume,
      const Wm3::Vector3f& supportSelector,
      const Vector4f& fadePlane,
      gpg::fastvector<T*>& destination
    );
  };

  static_assert(sizeof(SpatialShardData<UserEntity>) == 0x60, "SpatialShardData<T> size must be 0x60");
  static_assert(offsetof(SpatialShardData<UserEntity>, mTimeSinceRecalc) == 0x14, "SpatialShardData<T>::mTimeSinceRecalc offset must be 0x14");
  static_assert(offsetof(SpatialShardData<UserEntity>, mBounds) == 0x18, "SpatialShardData<T>::mBounds offset must be 0x18");
  static_assert(offsetof(SpatialShardData<UserEntity>, mMapUnits) == 0x30, "SpatialShardData<T>::mMapUnits offset must be 0x30");
  static_assert(offsetof(SpatialShardData<UserEntity>, mMapProjectiles) == 0x3C, "SpatialShardData<T>::mMapProjectiles offset must be 0x3C");
  static_assert(offsetof(SpatialShardData<UserEntity>, mMapProps) == 0x48, "SpatialShardData<T>::mMapProps offset must be 0x48");
  static_assert(offsetof(SpatialShardData<UserEntity>, mMapEntities) == 0x54, "SpatialShardData<T>::mMapEntities offset must be 0x54");

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
   */
  template <class T>
  struct SpatialDB
  {
    msvc8::vector<SpatialShard<T>*> mShards;  // +0x00, the 4x4 top-level shards
    SpatialShardData<T> mShardData;           // +0x10, entries outside the shard grid
    std::int32_t mMapWidth;                   // +0x70
    std::int32_t mMapHeight;                  // +0x74
    std::int32_t mShardWidth;                 // +0x78
    std::int32_t mShardHeight;                // +0x7C
    std::int32_t mShardLevel;                 // +0x80
    SpatialMap<T> mMapTree;                   // +0x84, registered entries not yet bounded

    /**
     * Address: 0x00501D80 (FUN_00501D80) -- member construction (the root lane
     * with no owning shard, the overflow map's head) and a `clear()` of the
     * shard vector.
     */
    SpatialDB();

    /**
     * Address: 0x00501E50 (FUN_00501E50) -- deletes the top-level shards; the
     * members release the rest.
     */
    ~SpatialDB();

    SpatialDB(const SpatialDB&) = delete;
    SpatialDB& operator=(const SpatialDB&) = delete;

    /** Address: 0x00501F50 -- rebuilds the top-level shards for a map size. */
    void ResizeForMap(std::int32_t width, std::int32_t height);

    /** Address: 0x00503F80 */
    std::int32_t Collect(gpg::fastvector<T*>& dest, EEntityType type);
    /** Address: 0x00504040 */
    std::int32_t CollectInBox(gpg::fastvector<T*>& dest, const Wm3::AxisAlignedBox3f& bounds);
    /** Address: 0x005040E0 */
    std::int32_t CollectInSphere(gpg::fastvector<T*>& dest, EEntityType type, const SphereBoundsProbe& probe);
    /** Address: 0x00504130 */
    std::int32_t CollectInVolume(gpg::fastvector<T*>& dest, EEntityType type, CGeomSolid3* volume);
    /** Address: 0x00504180 */
    std::int32_t CollectAllInVolume(
      gpg::fastvector<T*>& dest,
      CGeomSolid3* volume,
      const Wm3::Vector3f& supportSelector,
      const Vector4f& fadePlane
    );
    /** Address: 0x005041E0 */
    std::int32_t CollectInView(GeomCamera3* camera, gpg::fastvector<T*>& dest, EEntityType type);
  };

  /**
   * One object's registration in a `SpatialDB<T>` -- two words, embedded by
   * value in every participant (`MeshInstance` +0x0C, `UserEntity` +0x10,
   * `ShoreCell` +0x38, `CWldTerrainDecal` +0x0C, `WaveGenerator` +0x08).
   *
   *   - `mDb` (+0x00) is the database registered into. `Register` publishes it
   *     with `mov [edi], esi` before inserting.
   *   - `mNode` (+0x04) is the entry's iterator into whichever map holds it:
   *     the database's overflow map until the first `UpdateBounds`, a leaf
   *     lane's map after. Every member dereferences it immediately
   *     (`mov eax, [edi+4]; mov esi, [eax+0x28]` reads the entry's
   *     `mShardData`), because nothing calls one on an unregistered entry.
   *
   * Only the destructor and `Register` test `mDb`; `Unregister` zeroes it and
   * leaves `mNode` as it was.
   */
  template <class T>
  struct SpatialDBEntry
  {
    using iterator = typename SpatialMap<T>::iterator;

    SpatialDB<T>* mDb; // +0x00
    iterator mNode;    // +0x04

    /**
     * Address: 0x00501A70 (FUN_00501A70 -- the out-of-line copy: two zero
     * stores through `eax`; zero callers, no references, a linker-retained
     * copy nothing runs. Every owner's constructor inlines it. Formerly
     * `InitializeSpatialDbEntryPairZero` over a deleted overlay
     * in moho/mesh/Mesh.cpp (RULE THREE), removed 2026-09-29.)
     */
    SpatialDBEntry() noexcept
      : mDb(nullptr)
      , mNode()
    {}

    /**
     * Inlined at every owner's destructor as `cmp dword ptr [entry], 0` then
     * a call into `Unregister` 0x00501BC0 (0x007DE663 in `~MeshInstance`,
     * 0x008B888D in `~UserEntity`).
     *
     * Address: 0x00812760 (FUN_00812760 -- the out-of-line copy for
     * `SpatialDBEntry<ShoreCell>`; zero callers, no references, a
     * linker-retained copy nothing runs. Formerly
     * `DestroySpatialDbEntryIfBoundAdapter` in
     * moho/terrain/water/Shoreline.cpp, removed 2026-09-29.)
     */
    ~SpatialDBEntry()
    {
      if (mDb != nullptr) {
        Unregister();
      }
    }

    /** Address: 0x00501A80 -- rebinds this entry, unregistering any previous. */
    void Register(SpatialDB<T>* db, T* owner, std::int32_t routingMask);

    /** Address: 0x00501BC0 -- erases the entry from its map and clears `mDb`. */
    void Unregister();

    /** Address: 0x00501B00 -- re-inserts the entry under a new dissolve cutoff. */
    void UpdateDissolveCutoff(float cutoff);

    /** Address: 0x00501C10 -- republishes bounds, re-seating the entry if needed. */
    void UpdateBounds(const Wm3::AxisAlignedBox3f& bounds);
  };

  static_assert(sizeof(SpatialDBEntry<UserEntity>) == 0x08, "SpatialDBEntry size must be 0x08");
  static_assert(offsetof(SpatialDBEntry<UserEntity>, mNode) == 0x04, "SpatialDBEntry::mNode offset must be 0x04");
} // namespace moho
