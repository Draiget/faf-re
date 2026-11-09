#include "moho/mesh/MeshPrivate.h"


bool moho::ren_ParallelCull = true;
namespace
{

  constexpr std::uint32_t kSpatialEntityTypeUnit = 0x00000100u;
  constexpr std::uint32_t kSpatialEntityTypeProjectile = 0x00000400u;
  constexpr std::uint32_t kSpatialEntityTypeProp = 0x00000200u;
  constexpr std::uint32_t kSpatialEntityTypeEntity = 0x00000800u;
  constexpr std::int32_t kSpatialShardSlotCount = 16;
  constexpr std::int32_t kSpatialShardGridDimension = 4;
  constexpr std::int32_t kSpatialShardLevelSmall = 1;
  constexpr std::int32_t kSpatialShardLevelMedium = 2;
  constexpr std::int32_t kSpatialShardLevelLarge = 3;
  constexpr std::int32_t kSpatialShardLevelSmallThreshold = 0x100;
  constexpr std::int32_t kSpatialShardLevelMediumThreshold = 0x400;
  constexpr std::int32_t kSpatialShardCellSizeByLevel[4] = {
    16,   // index 0 (unused by shard constructors)
    64,   // index 1
    256,  // index 2
    1024, // index 3
  };

  [[nodiscard]] std::uint32_t EntityTypeBits(const moho::EEntityType type) noexcept
  {
    return static_cast<std::uint32_t>(type);
  }

  template <class T>
  [[nodiscard]] bool SpatialShardHasNoRequestedType(const moho::SpatialShard<T>& shard, const moho::EEntityType type) noexcept
  {
    return shard.CountType(type);
  }

  template <class T>
  [[nodiscard]] bool SpatialShardDataHasNoRequestedType(
    const moho::SpatialShardData<T>& data,
    const moho::EEntityType type
  ) noexcept
  {
    return moho::SpatialShardData<T>::HasType(&data, type);
  }

  [[nodiscard]] bool SolidContainsAabb(const moho::CGeomSolid3& solid, const Wm3::AxisAlignedBox3f& bounds) noexcept
  {
    for (const Wm3::Plane3f& plane : solid.planes_) {
      const float supportX = std::signbit(plane.Normal.x) ? bounds.Min.x : bounds.Max.x;
      const float supportY = std::signbit(plane.Normal.y) ? bounds.Min.y : bounds.Max.y;
      const float supportZ = std::signbit(plane.Normal.z) ? bounds.Min.z : bounds.Max.z;

      const float signedDistance =
        (plane.Normal.x * supportX) + (plane.Normal.y * supportY) + (plane.Normal.z * supportZ) - plane.Constant;
      if (signedDistance > 0.0f) {
        return false;
      }
    }

    return true;
  }

  using moho::SphereBoundsProbe;
  static_assert(sizeof(SphereBoundsProbe) == 0x10, "SphereBoundsProbe size must be 0x10");

  /**
   * Address: 0x00500C50 (FUN_00500C50)
   *
   * What it does:
   * Returns true when the sphere defined by `probe.center` / `probe.radius`
   * intersects (or fully contains) the axis-aligned box `bounds`. Implements
   * the classic "closest-point-on-AABB to sphere center, then compare to
   * radius squared" test — the binary computes per-axis distance via two
   * `max(min - p, p - max, 0)` reductions then sums their squares.
   *
   * IDA signature:
   *   BOOL sub_500C50(float *bounds@<eax>, float *sphere@<ecx>);
   * where `bounds = {minX, minY, minZ, maxX, maxY, maxZ}` and
   *       `sphere = {x, y, z, radius}`.
   */
  [[nodiscard]] bool SphereIntersectsAabb(
    const Wm3::AxisAlignedBox3f& bounds,
    const SphereBoundsProbe& probe
  ) noexcept
  {
    const auto axisDistance = [](const float minLane, const float maxLane, const float centerLane) noexcept {
      float gap = centerLane - maxLane;
      const float belowLane = minLane - centerLane;
      if (belowLane > gap) {
        gap = belowLane;
      }
      return gap < 0.0f ? 0.0f : gap;
    };

    const float dx = axisDistance(bounds.Min.x, bounds.Max.x, probe.center.x);
    const float dy = axisDistance(bounds.Min.y, bounds.Max.y, probe.center.y);
    const float dz = axisDistance(bounds.Min.z, bounds.Max.z, probe.center.z);

    return (probe.radius * probe.radius) >= ((dx * dx) + (dy * dy) + (dz * dz));
  }

  /**
   * Address: 0x00500D00 (FUN_00500D00)
   *
   * What it does:
   * Returns true when both the minimum-corner and the maximum-corner of
   * `bounds` lie strictly within the sphere. For an axis-aligned box the two
   * opposite corners are the furthest pair of vertices, so this serves as a
   * conservative "sphere contains AABB" test used by the spatial-shard sphere
   * collect leaf path to short-circuit per-entity intersection checks: when
   * it returns true the entire shard-data lane is inside the sphere and
   * every node owner is accepted unconditionally.
   *
   * IDA signature:
   *   bool sub_500D00(float *sphere@<edi>, float *bounds@<esi>);
   */
  [[nodiscard]] bool SphereContainsAabbDiagonal(
    const SphereBoundsProbe& probe,
    const Wm3::AxisAlignedBox3f& bounds
  ) noexcept
  {
    const auto distanceSquaredTo = [&probe](const float x, const float y, const float z) noexcept {
      const float dx = std::fabs(x - probe.center.x);
      const float dy = std::fabs(y - probe.center.y);
      const float dz = std::fabs(z - probe.center.z);
      return (dx * dx) + (dy * dy) + (dz * dz);
    };

    const float radiusSquared = probe.radius * probe.radius;
    if (distanceSquaredTo(bounds.Min.x, bounds.Min.y, bounds.Min.z) > radiusSquared) {
      return false;
    }
    return distanceSquaredTo(bounds.Max.x, bounds.Max.y, bounds.Max.z) <= radiusSquared;
  }

  /**
   * Address: 0x00500E50 (FUN_00500E50, Moho::CGeomSolid3::Intersects helper lane)
   *
   * What it does:
   * Dispatches one convex-volume vs AABB reject test used by spatial-shard
   * volume collection hot paths.
   */
  [[nodiscard]] bool IntersectsShardVolumeBounds(
    const moho::CGeomSolid3& volume,
    const Wm3::AxisAlignedBox3f& bounds
  ) noexcept
  {
    return volume.Intersects(bounds);
  }

  // The spatial maps are `moho::SpatialMap<T>` -- an `fa::multiset` of
  // `SpatialEntry<T>` in `SpatialEntryLess` order -- and the shard arrays are
  // `fa::vector`s (SpatialDb.h). Every tree and vector body the database
  // emitted in 0x00504310..0x00506230 (insert, hinted insert, `_Insert`,
  // erase, the rotations, `_Inc`/`_Dec`, `_Min`/`_Max`, `_Buynode`, `~_Tree`,
  // `resize`, `_Insert_n`, `_Xlen`, the word moves) is the containers' own and
  // is cited on `fa::multiset`, `fa::detail::rb_tree` and
  // `fa::vector`. The hand-rolled copies that used to live here implemented
  // all of it a second time over the same nodes -- the erase as a silent no-op
  // for a while (564d7e57d) -- so they are gone, and the source says
  // `map.insert(entry)` and `mShards.resize(16)`.

  [[nodiscard]] std::int32_t FloorSpatialCellCoordinate(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value * 0.0625f));
  }

  /**
   * Address: 0x00501990 (FUN_00501990, sub_501990)
   *
   * What it does:
   * Returns true when min-x/min-z cell coordinates changed between two AABBs
   * in 16-unit spatial bins.
   */
  [[nodiscard]] bool HasSpatialCellChanged(
    const Wm3::AxisAlignedBox3f& previousBounds,
    const Wm3::AxisAlignedBox3f& updatedBounds
  ) noexcept
  {
    return FloorSpatialCellCoordinate(previousBounds.Min.x) != FloorSpatialCellCoordinate(updatedBounds.Min.x)
      || FloorSpatialCellCoordinate(previousBounds.Min.z) != FloorSpatialCellCoordinate(updatedBounds.Min.z);
  }

  /**
   * Address: 0x00501620 (FUN_00501620, sub_501620)
   *
   * What it does:
   * Expands shard bounds with one AABB and propagates the merge through all
   * parent shards.
   */
  template <class T>
  void PropagateBoundsToShardChain(moho::SpatialShard<T>* shard, const Wm3::AxisAlignedBox3f& bounds) noexcept
  {
    for (moho::SpatialShard<T>* current = shard; current != nullptr; current = current->mParent) {
      current->mBounds.Min.x = std::min(current->mBounds.Min.x, bounds.Min.x);
      current->mBounds.Min.y = std::min(current->mBounds.Min.y, bounds.Min.y);
      current->mBounds.Min.z = std::min(current->mBounds.Min.z, bounds.Min.z);
      current->mBounds.Max.x = std::max(current->mBounds.Max.x, bounds.Max.x);
      current->mBounds.Max.y = std::max(current->mBounds.Max.y, bounds.Max.y);
      current->mBounds.Max.z = std::max(current->mBounds.Max.z, bounds.Max.z);
    }
  }

  /**
   * Address: 0x005016C0 (FUN_005016C0, sub_5016C0)
   *
   * What it does:
   * Increments one type-lane counter on a shard and all parent shards.
   */
  template <class T>
  void IncrementShardTypeCountChain(moho::SpatialShard<T>* shard, const std::uint32_t typeBits) noexcept
  {
    for (moho::SpatialShard<T>* current = shard; current != nullptr; current = current->mParent) {
      if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
        ++current->mUnitCount;
      } else if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
        ++current->mProjectileCount;
      } else if ((typeBits & kSpatialEntityTypeProp) != 0u) {
        ++current->mPropCount;
      } else if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
        ++current->mEntityCount;
      }
    }
  }

  /**
   * Appends the owner of every entry in `map` whose box `accept` takes -- the
   * range walk (`_Inc` 0x00505B40) and `push_back` (0x005050A0) every leaf
   * collect body runs over up to four maps.
   */
  template <class T, class Predicate>
  void CollectEntries(const moho::SpatialMap<T>& map, gpg::fastvector<T*>& destination, const Predicate& accept)
  {
    for (const moho::SpatialEntry<T>& entry : map) {
      if (accept(entry.mBox)) {
        destination.push_back(entry.mOwner);
      }
    }
  }

  /**
   * Address: 0x00502C60 (FUN_00502C60, Spatial shard AABB leaf collect helper)
   *
   * What it does:
   * Scans one leaf `SpatialShardData` lane and appends all entity owners whose
   * node AABBs intersect the query `bounds` for requested type masks.
   *
   * The box tests here and in `CollectInBox` are Wild Magic's inline
   * `AxisAlignedBox3<float>::TestIntersection` (Wm3AxisAlignedBox3.inl),
   * emitted into this code as one out-of-line body:
   * Address: 0x00506010 (FUN_00506010, Wm3::AxisAlignedBox3<float>::TestIntersection)
   * `this` is the query `bounds` (edi) and the argument the stored box (edx) at
   * 0x00502972, 0x00502A00 and 0x00503C1B, which is the binary's comparison
   * order: `Max[i] < box.Min[i]`, then `Min[i] > box.Max[i]`.
   */
  template <class T>
  void CollectInBoxFromLeafData(
    const Wm3::AxisAlignedBox3f& bounds,
    moho::SpatialShardData<T>& data,
    const moho::EEntityType type,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardDataHasNoRequestedType(data, type) || !bounds.TestIntersection(data.mBounds)) {
      return;
    }

    if (data.mTimeSinceRecalc > 500) {
      data.RecalculateBounds();
    }

    const std::uint32_t typeBits = EntityTypeBits(type);

    const auto intersectsQuery = [&bounds](const Wm3::AxisAlignedBox3f& nodeBox) {
      return bounds.TestIntersection(nodeBox);
    };

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      CollectEntries(data.mMapUnits, destination, intersectsQuery);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      CollectEntries(data.mMapProjectiles, destination, intersectsQuery);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      CollectEntries(data.mMapProps, destination, intersectsQuery);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      CollectEntries(data.mMapEntities, destination, intersectsQuery);
    }
  }

  template <class T>
  void CollectInVolumeFromLeafData(
    gpg::fastvector<T*>& destination,
    moho::SpatialShardData<T>& data,
    const moho::EEntityType type,
    const moho::CGeomSolid3& volume
  )
  {
    if (SpatialShardDataHasNoRequestedType(data, type) || !IntersectsShardVolumeBounds(volume, data.mBounds)) {
      return;
    }

    if (data.mTimeSinceRecalc > 500) {
      data.RecalculateBounds();
    }

    const bool boundsContainData = SolidContainsAabb(volume, data.mBounds);
    const std::uint32_t typeBits = EntityTypeBits(type);

    const auto intersectsOrContained = [&volume, boundsContainData](const Wm3::AxisAlignedBox3f& nodeBox) {
      return boundsContainData || IntersectsShardVolumeBounds(volume, nodeBox);
    };

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      CollectEntries(data.mMapUnits, destination, intersectsOrContained);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      CollectEntries(data.mMapProjectiles, destination, intersectsOrContained);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      CollectEntries(data.mMapProps, destination, intersectsOrContained);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      CollectEntries(data.mMapEntities, destination, intersectsOrContained);
    }
  }

  [[nodiscard]] float SelectSupportCoordinate(
    const float minValue,
    const float maxValue,
    const float supportSelectorLane
  ) noexcept
  {
    // FUN_00503730 bit-pack path chooses Max when sign bit is set and Min
    // otherwise for each lane.
    return std::signbit(supportSelectorLane) ? maxValue : minValue;
  }

  [[nodiscard]] float ComputeFadeThresholdForBounds(
    const moho::Vector4f& fadePlane,
    const Wm3::Vector3f& supportSelector,
    const Wm3::AxisAlignedBox3f& bounds
  ) noexcept
  {
    const float supportX = SelectSupportCoordinate(bounds.Min.x, bounds.Max.x, supportSelector.x);
    const float supportY = SelectSupportCoordinate(bounds.Min.y, bounds.Max.y, supportSelector.y);
    const float supportZ = SelectSupportCoordinate(bounds.Min.z, bounds.Max.z, supportSelector.z);
    return fadePlane.x * supportX + fadePlane.y * supportY + fadePlane.z * supportZ + fadePlane.w;
  }

  [[nodiscard]] Wm3::Vector3f BuildViewSupportSelector(const moho::GeomCamera3& camera) noexcept
  {
    Wm3::Vector3f supportSelector{};
    supportSelector.x = -camera.inverseView.r[2].x;
    supportSelector.y = -camera.inverseView.r[2].y;
    supportSelector.z = -camera.inverseView.r[2].z;
    return supportSelector;
  }

  /**
   * Address: 0x00503AA0 (FUN_00503AA0, sub_503AA0)
   *
   * What it does:
   * Builds view-space support selector lanes from camera inverse-view row 2
   * and runs leaf-data frustum/fade collection.
   */
  template <class T>
  void CollectInViewFromLeafData(
    gpg::fastvector<T*>& destination,
    moho::SpatialShardData<T>* const data,
    moho::GeomCamera3* const camera,
    const moho::EEntityType type
  )
  {
    const Wm3::Vector3f supportSelector = BuildViewSupportSelector(*camera);
    moho::SpatialShardData<T>::FindInVolumeFromData(
      camera->viewport.r[1],
      supportSelector,
      data,
      type,
      &camera->solid2,
      destination
    );
  }

  /**
   * Address: 0x00503EB0 (FUN_00503EB0, sub_503EB0)
   *
   * What it does:
   * Builds view-space support selector lanes from camera inverse-view row 2
   * and runs one shard frustum/fade collection pass.
   */
  template <class T>
  void CollectInViewFromShard(
    moho::GeomCamera3* const camera,
    gpg::fastvector<T*>& destination,
    moho::SpatialShard<T>* const shard,
    const moho::EEntityType type
  )
  {
    const Wm3::Vector3f supportSelector = BuildViewSupportSelector(*camera);
    moho::SpatialShardData<T>::FindInVolume(shard, type, &camera->solid2, supportSelector, camera->viewport.r[1], destination);
  }

  /**
   * The view collect's map walk. The map is in `SpatialEntryLess` order, so
   * once a fading entry's cutoff is within the view's threshold every entry
   * after it fades sooner and the walk stops.
   */
  template <class T>
  void CollectVolumeCandidatesWithFade(
    const moho::SpatialMap<T>& map,
    const moho::CGeomSolid3& volume,
    const bool dataBoundsContained,
    const float fadeThreshold,
    gpg::fastvector<T*>& destination
  )
  {
    for (const moho::SpatialEntry<T>& entry : map) {
      if (entry.mFadeOut > 0.0f && fadeThreshold >= entry.mFadeOut) {
        break;
      }

      if (dataBoundsContained || volume.Intersects(entry.mBox)) {
        destination.push_back(entry.mOwner);
      }
    }
  }

  /**
   * The collection half of `SpatialShardData<T>::FindInVolumeFromData`, run once the leaf has
   * passed its type and bounds tests and had its bounds refreshed.
   */
  template <class T>
  void CollectLeafVolumeCandidates(
    const moho::Vector4f& fadePlane,
    const Wm3::Vector3f& supportSelector,
    const moho::SpatialShardData<T>& data,
    const moho::EEntityType type,
    const moho::CGeomSolid3& volume,
    gpg::fastvector<T*>& destination
  )
  {
    const bool dataBoundsContained = SolidContainsAabb(volume, data.mBounds);
    const float fadeThreshold = ComputeFadeThresholdForBounds(fadePlane, supportSelector, data.mBounds);
    const std::uint32_t typeBits = EntityTypeBits(type);

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      CollectVolumeCandidatesWithFade(data.mMapUnits, volume, dataBoundsContained, fadeThreshold, destination);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      CollectVolumeCandidatesWithFade(data.mMapProjectiles, volume, dataBoundsContained, fadeThreshold, destination);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      CollectVolumeCandidatesWithFade(data.mMapProps, volume, dataBoundsContained, fadeThreshold, destination);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      CollectVolumeCandidatesWithFade(data.mMapEntities, volume, dataBoundsContained, fadeThreshold, destination);
    }
  }

  /// The leaf-level type and bounds tests of `SpatialShardData<T>::FindInVolumeFromData`.
  template <class T>
  [[nodiscard]] bool VolumeLeafPasses(
    const moho::SpatialShardData<T>& data, const moho::EEntityType type, const moho::CGeomSolid3& volume
  )
  {
    return !SpatialShardDataHasNoRequestedType(data, type) && IntersectsShardVolumeBounds(volume, data.mBounds);
  }

  /// The periodic bounds refresh `SpatialShardData<T>::FindInVolumeFromData` runs on a leaf that passed.
  template <class T>
  [[nodiscard]] bool VolumeLeafNeedsRefresh(const moho::SpatialShardData<T>& data)
  {
    return data.mTimeSinceRecalc > 500;
  }

  /**
   * The leaf-level gate of `SpatialShardData<T>::FindInVolumeFromData`: the type and bounds tests,
   * then the periodic bounds refresh. True when the leaf goes on to collection.
   */
  template <class T>
  [[nodiscard]] bool PrepareVolumeLeaf(
    moho::SpatialShardData<T>& data, const moho::EEntityType type, const moho::CGeomSolid3& volume
  )
  {
    if (!VolumeLeafPasses(data, type, volume)) {
      return false;
    }

    if (VolumeLeafNeedsRefresh(data)) {
      data.RecalculateBounds();
    }
    return true;
  }

  /// Engine addition (`ren_ParallelCull`): a run of sibling leaves a parallel volume query tests together.
  template <class T>
  struct VolumeLeafGroup
  {
    moho::SpatialShardData<T>* const* mLeaves;
    std::int32_t mCount;
  };

  /**
   * Engine addition (`ren_ParallelCull`): the serial half of a parallel volume query. Walks the
   * shard tree exactly as `SpatialShardData<T>::FindInVolume` does - same shard tests, same order -
   * down to the lowest shards, and records each one's 16 leaves as a group; the leaf tests run in
   * the parallel half. Leaf bounds refreshes are left to the caller: a refresh only changes that
   * leaf and its ancestors, and every ancestor's test has already run by the time the walk reaches
   * the leaf, so no test depends on them.
   */
  template <class T>
  void GatherVolumeLeafGroups(
    moho::SpatialShard<T>* const shard,
    const moho::EEntityType type,
    const moho::CGeomSolid3& volume,
    std::vector<VolumeLeafGroup<T>>& groups
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type) || !volume.Intersects(shard->mBounds)) {
      return;
    }

    if (shard->mLevel <= 0) {
      groups.push_back(VolumeLeafGroup<T>{shard->mData.data(), 16});
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      GatherVolumeLeafGroups(shard->mShards[index], type, volume, groups);
    }
  }

  moho::TConVar<bool> gTConVar_ren_ParallelCull(
    "ren_ParallelCull",
    "Run large view queries (visible meshes and decals, fog-of-war circles) on user worker threads "
    "(see user_Workers). Collects exactly what the serial queries collect, in the same order.",
    &moho::ren_ParallelCull
  );

  // Below this many leaf groups the query runs on the calling thread.
  constexpr std::size_t kParallelCullMinGroups = 8u;

  /**
   * Engine addition (`ren_ParallelCull`): a whole-database volume query, as `SpatialDB<T>::
   * CollectAllInVolume` / `CollectInView` run it, with the leaf work spread over the user worker
   * pool. Leaf groups are gathered serially in walk order (the root lane last), tested and
   * collected in parallel into per-group lists, and appended in group order, so `destination`
   * ends up exactly as the serial walk leaves it. False (and nothing done) when the query should
   * run serially instead.
   */
  template <class T>
  [[nodiscard]] bool CollectInVolumeParallel(
    fa::vector<moho::SpatialShard<T>*>& shards,
    moho::SpatialShardData<T>& rootData,
    const moho::EEntityType type,
    moho::CGeomSolid3& volume,
    const Wm3::Vector3f& supportSelector,
    const moho::Vector4f& fadePlane,
    gpg::fastvector<T*>& destination
  )
  {
    if (!moho::ren_ParallelCull || moho::CUserWorkerPool::ConfiguredWorkerCount() == 0u) {
      return false;
    }

    std::vector<VolumeLeafGroup<T>> groups;
    for (moho::SpatialShard<T>* const shard : shards) {
      if (shard != nullptr) {
        GatherVolumeLeafGroups(shard, type, volume, groups);
      }
    }
    moho::SpatialShardData<T>* const rootLeaf = &rootData;
    groups.push_back(VolumeLeafGroup<T>{&rootLeaf, 1});

    if (groups.size() < kParallelCullMinGroups) {
      for (const VolumeLeafGroup<T>& group : groups) {
        for (std::int32_t index = 0; index < group.mCount; ++index) {
          moho::SpatialShardData<T>& leaf = *group.mLeaves[index];
          if (!VolumeLeafPasses(leaf, type, volume)) {
            continue;
          }
          if (VolumeLeafNeedsRefresh(leaf)) {
            leaf.RecalculateBounds();
          }
          CollectLeafVolumeCandidates(fadePlane, supportSelector, leaf, type, volume, destination);
        }
      }
      return true;
    }

    // Each worker refreshes its own leaves' bounds before collecting from them; the owner shards,
    // which several leaves share, are brought up to date afterwards in leaf order. Every owner
    // ends with the bounds its last refresh computes from its final children - the same final
    // state the interleaved serial refreshes leave.
    const std::unique_ptr<gpg::fastvector<T*>[]> parts(new gpg::fastvector<T*>[groups.size()]);
    std::vector<std::uint32_t> refreshedMasks(groups.size(), 0u);
    moho::CUserWorkerPool::Get().ParallelFor(groups.size(), 1u, [&](const std::size_t begin, const std::size_t end) {
      for (std::size_t g = begin; g < end; ++g) {
        const VolumeLeafGroup<T>& group = groups[g];
        for (std::int32_t index = 0; index < group.mCount; ++index) {
          moho::SpatialShardData<T>& leaf = *group.mLeaves[index];
          if (!VolumeLeafPasses(leaf, type, volume)) {
            continue;
          }
          if (VolumeLeafNeedsRefresh(leaf)) {
            leaf.RecalculateOwnBounds();
            refreshedMasks[g] |= 1u << index;
          }
          CollectLeafVolumeCandidates(fadePlane, supportSelector, leaf, type, volume, parts[g]);
        }
      }
    });

    for (std::size_t g = 0; g < groups.size(); ++g) {
      for (std::int32_t index = 0; index < groups[g].mCount; ++index) {
        if ((refreshedMasks[g] & (1u << index)) != 0u && groups[g].mLeaves[index]->mShard != nullptr) {
          groups[g].mLeaves[index]->mShard->RecalculateBounds();
        }
      }
    }

    for (std::size_t g = 0; g < groups.size(); ++g) {
      for (T* const item : parts[g]) {
        destination.push_back(item);
      }
    }
    return true;
  }


  /**
   * Address: 0x00503B10 (FUN_00503B10, sub_503B10)
   *
   * What it does:
   * Walks shard children by x/z cell index until it reaches one leaf-data lane.
   */
  template <class T>
  [[nodiscard]] moho::SpatialShardData<T>*
  ResolveSpatialLeafDataForPoint(moho::SpatialShard<T>* shard, const float worldZ, const float worldX)
  {
    for (;;) {
      const std::int32_t level = shard->mLevel;
      const float cellSize = static_cast<float>(kSpatialShardCellSizeByLevel[level]);
      const std::int32_t laneX = static_cast<std::int32_t>((worldX - static_cast<float>(shard->mAreaRect.x0)) / cellSize);
      const std::int32_t laneZ = static_cast<std::int32_t>((worldZ - static_cast<float>(shard->mAreaRect.z0)) / cellSize);
      const std::int32_t laneIndex = laneX + kSpatialShardGridDimension * laneZ;

      if (level <= 0) {
        return shard->mData[laneIndex];
      }

      shard = shard->mShards[laneIndex];
    }
  }

  /**
   * Address: 0x00502120 (FUN_00502120, sub_502120)
   *
   * What it does:
   * Resolves one world position to leaf shard-data lane; falls back to inline
   * root shard-data lane when position is outside shard-grid coverage.
   *
   * Inside the 16-unit cell grid the top-level shard is indexed without a
   * null test, as the binary does: `ResizeForMap` leaves a slot null only
   * past the map extent, and the cell grid (`mShardWidth`/`mShardHeight`)
   * ends there.
   */
  template <class T>
  [[nodiscard]] moho::SpatialShardData<T>*
  ResolveSpatialLeafDataFromStoragePoint(const Wm3::Vec3f& point, moho::SpatialDB<T>& storage)
  {
    const std::int32_t coarseX = static_cast<std::int32_t>(std::floor(point.x * 0.0625f));
    const std::int32_t coarseZ = static_cast<std::int32_t>(std::floor(point.z * 0.0625f));
    if (coarseX < 0 || coarseZ < 0 || coarseX >= storage.mShardWidth || coarseZ >= storage.mShardHeight) {
      return &storage.mShardData;
    }

    const float shardCellSize = static_cast<float>(kSpatialShardCellSizeByLevel[storage.mShardLevel]);
    const std::int32_t shardX = static_cast<std::int32_t>(point.x / shardCellSize);
    const std::int32_t shardZ = static_cast<std::int32_t>(point.z / shardCellSize);
    const std::int32_t topIndex = shardX + kSpatialShardGridDimension * shardZ;
    return ResolveSpatialLeafDataForPoint(storage.mShards[topIndex], point.z, point.x);
  }
}

namespace moho
{
  /**
   * Address: 0x005011A0 (FUN_005011A0, Moho::SpatialShard::SpatialShard)
   *
   * What it does:
   * Initializes one spatial shard node and recursively allocates either child
   * shards (non-leaf levels) or 16 leaf-data lanes.
   */
  template <class T>
  SpatialShard<T>::SpatialShard(const std::int32_t level, SpatialShard<T>* const parent, const gpg::Rect2i& areaRect)
    : mParent(parent)
    , mAreaRect(areaRect)
    , mLevel(level)
    , mUnitCount(0)
    , mProjectileCount(0)
    , mPropCount(0)
    , mEntityCount(0)
    , mBounds()
    , mShards()
    , mData()
  {
    mBounds.Min.x = FLT_MAX;
    mBounds.Min.y = FLT_MAX;
    mBounds.Min.z = FLT_MAX;
    mBounds.Max.x = -FLT_MAX;
    mBounds.Max.y = -FLT_MAX;
    mBounds.Max.z = -FLT_MAX;

    if (mLevel > 0) {
      const std::int32_t dx = (mAreaRect.x1 - mAreaRect.x0) / kSpatialShardGridDimension;
      const std::int32_t dz = (mAreaRect.z1 - mAreaRect.z0) / kSpatialShardGridDimension;

      mShards.resize(kSpatialShardSlotCount);
      for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
        const std::int32_t col = index % kSpatialShardGridDimension;
        const std::int32_t row = index / kSpatialShardGridDimension;

        gpg::Rect2i childRect{};
        childRect.x0 = mAreaRect.x0 + dx * col;
        childRect.z0 = mAreaRect.z0 + dz * row;
        childRect.x1 = mAreaRect.x0 + dx * (col + 1);
        childRect.z1 = mAreaRect.z0 + dz * (row + 1);
        mShards[index] = new SpatialShard<T>(mLevel - 1, this, childRect);
      }
      return;
    }

    mData.resize(kSpatialShardSlotCount);
    for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
      mData[index] = new SpatialShardData<T>(this);
    }
  }

  /**
   * Address: 0x00501370 (FUN_00501370, Moho::SpatialShard::~SpatialShard)
   * Address: 0x00501790 (FUN_00501790 -- the scalar deleting destructor
   * `??_G`: this body, then `operator delete` when bit 0 of the flag is set;
   * what `delete mShards[index]` calls here, in `~SpatialDB` and in
   * `ResizeForMap`, since the recursion keeps the destructor out of line.)
   *
   * What it does:
   * Deletes the 16 owned child shards (or leaf lanes) and clears whichever
   * vector held them; both vectors then free their storage as members.
   */
  template <class T>
  SpatialShard<T>::~SpatialShard()
  {
    if (mLevel > 0) {
      for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
        delete mShards[index];
      }
      mShards.clear();
    } else {
      for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
        delete mData[index];
      }
      mData.clear();
    }
  }

  /**
   * Address: 0x00501490 (FUN_00501490, Moho::SpatialShard::CountType)
   *
   * What it does:
   * Returns true when the shard has no entries for requested type lanes.
   */
  template <class T>
  bool SpatialShard<T>::CountType(const EEntityType type) const
  {
    const std::uint32_t typeBits = EntityTypeBits(type);
    if (typeBits != 0u) {
      return ((typeBits & kSpatialEntityTypeUnit) == 0u || mUnitCount <= 0)
        && ((typeBits & kSpatialEntityTypeProjectile) == 0u || mProjectileCount <= 0)
        && ((typeBits & kSpatialEntityTypeProp) == 0u || mPropCount <= 0)
        && ((typeBits & kSpatialEntityTypeEntity) == 0u || mEntityCount <= 0);
    }

    return mUnitCount <= 0 && mProjectileCount <= 0 && mPropCount <= 0 && mEntityCount <= 0;
  }

  /**
   * Address: 0x00501710 (FUN_00501710, Moho::SpatialShard::DecrementCount)
   *
   * What it does:
   * Decrements the requested entity-lane count on this shard and every parent.
   */
  template <class T>
  void SpatialShard<T>::DecrementCount(SpatialShard<T>* shard, const EEntityType type)
  {
    for (SpatialShard<T>* current = shard; current != nullptr; current = current->mParent) {
      const std::uint32_t typeBits = EntityTypeBits(type);
      if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
        --current->mUnitCount;
      } else if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
        --current->mProjectileCount;
      } else if ((typeBits & kSpatialEntityTypeProp) != 0u) {
        --current->mPropCount;
      } else if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
        --current->mEntityCount;
      }
    }
  }

  /**
   * Address: 0x00501500 (FUN_00501500, Moho::SpatialShard::RecalculateBounds)
   *
   * What it does:
   * Rebuilds each shard lane bounds from child shard/data lanes and
   * propagates the update through parent shards.
   */
  template <class T>
  void SpatialShard<T>::RecalculateBounds()
  {
    for (SpatialShard<T>* shard = this; shard != nullptr; shard = shard->mParent) {
      Wm3::AxisAlignedBox3f mergedBounds{};
      mergedBounds.Min.x = FLT_MAX;
      mergedBounds.Min.y = FLT_MAX;
      mergedBounds.Min.z = FLT_MAX;
      mergedBounds.Max.x = -FLT_MAX;
      mergedBounds.Max.y = -FLT_MAX;
      mergedBounds.Max.z = -FLT_MAX;

      for (std::int32_t index = 0; index < 16; ++index) {
        const Wm3::AxisAlignedBox3f* sourceBounds = nullptr;
        if (shard->mLevel <= 0) {
          sourceBounds = &shard->mData[index]->mBounds;
        } else {
          sourceBounds = &shard->mShards[index]->mBounds;
        }

        mergedBounds.Min.x = std::min(mergedBounds.Min.x, sourceBounds->Min.x);
        mergedBounds.Min.y = std::min(mergedBounds.Min.y, sourceBounds->Min.y);
        mergedBounds.Min.z = std::min(mergedBounds.Min.z, sourceBounds->Min.z);
        mergedBounds.Max.x = std::max(mergedBounds.Max.x, sourceBounds->Max.x);
        mergedBounds.Max.y = std::max(mergedBounds.Max.y, sourceBounds->Max.y);
        mergedBounds.Max.z = std::max(mergedBounds.Max.z, sourceBounds->Max.z);
      }

      shard->mBounds = mergedBounds;
    }
  }

  /**
   * Address: 0x00501070 (FUN_00501070, Moho::SpatialShardData::HasType)
   *
   * What it does:
   * Returns true when leaf map lanes have no entries for requested type lanes.
   */
  template <class T>
  bool SpatialShardData<T>::HasType(const SpatialShardData<T>* const data, const EEntityType type)
  {
    const std::uint32_t typeBits = EntityTypeBits(type);
    if (typeBits != 0u) {
      return ((typeBits & kSpatialEntityTypeUnit) == 0u || data->mMapUnits.empty())
        && ((typeBits & kSpatialEntityTypeProjectile) == 0u || data->mMapProjectiles.empty())
        && ((typeBits & kSpatialEntityTypeProp) == 0u || data->mMapProps.empty())
        && ((typeBits & kSpatialEntityTypeEntity) == 0u || data->mMapEntities.empty());
    }

    return data->mMapUnits.empty() && data->mMapProjectiles.empty() && data->mMapProps.empty() &&
      data->mMapEntities.empty();
  }

  /**
   * Address: 0x00500F60 (FUN_00500F60, Moho::SpatialShardData::SpatialShardData)
   *
   * What it does:
   * Names the owning shard, zeroes the unnamed header and the staleness
   * counter, and seeds the bounds inverted. The four maps construct their
   * own heads (`_Buynode` 0x00505D20, self-linked, size zero).
   */
  template <class T>
  SpatialShardData<T>::SpatialShardData(SpatialShard<T>* const ownerShard)
    : mShard(ownerShard)
    , mUnknown_04_13{}
    , mTimeSinceRecalc(0)
    , mBounds()
    , mMapUnits()
    , mMapProjectiles()
    , mMapProps()
    , mMapEntities()
  {
    mBounds.Min.x = FLT_MAX;
    mBounds.Min.y = FLT_MAX;
    mBounds.Min.z = FLT_MAX;
    mBounds.Max.x = -FLT_MAX;
    mBounds.Max.y = -FLT_MAX;
    mBounds.Max.z = -FLT_MAX;
  }

  /**
   * Address: 0x005017E0 (FUN_005017E0, Moho::SpatialShardData::~SpatialShardData)
   *
   * What it does:
   * Member destruction only: each map's `~_Tree` (`erase(begin(), end())`
   * through 0x00505200, then the head freed), entities first, inlined here.
   */
  template <class T>
  SpatialShardData<T>::~SpatialShardData() = default;

  /**
   * Engine addition, not recovered from the binary: the leaf half of `RecalculateBounds` (below),
   * which is the binary's body up to the owner-shard update.
   */
  template <class T>
  void SpatialShardData<T>::RecalculateOwnBounds()
  {
    Wm3::AxisAlignedBox3f mergedBounds{};
    mergedBounds.Min.x = FLT_MAX;
    mergedBounds.Min.y = FLT_MAX;
    mergedBounds.Min.z = FLT_MAX;
    mergedBounds.Max.x = -FLT_MAX;
    mergedBounds.Max.y = -FLT_MAX;
    mergedBounds.Max.z = -FLT_MAX;

    const auto accumulateTreeBounds = [&mergedBounds](const SpatialMap<T>& map) {
      for (const SpatialEntry<T>& entry : map) {
        const Wm3::AxisAlignedBox3f& entryBox = entry.mBox;
        mergedBounds.Min.x = std::min(mergedBounds.Min.x, entryBox.Min.x);
        mergedBounds.Min.y = std::min(mergedBounds.Min.y, entryBox.Min.y);
        mergedBounds.Min.z = std::min(mergedBounds.Min.z, entryBox.Min.z);
        mergedBounds.Max.x = std::max(mergedBounds.Max.x, entryBox.Max.x);
        mergedBounds.Max.y = std::max(mergedBounds.Max.y, entryBox.Max.y);
        mergedBounds.Max.z = std::max(mergedBounds.Max.z, entryBox.Max.z);
      }
    };

    accumulateTreeBounds(mMapUnits);
    accumulateTreeBounds(mMapProjectiles);
    accumulateTreeBounds(mMapProps);
    accumulateTreeBounds(mMapEntities);

    mBounds = mergedBounds;
    mTimeSinceRecalc = 0;
  }

  /**
   * Address: 0x005023B0 (FUN_005023B0, Moho::SpatialShardData::RecalculateBounds)
   *
   * What it does:
   * Rebuilds aggregate bounds from all leaf-map lanes, then propagates shard
   * bounds through the owning shard chain.
   */
  template <class T>
  void SpatialShardData<T>::RecalculateBounds()
  {
    // The owner shard reads this leaf's new bounds; the refresh counter is not part of that.
    RecalculateOwnBounds();
    if (mShard != nullptr) {
      mShard->RecalculateBounds();
    }
  }

  /**
   * Address: 0x00502340 (FUN_00502340, Moho::SpatialShardData::RemoveNode)
   *
   * What it does:
   * Erases one entry from the map its routing mask selects and updates shard
   * counts up the owner chain.
   */
  template <class T>
  void SpatialShardData<T>::RemoveNode(const iterator node)
  {
    ++mTimeSinceRecalc;
    const EEntityType type = static_cast<EEntityType>(node->mEntityType);

    const std::uint32_t typeBits = EntityTypeBits(type);
    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      mMapUnits.erase(node);
    } else if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      mMapProjectiles.erase(node);
    } else if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      mMapProps.erase(node);
    } else {
      mMapEntities.erase(node);
    }

    if (mShard != nullptr) {
      SpatialShard<T>::DecrementCount(mShard, type);
    }
  }

  /**
   * Address: 0x00502200 (FUN_00502200, sub_502200)
   *
   * What it does:
   * Inserts one entry into the map its routing mask selects, widens this
   * lane's bounds by the entry's box, stores this lane into the entry through
   * the new iterator, and propagates the bounds and the type count up the
   * shard chain.
   */
  template <class T>
  typename SpatialShardData<T>::iterator SpatialShardData<T>::Insert(const SpatialEntry<T>& entry)
  {
    iterator inserted;
    const std::uint32_t typeBits = entry.mEntityType;
    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      inserted = mMapUnits.insert(entry);
    } else if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      inserted = mMapProjectiles.insert(entry);
    } else if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      inserted = mMapProps.insert(entry);
    } else {
      inserted = mMapEntities.insert(entry);
    }

    mBounds.Min.x = std::min(mBounds.Min.x, entry.mBox.Min.x);
    mBounds.Min.y = std::min(mBounds.Min.y, entry.mBox.Min.y);
    mBounds.Min.z = std::min(mBounds.Min.z, entry.mBox.Min.z);
    mBounds.Max.x = std::max(mBounds.Max.x, entry.mBox.Max.x);
    mBounds.Max.y = std::max(mBounds.Max.y, entry.mBox.Max.y);
    mBounds.Max.z = std::max(mBounds.Max.z, entry.mBox.Max.z);
    ++mTimeSinceRecalc;

    inserted->mShardData = this;

    if (mShard != nullptr) {
      PropagateBoundsToShardChain(mShard, mBounds);
      IncrementShardTypeCountChain(mShard, entry.mEntityType);
    }

    return inserted;
  }

  /**
   * Address: 0x00502780 (FUN_00502780, Moho::SpatialShardData::CollectFromData)
   *
   * What it does:
   * Appends all entity pointers from selected leaf maps to destination.
   */
  template <class T>
  void SpatialShardData<T>::CollectFromData(const EEntityType type, gpg::fastvector<T*>& destination, SpatialShardData<T>* const data)
  {
    if (SpatialShardDataHasNoRequestedType(*data, type)) {
      return;
    }

    const std::uint32_t typeBits = EntityTypeBits(type);
    const auto collectAll = [&destination](const SpatialMap<T>& map) {
      CollectEntries(map, destination, [](const Wm3::AxisAlignedBox3f&) { return true; });
    };

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      collectAll(data->mMapUnits);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      collectAll(data->mMapProjectiles);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      collectAll(data->mMapProps);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      collectAll(data->mMapEntities);
    }
  }

  /**
   * Address: 0x00503BB0 (FUN_00503BB0, Moho::SpatialShardData::Collect)
   *
   * What it does:
   * Recursively walks shard children (or leaf shard-data lanes at level 0)
   * and appends all entities matching `type`.
   */
  template <class T>
  void SpatialShardData<T>::Collect(
    SpatialShard<T>* const shard,
    const EEntityType type,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        CollectFromData(type, destination, shard->mData[index]);
      } else {
        Collect(shard->mShards[index], type, destination);
      }
    }
  }

  /**
   * Address: 0x00503C00 (FUN_00503C00, Moho::SpatialShardData::CollectInBox)
   *
   * What it does:
   * Recursively collects selected entities that intersect one AABB query.
   */
  template <class T>
  void SpatialShardData<T>::CollectInBox(
    SpatialShard<T>* const shard,
    const EEntityType type,
    const Wm3::AxisAlignedBox3f& bounds,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type) || !bounds.TestIntersection(shard->mBounds)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        shard->mData[index]->CollectInBoxFromData(bounds, type, destination);
      } else {
        CollectInBox(shard->mShards[index], type, bounds, destination);
      }
    }
  }

  /**
   * Address: 0x00502950 (FUN_00502950, Moho::SpatialShardData::CollectInBoxFromData)
   *
   * What it does:
   * Collects entities from this leaf-data lane that intersect one AABB query.
   */
  template <class T>
  void SpatialShardData<T>::CollectInBoxFromData(
    const Wm3::AxisAlignedBox3f& bounds,
    const EEntityType type,
    gpg::fastvector<T*>& destination
  )
  {
    CollectInBoxFromLeafData(bounds, *this, type, destination);
  }

  /**
   * Address: 0x00503DB0 (FUN_00503DB0, Moho::SpatialShardData::CollectInVolume)
   *
   * What it does:
   * Recursively collects selected entities that intersect one convex volume.
   */
  template <class T>
  void SpatialShardData<T>::CollectInVolume(
    SpatialShard<T>* const shard,
    const EEntityType type,
    CGeomSolid3* const volume,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type) || !volume->Intersects(shard->mBounds)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        shard->mData[index]->CollectInVolumeFromData(destination, type, volume);
      } else {
        CollectInVolume(shard->mShards[index], type, volume, destination);
      }
    }
  }

  /**
   * Address: 0x00503490 (FUN_00503490, Moho::SpatialShardData::CollectInVolumeFromData)
   *
   * What it does:
   * Collects entities from this leaf-data lane that intersect one convex
   * volume query.
   */
  template <class T>
  void SpatialShardData<T>::CollectInVolumeFromData(
    gpg::fastvector<T*>& destination,
    const EEntityType type,
    CGeomSolid3* const volume
  )
  {
    if (volume == nullptr) {
      return;
    }

    if (SpatialShardDataHasNoRequestedType(*this, type) || !IntersectsShardVolumeBounds(*volume, mBounds)) {
      return;
    }

    CollectInVolumeFromLeafData(destination, *this, type, *volume);
  }

  /**
   * Address: 0x005030C0 (FUN_005030C0, Moho::SpatialShardData::CollectInSphereFromData)
   *
   * What it does:
   * Sphere-collect leaf variant. Mirrors `CollectInVolumeFromData` but uses a
   * bounding sphere as the culling primitive. Returns `true` when the shard
   * had no entities of the requested type (the early-out path that mirrors
   * the recursive walker's reuse of the per-shard `CountType` reject), which
   * the recursive caller treats as a hint to short-circuit.
   */
  template <class T>
  bool SpatialShardData<T>::CollectInSphereFromData(
    const EEntityType type,
    const SphereBoundsProbe& probe,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardDataHasNoRequestedType(*this, type)) {
      return true;
    }

    if (!SphereIntersectsAabb(mBounds, probe)) {
      return false;
    }

    if (mTimeSinceRecalc > 500) {
      RecalculateBounds();
    }

    const bool dataBoundsContained = SphereContainsAabbDiagonal(probe, mBounds);
    const std::uint32_t typeBits = EntityTypeBits(type);

    const auto includeIfRelevant = [&probe, dataBoundsContained](
      const Wm3::AxisAlignedBox3f& nodeBox
    ) {
      return dataBoundsContained || SphereIntersectsAabb(nodeBox, probe);
    };

    if ((typeBits & kSpatialEntityTypeUnit) != 0u) {
      CollectEntries(mMapUnits, destination, includeIfRelevant);
    }

    if ((typeBits & kSpatialEntityTypeProjectile) != 0u) {
      CollectEntries(mMapProjectiles, destination, includeIfRelevant);
    }

    if ((typeBits & kSpatialEntityTypeProp) != 0u) {
      CollectEntries(mMapProps, destination, includeIfRelevant);
    }

    if ((typeBits & kSpatialEntityTypeEntity) != 0u) {
      CollectEntries(mMapEntities, destination, includeIfRelevant);
    }

    return dataBoundsContained;
  }

  /**
   * Address: 0x00503D40 (FUN_00503D40, Moho::SpatialShardData::CollectInSphere)
   *
   * What it does:
   * Sphere variant of the recursive `CollectInBox` / `CollectInVolume`
   * walker. Early-outs when the shard has no entities of the requested type
   * or when the sphere does not touch the shard's bounds, otherwise descends
   * each of the 16 child slots — recursing on non-leaf children and
   * delegating to the per-leaf `CollectInSphereFromData` at level 0.
   */
  template <class T>
  bool SpatialShardData<T>::CollectInSphere(
    SpatialShard<T>* const shard,
    const EEntityType type,
    const SphereBoundsProbe& probe,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type)) {
      return true;
    }

    if (!SphereIntersectsAabb(shard->mBounds, probe)) {
      return false;
    }

    bool result = false;
    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        result = shard->mData[index]->CollectInSphereFromData(type, probe, destination);
      } else {
        result = CollectInSphere(shard->mShards[index], type, probe, destination);
      }
    }
    return result;
  }

  /**
   * Address: 0x00503730 (FUN_00503730, Moho::SpatialShardData::FindInVolumeFromData)
   *
   * What it does:
   * Collects matching entities from one leaf shard-data lane using view-volume
   * culling plus per-node fade threshold early-out.
   */
  template <class T>
  void SpatialShardData<T>::FindInVolumeFromData(
    const Vector4f& fadePlane,
    const Wm3::Vector3f& supportSelector,
    SpatialShardData<T>* const data,
    const EEntityType type,
    CGeomSolid3* const volume,
    gpg::fastvector<T*>& destination
  )
  {
    if (PrepareVolumeLeaf(*data, type, *volume)) {
      CollectLeafVolumeCandidates(fadePlane, supportSelector, *data, type, *volume, destination);
    }
  }

  /**
   * Address: 0x00503E30 (FUN_00503E30, Moho::SpatialShardData::FindInVolume)
   *
   * What it does:
   * Recursively collects entities intersecting one query volume while passing
   * view/fade cull inputs into leaf shard-data filtering.
   */
  template <class T>
  void SpatialShardData<T>::FindInVolume(
    SpatialShard<T>* const shard,
    const EEntityType type,
    CGeomSolid3* const volume,
    const Wm3::Vector3f& supportSelector,
    const Vector4f& fadePlane,
    gpg::fastvector<T*>& destination
  )
  {
    if (SpatialShardHasNoRequestedType(*shard, type) || !volume->Intersects(shard->mBounds)) {
      return;
    }

    for (std::int32_t index = 0; index < 16; ++index) {
      if (shard->mLevel <= 0) {
        FindInVolumeFromData(fadePlane, supportSelector, shard->mData[index], type, volume, destination);
      } else {
        FindInVolume(shard->mShards[index], type, volume, supportSelector, fadePlane, destination);
      }
    }
  }

  /**
   * Address: 0x00501D80 (FUN_00501D80, Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance)
   * Address: 0x007E2AA0 (FUN_007E2AA0 -- a placement-construct bridge that
   * moves `this` onto the stack and calls this constructor; zero callers, no
   * references, a linker-retained copy nothing runs.)
   *
   * What it does:
   * Member construction -- the shard vector empty, the root lane with no
   * owning shard, the extents zero, the overflow map's head -- then a
   * `clear()` of the shard vector, as the body at 0x00501DFD does.
   */
  template <class T>
  SpatialDB<T>::SpatialDB()
    : mShards()
    , mShardData(nullptr)
    , mMapWidth(0)
    , mMapHeight(0)
    , mShardWidth(0)
    , mShardHeight(0)
    , mShardLevel(0)
    , mMapTree()
  {
    mShards.clear();
  }

  /**
   * Address: 0x00501F50 (FUN_00501F50, Moho::SpatialDB_MeshInstance::SpatialDB_MeshInstance)
   *
   * What it does:
   * On an extent change, records the new extents, deletes the old top-level
   * shards, and -- for a non-empty map -- picks the shard level from the
   * larger extent and builds the 4x4 top level, leaving null every slot that
   * would reach past the map.
   */
  template <class T>
  void SpatialDB<T>::ResizeForMap(const std::int32_t width, const std::int32_t height)
  {
    if (width == mMapWidth && height == mMapHeight) {
      return;
    }

    mMapWidth = width;
    mShardWidth = width / kSpatialShardSlotCount;
    mShardHeight = height / kSpatialShardSlotCount;
    mMapHeight = height;

    for (SpatialShard<T>* const shard : mShards) {
      if (shard != nullptr) {
        delete shard;
      }
    }
    mShards.clear();

    if (mMapWidth <= 0 || mMapHeight <= 0) {
      return;
    }

    const std::int32_t dominantExtent = std::max(mMapWidth, mMapHeight);
    if (dominantExtent <= kSpatialShardLevelSmallThreshold) {
      mShardLevel = kSpatialShardLevelSmall;
    } else if (dominantExtent <= kSpatialShardLevelMediumThreshold) {
      mShardLevel = kSpatialShardLevelMedium;
    } else {
      mShardLevel = kSpatialShardLevelLarge;
    }

    const std::int32_t shardSize = kSpatialShardCellSizeByLevel[mShardLevel];
    mShards.resize(kSpatialShardSlotCount);
    for (std::int32_t index = 0; index < kSpatialShardSlotCount; ++index) {
      const std::int32_t col = index % kSpatialShardGridDimension;
      const std::int32_t row = index / kSpatialShardGridDimension;

      gpg::Rect2i cellRect{};
      cellRect.x0 = shardSize * col;
      cellRect.z0 = shardSize * row;
      cellRect.x1 = shardSize * (col + 1);
      cellRect.z1 = shardSize * (row + 1);

      if (cellRect.x1 <= mMapWidth && cellRect.z1 <= mMapHeight) {
        mShards[index] = new SpatialShard<T>(mShardLevel - 1, nullptr, cellRect);
      } else {
        mShards[index] = nullptr;
      }
    }
  }

  /**
   * Address: 0x00501E50 (FUN_00501E50, Moho::SpatialDB<T>::~SpatialDB)
   *
   * What it does:
   * Deletes the top-level shards and clears the vector; the overflow map,
   * the root lane and the vector's storage then go as members.
   */
  template <class T>
  SpatialDB<T>::~SpatialDB()
  {
    for (SpatialShard<T>* const shard : mShards) {
      if (shard != nullptr) {
        delete shard;
      }
    }
    mShards.clear();
  }

  /**
   * Address: 0x00501A80 (FUN_00501A80, sub_501A80)
   * Address: 0x007E2AD0 (FUN_007E2AD0 -- a register-shape bridge into this
   * body with the mesh routing mask 0x800; zero callers, no references, a
   * linker-retained copy nothing runs.)
   * Address: 0x0089E520 (FUN_0089E520 -- a register-shape bridge that moves
   * the entry/database pair onto the stack shape this body expects; zero
   * callers, no references. Formerly `RegisterSpatialDbEntryAdapter` in
   * moho/entity/UserEntity.cpp, removed 2026-09-29.)
   *
   * What it does:
   * Drops any previous registration, then records the database and inserts
   * a fresh entry -- routing mask, owner, no leaf lane, no cutoff -- into its
   * overflow map at `end()`. The entry's box is left as
   * `AxisAlignedBox3f()` leaves it, unwritten, exactly as the binary's stack
   * temporary is: nothing reads it before the owner's first `UpdateBounds`,
   * which relinks an overflow entry unconditionally.
   */
  template <class T>
  void SpatialDBEntry<T>::Register(SpatialDB<T>* const db, T* const owner, const std::int32_t routingMask)
  {
    if (mDb != nullptr) {
      Unregister();
    }

    SpatialEntry<T> entry;
    entry.mEntityType = static_cast<std::uint32_t>(routingMask);
    entry.mShardData = nullptr;
    entry.mFadeOut = 0.0f;
    entry.mOwner = owner;

    mDb = db;
    mNode = db->mMapTree.insert(db->mMapTree.end(), entry);
  }

  /**
   * Address: 0x00501B00 (FUN_00501B00, sub_501B00)
   *
   * What it does:
   * Re-inserts this entry under a new dissolve cutoff -- the cutoff is the
   * map's sort key, so the entry is taken out and put back in order, into
   * its leaf lane when it has one and at the overflow map's `end()` when it
   * does not.
   */
  template <class T>
  void SpatialDBEntry<T>::UpdateDissolveCutoff(const float cutoff)
  {
    SpatialEntry<T> entry = *mNode;
    entry.mFadeOut = cutoff;

    if (SpatialShardData<T>* const data = mNode->mShardData; data != nullptr) {
      data->RemoveNode(mNode);
      mNode = data->Insert(entry);
    } else {
      mDb->mMapTree.erase(mNode);
      mNode = mDb->mMapTree.insert(mDb->mMapTree.end(), entry);
    }
  }

  /**
   * Address: 0x00501C10 (FUN_00501C10, sub_501C10)
   *
   * What it does:
   * Publishes the owner's new world box into its entry. An entry still in
   * the overflow map, or one whose box moved to another 16-unit cell, is
   * taken out and re-inserted into the leaf lane under its box's minimum
   * corner; otherwise the lane's bounds just widen to take the new box.
   */
  template <class T>
  void SpatialDBEntry<T>::UpdateBounds(const Wm3::AxisAlignedBox3f& bounds)
  {
    const bool requiresRelink = mNode->mShardData != nullptr ? HasSpatialCellChanged(mNode->mBox, bounds) : true;
    mNode->mBox = bounds;

    if (requiresRelink) {
      const SpatialEntry<T> entry = *mNode;
      if (entry.mShardData != nullptr) {
        entry.mShardData->RemoveNode(mNode);
      } else {
        mDb->mMapTree.erase(mNode);
      }

      mNode = ResolveSpatialLeafDataFromStoragePoint(bounds.Min, *mDb)->Insert(entry);
      return;
    }

    SpatialShardData<T>* const data = mNode->mShardData;
    data->mBounds.Min.x = std::min(data->mBounds.Min.x, bounds.Min.x);
    data->mBounds.Min.y = std::min(data->mBounds.Min.y, bounds.Min.y);
    data->mBounds.Min.z = std::min(data->mBounds.Min.z, bounds.Min.z);
    data->mBounds.Max.x = std::max(data->mBounds.Max.x, bounds.Max.x);
    data->mBounds.Max.y = std::max(data->mBounds.Max.y, bounds.Max.y);
    data->mBounds.Max.z = std::max(data->mBounds.Max.z, bounds.Max.z);

    if (data->mShard != nullptr) {
      PropagateBoundsToShardChain(data->mShard, data->mBounds);
    }
    ++data->mTimeSinceRecalc;
  }

  /**
   * Address: 0x00501BC0 (FUN_00501BC0, ??1SpatialDB_MeshInstance@Moho@@QAE@XZ)
   *
   * What it does:
   * Erases this entry from the leaf lane holding it (counts and all) or from
   * the overflow map, and clears `mDb`. `mNode` is left as it was; nothing
   * reads it again before the next `Register`.
   */
  template <class T>
  void SpatialDBEntry<T>::Unregister()
  {
    if (SpatialShardData<T>* const data = mNode->mShardData; data != nullptr) {
      data->RemoveNode(mNode);
    } else {
      mDb->mMapTree.erase(mNode);
    }
    mDb = nullptr;
  }

  /**
   * Address: 0x00504090 (FUN_00504090)
   *
   * What it does:
   * Walks all shard lanes in one mesh-instance view, collects node owners whose
   * AABBs intersect `bounds`, then appends matches from inline root shard data.
   */
  template <class T>
  [[maybe_unused]] std::int32_t CollectShardsInBoxIntoDestination(
    const Wm3::AxisAlignedBox3f& bounds,
    gpg::fastvector<T*>& destination,
    moho::SpatialDB<T>& db,
    const EEntityType type
  )
  {
    for (SpatialShard<T>* const shard : db.mShards) {
      if (shard != nullptr) {
        SpatialShardData<T>::CollectInBox(shard, type, bounds, destination);
      }
    }

    db.mShardData.CollectInBoxFromData(bounds, type, destination);
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Helper lane (no canonical address — inlined into
   * `SpatialDB<T>::CollectInVolume` at FUN_00504130 in the binary).
   *
   * What it does:
   * Walks all shard lanes in one mesh-instance view, collects node owners that
   * intersect `volume`, then appends matches from inline root shard data.
   */
  template <class T>
  [[nodiscard]] std::int32_t CollectShardsInVolumeIntoDestination(
    CGeomSolid3* const volume,
    gpg::fastvector<T*>& destination,
    moho::SpatialDB<T>& db,
    const EEntityType type
  )
  {
    for (SpatialShard<T>* const shard : db.mShards) {
      if (shard != nullptr) {
        SpatialShardData<T>::CollectInVolume(shard, type, volume, destination);
      }
    }

    db.mShardData.CollectInVolumeFromData(destination, type, volume);
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Helper lane shared by `SpatialDB<T>::CollectInSphere` (the
   * canonical FUN_005040E0 body). Walks all child shards in one
   * mesh-instance view, sphere-collecting node owners that touch the
   * bounding sphere into `destination`, then runs one sphere collect over
   * the inline root shard-data lane. Returns the count of destination
   * entries appended so far.
   */
  template <class T>
  std::int32_t CollectShardsInSphereIntoDestination(
    const SphereBoundsProbe& probe,
    gpg::fastvector<T*>& destination,
    moho::SpatialDB<T>& db,
    const EEntityType type
  )
  {
    for (SpatialShard<T>* const shard : db.mShards) {
      if (shard != nullptr) {
        (void)SpatialShardData<T>::CollectInSphere(shard, type, probe, destination);
      }
    }

    (void)db.mShardData.CollectInSphereFromData(type, probe, destination);
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Address: 0x00503F80 (FUN_00503F80, Moho::SpatialDB<T>::Collect)
   * Address: 0x0082BA50 (FUN_0082BA50 -- a register-order bridge into this
   * body for `SpatialDB<MeshInstance>`; zero callers, no references, a
   * linker-retained copy nothing runs. Formerly
   * `CollectMeshInstanceRegisterAdapter`, removed 2026-09-29.)
   *
   * What it does:
   * Collects requested entity lanes from shard hierarchy, inline root
   * shard-data lane, and every owner in the overflow map.
   */
  template <class T>
  std::int32_t SpatialDB<T>::Collect(
    gpg::fastvector<T*>& destination,
    const EEntityType type
  )
  {
    for (SpatialShard<T>* const shard : mShards) {
      if (shard != nullptr) {
        SpatialShardData<T>::Collect(shard, type, destination);
      }
    }

    SpatialShardData<T>::CollectFromData(type, destination, &mShardData);
    for (const SpatialEntry<T>& entry : mMapTree) {
      destination.push_back(entry.mOwner);
    }
    return static_cast<std::int32_t>(destination.size());
  }


  /**
   * Address: 0x00504040 (FUN_00504040, Moho::SpatialDB<T>::CollectInBox)
   * Address: 0x008C5A90 (FUN_008C5A90 -- a register-shape bridge into this
   * body; zero callers, no references, a linker-retained copy nothing runs.)
   *
   * What it does:
   * Walks all child shard pointers, collects unit entities intersecting
   * `bounds`, then collects from the inline root shard-data lane.
   */
  template <class T>
  std::int32_t SpatialDB<T>::CollectInBox(
    gpg::fastvector<T*>& destination,
    const Wm3::AxisAlignedBox3f& bounds
  )
  {
    constexpr EEntityType kUnitType = static_cast<EEntityType>(kSpatialEntityTypeUnit);
    return CollectShardsInBoxIntoDestination(bounds, destination, *this, kUnitType);
  }

  /**
   * Address: 0x005040E0 (FUN_005040E0, Moho::SpatialDB<T>::CollectInSphere)
   *
   * What it does:
   * Walks all child shard pointers, sphere-collecting matching entity owners
   * that touch the bounding sphere into `destination`, then collects from
   * the inline root shard-data lane.
   */
  template <class T>
  std::int32_t SpatialDB<T>::CollectInSphere(
    gpg::fastvector<T*>& destination,
    const EEntityType type,
    const SphereBoundsProbe& probe
  )
  {
    return CollectShardsInSphereIntoDestination(probe, destination, *this, type);
  }

  /**
   * Address: 0x00504130 (FUN_00504130, Moho::SpatialDB<T>::CollectInVolume)
   *
   * What it does:
   * Walks all child shard pointers, collects matching entities intersecting
   * `volume`, then collects from the inline root shard-data lane.
   */
  template <class T>
  std::int32_t SpatialDB<T>::CollectInVolume(
    gpg::fastvector<T*>& destination,
    const EEntityType type,
    CGeomSolid3* const volume
  )
  {
    return CollectShardsInVolumeIntoDestination(volume, destination, *this, type);
  }

  /**
   * Address: 0x00504180 (FUN_00504180, Moho::SpatialDB<T>::CollectAllInVolume)
   * Address: 0x007E2AC0 (FUN_007E2AC0 -- a register-shape bridge into this
   * body for `SpatialDB<MeshInstance>`; zero callers, no references, a
   * linker-retained copy nothing runs.)
   *
   * What it does:
   * Collects all render-relevant entity lanes (unit/prop/projectile/entity)
   * intersecting `volume` with fade-threshold cull inputs.
   */
  template <class T>
  std::int32_t SpatialDB<T>::CollectAllInVolume(
    gpg::fastvector<T*>& destination,
    CGeomSolid3* const volume,
    const Wm3::Vector3f& supportSelector,
    const Vector4f& fadePlane
  )
  {
    constexpr EEntityType kAllRenderableTypes = static_cast<EEntityType>(
      kSpatialEntityTypeUnit | kSpatialEntityTypeProjectile | kSpatialEntityTypeProp | kSpatialEntityTypeEntity
    );

    if (CollectInVolumeParallel(mShards, mShardData, kAllRenderableTypes, *volume, supportSelector, fadePlane, destination)) {
      return static_cast<std::int32_t>(destination.size());
    }

    for (SpatialShard<T>* const shard : mShards) {
      if (shard != nullptr) {
        SpatialShardData<T>::FindInVolume(shard, kAllRenderableTypes, volume, supportSelector, fadePlane, destination);
      }
    }

    SpatialShardData<T>::FindInVolumeFromData(
      fadePlane,
      supportSelector,
      &mShardData,
      kAllRenderableTypes,
      volume,
      destination
    );
    return static_cast<std::int32_t>(destination.size());
  }

  /**
   * Address: 0x005041E0 (FUN_005041E0, Moho::SpatialDB<T>::CollectInView)
   * Address: 0x007AE170 (FUN_007AE170 -- a register-shape bridge into this
   * body; zero callers, no references, a linker-retained copy nothing runs.)
   *
   * What it does:
   * Collects entities intersecting camera view/fade lanes from child shards
   * and inline root shard-data lane.
   */
  template <class T>
  std::int32_t SpatialDB<T>::CollectInView(
    GeomCamera3* const camera,
    gpg::fastvector<T*>& destination,
    const EEntityType type
  )
  {
    if (CollectInVolumeParallel(
          mShards, mShardData, type, camera->solid2, BuildViewSupportSelector(*camera), camera->viewport.r[1], destination
        )) {
      return static_cast<std::int32_t>(destination.size());
    }

    for (SpatialShard<T>* const shard : mShards) {
      if (shard != nullptr) {
        CollectInViewFromShard(camera, destination, shard, type);
      }
    }

    CollectInViewFromLeafData(destination, &mShardData, camera, type);
    return static_cast<std::int32_t>(destination.size());
  }

  // MSVC emits one out-of-line body per (template, element type), and this
  // binary carries exactly two of each: the renderer's SpatialDB<MeshInstance>
  // and the world session's SpatialDB<UserEntity>. /OPT:ICF then folded the
  // identical, pointer-only-differing pairs onto one address apiece, which is
  // why the export names only one of them.
  class WaveGenerator;
  class ShoreCell;
  class CWldTerrainDecal;

  template struct SpatialDB<MeshInstance>;
  template struct SpatialDB<UserEntity>;
  template struct SpatialDB<WaveGenerator>;
  template struct SpatialDB<ShoreCell>;
  template struct SpatialDB<CWldTerrainDecal>;
  template struct SpatialDBEntry<MeshInstance>;
  template struct SpatialDBEntry<UserEntity>;
  template struct SpatialDBEntry<WaveGenerator>;
  template struct SpatialDBEntry<ShoreCell>;
  template struct SpatialDBEntry<CWldTerrainDecal>;
}

