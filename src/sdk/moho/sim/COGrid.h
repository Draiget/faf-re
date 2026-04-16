#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/BitArray2D.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/sim/SFootprint.h"
#include "Wm3Sphere3.h"
#include "Wm3Vector3.h"

namespace moho
{
  class Entity;
  struct EntityCollisionCellSpan;
  class Sim;

  enum EEntityType : std::uint32_t
  {
    ENTITYTYPE_Unit = 0x0100,
    ENTITYTYPE_Prop = 0x0200,
    ENTITYTYPE_Entity = 0x0400,
    ENTITYTYPE_Projectile = 0x0800,
  };

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

  using CollisionSpanVector = gpg::core::FastVectorN<EntityCollisionCellSpan*, 20>;
  using EntityGatherVector = gpg::core::FastVectorN<Entity*, 20>;

  struct EntityLineCollision
  {
    Entity* entity;                    // +0x00
    Wm3::Vec3f direction;              // +0x04
    Wm3::Vec3f position;               // +0x10
    float distanceFromLineStart;       // +0x1C
  };
  static_assert(sizeof(EntityLineCollision) == 0x20, "EntityLineCollision size must be 0x20");
  static_assert(offsetof(EntityLineCollision, entity) == 0x00, "EntityLineCollision::entity offset must be 0x00");
  static_assert(
    offsetof(EntityLineCollision, direction) == 0x04, "EntityLineCollision::direction offset must be 0x04"
  );
  static_assert(
    offsetof(EntityLineCollision, position) == 0x10, "EntityLineCollision::position offset must be 0x10"
  );
  static_assert(
    offsetof(EntityLineCollision, distanceFromLineStart) == 0x1C,
    "EntityLineCollision::distanceFromLineStart offset must be 0x1C"
  );

  using EntityLineCollisionVector = gpg::core::FastVectorN<EntityLineCollision, 10>;

  struct EntityOccupationManager
  {
    std::int32_t mWidth;            // +0x00
    std::int32_t mHeight;           // +0x04
    std::int32_t mLastIndex;        // +0x08
    std::int32_t mGridWidthShift;   // +0x0C
    void** mUnitBuckets;            // +0x10
    void** mPropBuckets;            // +0x14
    void** mEntityBuckets;          // +0x18
    std::int32_t mUnknown1C;        // +0x1C
    std::int32_t mUnknown20;        // +0x20
    std::int32_t mUnknown24;        // +0x24
    void** mAllBlocksBegin;         // +0x28
    void** mAllBlocksEnd;           // +0x2C
    void** mAllBlocksCapacityEnd;   // +0x30

    /**
     * Address: 0x004FCD20 (FUN_004FCD20, Moho::EntityOccupationManager::EntityOccupationManager)
     *
     * What it does:
     * Quantizes world dimensions to 4x4 collision buckets and allocates/zeros
     * unit/prop/entity bucket arrays.
     */
    EntityOccupationManager(std::uint32_t width, std::uint32_t height);

    /**
     * Address: 0x004FCE10 (FUN_004FCE10, ??1EntityOccupationManager@Moho@@QAE@@Z)
     *
     * What it does:
     * Releases bucket arrays/chunk blocks and resets manager-owned vector lanes.
     */
    ~EntityOccupationManager();

    /**
     * Address: 0x004FD000 (FUN_004FD000, Moho::EntityOccupationManager::GatherUnmarkedUnitsInRect)
     *
     * What it does:
     * Gathers unmarked collision-span owners from selected bucket classes in `rect`,
     * marks while collecting, then clears marks before returning.
     */
    int GatherUnmarkedUnitsInRect(CollisionSpanVector& outSpans, const CollisionDBRect& rect, EEntityType flags);

    /**
     * Address: 0x00722DF0 (FUN_00722DF0, Moho::EntityOccupationManager::GatherUnmarkedEntities)
     *
     * What it does:
     * Calls `GatherUnmarkedUnitsInRect`, then remaps span pointers to owning `Entity*`
     * using the collision-span back-offset (`0x4C`).
     */
    int GatherUnmarkedEntities(EntityGatherVector& outEntities, const CollisionDBRect& rect, EEntityType flags);
  };

  using EntityOccupationGrid = EntityOccupationManager;

  static_assert(sizeof(EntityOccupationManager) == 0x34, "EntityOccupationManager size must be 0x34");
  static_assert(offsetof(EntityOccupationManager, mLastIndex) == 0x08, "EntityOccupationManager::mLastIndex offset must be 0x08");
  static_assert(
    offsetof(EntityOccupationManager, mGridWidthShift) == 0x0C,
    "EntityOccupationManager::mGridWidthShift offset must be 0x0C"
  );
  static_assert(
    offsetof(EntityOccupationManager, mAllBlocksBegin) == 0x28,
    "EntityOccupationManager::mAllBlocksBegin offset must be 0x28"
  );
  static_assert(
    offsetof(EntityOccupationManager, mAllBlocksCapacityEnd) == 0x30,
    "EntityOccupationManager::mAllBlocksCapacityEnd offset must be 0x30"
  );

  class COGrid
  {
  public:
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x007205B0 (FUN_007205B0, Moho::COGrid::COGrid)
     *
     * What it does:
     * Binds owner sim and initializes occupation managers/bitmaps from map
     * heightfield dimensions.
     */
    explicit COGrid(Sim* sim);

    Sim* sim;
    EntityOccupationManager mEntityOccupationManager;
    gpg::BitArray2D terrainOccupation;
    gpg::BitArray2D waterOccupation;
    gpg::BitArray2D mOccupation;

    /**
     * Address: 0x00720680 (FUN_00720680, Moho::COGrid::~COGrid)
     *
     * What it does:
     * Releases the three occupancy bit-arrays and the embedded occupation
     * manager in reverse construction order.
     */
    ~COGrid();

    /**
     * Address: 0x007206E0 (FUN_007206E0, Moho::COGrid::OccupyRect)
     *
     * What it does:
     * Marks `mOccupation` bits set for the provided grid-space rectangle.
     */
    void OccupyRect(const gpg::Rect2i& rect);

    /**
      * Alias of FUN_00721A90 (non-canonical helper lane).
     *
     * What it does:
     * Marks the requested bits set in the terrain and/or water occupancy
     * bitmaps over `rect`, then dirties the owning sim's path cluster cache.
     * `caps` selects which bitmap(s) to update: any bit in the terrain mask
     * (`OC_LAND|OC_SEABED|OC_SUB`) updates `terrainOccupation`, and `OC_WATER`
     * updates `waterOccupation`.
     */
    void ExecuteOccupy(EOccupancyCaps caps, const gpg::Rect2i& rect);

    /**
     * Address: 0x00721B30 (FUN_00721B30, Moho::COGrid::ReleaseOccupy)
     *
     * What it does:
     * Mirror of `ExecuteOccupy`: clears the same occupancy bits and dirties
     * the sim path cluster cache so the newly-freed cells re-enter pathing
     * consideration.
     */
    void ReleaseOccupy(EOccupancyCaps caps, const gpg::Rect2i& rect);

    /**
     * Address: 0x007229C0 (FUN_007229C0, Moho::COGrid::GetEntityCollisionsInLine)
     *
     * What it does:
     * Walks occupation buckets along one world-space segment, gathers unique
     * entity owners for visited collision spans, and appends per-entity
     * line-hit payloads for primitives whose `CollideLine` test succeeds.
     */
    void GetEntityCollisionsInLine(
      EntityLineCollisionVector& outCollisions,
      const Wm3::Vec3f& lineStart,
      const Wm3::Vec3f& lineEnd
    );

    /**
     * Address: 0x00721DC0 (FUN_00721DC0, Moho::COGrid::CollectEntitiesInBox)
     *
     * What it does:
     * Gathers unmarked entities matching `flags` within the query box's
     * axis-aligned cell span, then appends box-collision hits into
     * `outCollisions`.
     */
    void CollectEntitiesInBox(
      CollisionResultFastVectorN10& outCollisions,
      EEntityType flags,
      const Wm3::Box3f& box
    );

    /**
     * Address: 0x00721FB0 (FUN_00721FB0, Moho::COGrid::ForAllEntitiesIterator)
     *
     * What it does:
     * Gathers unmarked entities in one sphere AABB lane, then appends
     * per-entity sphere collision results. For larger spheres, first applies a
     * cheap containment pre-check against each entity cached collision bounds.
     */
    void ForAllEntitiesIterator(
      CollisionResultFastVectorN10& outCollisions,
      EEntityType flags,
      const Wm3::Sphere3f& sphere
    );
  };

  static_assert(offsetof(COGrid, mEntityOccupationManager) == 0x04, "COGrid::mEntityOccupationManager offset must be 0x04");
  static_assert(offsetof(COGrid, terrainOccupation) == 0x38, "COGrid::terrainOccupation offset must be 0x38");
  static_assert(offsetof(COGrid, waterOccupation) == 0x48, "COGrid::waterOccupation offset must be 0x48");
  static_assert(offsetof(COGrid, mOccupation) == 0x58, "COGrid::mOccupation offset must be 0x58");
  static_assert(sizeof(COGrid) == 0x68, "COGrid size must be 0x68");

  /**
   * Address: 0x004FCB40 (FUN_004FCB40, Moho::func_Rect2fToInt16)
   *
   * What it does:
   * Quantizes a world-space `gpg::Rect2f` into a 16-bit-per-axis
   * `CollisionDBRect` (one collision cell = 4 world units), clamping the
   * start corner into `[0, 0xFFFF]` and clamping width/height to at least 1.
   */
  CollisionDBRect* func_Rect2fToInt16(CollisionDBRect* out, const gpg::Rect2f& rect);

  /**
   * Address: 0x00720770 (FUN_00720770, Moho::struct_poi::RectFreeOfUnits)
   *
   * What it does:
   * Returns `true` when `rect` overlaps any live non-mobile unit's skirt
   * rectangle. The binary symbol is "RectFreeOfUnits" but the semantics is
   * actually "has blocking unit" — exposed under a corrected name.
   */
  [[nodiscard]] bool COGrid_RectHasBlockingUnit(const gpg::Rect2f& rect, COGrid& grid);

  /**
   * VFTABLE: 0x00E3192C
   * COL: 0x00E8E5B4
   */
  class COGridTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00722B80 (FUN_00722B80, Moho::COGridTypeInfo::COGridTypeInfo)
     *
     * What it does:
     * Constructs and preregisters reflected RTTI ownership for `COGrid`.
     */
    COGridTypeInfo();

    /**
     * Address: 0x00722C10 (FUN_00722C10, Moho::COGridTypeInfo::dtr)
     */
    ~COGridTypeInfo() override;

    /**
     * Address: 0x00722C00 (FUN_00722C00, Moho::COGridTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00722BE0 (FUN_00722BE0, Moho::COGridTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BDAA90 (FUN_00BDAA90, register_COGridTypeInfo)
   *
   * What it does:
   * Materializes startup `COGridTypeInfo` storage and installs process-exit cleanup.
   */
  int register_COGridTypeInfo();

  static_assert(sizeof(COGridTypeInfo) == 0x64, "COGridTypeInfo size must be 0x64");
} // namespace moho
