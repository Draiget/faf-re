#include "moho/sim/COGrid.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <typeinfo>

#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/Unit.h"
#include "moho/path/PathTables.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"

namespace
{
  struct EntityOccupationBucketItem
  {
    EntityOccupationBucketItem* mNext;
    moho::EntityCollisionCellSpan* mItem;
  };

  static_assert(sizeof(EntityOccupationBucketItem) == 0x08, "EntityOccupationBucketItem size must be 0x08");

  struct EntityCollisionCellSpanRuntimeView
  {
    std::uint8_t mUnknown00[0x0C];
    std::uint8_t mMarked;
    std::uint8_t mUnknown0D[3];
    std::uint32_t mTypeFlags;
  };

  static_assert(
    offsetof(EntityCollisionCellSpanRuntimeView, mMarked) == 0x0C,
    "EntityCollisionCellSpanRuntimeView::mMarked offset must be 0x0C"
  );
  static_assert(
    offsetof(EntityCollisionCellSpanRuntimeView, mTypeFlags) == 0x10,
    "EntityCollisionCellSpanRuntimeView::mTypeFlags offset must be 0x10"
  );

  [[nodiscard]] EntityCollisionCellSpanRuntimeView&
  AccessSpanRuntime(moho::EntityCollisionCellSpan* const span) noexcept
  {
    return *reinterpret_cast<EntityCollisionCellSpanRuntimeView*>(span);
  }

  [[nodiscard]] bool IsSpanMarked(moho::EntityCollisionCellSpan* const span) noexcept
  {
    return span && AccessSpanRuntime(span).mMarked != 0u;
  }

  void SetSpanMarked(moho::EntityCollisionCellSpan* const span, const bool marked) noexcept
  {
    if (!span) {
      return;
    }

    AccessSpanRuntime(span).mMarked = marked ? 1u : 0u;
  }

  [[nodiscard]] std::uint32_t SpanTypeFlags(moho::EntityCollisionCellSpan* const span) noexcept
  {
    return span ? AccessSpanRuntime(span).mTypeFlags : 0u;
  }

  struct GridTraversalLine
  {
    float x0;           // +0x00
    float z0;           // +0x04
    float x1;           // +0x08
    float z1;           // +0x0C
    float dx;           // +0x10
    float dz;           // +0x14
    std::int32_t step;  // +0x18
    std::int32_t xEdge; // +0x1C
    std::int32_t zEdge; // +0x20
    std::int32_t xMask; // +0x24
    std::int32_t zMask; // +0x28
  };
  static_assert(sizeof(GridTraversalLine) == 0x2C, "GridTraversalLine size must be 0x2C");

  [[nodiscard]] std::int32_t FloorToInt(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value));
  }

  void InitGridTraversalLine(
    GridTraversalLine& line,
    const std::int32_t step,
    const float xEnd,
    const float xStart,
    const float zStart,
    const float zEnd
  ) noexcept
  {
    line.step = step;

    if (xEnd < xStart) {
      line.x0 = -xStart;
      line.x1 = -xEnd;
      line.xMask = -step;
    } else {
      line.x0 = xStart;
      line.x1 = xEnd;
      line.xMask = 0;
    }

    std::int32_t zMask = 0;
    if (zEnd < zStart) {
      line.z0 = -zStart;
      line.z1 = -zEnd;
      zMask = -step;
    } else {
      line.z0 = zStart;
      line.z1 = zEnd;
    }

    line.dx = line.x1 - line.x0;
    line.dz = line.z1 - line.z0;
    line.zMask = zMask;

    const std::int32_t alignMask = -step;
    line.xEdge = FloorToInt(line.x0) & alignMask;
    line.zEdge = FloorToInt(line.z0) & alignMask;
  }

  void AdvanceGridTraversalEdge(GridTraversalLine& line) noexcept
  {
    const std::int32_t nextXEdge = line.xEdge + line.step;
    const std::int32_t nextZEdge = line.zEdge + line.step;

    const float xMetric = (static_cast<float>(nextXEdge) - line.x1) * line.dz;
    const float zMetric = (static_cast<float>(nextZEdge) - line.z1) * line.dx;
    if (zMetric <= xMetric) {
      line.zEdge = nextZEdge;
    } else {
      line.xEdge = nextXEdge;
    }
  }

  void GetGridTraversalCell(const GridTraversalLine& line, std::int32_t& outX, std::int32_t& outZ) noexcept
  {
    outX = line.xEdge ^ line.xMask;
    outZ = line.zEdge ^ line.zMask;
  }

  [[nodiscard]] bool IsGridTraversalBeyondEnd(const GridTraversalLine& line) noexcept
  {
    return static_cast<float>(line.xEdge) > line.x1 || static_cast<float>(line.zEdge) > line.z1;
  }

  [[nodiscard]] moho::Entity* EntityFromCollisionSpan(moho::EntityCollisionCellSpan* const span) noexcept
  {
    if (span == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<moho::Entity*>(
      reinterpret_cast<std::uint8_t*>(span) - offsetof(moho::Entity, mCollisionCellSpan)
    );
  }

  constexpr std::uint32_t kLineQueryEntitySpanTypeMask = 0x0D00u;
  constexpr float kWorldToOccupancyCellScale = 0.25f;

  std::int32_t GatherUnmarkedEntitiesInLine(
    moho::EntityOccupationManager& manager,
    moho::EntityGatherVector& outEntities,
    const Wm3::Vec3f& lineStart,
    const Wm3::Vec3f& lineEnd
  )
  {
    outEntities.ResetStorageToInline();

    GridTraversalLine line{};
    InitGridTraversalLine(
      line,
      1,
      lineEnd.x * kWorldToOccupancyCellScale,
      lineStart.x * kWorldToOccupancyCellScale,
      lineStart.z * kWorldToOccupancyCellScale,
      lineEnd.z * kWorldToOccupancyCellScale
    );

    auto** const entityBuckets = reinterpret_cast<EntityOccupationBucketItem**>(manager.mEntityBuckets);
    auto** const unitBuckets = reinterpret_cast<EntityOccupationBucketItem**>(manager.mUnitBuckets);

    while (!IsGridTraversalBeyondEnd(line)) {
      std::int32_t cellX = 0;
      std::int32_t cellZ = 0;
      GetGridTraversalCell(line, cellX, cellZ);

      const std::int32_t bucketIndex = manager.mLastIndex & (cellX + (cellZ << manager.mGridWidthShift));
      if (entityBuckets != nullptr) {
        for (EntityOccupationBucketItem* item = entityBuckets[bucketIndex]; item != nullptr; item = item->mNext) {
          moho::EntityCollisionCellSpan* const span = item->mItem;
          if (span == nullptr) {
            continue;
          }
          if ((SpanTypeFlags(span) & kLineQueryEntitySpanTypeMask) == 0u || IsSpanMarked(span)) {
            continue;
          }

          SetSpanMarked(span, true);
          outEntities.PushBack(EntityFromCollisionSpan(span));
        }
      }

      if (unitBuckets != nullptr) {
        for (EntityOccupationBucketItem* item = unitBuckets[bucketIndex]; item != nullptr; item = item->mNext) {
          moho::EntityCollisionCellSpan* const span = item->mItem;
          if (span == nullptr || IsSpanMarked(span)) {
            continue;
          }

          SetSpanMarked(span, true);
          outEntities.PushBack(EntityFromCollisionSpan(span));
        }
      }

      AdvanceGridTraversalEdge(line);
    }

    const std::int32_t count = static_cast<std::int32_t>(outEntities.end_ - outEntities.start_);
    for (std::int32_t index = 0; index < count; ++index) {
      moho::Entity* const entity = outEntities.start_[index];
      if (entity != nullptr) {
        SetSpanMarked(&entity->mCollisionCellSpan, false);
      }
    }
    return count;
  }

  using TypeInfo = moho::COGridTypeInfo;

  alignas(TypeInfo) unsigned char gCOGridTypeInfoStorage[sizeof(TypeInfo)];
  bool gCOGridTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetCOGridTypeInfo() noexcept
  {
    if (!gCOGridTypeInfoConstructed) {
      new (gCOGridTypeInfoStorage) TypeInfo();
      gCOGridTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCOGridTypeInfoStorage);
  }

  [[nodiscard]] std::uint32_t GetCoGridMapWidthMinusOne(const moho::Sim* const sim) noexcept
  {
    const moho::CHeightField* const field = sim->mMapData->GetHeightField();
    return static_cast<std::uint32_t>(field->width - 1);
  }

  [[nodiscard]] std::uint32_t GetCoGridMapHeightMinusOne(const moho::Sim* const sim) noexcept
  {
    const moho::CHeightField* const field = sim->mMapData->GetHeightField();
    return static_cast<std::uint32_t>(field->height - 1);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007205B0 (FUN_007205B0, Moho::COGrid::COGrid)
   */
  COGrid::COGrid(Sim* const simArg)
    : sim(simArg)
    , mEntityOccupationManager(GetCoGridMapWidthMinusOne(simArg), GetCoGridMapHeightMinusOne(simArg))
    , terrainOccupation(GetCoGridMapWidthMinusOne(simArg), GetCoGridMapHeightMinusOne(simArg))
    , waterOccupation(GetCoGridMapWidthMinusOne(simArg), GetCoGridMapHeightMinusOne(simArg))
    , mOccupation(GetCoGridMapWidthMinusOne(simArg), GetCoGridMapHeightMinusOne(simArg))
  {}

  /**
   * Address: 0x004FCD20 (FUN_004FCD20, Moho::EntityOccupationManager::EntityOccupationManager)
   */
  EntityOccupationManager::EntityOccupationManager(const std::uint32_t width, const std::uint32_t height)
    : mWidth(static_cast<std::int32_t>(width >> 2))
    , mHeight(static_cast<std::int32_t>(height >> 2))
    , mLastIndex(0)
    , mGridWidthShift(mWidth > 0 ? static_cast<std::int32_t>(std::bit_width(static_cast<std::uint32_t>(mWidth)) - 1u) : -1)
    , mUnitBuckets(nullptr)
    , mPropBuckets(nullptr)
    , mEntityBuckets(nullptr)
    , mUnknown1C(0)
    , mUnknown20(0)
    , mUnknown24(0)
    , mAllBlocksBegin(nullptr)
    , mAllBlocksEnd(nullptr)
    , mAllBlocksCapacityEnd(nullptr)
  {
    mLastIndex =
      static_cast<std::int32_t>((static_cast<std::uint32_t>(mWidth) * static_cast<std::uint32_t>(mHeight)) - 1u);

    const std::size_t bucketCount = static_cast<std::size_t>(mLastIndex + 1);
    const std::size_t bucketBytes = bucketCount * sizeof(void*);

    mUnitBuckets = static_cast<void**>(::operator new(bucketBytes));
    mPropBuckets = static_cast<void**>(::operator new(bucketBytes));
    mEntityBuckets = static_cast<void**>(::operator new(bucketBytes));

    std::memset(mUnitBuckets, 0, bucketBytes);
    std::memset(mPropBuckets, 0, bucketBytes);
    std::memset(mEntityBuckets, 0, bucketBytes);
  }

  /**
   * Address: 0x00720680 (FUN_00720680, Moho::COGrid::~COGrid)
   */
  COGrid::~COGrid() = default;

  /**
   * Address: 0x004FCE10 (FUN_004FCE10, ??1EntityOccupationManager@Moho@@QAE@@Z)
   */
  EntityOccupationManager::~EntityOccupationManager()
  {
    operator delete[](mUnitBuckets);
    operator delete[](mPropBuckets);
    operator delete[](mEntityBuckets);

    if (mAllBlocksBegin) {
      const std::ptrdiff_t count = mAllBlocksEnd - mAllBlocksBegin;
      for (std::ptrdiff_t index = 0; index < count; ++index) {
        operator delete[](mAllBlocksBegin[index]);
      }
    }

    if (mAllBlocksBegin) {
      operator delete(mAllBlocksBegin);
    }

    mAllBlocksBegin = nullptr;
    mAllBlocksEnd = nullptr;
    mAllBlocksCapacityEnd = nullptr;
  }

  /**
   * Address: 0x004FD000 (FUN_004FD000, Moho::EntityOccupationManager::GatherUnmarkedUnitsInRect)
   */
  int EntityOccupationManager::GatherUnmarkedUnitsInRect(
    CollisionSpanVector& outSpans, const CollisionDBRect& rect, const EEntityType flags
  )
  {
    outSpans.ResetStorageToInline();

    const int startX = static_cast<int>(rect.mStartX);
    const int startZ = static_cast<int>(rect.mStartZ);
    int currentRowBase = startX + (startZ << mGridWidthShift);

    int xCount = static_cast<int>(rect.mWidth);
    const int maxXCount = mWidth - startX;
    if (xCount >= maxXCount) {
      xCount = maxXCount;
    }

    int zCount = mHeight - startZ;
    const int requestedZCount = static_cast<int>(rect.mHeight);
    if (requestedZCount < zCount) {
      zCount = requestedZCount;
    }

    auto** const unitBuckets = reinterpret_cast<EntityOccupationBucketItem**>(mUnitBuckets);
    auto** const propBuckets = reinterpret_cast<EntityOccupationBucketItem**>(mPropBuckets);
    auto** const entityBuckets = reinterpret_cast<EntityOccupationBucketItem**>(mEntityBuckets);

    if (zCount > 0) {
      do {
        if (xCount > 0) {
          int position = currentRowBase;
          int remainingX = xCount;
          const std::uint32_t flagBits = static_cast<std::uint32_t>(flags);
          const bool includeUnits = (flagBits & ENTITYTYPE_Unit) != 0u;
          const bool includeProps = (flagBits & ENTITYTYPE_Prop) != 0u;
          const bool includeDynamic = (flagBits & (ENTITYTYPE_Projectile | ENTITYTYPE_Entity)) != 0u;

          do {
            const int bucketIndex = position & mLastIndex;

            if (includeUnits && unitBuckets) {
              for (EntityOccupationBucketItem* item = unitBuckets[bucketIndex]; item; item = item->mNext) {
                EntityCollisionCellSpan* const span = item->mItem;
                if (!IsSpanMarked(span)) {
                  SetSpanMarked(span, true);
                  outSpans.PushBack(span);
                }
              }
            }

            if (includeProps && propBuckets) {
              for (EntityOccupationBucketItem* item = propBuckets[bucketIndex]; item; item = item->mNext) {
                EntityCollisionCellSpan* const span = item->mItem;
                if (!IsSpanMarked(span)) {
                  SetSpanMarked(span, true);
                  outSpans.PushBack(span);
                }
              }
            }

            if (includeDynamic && entityBuckets) {
              for (EntityOccupationBucketItem* item = entityBuckets[bucketIndex]; item; item = item->mNext) {
                EntityCollisionCellSpan* const span = item->mItem;
                if (((flagBits & SpanTypeFlags(span)) != 0u) && !IsSpanMarked(span)) {
                  SetSpanMarked(span, true);
                  outSpans.PushBack(span);
                }
              }
            }

            ++position;
            --remainingX;
          } while (remainingX != 0);
        }

        currentRowBase += mWidth;
        --zCount;
      } while (zCount != 0);
    }

    const int count = static_cast<int>(outSpans.end_ - outSpans.start_);
    for (int index = 0; index < count; ++index) {
      SetSpanMarked(outSpans.start_[index], false);
    }

    return count;
  }

  /**
   * Address: 0x00722DF0 (FUN_00722DF0, Moho::EntityOccupationManager::GatherUnmarkedEntities)
   */
  int EntityOccupationManager::GatherUnmarkedEntities(
    EntityGatherVector& outEntities, const CollisionDBRect& rect, const EEntityType flags
  )
  {
    auto& spanVector = reinterpret_cast<CollisionSpanVector&>(outEntities);
    const int count = GatherUnmarkedUnitsInRect(spanVector, rect, flags);
    for (int index = 0; index < count; ++index) {
      outEntities.start_[index] = reinterpret_cast<Entity*>(
        reinterpret_cast<std::uint8_t*>(outEntities.start_[index]) - 0x4Cu
      );
    }
    return count;
  }

  /**
   * Address: 0x00722B80 (FUN_00722B80, Moho::COGridTypeInfo::COGridTypeInfo)
   */
  COGridTypeInfo::COGridTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(COGrid), this);
  }

  /**
   * Address: 0x00722C10 (FUN_00722C10, Moho::COGridTypeInfo::dtr)
   */
  COGridTypeInfo::~COGridTypeInfo() = default;

  /**
   * Address: 0x00722C00 (FUN_00722C00, Moho::COGridTypeInfo::GetName)
   */
  const char* COGridTypeInfo::GetName() const
  {
    return "COGrid";
  }

  /**
   * Address: 0x00722BE0 (FUN_00722BE0, Moho::COGridTypeInfo::Init)
   */
  void COGridTypeInfo::Init()
  {
    size_ = sizeof(COGrid);
    gpg::RType::Init();
    Finish();
  }

  /**
   * What it does:
   * Releases startup-owned `COGridTypeInfo` storage at process teardown.
   */
  void cleanup_COGridTypeInfo()
  {
    if (!gCOGridTypeInfoConstructed) {
      return;
    }

    GetCOGridTypeInfo().~COGridTypeInfo();
    gCOGridTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BDAA90 (FUN_00BDAA90, register_COGridTypeInfo)
   */
  int register_COGridTypeInfo()
  {
    (void)GetCOGridTypeInfo();
    return std::atexit(&cleanup_COGridTypeInfo);
  }

  namespace
  {
    // IDA showed `(caps & OC_TERRAIN)` where OC_TERRAIN was a stale-enum
    // composite that does not exist in the recovered SDK enum — the binary
    // actually tests the low three OC_* bits (land/seabed/sub) together as
    // the "terrain" occupancy bucket. Expose the mask explicitly so recovered
    // behavior code can keep using named bits instead of raw hex.
    constexpr std::uint8_t kTerrainOccupancyMask =
      static_cast<std::uint8_t>(EOccupancyCaps::OC_LAND)
      | static_cast<std::uint8_t>(EOccupancyCaps::OC_SEABED)
      | static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB);
  } // namespace

  /**
   * Address: 0x00721A90 (FUN_00721A90, Moho::COGrid::ExecuteOccupy)
   *
   * IDA signature:
   * void __usercall Moho::COGrid::ExecuteOccupy(
   *   Moho::EOccupancyCaps caps@<al>,
   *   Moho::COGrid *this@<edi>,
   *   gpg::Rect2i *rect@<esi>);
   *
   * What it does:
   * Sets the occupancy bits for `rect` in the terrain and/or water
   * bitmaps selected by `caps`, then asks the sim path tables to mark every
   * path-cluster covering `rect` dirty so future path queries see the newly
   * occupied cells.
   */
  void COGrid::ExecuteOccupy(const EOccupancyCaps caps, const gpg::Rect2i& rect)
  {
    const std::uint8_t capsBits = static_cast<std::uint8_t>(caps);
    const int rectWidth = rect.x1 - rect.x0;
    const int rectHeight = rect.z1 - rect.z0;

    if ((capsBits & kTerrainOccupancyMask) != 0u) {
      terrainOccupation.FillRect(rect.x0, rect.z0, rectWidth, rectHeight, true);
    }
    if ((capsBits & static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER)) != 0u) {
      waterOccupation.FillRect(rect.x0, rect.z0, rectWidth, rectHeight, true);
    }
    sim->mPathTables->DirtyClusters(rect);
  }

  /**
   * Address: 0x00721B30 (FUN_00721B30, Moho::COGrid::ReleaseOccupy)
   *
   * IDA signature:
   * void __usercall sub_721B30(char caps@<al>, Moho::COGrid *this@<edi>, gpg::Rect2i *rect@<esi>);
   *
   * What it does:
   * Mirror of `ExecuteOccupy` — clears the same occupancy bits over `rect`
   * and dirties the covering path clusters. Freed cells become available for
   * future construction / pathing again.
   */
  void COGrid::ReleaseOccupy(const EOccupancyCaps caps, const gpg::Rect2i& rect)
  {
    const std::uint8_t capsBits = static_cast<std::uint8_t>(caps);
    const int rectWidth = rect.x1 - rect.x0;
    const int rectHeight = rect.z1 - rect.z0;

    if ((capsBits & kTerrainOccupancyMask) != 0u) {
      terrainOccupation.FillRect(rect.x0, rect.z0, rectWidth, rectHeight, false);
    }
    if ((capsBits & static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER)) != 0u) {
      waterOccupation.FillRect(rect.x0, rect.z0, rectWidth, rectHeight, false);
    }
    sim->mPathTables->DirtyClusters(rect);
  }

  /**
   * Address: 0x007229C0 (FUN_007229C0, Moho::COGrid::GetEntityCollisionsInLine)
   */
  void COGrid::GetEntityCollisionsInLine(
    EntityLineCollisionVector& outCollisions,
    const Wm3::Vec3f& lineStart,
    const Wm3::Vec3f& lineEnd
  )
  {
    EntityGatherVector gatheredEntities{};
    const std::int32_t gatheredCount =
      GatherUnmarkedEntitiesInLine(mEntityOccupationManager, gatheredEntities, lineStart, lineEnd);

    outCollisions.ResetStorageToInline();

    for (std::int32_t index = 0; index < gatheredCount; ++index) {
      Entity* const candidate = gatheredEntities.start_[index];
      if (candidate == nullptr) {
        continue;
      }

      EntityCollisionUpdater* const collisionPrimitive = candidate->CollisionExtents;
      if (collisionPrimitive == nullptr) {
        continue;
      }

      CollisionLineResult collisionResult{};
      if (!collisionPrimitive->CollideLine(&lineStart, &lineEnd, &collisionResult)) {
        continue;
      }

      EntityLineCollision resultEntry{};
      resultEntry.entity = candidate;
      resultEntry.direction = collisionResult.direction;
      resultEntry.position = collisionResult.position;
      resultEntry.distanceFromLineStart = collisionResult.distanceFromLineStart;
      outCollisions.PushBack(resultEntry);
    }
  }

  /**
   * Address: 0x004FCB40 (FUN_004FCB40, Moho::func_Rect2fToInt16)
   *
   * IDA signature:
   * Moho::CollisionDBRect *__usercall func_Rect2fToInt16@<eax>(
   *   Moho::CollisionDBRect *out@<eax>, gpg::Rect2f *rect@<edx>);
   *
   * What it does:
   * Quantizes a world-space `gpg::Rect2f` into a 16-bit cell-space
   * `CollisionDBRect` by right-shifting each corner by 2 (4-world-unit
   * cells: `kWorldToCollisionCellShift`), clamping the start corners into
   * `[0, 0xFFFF]`, and ensuring the resulting width/height are at least 1.
   */
  CollisionDBRect* func_Rect2fToInt16(CollisionDBRect* const out, const gpg::Rect2f& rect)
  {
    constexpr int kCollisionCellMaxValue = 0xFFFF;

    int startX = static_cast<int>(rect.x0) >> 2;
    int startZ = static_cast<int>(rect.z0) >> 2;
    int endX = (static_cast<int>(rect.x1) + 3) >> 2;
    int endZ = (static_cast<int>(rect.z1) + 3) >> 2;

    if (startX >= kCollisionCellMaxValue) {
      startX = kCollisionCellMaxValue;
    }
    if (startX < 0) {
      startX = 0;
    }
    out->mStartX = static_cast<std::uint16_t>(startX);

    if (startZ >= kCollisionCellMaxValue) {
      startZ = kCollisionCellMaxValue;
    }
    if (startZ < 0) {
      startZ = 0;
    }
    out->mStartZ = static_cast<std::uint16_t>(startZ);

    int widthRemaining = kCollisionCellMaxValue - startX;
    int widthRequested = endX - startX;
    if (widthRequested >= widthRemaining) {
      widthRequested = widthRemaining;
    }
    if (widthRequested < 1) {
      widthRequested = 1;
    }
    out->mWidth = static_cast<std::uint16_t>(widthRequested);

    int heightRemaining = kCollisionCellMaxValue - startZ;
    int heightRequested = endZ - startZ;
    if (heightRequested >= heightRemaining) {
      heightRequested = heightRemaining;
    }
    if (heightRequested < 1) {
      heightRequested = 1;
    }
    out->mHeight = static_cast<std::uint16_t>(heightRequested);

    return out;
  }

  /**
   * Address: 0x00720770 (FUN_00720770, Moho::struct_poi::RectFreeOfUnits)
   *
   * IDA signature:
   * bool callcnv_E3 struct_poi::RectFreeOfUnits@<al>(
   *   gpg::Rect2f *rect@<ebx>, Moho::COGrid *this);
   *
   * What it does:
   * Returns `true` when `rect` intersects any live non-mobile unit's skirt
   * rectangle — despite the IDA name, the boolean is "has blocking unit",
   * not "rect is free". Walks the collision-cell DB for units in the
   * quantized rect, converts each collision span back to its owner
   * entity, filters to non-mobile units, and tests their per-unit skirt
   * rectangles against `rect` for overlap.
   */
  bool COGrid_RectHasBlockingUnit(const gpg::Rect2f& rect, COGrid& grid)
  {
    CollisionDBRect cellRect{};
    (void)func_Rect2fToInt16(&cellRect, rect);

    CollisionSpanVector gatheredSpans;
    (void)grid.mEntityOccupationManager.GatherUnmarkedUnitsInRect(gatheredSpans, cellRect, ENTITYTYPE_Unit);

    // The binary pre-converts each returned "span pointer" into its owning
    // entity pointer by subtracting 0x4C (the `Entity::mCollisionCellSpan`
    // subobject offset from the containing `Entity`). Mirror that here.
    const int gatheredCount = static_cast<int>(gatheredSpans.end_ - gatheredSpans.start_);
    for (int index = 0; index < gatheredCount; ++index) {
      auto* const spanPtr = gatheredSpans.start_[index];
      if (spanPtr == nullptr) {
        continue;
      }

      auto* const rawSpan = reinterpret_cast<std::uint8_t*>(spanPtr) - offsetof(Entity, mCollisionCellSpan);
      Entity* const ownerEntity = reinterpret_cast<Entity*>(rawSpan);

      Unit* const ownerUnit = ownerEntity->IsUnit();
      if (ownerUnit == nullptr) {
        continue;
      }
      if (ownerUnit->IsMobile()) {
        continue;
      }

      const Wm3::Vec3f& unitPosition = ownerUnit->GetPosition();
      const SCoordsVec2 unitPosXZ{unitPosition.x, unitPosition.z};
      const RUnitBlueprint* const unitBlueprint = ownerUnit->GetBlueprint();
      const gpg::Rect2f unitSkirtRect = unitBlueprint->GetSkirtRect(unitPosXZ);

      if (unitSkirtRect.x1 > rect.x0 && rect.x1 > unitSkirtRect.x0 &&
          unitSkirtRect.z1 > rect.z0 && rect.z1 > unitSkirtRect.z0 &&
          rect.x1 > rect.x0 && rect.z0 < rect.z1 &&
          unitSkirtRect.x1 > unitSkirtRect.x0 && unitSkirtRect.z0 < unitSkirtRect.z1) {
        return true;
      }
    }
    return false;
  }
} // namespace moho

namespace
{
  struct COGridTypeInfoBootstrap
  {
    COGridTypeInfoBootstrap()
    {
      (void)moho::register_COGridTypeInfo();
    }
  };

  [[maybe_unused]] COGridTypeInfoBootstrap gCOGridTypeInfoBootstrap;
} // namespace
