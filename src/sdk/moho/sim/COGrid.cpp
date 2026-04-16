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

  [[nodiscard]] std::uint16_t ClampCollisionCellStartToU16(const int value) noexcept
  {
    if (value <= 0) {
      return 0u;
    }
    if (value >= 0xFFFF) {
      return 0xFFFFu;
    }
    return static_cast<std::uint16_t>(value);
  }

  [[nodiscard]] std::uint16_t
  ClampCollisionCellExtentToU16(const int extentCandidate, const std::uint16_t startCell) noexcept
  {
    const int maxExtent = 0xFFFF - static_cast<int>(startCell);
    int extent = extentCandidate;
    if (extent >= maxExtent) {
      extent = maxExtent;
    }
    if (extent < 0) {
      extent = 0;
    }
    return static_cast<std::uint16_t>(extent);
  }

  [[nodiscard]] moho::CollisionDBRect BuildCollisionRectFromBounds(
    const moho::EntityCollisionBoundsView& bounds
  ) noexcept
  {
    const int minCellX = FloorToInt(bounds.minX) >> 2;
    const int minCellZ = FloorToInt(bounds.minZ) >> 2;
    const int maxCellX = (static_cast<int>(std::ceil(bounds.maxX)) + 3) >> 2;
    const int maxCellZ = (static_cast<int>(std::ceil(bounds.maxZ)) + 3) >> 2;

    moho::CollisionDBRect rect{};
    rect.mStartX = ClampCollisionCellStartToU16(minCellX);
    rect.mStartZ = ClampCollisionCellStartToU16(minCellZ);
    rect.mWidth = ClampCollisionCellExtentToU16(maxCellX - static_cast<int>(rect.mStartX), rect.mStartX);
    rect.mHeight = ClampCollisionCellExtentToU16(maxCellZ - static_cast<int>(rect.mStartZ), rect.mStartZ);
    return rect;
  }

  struct CompactOccupancyRectExtentView
  {
    std::uint8_t width; // +0x00
    std::uint8_t height; // +0x01
    std::uint8_t caps; // +0x02
  };
  static_assert(
    sizeof(CompactOccupancyRectExtentView) == 0x03,
    "CompactOccupancyRectExtentView size must be 0x03"
  );

  struct CompactOccupancyRectOriginView
  {
    std::int16_t x; // +0x00
    std::int16_t z; // +0x02
  };
  static_assert(
    sizeof(CompactOccupancyRectOriginView) == 0x04,
    "CompactOccupancyRectOriginView size must be 0x04"
  );

  /**
   * Address: 0x00720550 (FUN_00720550)
   *
   * What it does:
   * Fills one `BitArray2D` occupancy range defined by `rect` using `value`.
   */
  [[maybe_unused]] void FillBitArrayRectFromRect2i(
    gpg::BitArray2D& occupancy,
    const gpg::Rect2i& rect,
    const bool value
  )
  {
    occupancy.FillRect(
      rect.x0,
      rect.z0,
      rect.x1 - rect.x0,
      rect.z1 - rect.z0,
      value
    );
  }

  /**
   * Address: 0x00720710 (FUN_00720710)
   *
   * What it does:
   * Clears `COGrid::mOccupation` bits over `rect`.
   */
  [[maybe_unused]] void ClearCOGridOccupationRect(const gpg::Rect2i& rect, moho::COGrid& grid)
  {
    FillBitArrayRectFromRect2i(grid.mOccupation, rect, false);
  }

  /**
   * Address: 0x00720740 (FUN_00720740)
   *
   * What it does:
   * Returns whether any occupied bit is set in `grid.mOccupation` over `rect`.
   */
  [[maybe_unused]] bool IsCOGridOccupationRectBlocked(const gpg::Rect2i& rect, const moho::COGrid& grid)
  {
    return grid.mOccupation.GetRectOr(
      rect.x0,
      rect.z0,
      rect.x1 - rect.x0,
      rect.z1 - rect.z0,
      true
    );
  }

  /**
   * Address: 0x00721B90 (FUN_00721B90)
   *
   * What it does:
   * Expands one compact origin/extent occupancy payload into `Rect2i` and
   * forwards the release to `COGrid::ReleaseOccupy`.
   */
  [[maybe_unused]] void ReleaseCompactOccupancyRect(
    const CompactOccupancyRectExtentView& extent,
    const CompactOccupancyRectOriginView& origin,
    moho::COGrid& grid
  )
  {
    gpg::Rect2i rect{};
    rect.x0 = static_cast<int>(origin.x);
    rect.z0 = static_cast<int>(origin.z);
    rect.x1 = rect.x0 + static_cast<int>(extent.width);
    rect.z1 = rect.z0 + static_cast<int>(extent.height);
    grid.ReleaseOccupy(static_cast<moho::EOccupancyCaps>(extent.caps), rect);
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
   * Address: 0x00722DD0 (FUN_00722DD0)
   *
   * What it does:
   * In-place construction adapter for `EntityOccupationManager` that preserves
   * the binary register/return contract by returning destination storage.
   */
  [[maybe_unused]] EntityOccupationManager* ConstructEntityOccupationManagerInPlace(
    const std::uint32_t width,
    EntityOccupationManager& destination,
    const std::uint32_t height
  )
  {
    ::new (&destination) EntityOccupationManager(width, height);
    return &destination;
  }

  /**
   * Address: 0x00720680 (FUN_00720680, Moho::COGrid::~COGrid)
   */
  COGrid::~COGrid() = default;

  /**
   * Address: 0x007206E0 (FUN_007206E0, Moho::COGrid::OccupyRect)
   *
   * What it does:
   * Marks `mOccupation` set over `rect` by filling the rectangle extents.
   */
  void COGrid::OccupyRect(const gpg::Rect2i& rect)
  {
    mOccupation.FillRect(rect.x0, rect.z0, rect.x1 - rect.x0, rect.z1 - rect.z0, true);
  }

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
    * Alias of FUN_00721A90 (non-canonical helper lane).
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
   * Address: 0x00721BD0 (FUN_00721BD0)
   *
   * What it does:
   * Converts one world-space collision bounds lane into a quantized
   * collision-cell rectangle and gathers unmarked entity owners of `flags`
   * from this grid's occupation manager into `outEntities`.
   */
  [[maybe_unused]] int GatherUnmarkedEntitiesInBounds(
    const EntityCollisionBoundsView& bounds,
    COGrid& grid,
    const EEntityType flags,
    EntityGatherVector& outEntities
  )
  {
    const CollisionDBRect rect = BuildCollisionRectFromBounds(bounds);
    return grid.mEntityOccupationManager.GatherUnmarkedEntities(outEntities, rect, flags);
  }

  [[nodiscard]] static Wm3::AxisAlignedBox3f BuildAxisAlignedBoundsFromOrientedBox(const Wm3::Box3f& box) noexcept
  {
    const float centerX = box.Center[0];
    const float centerY = box.Center[1];
    const float centerZ = box.Center[2];

    const float radiusX =
      (std::fabs(box.Axis[0][0]) * box.Extent[0]) +
      (std::fabs(box.Axis[1][0]) * box.Extent[1]) +
      (std::fabs(box.Axis[2][0]) * box.Extent[2]);
    const float radiusY =
      (std::fabs(box.Axis[0][1]) * box.Extent[0]) +
      (std::fabs(box.Axis[1][1]) * box.Extent[1]) +
      (std::fabs(box.Axis[2][1]) * box.Extent[2]);
    const float radiusZ =
      (std::fabs(box.Axis[0][2]) * box.Extent[0]) +
      (std::fabs(box.Axis[1][2]) * box.Extent[1]) +
      (std::fabs(box.Axis[2][2]) * box.Extent[2]);

    Wm3::AxisAlignedBox3f out{};
    out.Min.x = centerX - radiusX;
    out.Min.y = centerY - radiusY;
    out.Min.z = centerZ - radiusZ;
    out.Max.x = centerX + radiusX;
    out.Max.y = centerY + radiusY;
    out.Max.z = centerZ + radiusZ;
    return out;
  }

  [[nodiscard]] static bool AxisAlignedBoundsOverlapEntityBounds(
    const Wm3::AxisAlignedBox3f& bounds,
    const Entity& entity
  ) noexcept
  {
    const Wm3::Vec3f& entityMin = entity.mCollisionBoundsMin;
    const Wm3::Vec3f& entityMax = entity.mCollisionBoundsMax;
    return bounds.Min.x <= entityMax.x && entityMin.x <= bounds.Max.x &&
      bounds.Min.y <= entityMax.y && entityMin.y <= bounds.Max.y &&
      bounds.Min.z <= entityMax.z && entityMin.z <= bounds.Max.z;
  }

  [[nodiscard]] static Wm3::AxisAlignedBox3f BuildAxisAlignedBoundsFromSphere(
    const Wm3::Sphere3f& sphere
  ) noexcept
  {
    Wm3::AxisAlignedBox3f bounds{};
    bounds.Min.x = sphere.Center.x - sphere.Radius;
    bounds.Min.y = sphere.Center.y - sphere.Radius;
    bounds.Min.z = sphere.Center.z - sphere.Radius;
    bounds.Max.x = sphere.Center.x + sphere.Radius;
    bounds.Max.y = sphere.Center.y + sphere.Radius;
    bounds.Max.z = sphere.Center.z + sphere.Radius;
    return bounds;
  }

  [[nodiscard]] static bool AxisAlignedBoundsContainEntityBounds(
    const Wm3::AxisAlignedBox3f& bounds,
    const Entity& entity
  ) noexcept
  {
    const Wm3::Vec3f& entityMin = entity.mCollisionBoundsMin;
    const Wm3::Vec3f& entityMax = entity.mCollisionBoundsMax;
    return bounds.Min.x <= entityMin.x && entityMax.x <= bounds.Max.x &&
      bounds.Min.y <= entityMin.y && entityMax.y <= bounds.Max.y &&
      bounds.Min.z <= entityMin.z && entityMax.z <= bounds.Max.z;
  }

  /**
   * Address: 0x00721DC0 (FUN_00721DC0, Moho::COGrid::CollectEntitiesInBox)
   *
   * What it does:
   * Gathers unmarked candidate entities in one query box's collision-cell
   * range, prefilters by cached per-entity AABB overlap, then appends
   * primitive `CollideBox` hits to `outCollisions`.
   */
  void COGrid::CollectEntitiesInBox(
    CollisionResultFastVectorN10& outCollisions,
    const EEntityType flags,
    const Wm3::Box3f& box
  )
  {
    const Wm3::AxisAlignedBox3f queryBounds = BuildAxisAlignedBoundsFromOrientedBox(box);
    const EntityCollisionBoundsView queryBoundsView{
      queryBounds.Min.x,
      queryBounds.Min.y,
      queryBounds.Min.z,
      queryBounds.Max.x,
      queryBounds.Max.y,
      queryBounds.Max.z
    };

    EntityGatherVector gatheredEntities{};
    const int gatheredCount = GatherUnmarkedEntitiesInBounds(
      queryBoundsView,
      *this,
      flags,
      gatheredEntities
    );

    outCollisions.ResetStorageToInline();

    for (int index = 0; index < gatheredCount; ++index) {
      Entity* const candidate = gatheredEntities.start_[index];
      if (candidate == nullptr || !AxisAlignedBoundsOverlapEntityBounds(queryBounds, *candidate)) {
        continue;
      }

      EntityCollisionUpdater* const collisionPrimitive = candidate->CollisionExtents;
      if (collisionPrimitive == nullptr) {
        continue;
      }

      CollisionPairResult collisionResult{};
      if (!collisionPrimitive->CollideBox(&box, &collisionResult)) {
        continue;
      }

      collisionResult.sourceEntity = candidate;
      outCollisions.PushBack(collisionResult);
    }
  }

  /**
   * Address: 0x00721FB0 (FUN_00721FB0, Moho::COGrid::ForAllEntitiesIterator)
   *
   * What it does:
   * Gathers unmarked candidate entities in one sphere bounds lane, then
   * appends per-entity sphere collision results. For larger radii, first
   * accepts entities whose cached bounds lie fully inside a reduced inner box.
   */
  void COGrid::ForAllEntitiesIterator(
    CollisionResultFastVectorN10& outCollisions,
    const EEntityType flags,
    const Wm3::Sphere3f& sphere
  )
  {
    const Wm3::AxisAlignedBox3f queryBounds = BuildAxisAlignedBoundsFromSphere(sphere);
    const EntityCollisionBoundsView queryBoundsView{
      queryBounds.Min.x,
      queryBounds.Min.y,
      queryBounds.Min.z,
      queryBounds.Max.x,
      queryBounds.Max.y,
      queryBounds.Max.z
    };

    EntityGatherVector gatheredEntities{};
    const int gatheredCount = GatherUnmarkedEntitiesInBounds(
      queryBoundsView,
      *this,
      flags,
      gatheredEntities
    );

    outCollisions.ResetStorageToInline();

    CollisionPairResult collisionResult{};
    if (sphere.Radius <= 3.0f) {
      for (int index = 0; index < gatheredCount; ++index) {
        Entity* const candidate = gatheredEntities.start_[index];
        if (candidate == nullptr) {
          continue;
        }

        EntityCollisionUpdater* const collisionPrimitive = candidate->CollisionExtents;
        if (collisionPrimitive == nullptr || !collisionPrimitive->CollideSphere(&sphere, &collisionResult)) {
          continue;
        }

        collisionResult.sourceEntity = candidate;
        outCollisions.PushBack(collisionResult);
      }
      return;
    }

    constexpr float kInnerBoundsScale = 0.70700002f;
    const float innerRadius = sphere.Radius * kInnerBoundsScale;
    Wm3::AxisAlignedBox3f innerBounds{};
    innerBounds.Min.x = sphere.Center.x - innerRadius;
    innerBounds.Min.y = sphere.Center.y - innerRadius;
    innerBounds.Min.z = sphere.Center.z - innerRadius;
    innerBounds.Max.x = sphere.Center.x + innerRadius;
    innerBounds.Max.y = sphere.Center.y + innerRadius;
    innerBounds.Max.z = sphere.Center.z + innerRadius;

    for (int index = 0; index < gatheredCount; ++index) {
      Entity* const candidate = gatheredEntities.start_[index];
      if (candidate == nullptr) {
        continue;
      }

      if (AxisAlignedBoundsContainEntityBounds(innerBounds, *candidate)) {
        collisionResult.sourceEntity = candidate;
        outCollisions.PushBack(collisionResult);
        continue;
      }

      EntityCollisionUpdater* const collisionPrimitive = candidate->CollisionExtents;
      if (collisionPrimitive == nullptr || !collisionPrimitive->CollideSphere(&sphere, &collisionResult)) {
        continue;
      }

      collisionResult.sourceEntity = candidate;
      outCollisions.PushBack(collisionResult);
    }
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
   * Address: 0x004FCA10 (FUN_004FCA10, Moho::CollisionDBRect::NotEqual)
   *
   * What it does:
   * Returns `true` when `this` and `other` differ in any lane.
   */
  bool CollisionDBRect::NotEqual(const CollisionDBRect& other) const noexcept
  {
    return other.mStartX != mStartX || other.mWidth != mWidth || other.mStartZ != mStartZ || other.mHeight != mHeight;
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
