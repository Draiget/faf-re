#include "gpg/core/utils/Logging.h"
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
#include <vector>

#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/Unit.h"
#include "moho/path/PathTables.h"
#include "Wm3Box3.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/GridTraversalLine.h"
#include "moho/sim/SimThreadRole.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using moho::AdvanceGridTraversalEdge;
  using moho::GetGridTraversalCell;
  using moho::GridTraversalLine;
  using moho::InitGridTraversalLine;
  using moho::IsGridTraversalBeyondEnd;

  [[nodiscard]] std::int32_t FloorToInt(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value));
  }

  [[nodiscard]] std::int32_t CeilToInt(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::ceil(value));
  }

  // One collision cell spans 4 world units, so world -> cell is a shift by 2.
  inline constexpr int kWorldToCollisionCellShift = 2;
} // namespace

/**
 * Address: 0x0040D860 (FUN_0040D860, ??0struct_Line@@QAE@@Z)
 *
 * IDA signature:
 * void __thiscall struct_Line::struct_Line(int step, struct_Line *line,
 *   float xEnd, float xStart, float zStart, float zEnd);
 *
 * What it does:
 * Initializes grid-walker line state from segment endpoints and step size.
 * Each axis whose end lies before its start is negated so the walk always runs
 * in the increasing direction, and the flip is recorded in that axis' mask.
 *
 * This is the one out-of-line definition; the binary has a real function here,
 * so it is deliberately not header-inline. The type and the three inlined
 * walker helpers live in moho/sim/GridTraversalLine.h.
 */
void moho::InitGridTraversalLine(
  GridTraversalLine& line,
  const std::int32_t step,
  const float xEnd,
  const float xStart,
  const float zStart,
  const float zEnd
) noexcept
{
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
}

/**
 * Address: 0x00475FD0 (FUN_00475FD0, sub_475FD0)
 *
 * IDA signature:
 * int __usercall sub_475FD0@<eax>(int result@<eax>);
 *
 * What it does:
 * Advances one grid-boundary edge (X or Z) based on segment crossing order.
 */
void moho::AdvanceGridTraversalEdge(GridTraversalLine& line) noexcept
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

/**
 * Address: 0x00476050 (FUN_00476050)
 *
 * IDA signature:
 * int *__usercall sub_476050@<eax>(int *result@<eax>, _DWORD *a2@<ecx>);
 *
 * What it does:
 * Decodes current signed cell coordinates from masked traversal edge state.
 */
void moho::GetGridTraversalCell(
  const GridTraversalLine& line, std::int32_t& outX, std::int32_t& outZ
) noexcept
{
  outX = line.xEdge ^ line.xMask;
  outZ = line.zEdge ^ line.zMask;
}

/**
 * Address: 0x00476070 (FUN_00476070)
 *
 * What it does:
 * Returns true once traversal edges move past the segment end coordinates.
 */
bool moho::IsGridTraversalBeyondEnd(const GridTraversalLine& line) noexcept
{
  return static_cast<float>(line.xEdge) > line.x1 || static_cast<float>(line.zEdge) > line.z1;
}

namespace
{
  constexpr std::uint32_t kLineQueryEntitySpanTypeMask = 0x0D00u;
  constexpr float kWorldToOccupancyCellScale = 0.25f;

  /**
   * Engine addition, not recovered from the binary: per-thread dedup for occupancy gathers run on
   * CSimWorkerPool workers.
   *
   * The binary dedups a gather through the shapes themselves. It sets `CollisionShapeBase::mMarked`
   * on each shape it collects and clears the marks after the walk (0x004FD200, 0x004FD000). Every
   * query is therefore a write to shared shapes, and two gathers running at once would corrupt each
   * other's marks.
   *
   * On a worker, the same walk dedups through this thread-private set instead: same shapes, same
   * order, no shared writes. The Sim thread keeps the binary's mark path. A generation stamp makes
   * `Begin` O(1), so the table is never cleared between queries.
   */
  class GatherVisitSet
  {
  public:
    void Begin() noexcept
    {
      if (++mStamp == 0u) {
        std::fill(mSlots.begin(), mSlots.end(), Slot{});
        mStamp = 1u;
      }
      mSize = 0u;
    }

    /// True the first time `shape` is seen since `Begin`.
    [[nodiscard]] bool Insert(const moho::CollisionShapeBase* const shape)
    {
      if ((mSize + 1u) * 2u > mSlots.size()) {
        Grow();
      }
      return Place(shape);
    }

  private:
    struct Slot
    {
      const moho::CollisionShapeBase* shape = nullptr;
      std::uint32_t stamp = 0u;
    };

    [[nodiscard]] bool Place(const moho::CollisionShapeBase* const shape) noexcept
    {
      const std::size_t mask = mSlots.size() - 1u;
      // Fibonacci hashing of the pointer; shapes are at least 4-byte aligned.
      std::size_t index = static_cast<std::size_t>((reinterpret_cast<std::uintptr_t>(shape) >> 2) * 2654435761u) & mask;
      for (;;) {
        Slot& slot = mSlots[index];
        if (slot.stamp != mStamp) {
          slot.shape = shape;
          slot.stamp = mStamp;
          ++mSize;
          return true;
        }
        if (slot.shape == shape) {
          return false;
        }
        index = (index + 1u) & mask;
      }
    }

    void Grow()
    {
      std::vector<Slot> previous = std::move(mSlots);
      mSlots.assign(previous.empty() ? 256u : previous.size() * 2u, Slot{});
      mSize = 0u;
      for (const Slot& slot : previous) {
        if (slot.stamp == mStamp) {
          (void)Place(slot.shape);
        }
      }
    }

    std::vector<Slot> mSlots;
    std::uint32_t mStamp = 0u;
    std::size_t mSize = 0u;
  };

  thread_local GatherVisitSet tGatherVisits;

  /**
   * Claims `shape` for the current gather. On the owning thread this is the binary's
   * `if (!mMarked) { mMarked = 1; ... }`; on a pool worker it is a thread-private set test.
   */
  [[nodiscard]] bool ClaimGatherShape(moho::CollisionShapeBase* const shape, const bool useSharedMarks)
  {
    if (useSharedMarks) {
      if (shape->mMarked != 0u) {
        return false;
      }
      shape->mMarked = 1u;
      return true;
    }
    return tGatherVisits.Insert(shape);
  }

  /**
   * Address: 0x004FD200 (FUN_004FD200)
   *
   * What it does:
   * Walks the occupancy grid along a 2-D line between (lineEnd.x, lineStart.z)
   * and (lineStart.x, lineEnd.z), gathering each unmarked
   * `CollisionShapeBase*` it visits into `outSpans`. The entity-bucket
   * sweep filters by `kLineQueryEntitySpanTypeMask`; the unit-bucket sweep
   * accepts everything not already marked. After the march, each freshly
   * gathered shape has its mark cleared. The output holds the bucket payload,
   * `CollisionShapeBase*`; `GatherUnmarkedEntitiesInLine` (0x00722E30) maps
   * each to its owning `Entity`.
   *
   * IDA signature:
   *   sub_4FD200(Wm3::Vector3f *p2, Wm3::Vector3f *p1,
   *              gpg::fastvector_CollisionShapeBase *a3,
   *              Moho::EntityOccupationManager *a4)
   */
  std::int32_t MarchLineAndGatherCollisionSpans(
    moho::EntityOccupationManager& manager,
    gpg::core::FastVectorN<moho::CollisionShapeBase*, 20>& outSpans,
    const Wm3::Vec3f& lineStart,
    const Wm3::Vec3f& lineEnd
  )
  {
    outSpans.ResetStorageToInline();

    GridTraversalLine line{};
    InitGridTraversalLine(
      line,
      1,
      lineEnd.x * kWorldToOccupancyCellScale,
      lineStart.x * kWorldToOccupancyCellScale,
      lineStart.z * kWorldToOccupancyCellScale,
      lineEnd.z * kWorldToOccupancyCellScale
    );

    moho::EntityCollisionCellNode** const entityBuckets = manager.mEntityBuckets;
    moho::EntityCollisionCellNode** const unitBuckets = manager.mUnitBuckets;

    // Pool workers must not write `mMarked` on shared shapes; see `GatherVisitSet`.
    const bool useSharedMarks = !moho::IsSimWorkerThread();
    if (!useSharedMarks) {
      tGatherVisits.Begin();
    }

    while (!IsGridTraversalBeyondEnd(line)) {
      std::int32_t cellX = 0;
      std::int32_t cellZ = 0;
      GetGridTraversalCell(line, cellX, cellZ);

      const std::int32_t bucketIndex = manager.mLastIndex & (cellX + (cellZ << manager.mGridWidthShift));
      if (entityBuckets != nullptr) {
        for (moho::EntityCollisionCellNode* node = entityBuckets[bucketIndex]; node != nullptr; node = node->next) {
          moho::CollisionShapeBase* const shape = node->owner;
          if ((shape->mBucketFlags & kLineQueryEntitySpanTypeMask) == 0u || !ClaimGatherShape(shape, useSharedMarks)) {
            continue;
          }

          outSpans.PushBack(shape);
        }
      }

      if (unitBuckets != nullptr) {
        for (moho::EntityCollisionCellNode* node = unitBuckets[bucketIndex]; node != nullptr; node = node->next) {
          moho::CollisionShapeBase* const shape = node->owner;
          if (!ClaimGatherShape(shape, useSharedMarks)) {
            continue;
          }

          outSpans.PushBack(shape);
        }
      }

      AdvanceGridTraversalEdge(line);
    }

    const std::int32_t count = static_cast<std::int32_t>(outSpans.end_ - outSpans.start_);
    if (useSharedMarks) {
      for (std::int32_t index = 0; index < count; ++index) {
        outSpans.start_[index]->mMarked = 0u;
      }
    }
    return count;
  }

  /**
   * Address: 0x00722E30 (FUN_00722E30)
   *
   * What it does:
   * Runs `MarchLineAndGatherCollisionSpans` (0x004FD200) on the caller's own
   * vector, then rewrites each `CollisionShapeBase*` in place as its owning
   * `Entity*` (`add reg, -4Ch`, the `CollisionShape<Entity>` base offset).
   */
  std::int32_t GatherUnmarkedEntitiesInLine(
    moho::EntityOccupationManager& manager,
    gpg::core::FastVectorN<moho::Entity*, 20>& outEntities,
    const Wm3::Vec3f& lineStart,
    const Wm3::Vec3f& lineEnd
  )
  {
    // The binary gathers into this same buffer: the shape pointers and the
    // entity pointers share one `FastVectorN<pointer, 20>` object.
    auto& shapes = reinterpret_cast<gpg::core::FastVectorN<moho::CollisionShapeBase*, 20>&>(outEntities);

    const std::int32_t count = MarchLineAndGatherCollisionSpans(manager, shapes, lineStart, lineEnd);

    for (std::int32_t index = 0; index < count; ++index) {
      outEntities.start_[index] = moho::CollisionShape<moho::Entity>::OwnerOf(shapes.start_[index]);
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
    , mFreeNodeHead(nullptr)
    , mFreeNodeCount(0)
  {
    mLastIndex =
      static_cast<std::int32_t>((static_cast<std::uint32_t>(mWidth) * static_cast<std::uint32_t>(mHeight)) - 1u);

    const std::size_t bucketCount = static_cast<std::size_t>(mLastIndex + 1);
    const std::size_t bucketBytes = bucketCount * sizeof(void*);

    mUnitBuckets = static_cast<EntityCollisionCellNode**>(::operator new(bucketBytes));
    mPropBuckets = static_cast<EntityCollisionCellNode**>(::operator new(bucketBytes));
    mEntityBuckets = static_cast<EntityCollisionCellNode**>(::operator new(bucketBytes));

    std::memset(mUnitBuckets, 0, bucketBytes);
    std::memset(mPropBuckets, 0, bucketBytes);
    std::memset(mEntityBuckets, 0, bucketBytes);
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
    mOccupation.FillRect(rect, true);
  }

  /**
   * Address: 0x00720710 (FUN_00720710)
   *
   * What it does:
   * Clears `mOccupation` bits over `rect`.
   */
  void COGrid::VacateRect(const gpg::Rect2i& rect)
  {
    mOccupation.FillRect(rect, false);
  }

  /**
   * Address: 0x00720740 (FUN_00720740)
   *
   * What it does:
   * Returns whether any `mOccupation` bit over `rect` is set.
   */
  bool COGrid::IsRectOccupied(const gpg::Rect2i& rect) const
  {
    return mOccupation.GetRectOr(rect.x0, rect.z0, rect.x1 - rect.x0, rect.z1 - rect.z0, true);
  }

  /**
   * Address: 0x004FCE10 (FUN_004FCE10, ??1EntityOccupationManager@Moho@@QAE@@Z)
   */
  EntityOccupationManager::~EntityOccupationManager()
  {
    operator delete[](mUnitBuckets);
    operator delete[](mPropBuckets);
    operator delete[](mEntityBuckets);

    // 0x004FCE2C..0x004FCE59; the vector's own storage is released by
    // ~vector (the `_Tidy` at 0x004FCE5C).
    const int blockCount = static_cast<int>(mAllBlocks.size());
    for (int index = 0; index < blockCount; ++index) {
      operator delete[](mAllBlocks[index]);
    }
  }

  /**
   * Address: 0x004FCE90 (FUN_004FCE90)
   *
   * What it does:
   * Ensures free-node list contains at least `requiredFreeNodes` entries by
   * allocating 0x2000-node chunks (0x10000 bytes each) and linking them.
   */
  void EntityOccupationManager::EnsureSize(const int requiredFreeNodes)
  {
    while (mFreeNodeCount < requiredFreeNodes) {
      auto* chunk = static_cast<EntityCollisionCellNode*>(::operator new(0x10000u));
      for (int i = 0; i < 0x1FFF; ++i) {
        chunk[i].next = &chunk[i + 1];
      }

      chunk[0x1FFF].next = mFreeNodeHead;
      mFreeNodeHead = chunk;

      mAllBlocks.push_back(chunk);
      mFreeNodeCount += 0x2000;
    }
  }

  /**
   * Chooses the bucket array for a shape's family bits: units, props, then
   * entities/projectiles; shared by `AddColShapeAt` and `RemoveColShapeAt`.
   */
  static EntityCollisionCellNode** SelectBucketArray(EntityOccupationManager& grid, const std::uint32_t bucketFlags) noexcept
  {
    if ((bucketFlags & 0x100u) != 0u) {
      return grid.mUnitBuckets;
    }
    if ((bucketFlags & 0x200u) != 0u) {
      return grid.mPropBuckets;
    }
    if ((bucketFlags & 0x0C00u) != 0u) {
      return grid.mEntityBuckets;
    }
    return nullptr;
  }

  /**
   * Address: 0x004FCF20 (FUN_004FCF20)
   *
   * What it does:
   * Pops one node from the grid free-list, tags ownership to `shape`, then
   * prepends it to the selected collision bucket chain.
   */
  void EntityOccupationManager::AddColShapeAt(CollisionShapeBase* const shape, const int bucketIndex)
  {
    if ((shape->mBucketFlags & 0x0F00u) == 0u) {
      return;
    }

    EntityCollisionCellNode* const node = mFreeNodeHead;
    mFreeNodeHead = node->next;
    node->owner = shape;

    EntityCollisionCellNode** const bucketHeads = SelectBucketArray(*this, shape->mBucketFlags);
    node->next = bucketHeads[bucketIndex];
    bucketHeads[bucketIndex] = node;

    --mFreeNodeCount;
  }

  /**
   * Address: 0x004FCF90 (FUN_004FCF90)
   *
   * What it does:
   * Removes `shape`'s node from the selected bucket chain and returns the node
   * to the grid free-list.
   */
  void EntityOccupationManager::RemoveColShapeAt(const int bucketIndex, CollisionShapeBase* const shape)
  {
    if ((shape->mBucketFlags & 0x0F00u) == 0u) {
      return;
    }

    EntityCollisionCellNode** const bucketHeads = SelectBucketArray(*this, shape->mBucketFlags);
    EntityCollisionCellNode** link = &bucketHeads[bucketIndex];
    EntityCollisionCellNode* node = *link;
    while (node->owner != shape) {
      link = &node->next;
      node = node->next;
    }

    *link = node->next;
    node->owner = nullptr;
    node->next = mFreeNodeHead;
    ++mFreeNodeCount;
    mFreeNodeHead = node;
  }

  /**
   * The binary has no null test here; the guard predates this move and only
   * matters for a shape whose grid was never set.
   */
  CollisionShapeBase::~CollisionShapeBase()
  {
    if (mSpatialGrid != nullptr) {
      Remove();
    }
  }

  /**
   * Address: 0x004FD420 (FUN_004FD420)
   *
   * What it does:
   * Adds current shape membership into collision buckets for all covered cells.
   */
  void CollisionShapeBase::Add()
  {
    EntityOccupationManager& grid = *mSpatialGrid;
    const std::int32_t requiredNodes =
      static_cast<std::int32_t>(static_cast<std::uint32_t>(mWidth) * static_cast<std::uint32_t>(mHeight));
    grid.EnsureSize(requiredNodes);

    int rowBase = static_cast<int>(mStartX) + (static_cast<int>(mStartZ) << grid.mGridWidthShift);
    for (int row = 0; row < static_cast<int>(mHeight); ++row) {
      for (int col = 0; col < static_cast<int>(mWidth); ++col) {
        grid.AddColShapeAt(this, (rowBase + col) & static_cast<int>(grid.mLastIndex));
      }
      rowBase += grid.mWidth;
    }
  }

  /**
   * Address: 0x004FD490 (FUN_004FD490)
   *
   * What it does:
   * Removes current shape membership from collision buckets for all covered cells.
   */
  void CollisionShapeBase::Remove()
  {
    EntityOccupationManager& grid = *mSpatialGrid;
    int rowBase = static_cast<int>(mStartX) + (static_cast<int>(mStartZ) << grid.mGridWidthShift);
    for (int row = 0; row < static_cast<int>(mHeight); ++row) {
      for (int col = 0; col < static_cast<int>(mWidth); ++col) {
        grid.RemoveColShapeAt((rowBase + col) & static_cast<int>(grid.mLastIndex), this);
      }
      rowBase += grid.mWidth;
    }
  }

  void CollisionShapeBase::RelinkTo(const CollisionDBRect& rect)
  {
    if (!rect.NotEqual(*this)) {
      return;
    }

    Remove();
    static_cast<CollisionDBRect&>(*this) = rect;
    Add();
  }

  /**
   * Address: 0x004FD4F0 (FUN_004FD4F0)
   *
   * What it does:
   * Reads primitive AABB, rebuilds quantized shape rectangle, and if changed:
   * removes old bucket membership, writes new rectangle, then re-adds membership.
   */
  void CollisionShapeBase::UpdateRect(const CColPrimitiveBase* const primitive)
  {
    CollisionDBRect rect{};
    if (primitive != nullptr) {
      (void)func_AABoxToRect(&rect, primitive->GetBoundingBox());
    }
    RelinkTo(rect);
  }

  /**
   * Address: 0x004FD590 (FUN_004FD590)
   *
   * What it does:
   * Rebuilds quantized collision-cell rectangle directly from bounds and
   * relinks bucket membership only when the rectangle changed.
   */
  void CollisionShapeBase::UpdateRect(const Wm3::AxisAlignedBox3f& bounds)
  {
    CollisionDBRect rect{};
    (void)func_AABoxToRect(&rect, bounds);
    RelinkTo(rect);
  }

  /**
   * Address: 0x004FD000 (FUN_004FD000, Moho::EntityOccupationManager::GatherUnmarkedUnitsInRect)
   */
  int EntityOccupationManager::GatherUnmarkedUnitsInRect(
    gpg::core::FastVectorN<CollisionShapeBase*, 20>& outSpans, const CollisionDBRect& rect, const EEntityType flags
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

    EntityCollisionCellNode** const unitBuckets = mUnitBuckets;
    EntityCollisionCellNode** const propBuckets = mPropBuckets;
    EntityCollisionCellNode** const entityBuckets = mEntityBuckets;

    // Pool workers must not write `mMarked` on shared shapes; see `GatherVisitSet`.
    const bool useSharedMarks = !IsSimWorkerThread();
    if (!useSharedMarks) {
      tGatherVisits.Begin();
    }

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
              for (EntityCollisionCellNode* node = unitBuckets[bucketIndex]; node; node = node->next) {
                CollisionShapeBase* const shape = node->owner;
                if (ClaimGatherShape(shape, useSharedMarks)) {
                  outSpans.PushBack(shape);
                }
              }
            }

            if (includeProps && propBuckets) {
              for (EntityCollisionCellNode* node = propBuckets[bucketIndex]; node; node = node->next) {
                CollisionShapeBase* const shape = node->owner;
                if (ClaimGatherShape(shape, useSharedMarks)) {
                  outSpans.PushBack(shape);
                }
              }
            }

            if (includeDynamic && entityBuckets) {
              for (EntityCollisionCellNode* node = entityBuckets[bucketIndex]; node; node = node->next) {
                CollisionShapeBase* const shape = node->owner;
                if (((flagBits & shape->mBucketFlags) != 0u) && ClaimGatherShape(shape, useSharedMarks)) {
                  outSpans.PushBack(shape);
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
    if (useSharedMarks) {
      for (int index = 0; index < count; ++index) {
        outSpans.start_[index]->mMarked = 0u;
      }
    }

    return count;
  }

  /**
   * Address: 0x00722DF0 (FUN_00722DF0, Moho::EntityOccupationManager::GatherUnmarkedEntities)
   */
  int EntityOccupationManager::GatherUnmarkedEntities(
    gpg::core::FastVectorN<Entity*, 20>& outEntities, const CollisionDBRect& rect, const EEntityType flags
  )
  {
    // Same buffer reuse as `GatherUnmarkedEntitiesInLine`: gather shapes into
    // the caller's vector, then rewrite each as its owning entity.
    auto& shapes = reinterpret_cast<gpg::core::FastVectorN<CollisionShapeBase*, 20>&>(outEntities);
    const int count = GatherUnmarkedUnitsInRect(shapes, rect, flags);
    for (int index = 0; index < count; ++index) {
      outEntities.start_[index] = CollisionShape<Entity>::OwnerOf(shapes.start_[index]);
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

  namespace
  {
    /**
     * The footprint's cells at `origin`: (x, z, x + mSizeX, z + mSizeZ), from
     * the 16-bit origin words and the footprint's two size bytes.
     */
    [[nodiscard]] gpg::Rect2i FootprintRectAt(const SOCellPos& origin, const SFootprint& footprint) noexcept
    {
      const int x0 = origin.x;
      const int z0 = origin.z;
      return gpg::Rect2i{x0, z0, x0 + footprint.mSizeX, z0 + footprint.mSizeZ};
    }
  } // namespace

  /**
   * Address: 0x00721AF0 (FUN_00721AF0)
   *
   * What it does:
   * Occupies the footprint's cells at `origin` with its own occupancy caps.
   */
  void COGrid::ExecuteOccupy(const SOCellPos& origin, const SFootprint& footprint)
  {
    ExecuteOccupy(footprint.mOccupancyCaps, FootprintRectAt(origin, footprint));
  }

  /**
   * Address: 0x00721B90 (FUN_00721B90)
   *
   * What it does:
   * Releases the footprint's cells at `origin`.
   */
  void COGrid::ReleaseOccupy(const SOCellPos& origin, const SFootprint& footprint)
  {
    ReleaseOccupy(footprint.mOccupancyCaps, FootprintRectAt(origin, footprint));
  }

  /**
   * Address: 0x00721BD0 (FUN_00721BD0)
   *
   * What it does:
   * Converts one world-space collision bounds lane into a quantized
   * collision-cell rectangle and gathers unmarked entity owners of `flags`
   * from this grid's occupation manager into `outEntities`.
   */
  int COGrid::GatherUnmarkedEntities(
    const Wm3::AxisAlignedBox3f& bounds,
    const EEntityType flags,
    gpg::core::FastVectorN<Entity*, 20>& outEntities
  )
  {
    CollisionDBRect rect{};
    (void)func_AABoxToRect(&rect, bounds);
    return mEntityOccupationManager.GatherUnmarkedEntities(outEntities, rect, flags);
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

  /**
   * AABB overlap as CollectEntitiesInBox (0x00721EC0), func_GatherUnmarkedUnitsInBox (0x00721D00)
   * and ForAllEntitiesIterator (0x00722171) test it: per axis `comiss boundsMin, entity.Max; ja`
   * and `comiss entity.Min, boundsMax; ja` reject. Written as `!(a > b)`, not `a <= b`, so that a
   * NaN bound compares unordered and passes, as the `ja` lets it.
   */
  [[nodiscard]] static bool AxisAlignedBoundsOverlapEntityBounds(
    const Wm3::AxisAlignedBox3f& bounds,
    const Entity& entity
  ) noexcept
  {
    const Wm3::Vec3f& entityMin = entity.mAABox.Min;
    const Wm3::Vec3f& entityMax = entity.mAABox.Max;
    return !(bounds.Min.x > entityMax.x) && !(entityMin.x > bounds.Max.x) &&
      !(bounds.Min.y > entityMax.y) && !(entityMin.y > bounds.Max.y) &&
      !(bounds.Min.z > entityMax.z) && !(entityMin.z > bounds.Max.z);
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

  /**
   * Address: 0x007227B0 (FUN_007227B0, Moho::COGrid::CollectEntitiesCollidingWithEntity)
   *
   * IDA signature:
   * void __stdcall sub_7227B0(int arg0, Moho::EEntityType a1, Moho::Entity *arg8,
   *                           gpg::fastvector_CollisionResult *argC);
   *
   * What it does:
   * Gathers all unmarked candidate entities matching `flags` inside `source`'s
   * cached world-space collision AABB, filters them with a per-candidate AABB
   * overlap pre-check (all three axes overlapping) to skip disjoint pairs, and
   * then invokes `CColPrimitiveBase::Collide` between each candidate's and
   * `source`'s collision shape. Hits are appended into `outCollisions` with
   * `sourceEntity` stamped to the owning candidate. The source entity itself is
   * always excluded from the gathered set.
   *
   * Nothing in the shipped binary calls it: no call instruction, xref, data
   * reference or stored pointer targets 0x007227B0 (the ten call edges the
   * callgraph index lists are spurious rows; none of those functions contain
   * the call). It is kept as the COGrid member the engine defined.
   */
  void COGrid::CollectEntitiesCollidingWithEntity(
    const EEntityType flags,
    Entity* const source,
    gpg::core::FastVectorN<CollisionResult, 10>& outCollisions
  )
  {
    CollisionDBRect queryRect{};
    (void)func_AABoxToRect(&queryRect, source->mAABox);

    gpg::core::FastVectorN<Entity*, 20> gatheredEntities{};
    const int gatheredCount =
      mEntityOccupationManager.GatherUnmarkedEntities(gatheredEntities, queryRect, flags);

    outCollisions.ResetStorageToInline();

    CollisionResult collisionResult{};
    collisionResult.sourceEntity = source;

    for (int index = 0; index < gatheredCount; ++index) {
      Entity* const candidate = gatheredEntities.start_[index];
      if (candidate == nullptr || candidate == source) {
        continue;
      }

      // AABB overlap pre-check: all three axes (x, y, z) must overlap between
      // source.mCollisionBounds and candidate.mCollisionBounds. The binary
      // compares source.Min <= candidate.Max && candidate.Min <= source.Max
      // per axis using a sliding pointer pair — express it here by named
      // lane access.
      const Wm3::Vec3f& sourceMin = source->mAABox.Min;
      const Wm3::Vec3f& sourceMax = source->mAABox.Max;
      const Wm3::Vec3f& candidateMin = candidate->mAABox.Min;
      const Wm3::Vec3f& candidateMax = candidate->mAABox.Max;
      if (!(sourceMin.x <= candidateMax.x && candidateMin.x <= sourceMax.x &&
            sourceMin.y <= candidateMax.y && candidateMin.y <= sourceMax.y &&
            sourceMin.z <= candidateMax.z && candidateMin.z <= sourceMax.z)) {
        continue;
      }

      CColPrimitiveBase* const sourcePrimitive = source->CollisionExtents;
      CColPrimitiveBase* const candidatePrimitive = candidate->CollisionExtents;
      if (candidatePrimitive == nullptr ||
          !candidatePrimitive->Collide(sourcePrimitive, &collisionResult)) {
        continue;
      }

      collisionResult.sourceEntity = candidate;
      outCollisions.PushBack(collisionResult);
    }
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
    gpg::core::FastVectorN<CollisionResult, 10>& outCollisions,
    const EEntityType flags,
    const Wm3::Box3f& box
  )
  {
    const Wm3::AxisAlignedBox3f queryBounds = BuildAxisAlignedBoundsFromOrientedBox(box);

    gpg::core::FastVectorN<Entity*, 20> gatheredEntities{};
    const int gatheredCount = GatherUnmarkedEntities(queryBounds, flags, gatheredEntities);

    outCollisions.ResetStorageToInline();

    for (int index = 0; index < gatheredCount; ++index) {
      Entity* const candidate = gatheredEntities.start_[index];
      if (candidate == nullptr || !AxisAlignedBoundsOverlapEntityBounds(queryBounds, *candidate)) {
        continue;
      }

      CColPrimitiveBase* const collisionPrimitive = candidate->CollisionExtents;
      if (collisionPrimitive == nullptr) {
        continue;
      }

      CollisionResult collisionResult{};
      if (!collisionPrimitive->CollideBox(&box, &collisionResult)) {
        continue;
      }

      collisionResult.sourceEntity = candidate;
      outCollisions.PushBack(collisionResult);
    }
  }

  /**
   * Address: 0x00721C00 (FUN_00721C00, Moho::func_GatherUnmarkedUnitsInBox)
   *
   * IDA signature:
   * void __stdcall func_GatherUnmarkedUnitsInBox(Moho::COGrid *a1,
   *     Wm3::AxisAlignedBox3f *box, gpg::fastvector_CollisionResult *into);
   *
   * What it does:
   * Coarse AABB spatial query: gathers unmarked unit entities whose cached
   * collision AABB overlaps `box` and appends one CollisionResult
   * (sourceEntity = entity) per hit. Mirrors COGrid::CollectEntitiesInBox minus
   * the precise CollideBox step. Matching the binary, the gathered candidate is
   * NOT null-checked before the bounds test.
   */
  void GatherUnmarkedUnitsInBox(
    COGrid& grid,
    const Wm3::AxisAlignedBox3f& box,
    gpg::core::FastVectorN<CollisionResult, 10>& into
  )
  {
    gpg::core::FastVectorN<Entity*, 20> gatheredEntities{};
    const int gatheredCount = grid.GatherUnmarkedEntities(box, ENTITYTYPE_Unit, gatheredEntities);

    into.ResetStorageToInline();

    for (int index = 0; index < gatheredCount; ++index) {
      Entity* const candidate = gatheredEntities.start_[index];
      if (!AxisAlignedBoundsOverlapEntityBounds(box, *candidate)) {
        continue;
      }

      CollisionResult result{};
      result.sourceEntity = candidate;
      into.PushBack(result);
    }
  }

  /**
   * Address: 0x00721340 (FUN_00721340, Moho::COGrid::UnitIsBlocked)
   *
   * IDA signature:
   * char __thiscall Moho::COGrid::UnitIsBlocked(
   *   Moho::SOCellPos* this, Moho::COGrid* a2, Moho::Unit* a3, int mode);
   *
   * What it does:
   * See the header declaration — footprint-AABB gather + per-candidate oriented
   * box intersection, first confirmed blocker wins.
   */
  bool COGrid::UnitIsBlocked(const SOCellPos& cellPos, COGrid& grid, Unit* const unit, const int mode)
  {
    // Query unit footprint drives both the gather AABB span and the later
    // oriented-box half-extents.
    const SFootprint& queryFootprint = unit->GetFootprint();
    const std::uint8_t sizeX = queryFootprint.mSizeX;
    const std::uint8_t sizeZ = queryFootprint.mSizeZ;
    const std::uint8_t maxSpan = (sizeX <= sizeZ) ? sizeZ : sizeX;

    Wm3::AxisAlignedBox3f box{};
    box.Min.x = static_cast<float>(cellPos.x);
    box.Max.x = static_cast<float>(cellPos.x + maxSpan);
    box.Min.y = -1000.0f;
    box.Max.y = 1000.0f;
    box.Min.z = static_cast<float>(cellPos.z);
    box.Max.z = static_cast<float>(cellPos.z + maxSpan);

    gpg::core::FastVectorN<CollisionResult, 10> nearbyUnits{};
    GatherUnmarkedUnitsInBox(grid, box, nearbyUnits);

    for (const CollisionResult& hit : nearbyUnits) {
      Entity* const source = hit.sourceEntity;
      Unit* const candidate = source ? source->IsUnit() : nullptr;
      if (candidate == nullptr) {
        continue;
      }

      const ELayer candidateLayer = candidate->mVarDat.mLayerMask;
      if (candidateLayer == LAYER_Land) {
        // Land candidate: skip only when the query ignores structures but the
        // candidate does not (asymmetric ignore); otherwise run the pair test.
        const bool queryIgnoresStructures =
          (static_cast<std::uint8_t>(unit->GetFootprint().mFlags) &
           static_cast<std::uint8_t>(EFootprintFlags::FPFLAG_IgnoreStructures)) != 0u;
        const bool candidateIgnoresStructures =
          (static_cast<std::uint8_t>(candidate->GetFootprint().mFlags) &
           static_cast<std::uint8_t>(EFootprintFlags::FPFLAG_IgnoreStructures)) != 0u;
        if (queryIgnoresStructures && !candidateIgnoresStructures) {
          continue;
        }
      } else if (candidateLayer == LAYER_Air || candidateLayer == LAYER_Sub) {
        // Airborne / submerged candidates never block a footprint placement.
        continue;
      }

      Unit* const other = candidate->IsUnit();
      const bool formationDiffers =
        unit->IsUnitState(UNITSTATE_Attacking) || other->IsUnitState(UNITSTATE_Attacking) ||
        unit->mInfoCache.mFormationLayer == nullptr ||
        unit->mInfoCache.mFormationLayer != other->mInfoCache.mFormationLayer;
      if (!formationDiffers || func_IsSourceUnit(mode, *unit, other)) {
        continue;
      }

      // Immobile / tiny-footprint candidates block outright.
      if (!other->IsMobile()) {
        return true;
      }
      if (other->GetMaxFootprintSize() <= 1) {
        return true;
      }

      // Precise oriented-box intersection using the query unit's footprint
      // half-extents (X, 1000, Z), centered on the query box XZ midpoint.
      const Wm3::Vector3f boxCenter{(box.Max.x + box.Min.x) * 0.5f, 0.0f, (box.Max.z + box.Min.z) * 0.5f};
      const Wm3::Box3f queryBox(
        boxCenter,
        Wm3::Vector3f{1.0f, 0.0f, 0.0f},
        Wm3::Vector3f{0.0f, 1.0f, 0.0f},
        Wm3::Vector3f{0.0f, 0.0f, 1.0f},
        static_cast<float>(queryFootprint.mSizeX) * 0.5f,
        1000.0f,
        static_cast<float>(queryFootprint.mSizeZ) * 0.5f
      );

      CollisionResult pairResult{};
      if (other->Intersects(queryBox, &pairResult)) {
        return true;
      }
    }

    return false;
  }

  // Rotates a vector by a quaternion (defined in Sim.cpp) — same free helper the
  // sibling manipulator/formation TUs forward-declare.
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);

  // Quaternion rotating a movement direction 90 degrees about +Y (built from a
  // 45-degree half-angle) — quat_45deg1 (register_quat_45deg1, FUN_00BDA970).
  // Stored (w, x, y, z): cos(pi/4)=sin(pi/4)=0.70710677.
  constexpr Wm3::Quaternionf kSweptPathCrossRotation{0.70710677f, 0.0f, 0.70710677f, 0.0f};

  /**
   * Address: 0x007216D0 (FUN_007216D0, Moho::SweptPathBlockedByUnit)
   *
   * IDA signature:
   * char __stdcall sub_7216D0(COGrid* grid, Unit* unit, Wm3::Vector3f* fromCenter,
   *   Wm3::Vector3f* toCenter, int mode);
   *
   * What it does:
   * Sweeps the moving unit's footprint from `fromCenter` to `toCenter` as an
   * oriented box (width = blueprint size, length = segment length, cross axis =
   * direction rotated 90 degrees about Y) and reports whether any nearby mobile
   * unit of a different formation-layer that is not an ignorable source unit
   * lies inside the swept volume.
   */
  [[nodiscard]] bool SweptPathBlockedByUnit(
    COGrid& grid, Unit* const unit, const Wm3::Vector3f& fromCenter, const Wm3::Vector3f& toCenter, const int mode)
  {
    if (fromCenter == toCenter) {
      // Endpoints coincide — nothing to sweep.
      return false;
    }

    Wm3::Vector3f segment{toCenter.x - fromCenter.x, 0.0f, toCenter.z - fromCenter.z};
    Wm3::Vector3f direction = segment;
    (void)direction.Normalize();

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    const Wm3::Vector3f center{
      (fromCenter.x + toCenter.x) * 0.5f,
      (fromCenter.y + toCenter.y) * 0.5f,
      (fromCenter.z + toCenter.z) * 0.5f};

    Wm3::Vector3f crossAxis;
    (void)MultQuadVec(&crossAxis, &direction, &kSweptPathCrossRotation);

    const float dx = fromCenter.x - toCenter.x;
    const float dz = fromCenter.z - toCenter.z;
    const float halfLength = std::sqrt((dz * dz) + (dx * dx)) * 0.5f;

    const Wm3::Box3f sweptBox(
      center,
      crossAxis,
      Wm3::Vector3f{0.0f, 1.0f, 0.0f},
      direction,
      static_cast<float>(blueprint->mSizeX) * 0.55555558f,
      1000.0f,
      halfLength);

    gpg::core::FastVectorN<CollisionResult, 10> hits{};
    grid.CollectEntitiesInBox(hits, ENTITYTYPE_Unit, sweptBox);

    for (const CollisionResult& hit : hits) {
      Entity* const source = hit.sourceEntity;
      Unit* const candidate = source ? source->IsUnit() : nullptr;
      if (candidate == nullptr) {
        continue;
      }
      const ELayer candidateLayer = candidate->mVarDat.mLayerMask;
      if (candidateLayer == LAYER_Air || candidateLayer == LAYER_Sub) {
        continue;
      }
      if (!unit->IsSameFormationLayerWith(candidate) && !func_IsSourceUnit(mode, *unit, candidate)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00721990 (FUN_00721990, Moho::PathTransitionBlocked)
   *
   * IDA signature:
   * char __userpurge sub_721990(__int16* toCell, SOCellPos* fromCell,
   *   COGrid* grid, Unit* unit, int mode);
   *
   * What it does:
   * Tests whether `unit` can occupy the transition from `fromCell` to `toCell`.
   * For a same-cell move it defers to COGrid::UnitIsBlocked; otherwise it sweeps
   * the footprint between the two cell centres (SweptPathBlockedByUnit).
   */
  bool PathTransitionBlocked(
    const SOCellPos& toCell, const SOCellPos& fromCell, COGrid& grid, Unit* const unit, const int mode)
  {
    if (fromCell.x == toCell.x && fromCell.z == toCell.z) {
      return COGrid::UnitIsBlocked(fromCell, grid, unit, mode);
    }

    const SFootprint& footprint = unit->GetFootprint();
    const float halfSizeX = static_cast<float>(footprint.mSizeX) * 0.5f;
    const float halfSizeZ = static_cast<float>(footprint.mSizeZ) * 0.5f;

    const Wm3::Vector3f fromCenter{
      halfSizeX + static_cast<float>(fromCell.x), 0.0f, halfSizeZ + static_cast<float>(fromCell.z)};
    const Wm3::Vector3f toCenter{
      halfSizeX + static_cast<float>(toCell.x), 0.0f, halfSizeZ + static_cast<float>(toCell.z)};

    return SweptPathBlockedByUnit(grid, unit, fromCenter, toCenter, mode);
  }

  /**
   * Address: 0x00721FB0 (FUN_00721FB0, Moho::COGrid::ForAllEntitiesIterator)
   *
   * What it does:
   * Gathers unmarked candidate entities in one sphere bounds lane, then
   * appends per-entity sphere collision results. For larger radii, first
   * accepts entities whose cached bounds overlap a reduced inner box (0.707r).
   */
  void COGrid::ForAllEntitiesIterator(
    gpg::core::FastVectorN<CollisionResult, 10>& outCollisions,
    const EEntityType flags,
    const Wm3::Sphere3f& sphere
  )
  {
    const Wm3::AxisAlignedBox3f queryBounds = BuildAxisAlignedBoundsFromSphere(sphere);

    gpg::core::FastVectorN<Entity*, 20> gatheredEntities{};
    const int gatheredCount = GatherUnmarkedEntities(queryBounds, flags, gatheredEntities);

    outCollisions.ResetStorageToInline();

    CollisionResult collisionResult{};
    if (sphere.Radius <= 3.0f) {
      for (int index = 0; index < gatheredCount; ++index) {
        Entity* const candidate = gatheredEntities.start_[index];
        if (candidate == nullptr) {
          continue;
        }

        CColPrimitiveBase* const collisionPrimitive = candidate->CollisionExtents;
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

      // 0x00722171..0x0072218F: per axis `comiss innerMin, entity.Max; ja reject` and
      // `comiss entity.Min, innerMax; ja reject` -- an AABB *overlap* test, so any entity touching
      // the inner box is accepted without the sphere test. (This site used to test containment,
      // which sent such entities on to `CollideSphere` and could drop hits the binary keeps.)
      if (AxisAlignedBoundsOverlapEntityBounds(innerBounds, *candidate)) {
        collisionResult.sourceEntity = candidate;
        outCollisions.PushBack(collisionResult);
        continue;
      }

      CColPrimitiveBase* const collisionPrimitive = candidate->CollisionExtents;
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
    gpg::core::FastVectorN<EntityLineCollision, 10>& outCollisions,
    const Wm3::Vec3f& lineStart,
    const Wm3::Vec3f& lineEnd
  )
  {
    gpg::core::FastVectorN<Entity*, 20> gatheredEntities{};
    const std::int32_t gatheredCount =
      GatherUnmarkedEntitiesInLine(mEntityOccupationManager, gatheredEntities, lineStart, lineEnd);

    outCollisions.ResetStorageToInline();

    for (std::int32_t index = 0; index < gatheredCount; ++index) {
      Entity* const candidate = gatheredEntities.start_[index];
      if (candidate == nullptr) {
        continue;
      }

      CColPrimitiveBase* const collisionPrimitive = candidate->CollisionExtents;
      if (collisionPrimitive == nullptr) {
        continue;
      }

      CollisionSegmentResult collisionResult{};
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
   * Address: 0x004FCBE0 (FUN_004FCBE0, Moho::func_AABoxToRect)
   *
   * IDA signature:
   * Moho::CollisionDBRect *__usercall func_AABoxToRect@<eax>(
   *   Wm3::AxisAlignedBox3f *box@<eax>, Moho::CollisionDBRect *out@<ebx>);
   *
   * What it does:
   * Quantizes the X/Z footprint of a world-space axis-aligned box into a
   * cell-space `CollisionDBRect`.
   *
   * The binary derives each corner with `frndint` plus a compare-and-adjust
   * rather than a library call -- `fld x; frndint; fld x; fcomip; cmovb
   * eax,-1` at 0x004FCBFD is `floor`, and the `cmova eax,1` variants at
   * 0x004FCC59 / 0x004FCC88 are `ceil`. Only the X and Z lanes are read
   * (`[box+0]`, `[box+8]`, `[box+0Ch]`, `[box+14h]`); the Y extent plays no
   * part, because collision cells tile the ground plane.
   *
   * Both extents are measured from the *clamped* start (`movzx esi, dx` at
   * 0x004FCCCE re-reads the value already stored to the rect), so a box that
   * starts past the last cell yields an empty rect rather than a negative
   * width that would wrap when stored as `uint16_t`.
   */
  CollisionDBRect* func_AABoxToRect(CollisionDBRect* const out, const Wm3::AxisAlignedBox3f& box)
  {
    const int minCellX = FloorToInt(box.Min.x) >> kWorldToCollisionCellShift;
    const int minCellZ = FloorToInt(box.Min.z) >> kWorldToCollisionCellShift;
    const int maxCellX = (CeilToInt(box.Max.x) + 3) >> kWorldToCollisionCellShift;
    const int maxCellZ = (CeilToInt(box.Max.z) + 3) >> kWorldToCollisionCellShift;

    out->mStartX = ClampCollisionCellStartToU16(minCellX);
    out->mStartZ = ClampCollisionCellStartToU16(minCellZ);
    out->mWidth = ClampCollisionCellExtentToU16(maxCellX - static_cast<int>(out->mStartX), out->mStartX);
    out->mHeight = ClampCollisionCellExtentToU16(maxCellZ - static_cast<int>(out->mStartZ), out->mStartZ);
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

    gpg::core::FastVectorN<CollisionShapeBase*, 20> gatheredSpans;
    (void)grid.mEntityOccupationManager.GatherUnmarkedUnitsInRect(gatheredSpans, cellRect, ENTITYTYPE_Unit);

    // Each gathered shape is the `CollisionShape<Entity>` base of its entity
    // (the binary's `-0x4C`).
    const int gatheredCount = static_cast<int>(gatheredSpans.end_ - gatheredSpans.start_);
    for (int index = 0; index < gatheredCount; ++index) {
      auto* const spanPtr = gatheredSpans.start_[index];
      if (spanPtr == nullptr) {
        continue;
      }

      Entity* const ownerEntity = CollisionShape<Entity>::OwnerOf(spanPtr);

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

  /**
   * Address: 0x00722350 (FUN_00722350, func_EntitiesAroundPoint)
   *
   * IDA signature:
   * void __userpurge func_EntitiesAroundPoint(
   *   gpg::fastvector_CollisionResult *out@<esi>, float dist@<xmm0>,
   *   Moho::COGrid *grid, Moho::EEntityType type, Wm3::Vector3f *pos);
   *
   * What it does:
   * Collects entities of `type` whose XZ distance to `center` is within `radius`
   * into `outResults` (one `CollisionResult` per hit, `sourceEntity` set). Builds
   * a radius-sized AABB (Y spanning [-10000, 10000]), quantizes it via
   * `func_AABoxToRect` (FUN_004FCBE0), gathers unmarked entities
   * in that cell rect from the grid occupation manager
   * (`GatherUnmarkedEntities` = FUN_00722DF0), clears `outResults`, then appends
   * each entity that passes the squared-XZ range test with `push_back`, whose
   * full arm is the `CollisionResult` `InsertAt` (FUN_00723090).
   */
  void EntitiesAroundPoint(
    gpg::core::FastVectorN<CollisionResult, 10>& outResults,
    const float radius,
    COGrid& grid,
    const EEntityType type,
    const Wm3::Vector3f& center
  )
  {
    const float radiusSquared = radius * radius;

    // AABB around the query centre with an effectively unbounded vertical extent
    // (matches the binary's -10000 / +10000 Y lanes).
    const Wm3::AxisAlignedBox3f queryBounds{
      Wm3::Vector3f{center.x - radius, -10000.0f, center.z - radius},
      Wm3::Vector3f{center.x + radius, 10000.0f, center.z + radius},
    };

    CollisionDBRect gatherRect{};
    (void)func_AABoxToRect(&gatherRect, queryBounds);

    gpg::core::FastVectorN<Entity*, 20> gatheredEntities{};
    grid.mEntityOccupationManager.GatherUnmarkedEntities(gatheredEntities, gatherRect, type);

    // Release any escaped heap storage and rebind to the inline window before
    // repopulating (binary frees the heap buffer and restores the inline
    // start/cap sentinel, then sets end == start).
    outResults.ResetStorageToInline();

    CollisionResult hit{};
    for (Entity* const entity : gatheredEntities) {
      const float deltaX = entity->mVarDat.mCurTransform.pos_.x - center.x;
      const float deltaZ = entity->mVarDat.mCurTransform.pos_.z - center.z;
      if (radiusSquared <= (deltaX * deltaX) + (deltaZ * deltaZ)) {
        continue;
      }

      hit.sourceEntity = entity;
      outResults.push_back(hit);
    }
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


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_COGridTypeInfo_dc0e5e, moho::register_COGridTypeInfo)
