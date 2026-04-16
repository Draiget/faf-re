#include "moho/ai/CAiPathFinder.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <list>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/ai/CAiPathNavigator.h"
#include "moho/misc/Listener.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace moho
{
  class RBroadcasterRType_NavPath final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00764010 (FUN_00764010, Moho::RBroadcasterRType_NavPath::dtr)
     *
     * What it does:
     * Tears down one broadcaster-navpath type-info descriptor and releases
     * inherited `gpg::RType` reflection storage lanes.
     */
    ~RBroadcasterRType_NavPath() override;

    [[nodiscard]] const char* GetName() const override;
  };

  class RListenerRType_NavPath final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00764070 (FUN_00764070, Moho::RListenerRType_NavPath::dtr)
     *
     * What it does:
     * Tears down one listener-navpath type-info descriptor and releases
     * inherited `gpg::RType` reflection storage lanes.
     */
    ~RListenerRType_NavPath() override;

    [[nodiscard]] const char* GetName() const override;
  };
} // namespace moho

namespace
{
  using PathCellVector = msvc8::vector<moho::HPathCell>;

  /**
   * Address: 0x005A9890 (FUN_005A9890)
   *
   * What it does:
   * Swaps two 32-bit payload lanes and returns the first lane pointer.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* SwapDwordPayloadLanes(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    if (!lhs || !rhs) {
      return lhs;
    }

    const std::uint32_t temp = *lhs;
    *lhs = *rhs;
    *rhs = temp;
    return lhs;
  }

  /**
   * Address: 0x005A9C90 (FUN_005A9C90)
   *
   * What it does:
   * Clears one packed `HPathCell` lane to zero.
   */
  [[maybe_unused]] [[nodiscard]] moho::HPathCell* ClearPackedPathCell(moho::HPathCell* const outCell) noexcept
  {
    if (!outCell) {
      return nullptr;
    }

    outCell->x = 0u;
    outCell->z = 0u;
    return outCell;
  }

  /**
   * Address: 0x005A9CA0 (FUN_005A9CA0)
   *
   * What it does:
   * Copies one packed `HPathCell` lane into destination storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::HPathCell* CopyPackedPathCell(
    moho::HPathCell* const outCell,
    const moho::HPathCell* const sourceCell
  ) noexcept
  {
    if (!outCell || !sourceCell) {
      return outCell;
    }

    *outCell = *sourceCell;
    return outCell;
  }

  /**
   * Address: 0x005A9CB0 (FUN_005A9CB0)
   *
   * What it does:
   * Returns the first 16-bit lane from one packed path-cell payload.
   */
  [[maybe_unused]] [[nodiscard]] std::uint16_t ReadPackedPathCellLane0(const moho::HPathCell* const cell) noexcept
  {
    return cell ? cell->x : 0u;
  }

  /**
   * Address: 0x005A9CC0 (FUN_005A9CC0)
   *
   * What it does:
   * Returns the second 16-bit lane from one packed path-cell payload.
   */
  [[maybe_unused]] [[nodiscard]] std::uint16_t ReadPackedPathCellLane1(const moho::HPathCell* const cell) noexcept
  {
    return cell ? cell->z : 0u;
  }

  /**
   * Address: 0x005A9D20 (FUN_005A9D20)
   *
   * What it does:
   * Returns the owner-unit alt-footprint mode flag byte.
   */
  [[maybe_unused]] [[nodiscard]] std::uint8_t ReadUnitAltFootprintFlag(const moho::Unit* const unit) noexcept
  {
    return unit ? unit->mUseAltFootprint : 0u;
  }

  /**
   * Address: 0x005AA100 (FUN_005AA100)
   *
   * What it does:
   * Writes one anchor-cell `(x, z)` word pair into a path-finder instance.
   */
  [[maybe_unused]] [[nodiscard]] moho::CAiPathFinder* SetPathFinderAnchorCellWords(
    moho::CAiPathFinder* const pathFinder,
    const std::uint16_t lane0,
    const std::uint16_t lane1
  ) noexcept
  {
    if (!pathFinder) {
      return nullptr;
    }

    pathFinder->mAnchorCell.x = lane0;
    pathFinder->mAnchorCell.z = lane1;
    return pathFinder;
  }

  /**
   * Address: 0x005AA580 (FUN_005AA580)
   *
   * What it does:
   * Returns whether one path-finder currently has an active queued-path flag.
   */
  [[maybe_unused]] [[nodiscard]] std::uint8_t ReadPathFinderQueuedFlag(const moho::CAiPathFinder& pathFinder) noexcept
  {
    return pathFinder.mIsQueuedOnPathQueue;
  }

  /**
   * Address: 0x005AD1E0 (FUN_005AD1E0)
   *
   * What it does:
   * Stores one raw search-mode lane into the path-finder search-type field.
   */
  [[maybe_unused]] [[nodiscard]] moho::CAiPathFinder* SetPathFinderSearchModeRaw(
    moho::CAiPathFinder* const pathFinder,
    const std::int32_t mode
  ) noexcept
  {
    if (!pathFinder) {
      return nullptr;
    }

    pathFinder->mSearchType = static_cast<moho::EAiPathSearchType>(mode);
    return pathFinder;
  }

  /**
   * Address: 0x005AD1F0 (FUN_005AD1F0)
   *
   * What it does:
   * Stores one goal-boundary probe mode flag byte onto a path-finder.
   */
  [[maybe_unused]] [[nodiscard]] moho::CAiPathFinder* SetPathFinderGoalBoundaryProbeFlag(
    moho::CAiPathFinder* const pathFinder,
    const std::uint8_t enabled
  ) noexcept
  {
    if (!pathFinder) {
      return nullptr;
    }

    pathFinder->mUseGoalBoundaryProbe = enabled;
    return pathFinder;
  }

  /**
   * Address: 0x005AD220 (FUN_005AD220)
   *
   * What it does:
   * Returns the path-finder owner unit pointer lane.
   */
  [[maybe_unused]] [[nodiscard]] moho::Unit* ReadPathFinderOwnerUnit(moho::CAiPathFinder* const pathFinder) noexcept
  {
    return pathFinder ? pathFinder->mUnit : nullptr;
  }

  struct RectHistoryNode
  {
    RectHistoryNode* next;
    RectHistoryNode* prev;
    gpg::Rect2i rect;
  };

  static_assert(sizeof(RectHistoryNode) == 0x18, "RectHistoryNode size must be 0x18");

  [[nodiscard]] RectHistoryNode* RectHistoryHead(const SRectListRuntime& history) noexcept
  {
    return static_cast<RectHistoryNode*>(history.mHead);
  }

  [[nodiscard]] RectHistoryNode* AllocateRectSentinel()
  {
    auto* const node = static_cast<RectHistoryNode*>(::operator new(sizeof(RectHistoryNode)));
    node->next = node;
    node->prev = node;
    node->rect = {};
    return node;
  }

  gpg::RType* gBroadcasterNavPathType = nullptr;
  gpg::RType* gUnitType = nullptr;
  gpg::RType* gSimType = nullptr;
  gpg::RType* gPathQueueType = nullptr;
  gpg::RType* gOGridType = nullptr;
  gpg::RType* gPathCellType = nullptr;
  gpg::RType* gGoalType = nullptr;
  gpg::RType* gSearchType = nullptr;
  gpg::RType* gRect2iListType = nullptr;
  gpg::RType* gMotionType = nullptr;
  msvc8::string gBroadcasterNavPathTypeName{};
  std::uint32_t gBroadcasterNavPathTypeNameInitGuard = 0u;

  [[nodiscard]] gpg::RType* CachedNavPathType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SNavPath));
    }
    return cached;
  }

  void cleanup_BroadcasterNavPathTypeName()
  {
    gBroadcasterNavPathTypeName.clear();
    gBroadcasterNavPathTypeNameInitGuard = 0u;
  }

  [[nodiscard]] gpg::RType* ResolveTypeByAnyName(const std::initializer_list<const char*> names)
  {
    for (const char* const name : names) {
      if (!name) {
        continue;
      }

      if (gpg::RType* const type = gpg::REF_FindTypeNamed(name)) {
        return type;
      }
    }

    return nullptr;
  }

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* CachedBroadcasterNavPathType()
  {
    if (!gBroadcasterNavPathType) {
      gBroadcasterNavPathType = ResolveTypeByAnyName(
        {"Broadcaster<Moho::NavPath const &>", "Moho::Broadcaster<Moho::NavPath const &>", "Broadcaster"}
      );
      if (!gBroadcasterNavPathType) {
        gBroadcasterNavPathType = gpg::LookupRType(typeid(Broadcaster));
      }
    }
    return gBroadcasterNavPathType;
  }

  [[nodiscard]] gpg::RType* CachedUnitType()
  {
    return CachedType<Unit>(gUnitType);
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (!Sim::sType) {
      Sim::sType = CachedType<Sim>(gSimType);
    }
    return Sim::sType;
  }

  [[nodiscard]] gpg::RType* CachedPathQueueType()
  {
    if (!gPathQueueType) {
      gPathQueueType = ResolveTypeByAnyName({"PathQueue", "Moho::PathQueue", "class Moho::PathQueue"});
    }
    return gPathQueueType;
  }

  [[nodiscard]] gpg::RType* CachedOGridType()
  {
    return CachedType<COGrid>(gOGridType);
  }

  [[nodiscard]] gpg::RType* CachedPathCellType()
  {
    return CachedType<HPathCell>(gPathCellType);
  }

  [[nodiscard]] gpg::RType* CachedGoalType()
  {
    return CachedType<SAiNavigatorGoal>(gGoalType);
  }

  [[nodiscard]] gpg::RType* CachedSearchType()
  {
    return CachedType<ESearchType>(gSearchType);
  }

  [[nodiscard]] gpg::RType* CachedRect2iListType()
  {
    if (!gRect2iListType) {
      gRect2iListType = gpg::LookupRType(typeid(std::list<gpg::Rect2i>));
      if (!gRect2iListType) {
        gRect2iListType = ResolveTypeByAnyName({"std::list<gpg::Rect2<int>>", "list<gpg::Rect2<int>>"});
      }
    }
    return gRect2iListType;
  }

  [[nodiscard]] gpg::RType* CachedMotionType()
  {
    return CachedType<ERuleBPUnitMovementType>(gMotionType);
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadPointerWithType(gpg::ReadArchive* const archive, const gpg::RRef& owner, gpg::RType* expectedType)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
    if (!tracked.object) {
      return nullptr;
    }

    if (!expectedType || !tracked.type) {
      return static_cast<TObject*>(tracked.object);
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return static_cast<TObject*>(upcast.mObj);
  }

  [[nodiscard]] void* ReadPointerUnchecked(gpg::ReadArchive* const archive, const gpg::RRef& owner, gpg::RType* expectedType)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
    if (!tracked.object) {
      return nullptr;
    }

    if (!expectedType || !tracked.type) {
      return tracked.object;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    return gpg::REF_UpcastPtr(source, expectedType).mObj;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object || !staticType) {
      out.mObj = object;
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType && staticType && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  template <typename TObject>
  void WritePointerWithType(
    gpg::WriteArchive* const archive,
    TObject* const object,
    gpg::RType* const staticType,
    const gpg::TrackedPointerState state,
    const gpg::RRef& owner
  )
  {
    if (!archive) {
      return;
    }

    if (object != nullptr && staticType == nullptr) {
      gpg::WriteRawPointer(archive, gpg::RRef{}, state, owner);
      return;
    }

    const gpg::RRef objectRef = MakeTypedRef(object, staticType);
    gpg::WriteRawPointer(archive, objectRef, state, owner);
  }

  void WritePointerUnchecked(
    gpg::WriteArchive* const archive,
    void* const object,
    gpg::RType* const staticType,
    const gpg::TrackedPointerState state,
    const gpg::RRef& owner
  )
  {
    if (!archive) {
      return;
    }

    gpg::RRef objectRef{};
    if (object != nullptr && staticType != nullptr) {
      objectRef.mObj = object;
      objectRef.mType = staticType;
    }
    gpg::WriteRawPointer(archive, objectRef, state, owner);
  }

} // namespace

/**
 * Address: 0x007635C0 (FUN_007635C0, Moho::RBroadcasterRType_NavPath::GetName)
 *
 * What it does:
 * Lazily builds and caches the reflected lexical type label
 * `Broadcaster<NavPath>` from runtime RTTI metadata.
 */
const char* moho::RBroadcasterRType_NavPath::GetName() const
{
  if ((gBroadcasterNavPathTypeNameInitGuard & 1u) == 0u) {
    gBroadcasterNavPathTypeNameInitGuard |= 1u;

    gpg::RType* const valueType = CachedNavPathType();
    const char* const valueTypeName = valueType ? valueType->GetName() : "NavPath";
    gBroadcasterNavPathTypeName =
      gpg::STR_Printf("Broadcaster<%s>", valueTypeName ? valueTypeName : "NavPath");
    (void)std::atexit(&cleanup_BroadcasterNavPathTypeName);
  }

  return gBroadcasterNavPathTypeName.c_str();
}

/**
 * Address: 0x00764010 (FUN_00764010, Moho::RBroadcasterRType_NavPath::dtr)
 *
 * What it does:
 * Tears down one broadcaster-navpath type-info descriptor and releases
 * inherited `gpg::RType` reflection storage lanes.
 */
moho::RBroadcasterRType_NavPath::~RBroadcasterRType_NavPath() = default;

/**
 * Address: 0x00763850 (FUN_00763850)
 *
 * What it does:
 * Serializes one reflected `vector<HPathCell>` payload by writing count and
 * then each path-cell element lane.
 */
[[maybe_unused]] void SerializePathCellVectorArchive(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  if (archive == nullptr) {
    return;
  }

  const auto* const vectorObject = reinterpret_cast<const PathCellVector*>(
    static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
  );

  const unsigned int count = vectorObject != nullptr ? static_cast<unsigned int>(vectorObject->size()) : 0u;
  archive->WriteUInt(count);
  if (count == 0u || vectorObject == nullptr) {
    return;
  }

  gpg::RType* const pathCellType = CachedPathCellType();
  GPG_ASSERT(pathCellType != nullptr);
  if (!pathCellType) {
    return;
  }

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  for (unsigned int i = 0; i < count; ++i) {
    archive->Write(pathCellType, const_cast<moho::HPathCell*>(&(*vectorObject)[static_cast<std::size_t>(i)]), owner);
  }
}

/**
 * Address: 0x00763F50 (FUN_00763F50, preregister_RBroadcasterRType_NavPath)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `moho::Broadcaster`.
 */
[[nodiscard]] gpg::RType* preregister_RBroadcasterRType_NavPath()
{
  static RBroadcasterRType_NavPath typeInfo;
  gpg::PreRegisterRType(typeid(Broadcaster), &typeInfo);
  return &typeInfo;
}

/**
 * What it does:
 * Returns the lexical type label for `Listener<NavPath>`.
 */
const char* moho::RListenerRType_NavPath::GetName() const
{
  return "Listener<NavPath>";
}

/**
 * Address: 0x00764070 (FUN_00764070, Moho::RListenerRType_NavPath::dtr)
 *
 * What it does:
 * Tears down one listener-navpath type-info descriptor and releases
 * inherited `gpg::RType` reflection storage lanes.
 */
moho::RListenerRType_NavPath::~RListenerRType_NavPath() = default;

/**
 * Address: 0x00763FB0 (FUN_00763FB0, preregister_RListenerRType_NavPath)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for
 * `moho::Listener<const moho::SNavPath&>`.
 */
[[nodiscard]] gpg::RType* preregister_RListenerRType_NavPath()
{
  using NavPathListener = Listener<const SNavPath&>;

  static RListenerRType_NavPath typeInfo;
  gpg::PreRegisterRType(typeid(NavPathListener), &typeInfo);
  return &typeInfo;
}

gpg::RType* CAiPathFinder::sType = nullptr;

/**
 * Address: 0x005A9EC0 (FUN_005A9EC0)
 */
CAiPathFinder::CAiPathFinder()
  : IPathTraveler()
  , Broadcaster()
  , mIsGoalBoundaryBlocked(0)
  , mIsQueuedOnPathQueue(0)
  , mUseGoalBoundaryProbe(0)
  , mPad17(0)
  , mUnit(nullptr)
  , mFootprint(nullptr)
  , mAltFootprint(nullptr)
  , mPathLayerSelector(0)
  , mSim(nullptr)
  , mPathQueueProxy(nullptr)
  , mOGrid(nullptr)
  , mAnchorCell{}
  , mResultCell{}
  , mGoal{}
  , mSearchType(AIPATHSEARCH_None)
  , mHasOccupancyMask(0)
  , mHasPathResult(0)
  , mPad66(0)
  , mPad67(0)
  , mRecentSearchRects{}
  , mUseWholeMap(0)
  , mInsidePlayableRect(1)
  , mPad76(0)
  , mPad77(0)
  , mMaxFootprintSpan(1)
{
  mPathQueueNode.mPrev = &mPathQueueNode;
  mPathQueueNode.mNext = &mPathQueueNode;
  static_cast<Broadcaster*>(this)->ListResetLinks();

  mRecentSearchRects.mAllocatorOrProxy = nullptr;
  mRecentSearchRects.mHead = AllocateRectSentinel();
  mRecentSearchRects.mSize = 0;
}

/**
 * Address: 0x005AA000 (FUN_005AA000)
 */
CAiPathFinder::~CAiPathFinder()
{
  ClearRectHistory();

  if (mRecentSearchRects.mHead) {
    ::operator delete(mRecentSearchRects.mHead);
    mRecentSearchRects.mHead = nullptr;
  }

  mPathQueueNode.mPrev = &mPathQueueNode;
  mPathQueueNode.mNext = &mPathQueueNode;
  static_cast<Broadcaster*>(this)->ListResetLinks();
}

/**
 * Address: 0x005AA060 (FUN_005AA060)
 */
void CAiPathFinder::SetUnit(Unit* const unit)
{
  mUnit = unit;
  mFootprint = nullptr;
  mAltFootprint = nullptr;
  mPathLayerSelector = 0;
  mSim = nullptr;
  mPathQueueProxy = nullptr;
  mOGrid = nullptr;
  mUseWholeMap = 0;
  mMaxFootprintSpan = 1;

  if (!unit) {
    mInsidePlayableRect = 0;
    return;
  }

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  if (blueprint) {
    mFootprint = blueprint->Physics.ResolvedFootprint;
    mAltFootprint = blueprint->Physics.ResolvedAltFootprint;
    mPathLayerSelector = static_cast<std::int32_t>(blueprint->Physics.MotionType);
  }

  if (const SFootprint* const footprint = GetFootprint()) {
    mMaxFootprintSpan = std::max<std::uint32_t>(footprint->mSizeX, footprint->mSizeZ);
  }

  mSim = unit->SimulationRef;
  mOGrid = mSim ? mSim->mOGrid : nullptr;

  if (unit->ArmyRef) {
    mPathQueueProxy = unit->ArmyRef->GetPathFinder();
    mUseWholeMap = unit->ArmyRef->UseWholeMap() ? 1u : 0u;
  }

  UpdatePlayableRectGate();
}

/**
 * Address: 0x005AA120 (FUN_005AA120)
 */
void CAiPathFinder::SetGoal(const SAiNavigatorGoal& goal)
{
  mGoal = goal;
  mIsGoalBoundaryBlocked = 0;

  const gpg::Rect2i rect = GoalOuterRect(goal);
  if (!IsStrictRect(rect)) {
    return;
  }

  for (std::int32_t x = rect.x0; x <= rect.x1; ++x) {
    for (std::int32_t z = rect.z0; z <= rect.z1; ++z) {
      const bool edge = (x == rect.x0) || (x == rect.x1) || (z == rect.z0) || (z == rect.z1);
      if (!edge) {
        continue;
      }

      const SOCellPos cell{
        static_cast<std::int16_t>(x),
        static_cast<std::int16_t>(z),
      };
      if (!IsInBounds(cell)) {
        mIsGoalBoundaryBlocked = 1;
        return;
      }
    }
  }
}

/**
 * Address: 0x005AA220 (FUN_005AA220)
 */
bool CAiPathFinder::RunDirectProbe()
{
  if (mIsGoalBoundaryBlocked == 0u) {
    return false;
  }

  mHasPathResult = 0;
  mResultCell = {};

  if (mUnit && mUnit->ArmyRef) {
    mUseWholeMap = mUnit->ArmyRef->UseWholeMap() ? 1u : 0u;
  }
  UpdatePlayableRectGate();

  QueueSearch();
  return mHasPathResult != 0u;
}

/**
 * Address: 0x005AA310 (FUN_005AA310)
 */
void CAiPathFinder::QueueSearch()
{
  mIsQueuedOnPathQueue = 1;
  mHasPathResult = 0;
  mHasOccupancyMask = (GetFootprint() != nullptr) ? 1u : 0u;

  if (mUnit && mUnit->ArmyRef) {
    mUseWholeMap = mUnit->ArmyRef->UseWholeMap() ? 1u : 0u;
  }
  UpdatePlayableRectGate();

  if (mSearchType == AIPATHSEARCH_None) {
    ClearRectHistory();
    return;
  }

  PushRectHistory(GoalOuterRect(mGoal));
}

/**
 * Address: 0x005A9D30 (FUN_005A9D30)
 */
const SFootprint* CAiPathFinder::GetFootprint() const
{
  if (mUnit && ReadUnitAltFootprintFlag(mUnit) != 0u && mAltFootprint) {
    return mAltFootprint;
  }
  return mFootprint;
}

/**
 * Address: 0x005AA710 (FUN_005AA710)
 */
bool CAiPathFinder::CanTraverseCell(const SOCellPos& cellPos) const
{
  if (!IsInBounds(cellPos)) {
    return false;
  }

  if (mSearchType != AIPATHSEARCH_None && IsBlockedByHistory(cellPos)) {
    return false;
  }

  if (mUseGoalBoundaryProbe != 0u && IsBlockedByHistory(cellPos)) {
    return false;
  }

  return true;
}

/**
 * Address: 0x005AA680 (FUN_005AA680)
 */
bool CAiPathFinder::IsInBounds(const SOCellPos& cellPos) const
{
  if (mUseWholeMap == 0u && mInsidePlayableRect != 0u) {
    if (!mSim || !mSim->mMapData) {
      return false;
    }

    const gpg::Rect2i& bounds = mSim->mMapData->mPlayableRect;
    const float margin = static_cast<float>(mMaxFootprintSpan);
    const float x = static_cast<float>(cellPos.x);
    const float z = static_cast<float>(cellPos.z);
    if ((x - margin) < static_cast<float>(bounds.x0) || (z - margin) < static_cast<float>(bounds.z0) ||
        static_cast<float>(bounds.x1) < (x + margin) || static_cast<float>(bounds.z1) < (z + margin)) {
      return false;
    }
  }
  return true;
}

/**
 * Address: 0x005A9D60 (FUN_005A9D60)
 *
 * What it does:
 * Computes the octile-distance core term `max(|a|,|b|) + min(|a|,|b|) *
 * 0.41421354f` used by AI pathfinder heuristic lanes.
 */
[[maybe_unused]] static float ComputeOctileDistanceCore(const float a, const float b) noexcept
{
  float major = std::fabs(a);
  float minor = std::fabs(b);
  if (minor > major) {
    std::swap(major, minor);
  }

  return major + minor * 0.41421354f;
}

/**
 * Address: 0x005AA590 (FUN_005AA590)
 */
float CAiPathFinder::GetHeuristicCost(const SOCellPos& cellPos) const
{
  const gpg::Rect2i outer = GoalOuterRect(mGoal);

  int dx = std::max(0, outer.x0 - static_cast<int>(cellPos.x));
  dx = std::max(dx, static_cast<int>(cellPos.x) - outer.x1 + 1);

  int dz = std::max(0, outer.z0 - static_cast<int>(cellPos.z));
  dz = std::max(dz, static_cast<int>(cellPos.z) - outer.z1 + 1);

  const float adx = std::fabs(static_cast<float>(dx));
  const float adz = std::fabs(static_cast<float>(dz));
  return ComputeOctileDistanceCore(adx, adz) * 1.01f;
}

/**
 * Address: 0x005AA850 (FUN_005AA850)
 */
void CAiPathFinder::GetAnchorCell(HPathCell* const outCell) const
{
  if (!outCell) {
    return;
  }
  (void)CopyPackedPathCell(outCell, &mAnchorCell);
}

/**
 * Address: 0x005AA960 (FUN_005AA960)
 */
bool CAiPathFinder::IsGoalCandidateCell(const SOCellPos& cellPos) const
{
  const gpg::Rect2i outer = GoalOuterRect(mGoal);
  if (!CellInRectInclusiveExclusive(cellPos, outer)) {
    return false;
  }

  const gpg::Rect2i inner = GoalInnerRect(mGoal);
  if (static_cast<int>(cellPos.x) < inner.x0 || inner.x1 <= static_cast<int>(cellPos.x)) {
    return true;
  }
  return static_cast<int>(cellPos.z) < inner.z0 || inner.z1 <= static_cast<int>(cellPos.z);
}

/**
 * Address: 0x005AA9A0 (FUN_005AA9A0)
 */
void CAiPathFinder::OnPathAccepted(const SNavPath& path)
{
  mHasPathResult = 1;
  mIsQueuedOnPathQueue = 0;
  mResultCell = LastPathCell(path);
  BroadcastPathEvent();
}

/**
 * Address: 0x005AA860 (FUN_005AA860)
 */
bool CAiPathFinder::ShouldSearchRect(const gpg::Rect2i& rect) const
{
  if (!IsStrictRect(rect)) {
    return false;
  }

  if (mSearchType == AIPATHSEARCH_None || mUseGoalBoundaryProbe != 0u) {
    const SOCellPos anchor{
      static_cast<std::int16_t>(mAnchorCell.x),
      static_cast<std::int16_t>(mAnchorCell.z),
    };
    return CellInRectInclusiveExclusive(anchor, rect);
  }

  if (RectHistoryIntersects(rect)) {
    return true;
  }

  const gpg::Rect2i goalOuter = GoalOuterRect(mGoal);
  if (!RectsOverlapStrict(rect, goalOuter)) {
    return false;
  }

  const gpg::Rect2i goalInner = GoalInnerRect(mGoal);
  return !RectInsideRect(rect, goalInner);
}

/**
 * Address: 0x005AA9E0 (FUN_005AA9E0)
 */
void CAiPathFinder::OnPathSearchCancelled()
{
  mHasPathResult = 0;
  mIsQueuedOnPathQueue = 0;
}

/**
 * Address: 0x005AA9F0 (FUN_005AA9F0)
 */
void CAiPathFinder::OnPathRejected(const SNavPath& path)
{
  mHasPathResult = 0;
  mIsQueuedOnPathQueue = 0;
  mResultCell = LastPathCell(path);
  BroadcastPathEvent();
}

/**
 * Address: 0x005AAA30 (FUN_005AAA30)
 */
std::int32_t CAiPathFinder::GetPathcap() const
{
  Unit* const ownerUnit = ReadPathFinderOwnerUnit(const_cast<CAiPathFinder*>(this));
  if (!ownerUnit || !ownerUnit->ArmyRef) {
    return 0;
  }

  if (mIsGoalBoundaryBlocked == 0u) {
    return ownerUnit->ArmyRef->GetPathcapBoth();
  }

  if (mPathLayerSelector == 1) {
    return ownerUnit->ArmyRef->GetPathcapLand();
  }
  if (mPathLayerSelector == 3) {
    return ownerUnit->ArmyRef->GetPathcapSea();
  }
  return ownerUnit->ArmyRef->GetPathcapBoth();
}

/**
 * Address: 0x005A9D50 (FUN_005A9D50)
 */
void CAiPathFinder::GetResultCell(HPathCell* const outCell) const
{
  if (!outCell) {
    return;
  }
  (void)CopyPackedPathCell(outCell, &mResultCell);
}

/**
 * Address: 0x005ABED0 (FUN_005ABED0, Moho::CAiPathFinder::MemberDeserialize)
 */
void CAiPathFinder::MemberDeserialize(gpg::ReadArchive* const archive, const int)
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};

  if (gpg::RType* const broadcasterType = CachedBroadcasterNavPathType()) {
    archive->Read(broadcasterType, static_cast<Broadcaster*>(this), owner);
  }

  bool boolValue = false;
  archive->ReadBool(&boolValue);
  mIsGoalBoundaryBlocked = boolValue ? 1u : 0u;
  archive->ReadBool(&boolValue);
  mIsQueuedOnPathQueue = boolValue ? 1u : 0u;
  archive->ReadBool(&boolValue);
  mUseWholeMap = boolValue ? 1u : 0u;
  archive->ReadBool(&boolValue);
  (void)SetPathFinderGoalBoundaryProbeFlag(this, boolValue ? 1u : 0u);
  archive->ReadBool(&boolValue);
  mInsidePlayableRect = boolValue ? 1u : 0u;

  int footprintSpan = 0;
  archive->ReadInt(&footprintSpan);
  mMaxFootprintSpan = footprintSpan < 0 ? 0u : static_cast<std::uint32_t>(footprintSpan);

  mUnit = ReadPointerWithType<Unit>(archive, owner, CachedUnitType());
  mSim = ReadPointerWithType<Sim>(archive, owner, CachedSimType());
  mPathQueueProxy = ReadPointerUnchecked(archive, owner, CachedPathQueueType());
  mOGrid = ReadPointerWithType<COGrid>(archive, owner, CachedOGridType());

  if (gpg::RType* const pathCellType = CachedPathCellType()) {
    archive->Read(pathCellType, &mAnchorCell, owner);
    archive->Read(pathCellType, &mResultCell, owner);
  }

  if (gpg::RType* const goalType = CachedGoalType()) {
    archive->Read(goalType, &mGoal, owner);
  }

  if (gpg::RType* const searchType = CachedSearchType()) {
    ESearchType search = AIPATHSEARCH_None;
    archive->Read(searchType, &search, owner);
    (void)SetPathFinderSearchModeRaw(this, static_cast<std::int32_t>(search));
  }

  archive->ReadBool(&boolValue);
  mHasOccupancyMask = boolValue ? 1u : 0u;
  archive->ReadBool(&boolValue);
  mHasPathResult = boolValue ? 1u : 0u;

  if (gpg::RType* const rectListType = CachedRect2iListType()) {
    archive->Read(rectListType, &mRecentSearchRects, owner);
  }

  if (gpg::RType* const motionType = CachedMotionType()) {
    ERuleBPUnitMovementType movementType = RULEUMT_None;
    archive->Read(motionType, &movementType, owner);
    mPathLayerSelector = static_cast<std::int32_t>(movementType);
  }

  if (mUnit) {
    const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
    mFootprint = blueprint ? blueprint->Physics.ResolvedFootprint : nullptr;
    mAltFootprint = blueprint ? blueprint->Physics.ResolvedAltFootprint : nullptr;
  } else {
    mFootprint = nullptr;
    mAltFootprint = nullptr;
  }
}

/**
 * Address: 0x005AC150 (FUN_005AC150, Moho::CAiPathFinder::MemberSerialize)
 */
void CAiPathFinder::MemberSerialize(gpg::WriteArchive* const archive, const int)
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};

  if (gpg::RType* const broadcasterType = CachedBroadcasterNavPathType()) {
    archive->Write(broadcasterType, static_cast<const Broadcaster*>(this), owner);
  }

  archive->WriteBool(mIsGoalBoundaryBlocked != 0u);
  archive->WriteBool(ReadPathFinderQueuedFlag(*this) != 0u);
  archive->WriteBool(mUseWholeMap != 0u);
  archive->WriteBool(mUseGoalBoundaryProbe != 0u);
  archive->WriteBool(mInsidePlayableRect != 0u);
  archive->WriteInt(static_cast<int>(mMaxFootprintSpan));

  WritePointerWithType(archive, mUnit, CachedUnitType(), gpg::TrackedPointerState::Unowned, owner);
  WritePointerWithType(archive, mSim, CachedSimType(), gpg::TrackedPointerState::Unowned, owner);
  WritePointerUnchecked(archive, mPathQueueProxy, CachedPathQueueType(), gpg::TrackedPointerState::Unowned, owner);
  WritePointerWithType(archive, mOGrid, CachedOGridType(), gpg::TrackedPointerState::Unowned, owner);

  if (gpg::RType* const pathCellType = CachedPathCellType()) {
    archive->Write(pathCellType, &mAnchorCell, owner);
    archive->Write(pathCellType, &mResultCell, owner);
  }

  if (gpg::RType* const goalType = CachedGoalType()) {
    archive->Write(goalType, &mGoal, owner);
  }

  if (gpg::RType* const searchType = CachedSearchType()) {
    ESearchType search = mSearchType;
    archive->Write(searchType, &search, owner);
  }

  archive->WriteBool(mHasOccupancyMask != 0u);
  archive->WriteBool(mHasPathResult != 0u);

  if (gpg::RType* const rectListType = CachedRect2iListType()) {
    archive->Write(rectListType, &mRecentSearchRects, owner);
  }

  if (gpg::RType* const motionType = CachedMotionType()) {
    const ERuleBPUnitMovementType movementType = static_cast<ERuleBPUnitMovementType>(mPathLayerSelector);
    archive->Write(motionType, &movementType, owner);
  }
}

void CAiPathFinder::ClearRectHistory()
{
  RectHistoryNode* const head = RectHistoryHead(mRecentSearchRects);
  if (!head) {
    mRecentSearchRects.mSize = 0;
    return;
  }

  RectHistoryNode* it = head->next;
  while (it != head) {
    RectHistoryNode* const next = it->next;
    ::operator delete(it);
    it = next;
  }

  head->next = head;
  head->prev = head;
  mRecentSearchRects.mSize = 0;
}

void CAiPathFinder::PushRectHistory(const gpg::Rect2i& rect)
{
  if (!IsStrictRect(rect)) {
    return;
  }

  RectHistoryNode* head = RectHistoryHead(mRecentSearchRects);
  if (!head) {
    mRecentSearchRects.mHead = AllocateRectSentinel();
    head = RectHistoryHead(mRecentSearchRects);
  }

  while (mRecentSearchRects.mSize > 2) {
    RectHistoryNode* const oldest = head->next;
    if (oldest == head) {
      mRecentSearchRects.mSize = 0;
      break;
    }
    oldest->next->prev = oldest->prev;
    oldest->prev->next = oldest->next;
    ::operator delete(oldest);
    --mRecentSearchRects.mSize;
  }

  auto* const node = static_cast<RectHistoryNode*>(::operator new(sizeof(RectHistoryNode)));
  node->rect = rect;
  node->next = head->next;
  node->prev = head;
  head->next->prev = node;
  head->next = node;
  ++mRecentSearchRects.mSize;
}

void CAiPathFinder::BroadcastPathEvent()
{
  Broadcaster* const head = static_cast<Broadcaster*>(this);
  if (!head || head->ListIsSingleton()) {
    return;
  }

  Broadcaster pending{};
  head->move_nodes_to(pending);

  const SNavPath emptyPath{};

  for (auto* pendingNode = pending.pop_back(); pendingNode; pendingNode = pending.pop_back()) {
    auto* const node = static_cast<Broadcaster*>(pendingNode);
    head->push_front(node);

    if (auto* const navigator = CAiPathNavigator::FromListenerLink(node)) {
      (void)navigator->OnEvent(emptyPath);
    }
  }
}

void CAiPathFinder::UpdatePlayableRectGate()
{
  if (!mUnit || !mSim || !mSim->mMapData || !GetFootprint()) {
    mInsidePlayableRect = 0;
    return;
  }

  const gpg::Rect2i& bounds = mSim->mMapData->mPlayableRect;
  const Wm3::Vec3f& pos = mUnit->GetPosition();
  const float span = static_cast<float>(mMaxFootprintSpan);
  mInsidePlayableRect =
    ((static_cast<float>(bounds.x0) <= (pos.x - span)) && (static_cast<float>(bounds.z0) <= (pos.z - span)) &&
     ((pos.x + span) <= static_cast<float>(bounds.x1)) && ((pos.z + span) <= static_cast<float>(bounds.z1)))
      ? 1u
      : 0u;
}

bool CAiPathFinder::RectHistoryIntersects(const gpg::Rect2i& rect) const
{
  const RectHistoryNode* const head = RectHistoryHead(mRecentSearchRects);
  if (!head) {
    return false;
  }

  for (const RectHistoryNode* it = head->next; it != head; it = it->next) {
    if (RectsOverlapStrict(rect, it->rect)) {
      return true;
    }
  }
  return false;
}

bool CAiPathFinder::IsBlockedByHistory(const SOCellPos& cellPos) const
{
  const RectHistoryNode* const head = RectHistoryHead(mRecentSearchRects);
  if (!head) {
    return false;
  }

  for (const RectHistoryNode* it = head->next; it != head; it = it->next) {
    if (CellInRectInclusiveExclusive(cellPos, it->rect)) {
      return true;
    }
  }
  return false;
}

bool CAiPathFinder::IsStrictRect(const gpg::Rect2i& rect)
{
  return rect.x0 < rect.x1 && rect.z0 < rect.z1;
}

bool CAiPathFinder::CellInRectInclusiveExclusive(const SOCellPos& cellPos, const gpg::Rect2i& rect)
{
  const int x = static_cast<int>(cellPos.x);
  const int z = static_cast<int>(cellPos.z);
  return rect.x0 <= x && x < rect.x1 && rect.z0 <= z && z < rect.z1;
}

bool CAiPathFinder::RectsOverlapStrict(const gpg::Rect2i& lhs, const gpg::Rect2i& rhs)
{
  return lhs.x0 < rhs.x1 && rhs.x0 < lhs.x1 && lhs.z0 < rhs.z1 && rhs.z0 < lhs.z1;
}

bool CAiPathFinder::RectInsideRect(const gpg::Rect2i& inner, const gpg::Rect2i& outer)
{
  return outer.x0 <= inner.x0 && inner.x1 <= outer.x1 && outer.z0 <= inner.z0 && inner.z1 <= outer.z1;
}

gpg::Rect2i CAiPathFinder::GoalOuterRect(const SAiNavigatorGoal& goal)
{
  return {goal.minX, goal.minZ, goal.maxX, goal.maxZ};
}

gpg::Rect2i CAiPathFinder::GoalInnerRect(const SAiNavigatorGoal& goal)
{
  return {goal.aux0, goal.aux1, goal.aux2, goal.aux3};
}

HPathCell CAiPathFinder::LastPathCell(const SNavPath& path)
{
  if (!path.start || !path.finish || path.finish <= path.start) {
    return {};
  }

  const SOCellPos& cell = path.finish[-1];
  return {
    static_cast<std::uint16_t>(cell.x),
    static_cast<std::uint16_t>(cell.z),
  };
}
