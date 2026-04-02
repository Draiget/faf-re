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
#include "gpg/core/containers/WriteArchive.h"
#include "moho/ai/CAiPathNavigator.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
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
  if (mUnit && mUnit->mUseAltFootprint != 0 && mAltFootprint) {
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
  const float major = std::max(adx, adz);
  const float minor = std::min(adx, adz);
  return (minor * 0.41421354f + major) * 1.01f;
}

/**
 * Address: 0x005AA850 (FUN_005AA850)
 */
void CAiPathFinder::GetAnchorCell(HPathCell* const outCell) const
{
  if (!outCell) {
    return;
  }
  *outCell = mAnchorCell;
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
  if (!mUnit || !mUnit->ArmyRef) {
    return 0;
  }

  if (mIsGoalBoundaryBlocked == 0u) {
    return mUnit->ArmyRef->GetPathcapBoth();
  }

  if (mPathLayerSelector == 1) {
    return mUnit->ArmyRef->GetPathcapLand();
  }
  if (mPathLayerSelector == 3) {
    return mUnit->ArmyRef->GetPathcapSea();
  }
  return mUnit->ArmyRef->GetPathcapBoth();
}

/**
 * Address: 0x005A9D50 (FUN_005A9D50)
 */
void CAiPathFinder::GetResultCell(HPathCell* const outCell) const
{
  if (!outCell) {
    return;
  }
  *outCell = mResultCell;
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
  mUseGoalBoundaryProbe = boolValue ? 1u : 0u;
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
    mSearchType = search;
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
  archive->WriteBool(mIsQueuedOnPathQueue != 0u);
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
