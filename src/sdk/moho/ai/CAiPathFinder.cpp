#include "moho/ai/CAiPathFinder.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <new>

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
