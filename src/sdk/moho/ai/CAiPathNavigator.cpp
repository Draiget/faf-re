#include "moho/ai/CAiPathNavigator.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

#include "moho/ai/CAiPathFinder.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  constexpr std::uint64_t kUnitPathFlag = 0x1000000ull;
  constexpr std::uint64_t kUnitPathingBusyFlag = 0x800000ull;
  constexpr std::uint64_t kUnitPatrolStallFlag = 0x2000000ull;

  struct UnitLayerTokenView
  {
    std::uint8_t pad[0x120];
    std::uint32_t layerToken;
  };

  static_assert(offsetof(UnitLayerTokenView, layerToken) == 0x120, "UnitLayerTokenView::layerToken offset must be 0x120");

  [[nodiscard]] bool HasVectorValue(const Wm3::Vector3f& vec) noexcept
  {
    const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
    return Wm3::Vector3f::Compare(&vec, &zero);
  }

  [[nodiscard]] bool HasGoalArea(const SAiNavigatorGoal& goal) noexcept
  {
    return goal.minX < goal.maxX && goal.minZ < goal.maxZ;
  }

  [[nodiscard]] SOCellPos ToCellPos(const Wm3::Vector3f& position, const SFootprint& footprint) noexcept
  {
    SOCellPos cell{};
    cell.x = static_cast<std::int16_t>(position.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    cell.z = static_cast<std::int16_t>(position.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));
    return cell;
  }

  [[nodiscard]] Wm3::Vector3f ToWorldPos(const SOCellPos& cellPos, const Unit& unit, const SFootprint& footprint) noexcept
  {
    const Wm3::Vector3f unitPos = unit.GetPosition();
    return {
      static_cast<float>(cellPos.x) + (static_cast<float>(footprint.mSizeX) * 0.5f),
      unitPos.y,
      static_cast<float>(cellPos.z) + (static_cast<float>(footprint.mSizeZ) * 0.5f),
    };
  }

  [[nodiscard]] SOCellPos GoalAnchorCell(const SAiNavigatorGoal& goal) noexcept
  {
    return {
      static_cast<std::int16_t>(goal.minX),
      static_cast<std::int16_t>(goal.minZ),
    };
  }

  [[nodiscard]] SOCellPos GoalCenterCell(const SAiNavigatorGoal& goal) noexcept
  {
    return {
      static_cast<std::int16_t>((goal.minX + goal.maxX) / 2),
      static_cast<std::int16_t>((goal.minZ + goal.maxZ) / 2),
    };
  }

  [[nodiscard]] SAiNavigatorGoal BuildSingleCellGoal(const SOCellPos& cell) noexcept
  {
    return {
      static_cast<std::int32_t>(cell.x),
      static_cast<std::int32_t>(cell.z),
      static_cast<std::int32_t>(cell.x) + 1,
      static_cast<std::int32_t>(cell.z) + 1,
      0,
      0,
      0,
      0,
      0,
    };
  }

  [[nodiscard]] std::uint32_t PackCell(const SOCellPos& cell) noexcept
  {
    std::uint32_t packed = 0;
    std::memcpy(&packed, &cell, sizeof(packed));
    return packed;
  }

  [[nodiscard]] Broadcaster* NavigatorListenerNode(CAiPathNavigator& navigator) noexcept
  {
    return &navigator.mListenerLink;
  }

  [[nodiscard]] Broadcaster* PathFinderListenerHead(CAiPathFinder* pathFinder) noexcept
  {
    if (!pathFinder) {
      return nullptr;
    }
    return static_cast<Broadcaster*>(pathFinder);
  }

  void DetachListenerNode(CAiPathNavigator& navigator) noexcept
  {
    NavigatorListenerNode(navigator)->ListUnlink();
  }

  void AttachListenerNodeToPathFinder(CAiPathNavigator& navigator) noexcept
  {
    Broadcaster* const node = NavigatorListenerNode(navigator);
    node->ListUnlink();

    Broadcaster* const head = PathFinderListenerHead(navigator.mPathFinder);
    if (!head) {
      return;
    }
    head->push_front(node);
  }

  void DetachWeakUnit(WeakPtr<Unit>& link) noexcept
  {
    link.ResetFromObject(nullptr);
  }

  [[nodiscard]] Unit* GetOwningUnit(const CAiPathNavigator& navigator) noexcept
  {
    return navigator.mPathFinder ? navigator.mPathFinder->mUnit : nullptr;
  }

  [[nodiscard]] const SFootprint* GetActiveFootprint(const CAiPathNavigator& navigator) noexcept
  {
    const auto* const pathFinder = navigator.mPathFinder;
    if (!pathFinder || !pathFinder->mUnit) {
      return nullptr;
    }
    return pathFinder->GetFootprint();
  }

  [[nodiscard]] std::uint32_t ReadUnitLayerToken(const Unit* const unit) noexcept
  {
    if (!unit) {
      return 0;
    }
    const auto* const view = reinterpret_cast<const UnitLayerTokenView*>(unit);
    return view->layerToken;
  }

  void ClearUnitPathBits(Unit* const unit)
  {
    if (!unit) {
      return;
    }
    unit->UnitStateMask &= ~(kUnitPathFlag | kUnitPathingBusyFlag | kUnitPatrolStallFlag);
  }

  void ClearUnitPathingBusyBit(Unit* const unit)
  {
    if (!unit) {
      return;
    }
    unit->UnitStateMask &= ~kUnitPathingBusyFlag;
  }

  void SetUnitPathBits(Unit* const unit, const std::uint64_t bits)
  {
    if (!unit) {
      return;
    }
    unit->UnitStateMask |= bits;
  }

  [[nodiscard]] float CellDistance(const SOCellPos a, const SOCellPos b) noexcept
  {
    const float dx = static_cast<float>(static_cast<std::int32_t>(a.x) - static_cast<std::int32_t>(b.x));
    const float dz = static_cast<float>(static_cast<std::int32_t>(a.z) - static_cast<std::int32_t>(b.z));
    return std::sqrt((dx * dx) + (dz * dz));
  }

  [[nodiscard]] std::int32_t ManhattanDistance(const SOCellPos a, const SOCellPos b) noexcept
  {
    const std::int32_t dx = std::abs(static_cast<std::int32_t>(a.x) - static_cast<std::int32_t>(b.x));
    const std::int32_t dz = std::abs(static_cast<std::int32_t>(a.z) - static_cast<std::int32_t>(b.z));
    return dx + dz;
  }

  [[nodiscard]] bool CanPathCellTransition(const CAiPathNavigator& navigator, const SOCellPos, const SOCellPos toCell)
  {
    if (!navigator.mPathFinder) {
      return false;
    }
    return navigator.mPathFinder->CanTraverseCell(toCell);
  }

  [[nodiscard]] bool CanReachCellFromCurrent(const CAiPathNavigator& navigator, const SOCellPos targetCell)
  {
    if (!navigator.mPathFinder) {
      return false;
    }

    if (!CanPathCellTransition(navigator, navigator.mCurrentPos, targetCell)) {
      return false;
    }

    if (ManhattanDistance(navigator.mCurrentPos, targetCell) <= 1) {
      return true;
    }

    return navigator.mPathFinder->CanTraverseCell(targetCell);
  }

  [[nodiscard]] bool UpdateForwardProbeFlag(CAiPathNavigator& navigator)
  {
    if (!navigator.mPathFinder) {
      navigator.mHasForwardProbe = 0;
      return false;
    }

    const bool canOccupyCurrent = navigator.mPathFinder->CanTraverseCell(navigator.mCurrentPos);
    const bool canReachForward = CanReachCellFromCurrent(navigator, navigator.mCurrentPos);
    navigator.mHasForwardProbe = (canOccupyCurrent && canReachForward) ? 1u : 0u;
    return navigator.mHasForwardProbe != 0u;
  }

  [[nodiscard]] std::int32_t ComputeDirectPrefixSpan(CAiPathNavigator& navigator)
  {
    if (navigator.mPath.CountInt() <= 0) {
      return 0;
    }

    if (PackCell(navigator.mCurrentPos) == PackCell(navigator.mPath.start[0]) && navigator.mPath.CountInt() > 1) {
      navigator.mPath.EraseFrontCells(1);
    }

    const std::int32_t pathSize = navigator.mPath.CountInt();
    if (pathSize <= 0) {
      return 0;
    }

    const SOCellPos firstCell = navigator.mPath.start[0];
    if (std::abs(static_cast<std::int32_t>(firstCell.x) - static_cast<std::int32_t>(navigator.mCurrentPos.x)) > 1 ||
        std::abs(static_cast<std::int32_t>(firstCell.z) - static_cast<std::int32_t>(navigator.mCurrentPos.z)) > 1 ||
        !CanPathCellTransition(navigator, navigator.mCurrentPos, firstCell) || !CanReachCellFromCurrent(navigator, firstCell)) {
      return 0;
    }

    std::int32_t bestIndex = 0;
    std::int32_t directionX = static_cast<std::int32_t>(firstCell.x) - static_cast<std::int32_t>(navigator.mCurrentPos.x);
    std::int32_t directionZ = static_cast<std::int32_t>(firstCell.z) - static_cast<std::int32_t>(navigator.mCurrentPos.z);

    for (std::int32_t idx = 1; idx < pathSize; ++idx) {
      const SOCellPos prev = navigator.mPath.start[idx - 1];
      const SOCellPos cell = navigator.mPath.start[idx];
      const std::int32_t nextDirectionX = static_cast<std::int32_t>(cell.x) - static_cast<std::int32_t>(prev.x);
      const std::int32_t nextDirectionZ = static_cast<std::int32_t>(cell.z) - static_cast<std::int32_t>(prev.z);
      if (nextDirectionX != directionX || nextDirectionZ != directionZ) {
        break;
      }

      if (!CanPathCellTransition(navigator, navigator.mCurrentPos, cell) || !CanReachCellFromCurrent(navigator, cell)) {
        break;
      }

      bestIndex = idx;
      directionX = nextDirectionX;
      directionZ = nextDirectionZ;
    }

    return bestIndex;
  }

  [[nodiscard]] EAiPathSearchType AsSearchType(const std::int32_t mode) noexcept
  {
    switch (mode) {
    case 1:
      return AIPATHSEARCH_Initial;
    case 2:
      return AIPATHSEARCH_Repath;
    case 3:
      return AIPATHSEARCH_Leader;
    default:
      return AIPATHSEARCH_None;
    }
  }
} // namespace

gpg::RType* CAiPathNavigator::sType = nullptr;

CAiPathNavigator* CAiPathNavigator::FromListenerLink(Broadcaster* const link) noexcept
{
  return Broadcaster::owner_from_member<CAiPathNavigator, Broadcaster, &CAiPathNavigator::mListenerLink>(link);
}

const CAiPathNavigator* CAiPathNavigator::FromListenerLink(const Broadcaster* const link) noexcept
{
  return Broadcaster::owner_from_member<CAiPathNavigator, Broadcaster, &CAiPathNavigator::mListenerLink>(link);
}

/**
 * Address: 0x005AD3E0 (FUN_005AD3E0, unit ctor)
 */
CAiPathNavigator::CAiPathNavigator(Unit* const unit)
  : mListenerLink{}
  , mState(AIPATHNAVSTATE_Idle)
  , mPathFinder(nullptr)
  , mPath{}
  , mCurrentPos{0, 0}
  , mTargetPos{0, 0}
  , mLastBlockedCell(0)
  , mGoal{}
  , mLastPathLayerToken(unit ? ReadUnitLayerToken(unit) : 0u)
  , mSim(unit ? unit->SimulationRef : nullptr)
  , mLastPathNodeIndex(-1)
  , mPathSearchFailCount(0)
  , mPathRetryDelayFrames(0)
  , mNoForwardDistanceFailCount(0)
  , mRepathDistanceThreshold(std::numeric_limits<float>::infinity())
  , mLastRepathTick(0)
  , mNoProgressTickCount(0)
  , mLastFormationSyncTick(0)
  , mLeaderLink{}
  , mLeaderTargetPos(Wm3::Vector3f::Zero())
  , mIsInFormation(0)
  , mLeaderBusy(0)
  , mHasLeaderTargetPos(0)
  , mHasForwardProbe(0)
  , mRepathRequested(0)
  , mUseExtendedPathProbe(0)
  , mTargetWithinOneCell(0)
  , mPad97(0)
  , mPathRequestMode(0)
  , mPathRequestCountdown(0)
  , mTickBucket7(unit ? (unit->GetEntityId() % 7) : 0)
  , mTickBucket13(unit ? (unit->GetEntityId() % 13) : 0)
{
  mListenerLink.ListResetLinks();

  mPath.reserved0 = 0;
  mPath.start = nullptr;
  mPath.finish = nullptr;
  mPath.capacity = nullptr;

  mPathFinder = new CAiPathFinder();
  mPathFinder->SetUnit(unit);
}

/**
 * Address: 0x005A44B0 (FUN_005A44B0, core dtor body)
 * Address: 0x005A44C0 (FUN_005A44C0, duplicated thunked entry)
 */
CAiPathNavigator::~CAiPathNavigator()
{
  DetachListenerNode(*this);
  DetachWeakUnit(mLeaderLink);
  mPath.FreeStorage();

  if (mPathFinder) {
    delete mPathFinder;
    mPathFinder = nullptr;
  }

  mListenerLink.ListResetLinks();
}

/**
 * Address: 0x005AEEB0 (FUN_005AEEB0)
 */
bool CAiPathNavigator::OnEvent(const SNavPath& path)
{
  DetachListenerNode(*this);

  Unit* const unit = GetOwningUnit(*this);
  const std::int32_t incomingCount = path.CountInt();

  if (mState == AIPATHNAVSTATE_PathEvent3) {
    mPath.AssignCopy(path);
    ClearUnitPathingBusyBit(unit);

    if (mPath.CountInt() == 0) {
      mState = AIPATHNAVSTATE_Failed;
      mPathRetryDelayFrames = 0;
      SetUnitPathBits(unit, kUnitPathFlag);
      if (unit && unit->IsUnitState(UNITSTATE_Patrolling)) {
        SetUnitPathBits(unit, kUnitPatrolStallFlag);
      }
      return false;
    }

    const SOCellPos tailCell = mPath.finish[-1];
    if (!IsCellInGoal(tailCell)) {
      SetUnitPathBits(unit, kUnitPathFlag);
      const SOCellPos centerCell = GoalCenterCell(mGoal);
      if (CanPathCellTransition(*this, centerCell, centerCell)) {
        mPath.AppendCell(centerCell);
      }
    }

    mPathSearchFailCount = 0;
    mPathRetryDelayFrames = 0;
    mRepathDistanceThreshold = std::numeric_limits<float>::infinity();
    mState = AIPATHNAVSTATE_HasPath;
    if (mPathFinder) {
      mPathFinder->mSearchType = AIPATHSEARCH_None;
    }
    return true;
  }

  if (mState != AIPATHNAVSTATE_PathEvent4) {
    GPG_ASSERT(false);
    return false;
  }

  if (incomingCount == 0) {
    if (mPathSearchFailCount >= 3) {
      ++mNoForwardDistanceFailCount;
      if (mNoForwardDistanceFailCount >= 3) {
        mState = AIPATHNAVSTATE_Failed;
        mPathRetryDelayFrames = 0;
      } else {
        mPathSearchFailCount = 0;
        RequestPath(1);
      }
      return mState != AIPATHNAVSTATE_Failed;
    }

    ++mPathSearchFailCount;
    mPathRetryDelayFrames = 10;
    return true;
  }

  bool mergedWithFront = false;
  if (mPath.CountInt() > 0) {
    const SOCellPos incomingBack = path.finish[-1];
    if (incomingBack.x == mPath.start[0].x && incomingBack.z == mPath.start[0].z) {
      mLastBlockedCell = 0;
      mPathSearchFailCount = 0;

      if (incomingCount > 1) {
        mPath.PrependCells(path.start, path.finish - 1);
      }
      mergedWithFront = true;
    }
  }

  if (!mergedWithFront) {
    if (mPath.CountInt() > 0 && incomingCount <= 2) {
      const SOCellPos firstCell = mPath.start[0];
      const bool canStayOnFirstCell = CanPathCellTransition(*this, firstCell, firstCell) &&
        CanPathCellTransition(*this, firstCell, firstCell);
      if (canStayOnFirstCell) {
        const std::uint32_t packedFirstCell = PackCell(firstCell);
        if (mLastBlockedCell == packedFirstCell) {
          mState = AIPATHNAVSTATE_Failed;
          mPathRetryDelayFrames = 0;
          mPathSearchFailCount = 0;
          return false;
        }
        mLastBlockedCell = packedFirstCell;
      } else {
        if (mPathSearchFailCount < 3) {
          ++mPathSearchFailCount;
          mPathRetryDelayFrames = 10;
          return true;
        }
        mState = AIPATHNAVSTATE_Failed;
        mPathRetryDelayFrames = 0;
        mPathSearchFailCount = 0;
        return false;
      }
    }

    mPath.PrependCells(path.start, path.finish);
  }

  mNoForwardDistanceFailCount = 0;
  mPathRetryDelayFrames = 0;
  mRepathDistanceThreshold = std::numeric_limits<float>::infinity();
  if (mPathFinder) {
    mPathFinder->mSearchType = AIPATHSEARCH_None;
  }

  const std::int32_t mergeAdjust = mergedWithFront ? 1 : 0;
  if (mLastPathNodeIndex < 0) {
    mLastPathNodeIndex = mPath.CountInt() - 1;
  } else {
    mLastPathNodeIndex += incomingCount - mergeAdjust;
  }

  mState = AIPATHNAVSTATE_HasPath;
  return true;
}

/**
 * Address: 0x005AD6E0 (FUN_005AD6E0)
 */
void CAiPathNavigator::ConfigureGoal(const SAiNavigatorGoal& goal, const bool ignoreFormation)
{
  mGoal = goal;
  mLastPathLayerToken = 0;
  mLeaderTargetPos = Wm3::Vector3f::Zero();
  mLeaderBusy = 0;
  mHasLeaderTargetPos = 0;
  mUseExtendedPathProbe = 0;
  mTargetWithinOneCell = 0;
  DetachWeakUnit(mLeaderLink);

  Unit* const unit = GetOwningUnit(*this);
  if (unit) {
    unit->UnitStateMask &= ~kUnitPathFlag;
  }

  mIsInFormation = 0;
  if (!ignoreFormation) {
    // Formation leader chain (`Unit::GetFormation` / `IUnit::AddToChain`) is still
    // pending typed recovery in this pass.
    mIsInFormation = 0;
  }
}

/**
 * Address: 0x005AD9C0 (FUN_005AD9C0)
 */
void CAiPathNavigator::ResetPathState()
{
  mTargetPos = mCurrentPos;
  if (mPath.start) {
    mPath.finish = mPath.start;
  }

  DetachListenerNode(*this);

  if (mPathFinder) {
    mPathFinder->OnPathSearchCancelled();
    mPathFinder->mSearchType = AIPATHSEARCH_None;
  }

  mState = AIPATHNAVSTATE_Idle;
  mPathRetryDelayFrames = 0;
  mPathSearchFailCount = 0;
  mNoForwardDistanceFailCount = 0;
  mLastPathLayerToken = 0;
  mLeaderTargetPos = Wm3::Vector3f::Zero();
  mLeaderBusy = 0;
  mHasLeaderTargetPos = 0;
  mHasForwardProbe = 0;
  mRepathRequested = 0;
  mUseExtendedPathProbe = 0;
  mTargetWithinOneCell = 0;
  mIsInFormation = 0;
  mPathRequestCountdown = 0;
  mLastPathNodeIndex = -1;
  mLastBlockedCell = 0;
  mRepathDistanceThreshold = std::numeric_limits<float>::infinity();
  mNoProgressTickCount = 0;
  mLastRepathTick = 0;
  mLastFormationSyncTick = 0;

  DetachWeakUnit(mLeaderLink);

  Unit* const unit = GetOwningUnit(*this);
  if (unit) {
    ClearUnitPathBits(unit);
    unit->FootprintDown = false;
  }
}

/**
 * Address: 0x005ADBA0 (FUN_005ADBA0)
 */
void CAiPathNavigator::BeginThinking()
{
  mState = AIPATHNAVSTATE_Thinking;
  mPathRequestMode = 0;
  mPathRequestCountdown = 1;
}

/**
 * Address: 0x005ADFE0 (FUN_005ADFE0)
 */
void CAiPathNavigator::RequestPath(const std::int32_t requestMode)
{
  mPathRequestMode = requestMode;
  mLeaderTargetPos = Wm3::Vector3f::Zero();
  mLastBlockedCell = 0;
  mPathRetryDelayFrames = 0;
  mRepathRequested = 0;

  if (!mPathFinder) {
    mHasForwardProbe = 0;
    return;
  }

  mPathFinder->mAnchorCell.x = static_cast<std::uint16_t>(mCurrentPos.x);
  mPathFinder->mAnchorCell.z = static_cast<std::uint16_t>(mCurrentPos.z);
  mPathFinder->SetGoal(mGoal);
  mPathFinder->mSearchType = AsSearchType(requestMode);

  Unit* const unit = GetOwningUnit(*this);
  if (mLeaderBusy == 0u) {
    SetUnitPathBits(unit, kUnitPathingBusyFlag);
    mPathFinder->QueueSearch();
    mState = AIPATHNAVSTATE_PathEvent3;
    AttachListenerNodeToPathFinder(*this);
  } else {
    mPath.AppendCell(GoalAnchorCell(mGoal));
    mState = AIPATHNAVSTATE_FollowingLeader;
  }

  mTargetWithinOneCell = 0;
  (void)UpdateForwardProbeFlag(*this);
}

/**
 * Address: 0x005AEC70 (FUN_005AEC70)
 */
void CAiPathNavigator::RequestContinuationPath(std::int32_t requestMode)
{
  if (mPath.CountInt() <= 0) {
    ResetPathState();
    return;
  }

  if (PackCell(mPath.start[0]) == PackCell(mCurrentPos)) {
    mPath.EraseFrontCells(1);
    if (mPath.CountInt() <= 0) {
      ResetPathState();
      return;
    }
  }

  while (mPath.CountInt() > 1) {
    const SOCellPos firstCell = mPath.start[0];
    const bool canTraverseFirst = CanPathCellTransition(*this, firstCell, firstCell);
    if (!canTraverseFirst || ManhattanDistance(firstCell, mCurrentPos) > 1) {
      break;
    }
    mPath.EraseFrontCells(1);
  }

  (void)UpdateForwardProbeFlag(*this);

  Unit* const unit = GetOwningUnit(*this);
  if (unit && unit->IsUnitState(UNITSTATE_Attacking)) {
    requestMode = 3;
    mUseExtendedPathProbe = 1;
  }
  if (requestMode == 3) {
    mUseExtendedPathProbe = 1;
  }

  mTargetWithinOneCell = 0;

  if (!mPathFinder || mPath.CountInt() <= 0) {
    return;
  }

  mPathFinder->mSearchType = AsSearchType(requestMode);
  mPathFinder->mAnchorCell.x = static_cast<std::uint16_t>(mCurrentPos.x);
  mPathFinder->mAnchorCell.z = static_cast<std::uint16_t>(mCurrentPos.z);
  mPathFinder->SetGoal(BuildSingleCellGoal(mPath.start[0]));
  mPathFinder->QueueSearch();

  mState = AIPATHNAVSTATE_PathEvent4;
  AttachListenerNodeToPathFinder(*this);
  mPathRetryDelayFrames = 0;
}

/**
 * Address: 0x005AE210 (FUN_005AE210)
 */
void CAiPathNavigator::SetCurrentPosition(const Wm3::Vector3f& position)
{
  const SFootprint* const footprint = GetActiveFootprint(*this);
  if (!footprint) {
    return;
  }

  mCurrentPos = ToCellPos(position, *footprint);
}

/**
 * Address: 0x005AF6D0 (FUN_005AF6D0)
 */
void CAiPathNavigator::SetTargetPoint(const std::int32_t targetIndex)
{
  mPath.EraseFrontCells(targetIndex);
  if (mPath.CountInt() <= 0) {
    return;
  }

  mTargetPos = mPath.start[0];
  mState = AIPATHNAVSTATE_HasPath;
  mPathRetryDelayFrames = 0;
  mTargetWithinOneCell = (ManhattanDistance(mCurrentPos, mTargetPos) <= 1) ? 1u : 0u;
}

/**
 * Address: 0x005AF7E0 (FUN_005AF7E0)
 */
bool CAiPathNavigator::TryAdvanceTargetPoint()
{
  const std::int32_t pathSize = mPath.CountInt();
  if (pathSize <= 0) {
    return false;
  }

  const std::int32_t firstReachableIndex = (mHasForwardProbe != 0u) ? std::max(0, ComputeDirectPrefixSpan(*this)) : 0;
  const std::int32_t furthestCandidateIndex = (mHasForwardProbe != 0u)
    ? std::min(pathSize - 1, std::max(10, firstReachableIndex))
    : std::min(pathSize - 1, 1);

  std::int32_t selectedIndex = -1;
  for (std::int32_t idx = furthestCandidateIndex; idx >= firstReachableIndex; --idx) {
    const SOCellPos candidate = mPath.start[idx];
    if (idx != firstReachableIndex && CellDistance(mCurrentPos, candidate) >= 50.0f) {
      continue;
    }

    const bool canTraverse = CanPathCellTransition(*this, mCurrentPos, candidate);
    const bool canReach = CanReachCellFromCurrent(*this, candidate);
    if (canTraverse && canReach) {
      mHasForwardProbe = 1;
      selectedIndex = idx;
      break;
    }

    if (mHasForwardProbe == 0u && mRepathRequested == 0u) {
      selectedIndex = idx;
      break;
    }
  }

  if (selectedIndex < firstReachableIndex) {
    if (mUseExtendedPathProbe != 0u && furthestCandidateIndex > 0) {
      SetTargetPoint(0);
      mUseExtendedPathProbe = 0;
      return true;
    }

    if (firstReachableIndex > 0) {
      mPath.EraseFrontCells(firstReachableIndex - 1);
    }
    return false;
  }

  if (selectedIndex == 0 && furthestCandidateIndex > firstReachableIndex && mPath.CountInt() > 1 &&
      !CanPathCellTransition(*this, mPath.start[0], mPath.start[1]) && CellDistance(mCurrentPos, mTargetPos) < 10.0f) {
    mPath.EraseFrontCells(1);
    return false;
  }

  if (mNoProgressTickCount <= 30 || selectedIndex > 0) {
    SetTargetPoint(selectedIndex);
    mTargetWithinOneCell = 0;
    return true;
  }

  return false;
}

/**
 * Address: 0x005AE2D0 (FUN_005AE2D0)
 */
void CAiPathNavigator::UpdateCurrentPosition(const Wm3::Vector3f& position)
{
  SetCurrentPosition(position);

  const std::uint32_t currentTick = (mSim != nullptr) ? mSim->mCurTick : 0u;

  if (mPathRequestCountdown > 0) {
    --mPathRequestCountdown;
    if (mPathRequestCountdown == 0) {
      RequestPath(mPathRequestMode);
    }
    mTargetPos = mCurrentPos;
    return;
  }

  if (mPathRetryDelayFrames > 0) {
    --mPathRetryDelayFrames;
    if (mPathRetryDelayFrames == 0) {
      RequestContinuationPath(2);
    }
    return;
  }

  while (mPath.CountInt() > 1) {
    const SOCellPos first = mPath.start[0];
    const SOCellPos second = mPath.start[1];
    if (CellDistance(mCurrentPos, first) < CellDistance(mCurrentPos, second) || !CanReachCellFromCurrent(*this, second)) {
      break;
    }
    mPath.EraseFrontCells(1);
  }

  if (mState != AIPATHNAVSTATE_HasPath && mState != AIPATHNAVSTATE_FollowingLeader) {
    mTargetPos = mCurrentPos;
    return;
  }

  if (mPath.CountInt() <= 0) {
    mState = AIPATHNAVSTATE_Failed;
    mPathRetryDelayFrames = 0;
    mTargetPos = mCurrentPos;
    return;
  }

  const SOCellPos pathTail = mPath.finish[-1];
  if (PackCell(mCurrentPos) == PackCell(pathTail)) {
    mState = AIPATHNAVSTATE_Idle;
    mPathRetryDelayFrames = 0;
    mTargetPos = mCurrentPos;
    return;
  }

  if (!TryAdvanceTargetPoint()) {
    mTargetPos = mPath.start[0];
  }

  Unit* const unit = GetOwningUnit(*this);
  if (!unit || mLeaderBusy != 0u) {
    return;
  }

  const std::uint32_t layerToken = ReadUnitLayerToken(unit);
  if (layerToken != mLastPathLayerToken) {
    mLastPathLayerToken = layerToken;
    RequestContinuationPath(2);
    return;
  }

  const bool hasMoved = (unit->Position.x != unit->PrevPosition.x) || (unit->Position.y != unit->PrevPosition.y) ||
    (unit->Position.z != unit->PrevPosition.z);
  if (!hasMoved && !unit->IsUnitState(UNITSTATE_Moving)) {
    ++mNoProgressTickCount;
  } else {
    mNoProgressTickCount = 0;
  }

  const float currentTargetDistance = CellDistance(mCurrentPos, mTargetPos);
  if (mRepathDistanceThreshold < currentTargetDistance || mRepathRequested != 0u || mNoProgressTickCount > 30) {
    mLastRepathTick = static_cast<std::int32_t>(currentTick);

    if (TryAdvanceTargetPoint()) {
      mHasLeaderTargetPos = 0;
      mRepathDistanceThreshold = CellDistance(mCurrentPos, mTargetPos) * 0.5f;
      mLeaderTargetPos = Wm3::Vector3f::Zero();
      mRepathRequested = 0;
      return;
    }

    if (mNoProgressTickCount > 30) {
      mState = AIPATHNAVSTATE_Idle;
      mPathRetryDelayFrames = 0;
      mTargetPos = mCurrentPos;
      return;
    }

    if (mRepathRequested != 0u) {
      mRepathRequested = 0;
      RequestContinuationPath(3);
      return;
    }

    RequestContinuationPath(2);
  }
}

/**
 * Address: 0x005AD800 (FUN_005AD800)
 */
bool CAiPathNavigator::IsCellInGoal(const SOCellPos& cellPos) const
{
  const int x = static_cast<int>(cellPos.x);
  if (x < mGoal.minX || x >= mGoal.maxX) {
    return false;
  }

  const int z = static_cast<int>(cellPos.z);
  return z >= mGoal.minZ && z < mGoal.maxZ;
}

/**
 * Address: 0x005AD8B0 (FUN_005AD8B0)
 */
Wm3::Vector3f CAiPathNavigator::GetTargetPos() const
{
  if (mHasLeaderTargetPos != 0u && HasVectorValue(mLeaderTargetPos)) {
    return mLeaderTargetPos;
  }

  Unit* const unit = GetOwningUnit(*this);
  const SFootprint* const footprint = GetActiveFootprint(*this);
  if (!unit || !footprint) {
    return Wm3::Vector3f::Zero();
  }
  return ToWorldPos(mTargetPos, *unit, *footprint);
}

/**
 * Address: 0x005ADAD0 (FUN_005ADAD0 callsite from FUN_005A3CD0)
 */
bool CAiPathNavigator::CanPathTo(const SAiNavigatorGoal& goal, Wm3::Vector3f* const outTargetPos) const
{
  if (!HasGoalArea(goal)) {
    return false;
  }

  if (!outTargetPos) {
    return true;
  }

  Unit* const unit = GetOwningUnit(*this);
  const SFootprint* const footprint = GetActiveFootprint(*this);
  if (!unit || !footprint) {
    *outTargetPos = Wm3::Vector3f::Zero();
    return true;
  }

  const SOCellPos anchor = GoalAnchorCell(goal);
  *outTargetPos = ToWorldPos(anchor, *unit, *footprint);
  return true;
}

