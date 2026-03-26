#include "moho/ai/CAiNavigatorAir.h"

#include <cmath>
#include <cstdint>
#include <limits>

#include "moho/ai/IAiSteering.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/SFootprint.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  struct UnitNavigatorAirRuntimeView
  {
    std::uint8_t pad_0000_0584[0x584];
    void* mFollowTargetOwnerSlot;     // +0x584
    std::uint8_t pad_0588_059C[0x14];
    Wm3::Vector3f mCurrentMoveTarget; // +0x59C
  };

  static_assert(
    offsetof(UnitNavigatorAirRuntimeView, mFollowTargetOwnerSlot) == 0x584,
    "UnitNavigatorAirRuntimeView::mFollowTargetOwnerSlot offset must be 0x584"
  );
  static_assert(
    offsetof(UnitNavigatorAirRuntimeView, mCurrentMoveTarget) == 0x59C,
    "UnitNavigatorAirRuntimeView::mCurrentMoveTarget offset must be 0x59C"
  );

  [[nodiscard]] bool IsWeakSentinelSlot(void* const slot) noexcept
  {
    return reinterpret_cast<std::uintptr_t>(slot) == sizeof(void*);
  }

  template <typename T>
  [[nodiscard]] T* DecodeWeakOwnerSlot(void* const slot) noexcept
  {
    if (!slot || IsWeakSentinelSlot(slot)) {
      return nullptr;
    }
    const auto raw = reinterpret_cast<std::uintptr_t>(slot);
    return reinterpret_cast<T*>(raw - sizeof(void*));
  }

  [[nodiscard]] std::int16_t GridCellCoord(const float worldCoord, const std::uint8_t footprintAxisSize) noexcept
  {
    return static_cast<std::int16_t>(std::lround(worldCoord - (static_cast<float>(footprintAxisSize) * 0.5f)));
  }

  [[nodiscard]] Wm3::Vector3f CellToWorldPos(
    const std::int32_t cellX,
    const std::int32_t cellZ,
    const SFootprint& footprint,
    const float worldY
  ) noexcept
  {
    return {
      static_cast<float>(cellX) + (static_cast<float>(footprint.mSizeX) * 0.5f),
      worldY,
      static_cast<float>(cellZ) + (static_cast<float>(footprint.mSizeZ) * 0.5f),
    };
  }

  [[nodiscard]] bool IsUnitIdleState(const Unit& unit) noexcept
  {
    const CUnitCommandQueue* const commandQueue = unit.CommandQueue;
    if (!commandQueue) {
      return true;
    }

    const auto* const begin = commandQueue->mCommandVec.begin();
    const auto* const end = commandQueue->mCommandVec.end();
    if (!begin || begin == end) {
      return true;
    }

    const void* const headSlot = begin->ownerLinkSlot;
    return headSlot == nullptr || IsWeakSentinelSlot(const_cast<void*>(headSlot));
  }

  [[nodiscard]] bool HasMovedSincePrev(const Unit& unit) noexcept
  {
    return unit.Position.x != unit.PrevPosition.x || unit.Position.y != unit.PrevPosition.y ||
      unit.Position.z != unit.PrevPosition.z;
  }

  [[nodiscard]] Wm3::Vector3f EstimateAirAbortStopPosition(const Unit& unit) noexcept
  {
    const Wm3::Vector3f& position = unit.GetPosition();
    const Wm3::Vector3f velocity = unit.GetVelocity();

    // FUN_0062CD40 predicts a short near-future stop point; without full
    // SPhysBody access here we keep the same horizon and preserve Y.
    return {
      position.x + (velocity.x * 10.0f),
      position.y,
      position.z + (velocity.z * 10.0f),
    };
  }
} // namespace

gpg::RType* CAiNavigatorAir::sType = nullptr;

/**
 * Address: 0x005A5390 (FUN_005A5390, default ctor)
 */
CAiNavigatorAir::CAiNavigatorAir()
  : CAiNavigatorImpl()
  , mDestinationUnitLink{}
  , mCurrentTargetPos(Wm3::Vector3f::Zero())
  , mGoalPos(Wm3::Vector3f::Zero())
  , mTrackFormationTarget(0)
  , mPad89{0, 0, 0}
{}

/**
 * Address: 0x005A4880 (FUN_005A4880, unit ctor)
 */
CAiNavigatorAir::CAiNavigatorAir(Unit* const unit)
  : CAiNavigatorImpl(unit)
  , mDestinationUnitLink{}
  , mCurrentTargetPos(Wm3::Vector3f::Zero())
  , mGoalPos(Wm3::Vector3f::Zero())
  , mTrackFormationTarget(0)
  , mPad89{0, 0, 0}
{}

/**
 * Address: 0x005A53F0 (FUN_005A53F0, scalar deleting thunk/core dtor)
 */
CAiNavigatorAir::~CAiNavigatorAir()
{
  mDestinationUnitLink.ResetFromObject(nullptr);
}

/**
 * Address: 0x005A4C60 (FUN_005A4C60)
 */
void CAiNavigatorAir::SetGoal(const SAiNavigatorGoal& goal)
{
  if (!mUnit || mUnit->IsUnitState(UNITSTATE_Attached)) {
    return;
  }

  mTrackFormationTarget = 0;
  mDestinationUnitLink.ResetFromObject(nullptr);

  mGoalPos = BuildGoalWorldPos(goal);
  mCurrentTargetPos = mGoalPos;

  if (mUnit->UnitMotion) {
    ELayer targetLayer = static_cast<ELayer>(goal.aux4);
    if (targetLayer == LAYER_None) {
      const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
      if (blueprint && blueprint->Air.CanFly != 0u) {
        targetLayer = LAYER_Air;
      } else {
        targetLayer = mUnit->mCurrentLayer;
      }
    }
    mUnit->UnitMotion->SetTarget(mCurrentTargetPos, Wm3::Vector3f::Zero(), targetLayer);
  }

  mStatus = AINAVSTATUS_Steering;

  if (mIgnoreFormation == 0u) {
    const auto* const unitView = reinterpret_cast<const UnitNavigatorAirRuntimeView*>(mUnit);
    mTrackFormationTarget = static_cast<std::uint8_t>(DecodeWeakOwnerSlot<Unit>(unitView->mFollowTargetOwnerSlot) != nullptr);
  }
}

/**
 * Address: 0x005A4A70 (FUN_005A4A70)
 */
void CAiNavigatorAir::SetDestUnit(Unit* const destinationUnit)
{
  mDestinationUnitLink.ResetFromObject(destinationUnit);
  UpdateCurrentTargetFromDestinationEntity();
}

/**
 * Address: 0x005A4F00 (FUN_005A4F00)
 */
void CAiNavigatorAir::AbortMove()
{
  if (mUnit && mUnit->UnitMotion) {
    const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
    if (blueprint && blueprint->Air.CanFly != 0u) {
      const Wm3::Vector3f stopPos = EstimateAirAbortStopPosition(*mUnit);
      mUnit->UnitMotion->Stop(&stopPos);
    } else if (blueprint && blueprint->Physics.MaxAcceleration > 0.0f) {
      const Wm3::Vector3f velocity = mUnit->GetVelocity();
      const float velocityLenSq = Wm3::Vector3f::LengthSq(velocity);
      if (velocityLenSq > 0.0f) {
        const float speedTimesTen = std::sqrt(velocityLenSq) * 10.0f;
        const float brakingDistance =
          (speedTimesTen * speedTimesTen) / (blueprint->Physics.MaxAcceleration * 2.0f);

        const float invVelocityLen = 1.0f / std::sqrt(velocityLenSq);
        Wm3::Vector3f stopPos = mUnit->GetPosition();
        stopPos.x += (velocity.x * invVelocityLen) * brakingDistance;
        stopPos.y += (velocity.y * invVelocityLen) * brakingDistance;
        stopPos.z += (velocity.z * invVelocityLen) * brakingDistance;
        mUnit->UnitMotion->Stop(&stopPos);
      } else {
        mUnit->UnitMotion->Stop(nullptr);
      }
    } else {
      mUnit->UnitMotion->Stop(nullptr);
    }
  }

  mTrackFormationTarget = 0;
  CAiNavigatorImpl::AbortMove();
}

/**
 * Address: 0x005A5080 (FUN_005A5080)
 */
void CAiNavigatorAir::SetSpeedThroughGoal(const bool enabled)
{
  if (!mUnit || !mUnit->AiSteering) {
    return;
  }

  mUnit->AiSteering->UseTopSpeed(true);
  mUnit->AiSteering->CalcAtTopSpeed1(enabled);
}

/**
 * Address: 0x005A50B0 (FUN_005A50B0)
 */
Wm3::Vector3f CAiNavigatorAir::GetCurrentTargetPos() const
{
  return mCurrentTargetPos;
}

/**
 * Address: 0x005A49F0 (FUN_005A49F0)
 */
Wm3::Vector3f CAiNavigatorAir::GetGoalPos() const
{
  if (mStatus == AINAVSTATUS_Steering) {
    return mGoalPos;
  }

  if (!mUnit) {
    return Wm3::Vector3f::Zero();
  }
  return mUnit->GetPosition();
}

/**
 * Address: 0x005A4E50 (FUN_005A4E50)
 */
bool CAiNavigatorAir::HasGoodPath() const
{
  return mStatus == AINAVSTATUS_Steering;
}

/**
 * Address: 0x005A4E60 (FUN_005A4E60)
 */
bool CAiNavigatorAir::FollowingLeader() const
{
  if (!mUnit || mTrackFormationTarget == 0u) {
    return false;
  }

  const auto* const unitView = reinterpret_cast<const UnitNavigatorAirRuntimeView*>(mUnit);
  Unit* const leaderUnit = DecodeWeakOwnerSlot<Unit>(unitView->mFollowTargetOwnerSlot);
  if (leaderUnit) {
    return leaderUnit != mUnit;
  }
  return true;
}

/**
 * Address: 0x005A4A40 (FUN_005A4A40)
 */
void CAiNavigatorAir::IgnoreFormation(const bool ignore)
{
  mIgnoreFormation = static_cast<std::uint8_t>(ignore);
  if (ignore) {
    mTrackFormationTarget = 0;
  }
}

/**
 * Address: 0x005A4A60 (FUN_005A4A60)
 */
bool CAiNavigatorAir::IsIgnoringFormation() const
{
  return mIgnoreFormation != 0;
}

/**
 * Address: 0x005A48E0 (FUN_005A48E0)
 */
bool CAiNavigatorAir::AtGoal() const
{
  if (!mUnit) {
    return false;
  }

  const SFootprint& footprint = mUnit->GetFootprint();
  const Wm3::Vector3f currentPos = mUnit->GetPosition();

  const std::int16_t currentCellX = GridCellCoord(currentPos.x, footprint.mSizeX);
  const std::int16_t currentCellZ = GridCellCoord(currentPos.z, footprint.mSizeZ);
  const std::int16_t goalCellX = GridCellCoord(mCurrentTargetPos.x, footprint.mSizeX);
  const std::int16_t goalCellZ = GridCellCoord(mCurrentTargetPos.z, footprint.mSizeZ);
  return currentCellX == goalCellX && currentCellZ == goalCellZ;
}

/**
 * Address: 0x005A49E0 (FUN_005A49E0)
 */
bool CAiNavigatorAir::CanPathTo(const SAiNavigatorGoal&) const
{
  return true;
}

/**
 * Address: 0x005A50D0 (FUN_005A50D0, CAiNavigatorAir::Execute)
 */
int CAiNavigatorAir::Execute()
{
  if (mStatus != AINAVSTATUS_Steering || !mUnit) {
    return 1;
  }

  Unit* const destinationUnit = mDestinationUnitLink.GetObjectPtr();
  if (destinationUnit && destinationUnit->IsMobile() && HasMovedSincePrev(*destinationUnit) &&
      mUnit->IsInCategory("TARGETCHASER")) {
    UpdateCurrentTargetFromDestinationEntity();
    return 1;
  }

  const SFootprint& footprint = mUnit->GetFootprint();
  const std::int16_t currentTargetCellX = GridCellCoord(mCurrentTargetPos.x, footprint.mSizeX);
  const std::int16_t currentTargetCellZ = GridCellCoord(mCurrentTargetPos.z, footprint.mSizeZ);
  const std::int16_t goalCellX = GridCellCoord(mGoalPos.x, footprint.mSizeX);
  const std::int16_t goalCellZ = GridCellCoord(mGoalPos.z, footprint.mSizeZ);

  if (mUnit->UnitMotion && mUnit->UnitMotion->AtTarget() &&
      static_cast<std::uint16_t>(currentTargetCellX) == static_cast<std::uint16_t>(goalCellX) &&
      static_cast<std::uint16_t>(currentTargetCellZ) == static_cast<std::uint16_t>(goalCellZ)) {
    if (!mDestinationUnitLink.HasValue()) {
      mStatus = AINAVSTATUS_Idle;
      DispatchNavigatorEvent(AINAVEVENT_Succeeded);
      return 1;
    }

    UpdateCurrentTargetFromDestinationEntity();
    return 1;
  }

  if (mUnit->IsUnitState(UNITSTATE_Refueling)) {
    Unit* const focusUnit = DecodeWeakOwnerSlot<Unit>(mUnit->FocusEntityRef.valueWithTag);
    if (focusUnit && focusUnit->IsMobile() &&
        (focusUnit->IsDead() || focusUnit->DestroyQueued() || !IsUnitIdleState(*focusUnit) ||
         focusUnit->IsUnitState(UNITSTATE_MovingUp) || focusUnit->IsUnitState(UNITSTATE_MovingDown))) {
      mStatus = AINAVSTATUS_Idle;
      DispatchNavigatorEvent(AINAVEVENT_Failed);
    }
  } else {
    UpdateCurrentTargetFromFormation();
  }

  return 1;
}

/**
 * Address: 0x005A4B00 (FUN_005A4B00, helper used by FUN_005A4C60)
 */
Wm3::Vector3f CAiNavigatorAir::BuildGoalWorldPos(const SAiNavigatorGoal& goal) const
{
  if (!mUnit) {
    return Wm3::Vector3f::Zero();
  }

  const SFootprint& footprint = mUnit->GetFootprint();
  const Wm3::Vector3f unitPos = mUnit->GetPosition();

  const std::int16_t unitCellX = GridCellCoord(unitPos.x, footprint.mSizeX);
  const std::int16_t unitCellZ = GridCellCoord(unitPos.z, footprint.mSizeZ);

  const std::int32_t minX = goal.minX;
  const std::int32_t minZ = goal.minZ;
  const std::int32_t maxX = goal.maxX;
  const std::int32_t maxZ = goal.maxZ;
  if (minX == (maxX - 1) && minZ == (maxZ - 1)) {
    return CellToWorldPos(minX, minZ, footprint, unitPos.y);
  }

  std::int32_t bestX = minX;
  std::int32_t bestZ = minZ;
  float bestDistSq = std::numeric_limits<float>::infinity();

  for (std::int32_t x = minX; x < maxX; ++x) {
    for (std::int32_t z = minZ; z < maxZ; ++z) {
      const bool onPerimeter = (x == minX) || (x == (maxX - 1)) || (z == minZ) || (z == (maxZ - 1));
      if (!onPerimeter) {
        continue;
      }

      const auto dx = static_cast<std::int16_t>(unitCellX - static_cast<std::int16_t>(x));
      const auto dz = static_cast<std::int16_t>(unitCellZ - static_cast<std::int16_t>(z));
      const float distSq = (static_cast<float>(dx) * static_cast<float>(dx)) +
        (static_cast<float>(dz) * static_cast<float>(dz));
      if (distSq < bestDistSq) {
        bestDistSq = distSq;
        bestX = x;
        bestZ = z;
      }
    }
  }

  return CellToWorldPos(bestX, bestZ, footprint, unitPos.y);
}

/**
 * Address: 0x005A4A90 (FUN_005A4A90, helper chain)
 */
void CAiNavigatorAir::ApplyCurrentTargetToMotion()
{
  if (!mUnit || !mUnit->UnitMotion) {
    return;
  }

  ELayer targetLayer = mUnit->mCurrentLayer;
  const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
  if (blueprint && blueprint->Air.CanFly != 0u) {
    targetLayer = LAYER_Air;
  }

  mUnit->UnitMotion->SetTarget(mCurrentTargetPos, Wm3::Vector3f::Zero(), targetLayer);
}

/**
 * Address: 0x005A4EA0 (FUN_005A4EA0)
 */
void CAiNavigatorAir::UpdateCurrentTargetFromDestinationEntity()
{
  Unit* const destinationUnit = mDestinationUnitLink.GetObjectPtr();
  if (!destinationUnit) {
    AbortMove();
    return;
  }

  mCurrentTargetPos = destinationUnit->GetPosition();
  if (mUnit && mUnit->UnitMotion) {
    mUnit->UnitMotion->SetTarget(mCurrentTargetPos, Wm3::Vector3f::Zero(), LAYER_None);
  }
  mStatus = AINAVSTATUS_Steering;
}

/**
 * Address: 0x005A4D80 (FUN_005A4D80)
 */
void CAiNavigatorAir::UpdateCurrentTargetFromFormation()
{
  if (!mUnit || mTrackFormationTarget == 0u || mIgnoreFormation != 0u || mUnit->IsUnitState(UNITSTATE_Ferrying)) {
    return;
  }

  const auto* const unitView = reinterpret_cast<const UnitNavigatorAirRuntimeView*>(mUnit);
  Unit* const leaderUnit = DecodeWeakOwnerSlot<Unit>(unitView->mFollowTargetOwnerSlot);
  if (leaderUnit && leaderUnit != mUnit && leaderUnit->AiNavigator && leaderUnit->AiNavigator->HasGoodPath()) {
    mCurrentTargetPos = unitView->mCurrentMoveTarget;
    ApplyCurrentTargetToMotion();
    return;
  }

  mTrackFormationTarget = 0;
  mCurrentTargetPos = mGoalPos;
  ApplyCurrentTargetToMotion();
}
