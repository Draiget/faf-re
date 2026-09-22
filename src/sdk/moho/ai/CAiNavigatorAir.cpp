#include "moho/ai/CAiNavigatorAir.h"

#include <cmath>
#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
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

    // The queue holds `WeakPtr<CUnitCommand>`; a head command whose node is no
    // longer in its owner's chain is a detached command, which is what the
    // binary's `slot == 0 || slot == 4` pair tests for.
    return !begin->IsLinkedInOwnerChain();
  }

  [[nodiscard]] bool HasMovedSincePrev(const Entity& entity) noexcept
  {
    return entity.mVarDat.mCurTransform.pos_.x != entity.mVarDat.mLastTransform.pos_.x || entity.mVarDat.mCurTransform.pos_.y != entity.mVarDat.mLastTransform.pos_.y ||
      entity.mVarDat.mCurTransform.pos_.z != entity.mVarDat.mLastTransform.pos_.z;
  }

  [[nodiscard]] Wm3::Vector3f EstimateAirAbortStopPosition(const Unit& unit) noexcept
  {
    Wm3::Vector3f out = Wm3::Vector3f::Zero();
    unit.PredictAheadBomb(&out, 1.0f);
    return out;
  }

  [[nodiscard]] gpg::RType* CachedCAiNavigatorImplType()
  {
    if (!CAiNavigatorImpl::sType) {
      CAiNavigatorImpl::sType = gpg::LookupRType(typeid(CAiNavigatorImpl));
    }
    return CAiNavigatorImpl::sType;
  }

  /**
   * The reflected type of the destination lane. 0x005A912C reads its cached
   * `RType` through the type descriptor at 0x00F6B8A4, whose name is
   * `.?AV?$WeakPtr@VEntity@Moho@@@Moho@@`.
   */
  [[nodiscard]] gpg::RType* CachedWeakEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(WeakPtr<Entity>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return cached;
  }
} // namespace

gpg::RType* CAiNavigatorAir::sType = nullptr;

/**
 * Address: 0x005A5390 (FUN_005A5390, default ctor)
 */
CAiNavigatorAir::CAiNavigatorAir()
  : CAiNavigatorImpl()
  , mDestinationEntity{}
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
  , mDestinationEntity{}
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
  mDestinationEntity.ResetFromObject(nullptr);
}

/**
 * Address: 0x005A9100 (FUN_005A9100, Moho::CAiNavigatorAir::MemberDeserialize)
 *
 * What it does:
 * Loads base navigator state, destination weak link, current target, goal
 * position, and formation-tracking flag.
 */
void CAiNavigatorAir::MemberDeserialize(CAiNavigatorAir* const object, gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Read(CachedCAiNavigatorImplType(), object, ownerRef);

  WeakPtr<Entity> destination{};
  archive->Read(
    CachedWeakEntityType(),
    object ? static_cast<void*>(&object->mDestinationEntity) : static_cast<void*>(&destination),
    ownerRef
  );

  Wm3::Vector3f currentTarget = Wm3::Vector3f::Zero();
  archive->Read(
    CachedVector3fType(),
    object ? static_cast<void*>(&object->mCurrentTargetPos) : static_cast<void*>(&currentTarget),
    ownerRef
  );

  Wm3::Vector3f goalPos = Wm3::Vector3f::Zero();
  archive->Read(
    CachedVector3fType(),
    object ? static_cast<void*>(&object->mGoalPos) : static_cast<void*>(&goalPos),
    ownerRef
  );

  bool trackFormation = false;
  archive->ReadBool(&trackFormation);
  if (object) {
    object->mTrackFormationTarget = trackFormation ? 1u : 0u;
  }
}

/**
 * Address: 0x005A91F0 (FUN_005A91F0, Moho::CAiNavigatorAir::MemberSerialize)
 *
 * What it does:
 * Saves base navigator state, destination weak link, current target, goal
 * position, and formation-tracking flag.
 */
void CAiNavigatorAir::MemberSerialize(const CAiNavigatorAir* const object, gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Write(CachedCAiNavigatorImplType(), object, ownerRef);

  const WeakPtr<Entity> destination{};
  archive->Write(
    CachedWeakEntityType(),
    object ? static_cast<const void*>(&object->mDestinationEntity) : static_cast<const void*>(&destination),
    ownerRef
  );

  const Wm3::Vector3f currentTarget = Wm3::Vector3f::Zero();
  archive->Write(
    CachedVector3fType(),
    object ? static_cast<const void*>(&object->mCurrentTargetPos) : static_cast<const void*>(&currentTarget),
    ownerRef
  );

  const Wm3::Vector3f goalPos = Wm3::Vector3f::Zero();
  archive->Write(
    CachedVector3fType(),
    object ? static_cast<const void*>(&object->mGoalPos) : static_cast<const void*>(&goalPos),
    ownerRef
  );

  archive->WriteBool(object && object->mTrackFormationTarget != 0u);
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
  mDestinationEntity.ResetFromObject(nullptr);

  mGoalPos = BuildGoalWorldPos(goal);
  mCurrentTargetPos = mGoalPos;

  if (mUnit->UnitMotion) {
    ELayer targetLayer = static_cast<ELayer>(goal.aux4);
    if (targetLayer == LAYER_None) {
      const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
      if (blueprint && blueprint->Air.CanFly != 0u) {
        targetLayer = LAYER_Air;
      } else {
        targetLayer = mUnit->mVarDat.mLayerMask;
      }
    }
    mUnit->UnitMotion->SetTarget(mCurrentTargetPos, Wm3::Vector3f::Zero(), targetLayer);
  }

  mStatus = AINAVSTATUS_Steering;

  if (mIgnoreFormation == 0u) {
    mTrackFormationTarget =
      static_cast<std::uint8_t>(mUnit->mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>() != nullptr);
  }
}

/**
 * Address: 0x005A4A70 (FUN_005A4A70)
 */
void CAiNavigatorAir::SetDestUnit(Entity* const destinationEntity)
{
  mDestinationEntity.ResetFromObject(destinationEntity);
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

  Unit* const leaderUnit = mUnit->mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
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

  Entity* const destinationEntity = mDestinationEntity.GetObjectPtr();
  if (destinationEntity && destinationEntity->IsMobile() && HasMovedSincePrev(*destinationEntity) &&
      mUnit->IsInCategory("TARGETCHASER")) {
    UpdateCurrentTargetFromDestinationEntity();
    return 1;
  }

  const SFootprint& footprint = mUnit->GetFootprint();
  const std::int16_t currentTargetCellX = GridCellCoord(mCurrentTargetPos.x, footprint.mSizeX);
  const std::int16_t currentTargetCellZ = GridCellCoord(mCurrentTargetPos.z, footprint.mSizeZ);
  const std::int16_t goalCellX = GridCellCoord(mGoalPos.x, footprint.mSizeX);
  const std::int16_t goalCellZ = GridCellCoord(mGoalPos.z, footprint.mSizeZ);

  // TEMPORARY PROBE -- air-transport "unloads instantly at the current position,
  // then flies to the drop point" triage. Delete once resolved.
  //
  // Every function feeding this decision has now been verified 1:1 against the
  // binary -- AtTarget (0x006B9730), ShouldHoverInsteadOfLand (0x006BC820),
  // SetGoal's goal->current-target copy (0x005A4C60 +112..+120 from +124..+132),
  // and this cell test itself. On paper the original arrives instantly too,
  // which cannot be right, so the remaining difference is WHEN this runs
  // relative to CalcMoveAir -- the only thing that converts UMVE_Hover into
  // UMVE_Up and so makes AtTarget stop returning true regardless of distance.
  //
  // This reports the decision inputs on the first ticks after a goal is set. A
  // line with atTarget=1 and a large dist is the bug reproducing: arrival
  // declared while still far away, because vert=Hover skipped the distance test.
  {
    static int sProbe = 0;
    if (sProbe++ < 60) {
      const CUnitMotion* const motion = mUnit->UnitMotion;
      const float dx = mGoalPos.x - mUnit->GetPosition().x;
      const float dz = mGoalPos.z - mUnit->GetPosition().z;
      gpg::Warnf(
        "[XPORTARRIVE] atTarget=%d vert=%d curLayer=%d tgtLayer=%d dist=%.1f cells=(%d,%d)vs(%d,%d)",
        (motion != nullptr && motion->AtTarget()) ? 1 : 0,
        motion != nullptr ? static_cast<int>(motion->mVertEvent) : -1,
        static_cast<int>(mUnit->mVarDat.mLayerMask),
        motion != nullptr ? static_cast<int>(motion->mLayer) : -1,
        std::sqrt((dx * dx) + (dz * dz)),
        static_cast<int>(currentTargetCellX), static_cast<int>(currentTargetCellZ),
        static_cast<int>(goalCellX), static_cast<int>(goalCellZ)
      );
    }
  }

  if (mUnit->UnitMotion && mUnit->UnitMotion->AtTarget() &&
      static_cast<std::uint16_t>(currentTargetCellX) == static_cast<std::uint16_t>(goalCellX) &&
      static_cast<std::uint16_t>(currentTargetCellZ) == static_cast<std::uint16_t>(goalCellZ)) {
    if (!mDestinationEntity.HasValue()) {
      mStatus = AINAVSTATUS_Idle;
      DispatchNavigatorEvent(AINAVEVENT_Succeeded);
      return 1;
    }

    UpdateCurrentTargetFromDestinationEntity();
    return 1;
  }

  if (mUnit->IsUnitState(UNITSTATE_Refueling)) {
    // `FocusEntityRef` is an *entity* weak ref, so the decoded pointer is an
    // `Entity*` and has to be narrowed before any `Unit` member is touched.
    // 0x005A52F9 does exactly that: it decodes the slot to `slot - 4` and then
    // dispatches vtable +0x10 - `Entity::IsUnit`, the first virtual Entity adds
    // after CScriptObject's four - with no arguments, and uses the *returned*
    // pointer for everything that follows.
    //
    // The previous form decoded the slot straight to `Unit*`. That is a
    // different pointer: `Unit` is `IUnit, Entity`, so the Entity subobject
    // sits at +0x08 and `IsUnit()` adjusts by that much. Skipping the call left
    // every member access eight bytes low, against IUnit's vtable rather than
    // its own. The formation lead a few lines down genuinely does not need this
    // - its chain is a `WeakPtr<Unit>` (Unit.cpp:15770) and 0x005A4DCE
    // dispatches slot 0 on `slot - 4` directly - which is why only this site
    // narrows.
    Entity* const focusEntity = mUnit->FocusEntityRef.ResolveObjectPtr<Entity>();
    Unit* const focusUnit = (focusEntity != nullptr) ? focusEntity->IsUnit() : nullptr;
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

  ELayer targetLayer = mUnit->mVarDat.mLayerMask;
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
  Entity* const destinationEntity = mDestinationEntity.GetObjectPtr();
  if (!destinationEntity) {
    AbortMove();
    return;
  }

  // 0x005A4EC3 passes `&destination->Position` (Entity +0xAC) straight to
  // motion and never writes `mCurrentTargetPos` - the chase target lives on
  // the entity, so re-reading it each retarget is the point.
  if (mUnit && mUnit->UnitMotion) {
    mUnit->UnitMotion->SetTarget(destinationEntity->mVarDat.mCurTransform.pos_, Wm3::Vector3f::Zero(), LAYER_None);
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

  Unit* const leaderUnit = mUnit->mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
  if (leaderUnit && leaderUnit != mUnit && leaderUnit->AiNavigator && leaderUnit->AiNavigator->HasGoodPath()) {
    mCurrentTargetPos = mUnit->mInfoCache.mFormationHeadingHint;
    ApplyCurrentTargetToMotion();
    return;
  }

  mTrackFormationTarget = 0;
  mCurrentTargetPos = mGoalPos;
  ApplyCurrentTargetToMotion();
}
