#include "moho/ai/CAiNavigatorLand.h"

#include <cmath>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/ai/IAiSteering.h"
#include "moho/sim/SFootprint.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  struct SRect2iView
  {
    std::int32_t x0;
    std::int32_t z0;
    std::int32_t x1;
    std::int32_t z1;
  };

  [[nodiscard]] bool IsRegularRect(const SRect2iView& rect) noexcept
  {
    return rect.x0 >= rect.x1 || rect.z0 >= rect.z1;
  }

  [[nodiscard]] bool RectsOverlapStrict(const SRect2iView& lhs, const SRect2iView& rhs) noexcept
  {
    return lhs.x0 < rhs.x1 && rhs.x0 < lhs.x1 && lhs.z0 < rhs.z1 && rhs.z0 < lhs.z1;
  }

  [[nodiscard]] std::int32_t GridCoordFromWorldCenter(const float worldCoord, const std::uint8_t footprintSize) noexcept
  {
    return static_cast<std::int32_t>(worldCoord - (static_cast<float>(footprintSize) * 0.5f));
  }

  [[nodiscard]] Wm3::Vector3f GoalCellToWorldPos(const Unit& unit, const SAiNavigatorGoal& goal) noexcept
  {
    const SFootprint& footprint = unit.GetFootprint();
    const Wm3::Vector3f unitPos = unit.GetPosition();
    return {
      static_cast<float>(goal.minX) + (static_cast<float>(footprint.mSizeX) * 0.5f),
      unitPos.y,
      static_cast<float>(goal.minZ) + (static_cast<float>(footprint.mSizeZ) * 0.5f),
    };
  }

  [[nodiscard]] bool GoalMatchForSetGoalDedup(const SAiNavigatorGoal& lhs, const SAiNavigatorGoal& rhs) noexcept
  {
    return lhs.minX == rhs.minX && lhs.minZ == rhs.minZ && lhs.maxX == rhs.maxX && lhs.maxZ == rhs.maxZ &&
      lhs.aux0 == rhs.aux0 && lhs.aux1 == rhs.aux1 && lhs.aux2 == rhs.aux2 && lhs.aux3 == rhs.aux3;
  }

  [[nodiscard]] bool IsSingleCellGoal(const SAiNavigatorGoal& goal) noexcept
  {
    return goal.minX == (goal.maxX - 1) && goal.minZ == (goal.maxZ - 1);
  }

  [[nodiscard]] SAiNavigatorGoal BuildSingleCellGoal(const std::int32_t cellX, const std::int32_t cellZ) noexcept
  {
    return {
      cellX,
      cellZ,
      cellX + 1,
      cellZ + 1,
      0,
      0,
      0,
      0,
      0,
    };
  }

  [[nodiscard]] SOCellPos TargetWorldToCell(const Wm3::Vector3f& worldPos, const SFootprint& footprint) noexcept
  {
    SOCellPos cell{};
    cell.x = static_cast<std::int16_t>(worldPos.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    cell.z = static_cast<std::int16_t>(worldPos.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));
    return cell;
  }

  [[nodiscard]] gpg::RType* CachedCAiNavigatorImplType()
  {
    if (!CAiNavigatorImpl::sType) {
      CAiNavigatorImpl::sType = gpg::LookupRType(typeid(CAiNavigatorImpl));
    }
    return CAiNavigatorImpl::sType;
  }

  [[nodiscard]] gpg::RType* CachedCAiPathNavigatorType()
  {
    if (!CAiPathNavigator::sType) {
      CAiPathNavigator::sType = gpg::LookupRType(typeid(CAiPathNavigator));
    }
    return CAiPathNavigator::sType;
  }

  [[nodiscard]] gpg::RType* CachedWeakUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(WeakPtr<Unit>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSAiNavigatorGoalType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SAiNavigatorGoal));
    }
    return cached;
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadPointerWithType(
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef,
    gpg::RType* const expectedType
  )
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    const gpg::RRef source{tracked.object, tracked.type};
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return static_cast<TObject*>(upcast.mObj);
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* const object, gpg::RType* const staticType)
  {
    gpg::RRef ref{};
    ref.mObj = nullptr;
    ref.mType = staticType;
    if (!object) {
      return ref;
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
      ref.mObj = object;
      ref.mType = dynamicType ? dynamicType : staticType;
      return ref;
    }

    ref.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    ref.mType = dynamicType;
    return ref;
  }

  template <typename TObject>
  void WritePointerWithType(
    gpg::WriteArchive* const archive,
    TObject* const object,
    gpg::RType* const staticType,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef objectRef = MakeTypedRef(object, staticType);
    gpg::WriteRawPointer(archive, objectRef, state, ownerRef);
  }
} // namespace

gpg::RType* CAiNavigatorLand::sType = nullptr;

/**
 * Address: 0x005A4420 (FUN_005A4420, default ctor)
 */
CAiNavigatorLand::CAiNavigatorLand()
  : CAiNavigatorImpl()
  , mPathNavigator(nullptr)
  , mDestinationUnit{}
  , mGoal{0, 0, 1, 1, 0, 0, 0, 0, 0}
{}

/**
 * Address: 0x005A3AC0 (FUN_005A3AC0, unit ctor)
 */
CAiNavigatorLand::CAiNavigatorLand(Unit* const unit)
  : CAiNavigatorImpl(unit)
  , mPathNavigator(nullptr)
  , mDestinationUnit{}
  , mGoal{0, 0, 0, 0, 0, 0, 0, 0, 0}
{
  if (unit) {
    unit->GetBlueprint();
    mPathNavigator = new CAiPathNavigator(unit);
  }
}

/**
 * Address: 0x005A4490 (FUN_005A4490, scalar deleting thunk)
 * Address: 0x005A3B80 (FUN_005A3B80, core dtor)
 */
CAiNavigatorLand::~CAiNavigatorLand()
{
  mDestinationUnit.ResetFromObject(nullptr);

  delete mPathNavigator;
  mPathNavigator = nullptr;
}

/**
 * Address: 0x005A8F40 (FUN_005A8F40, Moho::CAiNavigatorLand::MemberDeserialize)
 *
 * What it does:
 * Loads base navigator state, owned path-navigator pointer, destination-unit
 * weak link, and goal rectangle payload.
 */
void CAiNavigatorLand::MemberDeserialize(CAiNavigatorLand* const object, gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Read(CachedCAiNavigatorImplType(), object, ownerRef);

  CAiPathNavigator* const loadedPathNavigator =
    ReadPointerWithType<CAiPathNavigator>(archive, ownerRef, CachedCAiPathNavigatorType());

  if (object) {
    CAiPathNavigator* const oldPathNavigator = object->mPathNavigator;
    object->mPathNavigator = loadedPathNavigator;
    if (oldPathNavigator) {
      delete oldPathNavigator;
    }
  } else if (loadedPathNavigator) {
    delete loadedPathNavigator;
  }

  WeakPtr<Unit> destinationUnit{};
  archive->Read(
    CachedWeakUnitType(),
    object ? static_cast<void*>(&object->mDestinationUnit) : static_cast<void*>(&destinationUnit),
    ownerRef
  );

  SAiNavigatorGoal goal{};
  archive->Read(
    CachedSAiNavigatorGoalType(),
    object ? static_cast<void*>(&object->mGoal) : static_cast<void*>(&goal),
    ownerRef
  );
}

/**
 * Address: 0x005A9030 (FUN_005A9030, Moho::CAiNavigatorLand::MemberSerialize)
 *
 * What it does:
 * Saves base navigator state, owned path-navigator pointer,
 * destination-unit weak link, and goal rectangle payload.
 */
void CAiNavigatorLand::MemberSerialize(const CAiNavigatorLand* const object, gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Write(CachedCAiNavigatorImplType(), object, ownerRef);

  WritePointerWithType(
    archive,
    object ? object->mPathNavigator : nullptr,
    CachedCAiPathNavigatorType(),
    gpg::TrackedPointerState::Owned,
    ownerRef
  );

  const WeakPtr<Unit> destinationUnit{};
  archive->Write(
    CachedWeakUnitType(),
    object ? static_cast<const void*>(&object->mDestinationUnit) : static_cast<const void*>(&destinationUnit),
    ownerRef
  );

  const SAiNavigatorGoal goal{};
  archive->Write(
    CachedSAiNavigatorGoalType(),
    object ? static_cast<const void*>(&object->mGoal) : static_cast<const void*>(&goal),
    ownerRef
  );
}

/**
 * Address: 0x005A3ED0 (FUN_005A3ED0)
 */
void CAiNavigatorLand::SetGoal(const SAiNavigatorGoal& goal)
{
  if (mStatus == AINAVSTATUS_Thinking && GoalMatchForSetGoalDedup(goal, mGoal)) {
    return;
  }

  if (goal.minX == 0 && goal.minZ == 0) {
    return;
  }

  SAiNavigatorGoal finalGoal = goal;
  if (IsSingleCellGoal(goal)) {
    finalGoal = BuildSingleCellGoal(goal.minX, goal.minZ);
    if (mStatus == AINAVSTATUS_Thinking && finalGoal.minX == mGoal.minX && finalGoal.minZ == mGoal.minZ) {
      return;
    }
  }

  ApplyGoalAndStartPathing(finalGoal);
}

/**
 * Address: 0x005A4180 (FUN_005A4180)
 */
void CAiNavigatorLand::SetDestUnit(Unit* const destinationUnit)
{
  if (!destinationUnit) {
    mDestinationUnit.ResetFromObject(nullptr);
    return;
  }

  const Wm3::Vector3f targetPos = destinationUnit->GetPosition();
  const std::int32_t cellX = static_cast<std::int32_t>(targetPos.x - 0.5f);
  const std::int32_t cellZ = static_cast<std::int32_t>(targetPos.z - 0.5f);
  SetGoal(BuildSingleCellGoal(cellX, cellZ));
  mDestinationUnit.ResetFromObject(destinationUnit);
}

/**
 * Address: 0x005A4240 (FUN_005A4240)
 */
void CAiNavigatorLand::SetSpeedThroughGoal(const bool enabled)
{
  if (!mUnit || !mUnit->AiSteering) {
    return;
  }
  mUnit->AiSteering->CalcAtTopSpeed1(enabled);
}

/**
 * Address: 0x005A4260 (FUN_005A4260)
 */
Wm3::Vector3f CAiNavigatorLand::GetCurrentTargetPos() const
{
  if (!mPathNavigator) {
    return mUnit ? mUnit->GetPosition() : Wm3::Vector3f::Zero();
  }
  return mPathNavigator->GetTargetPos();
}

/**
 * Address: 0x005A3D80 (FUN_005A3D80)
 */
Wm3::Vector3f CAiNavigatorLand::GetGoalPos() const
{
  if (mStatus == AINAVSTATUS_Idle || !mUnit) {
    return mUnit ? mUnit->GetPosition() : Wm3::Vector3f::Zero();
  }
  return GoalCellToWorldPos(*mUnit, mGoal);
}

/**
 * Address: 0x005A3EB0 (FUN_005A3EB0)
 */
bool CAiNavigatorLand::HasGoodPath() const
{
  return mPathNavigator && mPathNavigator->mState == AIPATHNAVSTATE_HasPath;
}

/**
 * Address: 0x005A3EC0 (FUN_005A3EC0)
 */
bool CAiNavigatorLand::FollowingLeader() const
{
  return mPathNavigator && mPathNavigator->mState == AIPATHNAVSTATE_FollowingLeader;
}

/**
 * Address: 0x005A3D60 (FUN_005A3D60)
 */
void CAiNavigatorLand::IgnoreFormation(const bool ignore)
{
  mIgnoreFormation = static_cast<std::uint8_t>(ignore);
}

/**
 * Address: 0x005A3D70 (FUN_005A3D70)
 */
bool CAiNavigatorLand::IsIgnoringFormation() const
{
  return mIgnoreFormation != 0u;
}

/**
 * Address: 0x005A3BD0 (FUN_005A3BD0)
 */
bool CAiNavigatorLand::AtGoal() const
{
  if (!mUnit) {
    return false;
  }

  const SFootprint& footprint = mUnit->GetFootprint();
  const Wm3::Vector3f pos = mUnit->GetPosition();

  const std::int32_t baseX = GridCoordFromWorldCenter(pos.x, footprint.mSizeX);
  const std::int32_t baseZ = GridCoordFromWorldCenter(pos.z, footprint.mSizeZ);
  const std::int32_t spanX = static_cast<std::int32_t>(footprint.mSizeX);
  const std::int32_t spanZ = static_cast<std::int32_t>(footprint.mSizeZ);

  const SRect2iView unitRect{
    baseX - spanX,
    baseZ - spanZ,
    baseX + spanX,
    baseZ + spanZ,
  };

  const SRect2iView goalRect{
    mGoal.minX,
    mGoal.minZ,
    mGoal.maxX,
    mGoal.maxZ,
  };

  if (IsRegularRect(goalRect) || IsRegularRect(unitRect)) {
    return false;
  }

  return RectsOverlapStrict(goalRect, unitRect);
}

/**
 * Address: 0x005A3CD0 (FUN_005A3CD0)
 */
bool CAiNavigatorLand::CanPathTo(const SAiNavigatorGoal& goal) const
{
  if (!mUnit) {
    return false;
  }

  CAiPathNavigator tempPathNavigator{mUnit};
  tempPathNavigator.SetCurrentPosition(mUnit->GetPosition());
  Wm3::Vector3f scratchTarget{};
  return tempPathNavigator.CanPathTo(goal, &scratchTarget);
}

/**
 * Address: 0x005A3E80 (FUN_005A3E80)
 */
void CAiNavigatorLand::Func1()
{
  if (!mPathNavigator) {
    return;
  }

  if (mPathNavigator->mLeaderBusy == 0u) {
    mPathNavigator->mRepathRequested = 1u;
  }
}

/**
 * Address: 0x005A3EA0 (FUN_005A3EA0)
 */
SNavPath* CAiNavigatorLand::GetNavPath() const
{
  return mPathNavigator ? mPathNavigator->GetPath() : nullptr;
}

/**
 * Address: 0x005A3E00 (FUN_005A3E00)
 */
bool CAiNavigatorLand::NavigatorMakeIdle()
{
  if (mStatus != AINAVSTATUS_Idle) {
    mStatus = AINAVSTATUS_Idle;
  }

  if (mPathNavigator) {
    mPathNavigator->ResetPathState();
  }

  mDestinationUnit.ResetFromObject(nullptr);

  if (mUnit && mUnit->AiSteering) {
    mUnit->AiSteering->SetWaypoints(nullptr, 0);
  }

  return true;
}

/**
 * Address: 0x005A4280 (FUN_005A4280, CAiNavigatorLand::Execute)
 */
int CAiNavigatorLand::Execute()
{
  if (!mUnit || !mPathNavigator) {
    return 1;
  }

  if (mStatus < AINAVSTATUS_Thinking || mStatus > AINAVSTATUS_Steering) {
    return 1;
  }

  IAiSteering* const steering = mUnit->AiSteering;
  if (!steering) {
    return 1;
  }

  mPathNavigator->UpdateCurrentPosition(mUnit->GetPosition());
  const Wm3::Vector3f targetPos = mPathNavigator->GetTargetPos();

  if (mPathNavigator->mState != AIPATHNAVSTATE_Thinking) {
    const Wm3::Vector3f currentWaypoint = steering->GetWaypoint();
    if (Wm3::Vector3f::Compare(&targetPos, &currentWaypoint)) {
      const SOCellPos targetCell = TargetWorldToCell(targetPos, mUnit->GetFootprint());
      steering->UseTopSpeed(mPathNavigator->IsCellInGoal(targetCell));

      if (mStatus == AINAVSTATUS_Thinking) {
        steering->CalcAtTopSpeed2(false);
      } else {
        steering->CalcAtTopSpeed2(mPathNavigator->mLastPathNodeIndex < 0);
      }

      steering->SetWaypoints(&targetPos, 1);
      mStatus = AINAVSTATUS_Steering;
    }
  }

  if (mPathNavigator->mState <= AIPATHNAVSTATE_Failed) {
    steering->Stop();
    NavigatorMakeIdle();

    const EAiNavigatorEvent eventCode =
      (mPathNavigator->mState == AIPATHNAVSTATE_Idle) ? AINAVEVENT_Succeeded : AINAVEVENT_Failed;
    DispatchNavigatorEvent(eventCode);
  }

  return 1;
}

void CAiNavigatorLand::ApplyGoalAndStartPathing(const SAiNavigatorGoal& goal)
{
  mGoal = goal;

  if (mPathNavigator) {
    mPathNavigator->ResetPathState();
    mPathNavigator->ConfigureGoal(goal, mIgnoreFormation != 0);
  }

  mStatus = AINAVSTATUS_Thinking;

  if (mUnit && mPathNavigator) {
    mPathNavigator->SetCurrentPosition(mUnit->GetPosition());
    mPathNavigator->BeginThinking();
  }
}
