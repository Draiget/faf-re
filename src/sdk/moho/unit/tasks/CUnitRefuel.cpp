#include "moho/unit/tasks/CUnitRefuel.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/math/Vector3f.h"
#include "moho/path/SNavGoal.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/SFootprint.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace
{
  // Fuel is treated as "full" slightly below 1.0 so a tick of consumption
  // while docked cannot push the task back out of its completion test.
  constexpr float kRefuelCompleteFuelRatio = 0.99f;
  // Cosine of the largest heading error tolerated before the platform is
  // allowed to grab the unit; a landing unit must be nearly aligned with the
  // attach facing (land units skip the test entirely).
  constexpr float kAttachFacingAlignment = 0.95f;

  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState state) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<std::int32_t>(state) + 1);
  }

  /**
   * Third basis vector (local +Z, i.e. "forward") of an orientation
   * quaternion, expanded inline exactly as the binary does at 0x00621CC1 and
   * 0x0062189B. `VAxes3` builds all three axes from the same quaternion but
   * spells its `vZ` lane differently, so the axis is derived here rather than
   * routed through that type.
   */
  [[nodiscard]] Wm3::Vec3f OrientationForwardAxis(const Wm3::Quatf& orientation) noexcept
  {
    return Wm3::Vec3f{
      2.0f * ((orientation.x * orientation.z) + (orientation.w * orientation.y)),
      2.0f * ((orientation.y * orientation.z) - (orientation.w * orientation.x)),
      1.0f - (2.0f * ((orientation.x * orientation.x) + (orientation.y * orientation.y)))
    };
  }

  [[nodiscard]] float DotProduct(const Wm3::Vec3f& lhs, const Wm3::Vec3f& rhs) noexcept
  {
    return (lhs.x * rhs.x) + (lhs.y * rhs.y) + (lhs.z * rhs.z);
  }

  /**
   * One-cell navigation goal covering `worldPos`, sized against `footprint`
   * (the moving unit's own footprint, never the platform's).
   */
  [[nodiscard]] moho::SNavGoal SingleCellGoalAt(const Wm3::Vec3f& worldPos, const moho::SFootprint& footprint)
  {
    return moho::SNavGoal{footprint.ToCellPos(worldPos)};
  }

  /**
   * True when `command` still targets an air unit that is refuelling and is
   * not the staging structure itself — i.e. the shared dock command has more
   * work left, so the unit that just undocked should clear the pad instead of
   * simply ending its task. `excludedCategory` names the platform side of the
   * handshake ("AIRSTAGINGPLATFORM" for pads, "CARRIER" for carriers).
   */
  [[nodiscard]] bool CommandHasRefuellingAirUnit(
    const moho::CUnitCommand* const command,
    const char* const excludedCategory
  )
  {
    if (!command) {
      return false;
    }

    for (moho::CScriptObject* const entry : command->mUnitSet.mVec) {
      moho::Unit* const candidate = moho::SCommandUnitSet::UnitFromEntry(entry);
      if (!candidate || !candidate->mIsAir) {
        continue;
      }

      if (candidate->IsInCategory(excludedCategory)) {
        continue;
      }

      if (candidate->IsUnitState(moho::UNITSTATE_Refueling)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Points the owning unit's navigator at the platform's cell. When
   * `speedThrough` is set the unit is additionally flagged
   * `UNITSTATE_ForceSpeedThrough` and the navigator is told to fly through
   * the goal rather than stop on it — the shape used while the unit is still
   * trying to reach the pad. Without it this is the plain "go stand there and
   * let the task die" tail.
   */
  void SteerTowardPlatform(moho::Unit& unit, moho::Unit& platform, const bool speedThrough)
  {
    const moho::SNavGoal goal = SingleCellGoalAt(platform.GetPosition(), unit.GetFootprint());

    if (speedThrough) {
      unit.UnitStateMask |= (1ull << moho::UNITSTATE_ForceSpeedThrough);
    }

    moho::IAiNavigator* const navigator = unit.AiNavigator;
    if (!navigator) {
      return;
    }

    if (speedThrough) {
      navigator->SetSpeedThroughGoal(true);
    }
    navigator->SetGoal(goal);
  }

  [[nodiscard]] gpg::RType* CachedCUnitRefuelType()
  {
    gpg::RType* type = moho::CUnitRefuel::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitRefuel));
      moho::CUnitRefuel::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00622460 (FUN_00622460, CUnitRefuel::MemberDeserialize thunk)
   *
   * What it does:
   * Forwards one serializer load callback lane to `CUnitRefuel::MemberDeserialize`.
   */
  [[maybe_unused]] void CUnitRefuelDeserializeThunkPrimary(
    moho::CUnitRefuel* const task,
    gpg::ReadArchive* const archive
  )
  {
    if (task != nullptr) {
      task->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x006224B0 (FUN_006224B0, CUnitRefuel::MemberDeserialize thunk)
   * Address: 0x0063A290 (FUN_0063A290)
   * Address: 0x0089BEA0 (FUN_0089BEA0)
   *
   * What it does:
   * Secondary load-callback forwarder to `CUnitRefuel::MemberDeserialize`.
   */
  [[maybe_unused]] void CUnitRefuelDeserializeThunkSecondary(
    moho::CUnitRefuel* const task,
    gpg::ReadArchive* const archive
  )
  {
    if (task != nullptr) {
      task->MemberDeserialize(archive);
    }
  }

  struct CUnitRefuelSerializerStartupNode
  {
    void* mVtable = nullptr;                    // +0x00
    gpg::SerHelperBase* mHelperNext = nullptr; // +0x04
    gpg::SerHelperBase* mHelperPrev = nullptr; // +0x08
    gpg::RType::load_func_t mLoad = nullptr;   // +0x0C
    gpg::RType::save_func_t mSave = nullptr;   // +0x10
  };

  static_assert(
    offsetof(CUnitRefuelSerializerStartupNode, mHelperNext) == 0x04,
    "CUnitRefuelSerializerStartupNode::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitRefuelSerializerStartupNode, mHelperPrev) == 0x08,
    "CUnitRefuelSerializerStartupNode::mHelperPrev offset must be 0x08"
  );
  static_assert(
    sizeof(CUnitRefuelSerializerStartupNode) == 0x14,
    "CUnitRefuelSerializerStartupNode size must be 0x14"
  );

  CUnitRefuelSerializerStartupNode gCUnitRefuelSerializerStartupNode{};

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(CUnitRefuelSerializerStartupNode& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(CUnitRefuelSerializerStartupNode& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitRefuel::sType = nullptr;

  /**
   * Address: 0x00620F30 (FUN_00620F30, ??0CUnitRefuel@Moho@@QAE@XZ)
   *
   * What it does:
   * Builds one default refuel-task lane with null target and cleared
   * reservation/carrier flags.
   */
  CUnitRefuel::CUnitRefuel()
    : CCommandTask()
    , mTargetUnit{}
    , mHasTransportReservation(false)
    , mIsCarrier(false)
    , mPad3A{}
  {
  }

  /**
   * Address: 0x00620F50 (FUN_00620F50, ??0CUnitRefuel@Moho@@QAE@@Z)
   */
  CUnitRefuel::CUnitRefuel(Unit* const targetUnit, IAiCommandDispatchImpl* const dispatchTask)
    : CCommandTask(static_cast<CCommandTask*>(dispatchTask))
    , mTargetUnit{}
    , mHasTransportReservation(false)
    , mIsCarrier(false)
    , mPad3A{}
  {
    mTargetUnit.ResetFromObject(targetUnit);

    if (mUnit != nullptr) {
      mUnit->UnitStateMask |= (1ull << UNITSTATE_Refueling);
      mUnit->UpdateSpeedThroughStatus();
    }

    Unit* const linkedTarget = mTargetUnit.GetObjectPtr();
    mIsCarrier = (linkedTarget != nullptr) && linkedTarget->IsInCategory("CARRIER");

    if (mUnit != nullptr && mUnit->AiNavigator != nullptr) {
      mUnit->AiNavigator->IgnoreFormation(true);
    }
  }

  /**
   * Address: 0x00621430 (FUN_00621430, cleanup_CUnitRefuelSerializerStartupThunkA)
   *
   * What it does:
   * Unlinks one startup helper lane for the `CUnitRefuel` serializer helper
   * node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CUnitRefuelSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(gCUnitRefuelSerializerStartupNode);
  }

  /**
   * Address: 0x00621460 (FUN_00621460, cleanup_CUnitRefuelSerializerStartupThunkB)
   *
   * What it does:
   * Unlinks the mirrored startup helper lane for the `CUnitRefuel` serializer
   * helper node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CUnitRefuelSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(gCUnitRefuelSerializerStartupNode);
  }

  /**
   * Address: 0x00621060 (FUN_00621060, ??1CUnitRefuel@Moho@@QAE@@Z)
   */
  CUnitRefuel::~CUnitRefuel()
  {
    mUnit->UnitStateMask &= ~(1ull << UNITSTATE_ForceSpeedThrough);
    mUnit->UnitStateMask &= ~(1ull << UNITSTATE_Refueling);
    mUnit->UpdateSpeedThroughStatus();

    if (mUnit->AiNavigator != nullptr) {
      mUnit->AiNavigator->IgnoreFormation(false);
    }

    Unit* const targetUnit = mTargetUnit.GetObjectPtr();
    if (mHasTransportReservation) {
      if (mUnit->UnitMotion != nullptr) {
        mUnit->UnitMotion->mHeight = std::numeric_limits<float>::infinity();
      }

      if (targetUnit != nullptr && !targetUnit->IsDead() && !mIsCarrier) {
        targetUnit->AiTransport->TransportRemovePickupUnit(mUnit, true);
      }
    }

    bool targetIsCarrier = false;
    if (targetUnit != nullptr && !targetUnit->IsDead()) {
      targetIsCarrier = targetUnit->IsInCategory("CARRIER");
    }

    if (targetIsCarrier) {
      targetUnit->AiTransport->TransportResetReservation();
    }

    *mDispatchResult = static_cast<EAiResult>(1);
    mTargetUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x00622680 (FUN_00622680, Moho::CUnitRefuel::MemberDeserialize)
   *
   * What it does:
   * Reads `CCommandTask` base state, then reads target weak pointer and
   * refuel-mode booleans from archive lanes.
   */
  void CUnitRefuel::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef baseRef{};
    archive->Read(CachedCCommandTaskType(), this, baseRef);

    const gpg::RRef targetRef{};
    archive->Read(CachedWeakPtrUnitType(), &mTargetUnit, targetRef);

    archive->ReadBool(&mHasTransportReservation);
    archive->ReadBool(&mIsCarrier);
  }

  /**
   * Address: 0x00622710 (FUN_00622710, Moho::CUnitRefuel::MemberSerialize)
   *
   * What it does:
   * Writes `CCommandTask` base state, then writes target weak pointer and
   * refuel-mode booleans into archive lanes.
   */
  void CUnitRefuel::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef baseRef{};
    archive->Write(CachedCCommandTaskType(), this, baseRef);

    const gpg::RRef targetRef{};
    archive->Write(CachedWeakPtrUnitType(), &mTargetUnit, targetRef);

    archive->WriteBool(mHasTransportReservation);
    archive->WriteBool(mIsCarrier);
  }

  /**
   * Address: 0x00621490 (FUN_00621490, ?TaskTick@CUnitRefuel@Moho@@UAE?AW4ETaskStatus@2@XZ)
   *
   * What it does:
   * Refuel/rearm state machine. See the header for the abort conditions; the
   * per-state behaviour is documented inline below.
   */
  int CUnitRefuel::Execute()
  {
    Unit* const unit = mUnit;
    if (unit->IsDead()) {
      return -1;
    }

    // Every remaining guard interrogates the *platform*, not the unit: a
    // platform that dies, lifts off, sets down, or picks up any command of its
    // own kills the refuel task of everything currently docked on it.
    Unit* const platform = mTargetUnit.GetObjectPtr();
    if (!platform || platform->IsDead()) {
      return -1;
    }

    if (platform->IsUnitState(UNITSTATE_MovingUp) || platform->IsUnitState(UNITSTATE_MovingDown)) {
      return -1;
    }

    if (!platform->IsIdleState()) {
      return -1;
    }

    if (platform->mCurrentLayer == LAYER_Seabed || platform->mCurrentLayer == LAYER_Sub) {
      // The platform submerged. This is the one abort path that releases an
      // already-attached unit before tearing the task down.
      if (unit->IsUnitState(UNITSTATE_Attached) && platform->AiTransport != nullptr) {
        platform->AiTransport->TransportDetachUnit(unit);
      }
      return -1;
    }

    IAiTransport* const transport = platform->AiTransport;

    if (mIsCarrier) {
      switch (mTaskState) {
      case TASKSTATE_Preparing:
        // Reserve a bay. Once the carrier confirms free storage the unit stops
        // speed-through flying and a dedicated carrier-land task takes over the
        // approach; otherwise keep steering at the carrier (unless the unit is
        // patrolling or guarding, where the refuel attempt is simply dropped).
        if (transport != nullptr && transport->TransportHasAvailableStorage()) {
          unit->UnitStateMask &= ~(1ull << UNITSTATE_ForceSpeedThrough);
          IAiCommandDispatchImpl::IssueCarrierLandTask(platform, this);
          mTaskState = NextTaskState(mTaskState);
          mHasTransportReservation = true;
          return 0;
        }

        if (unit->IsUnitState(UNITSTATE_Patrolling) || unit->IsUnitState(UNITSTATE_Guarding)) {
          return -1;
        }

        SteerTowardPlatform(*unit, *platform, true);
        return 10;

      case TASKSTATE_Waiting: {
        // Stowed inside the carrier. Wait for a full tank and full health, then
        // pop back out: the carrier hands back the launch transform, the unit is
        // snapped onto it, and it leaves along its own forward axis at the
        // blueprint's maximum airspeed.
        if (!unit->IsUnitState(UNITSTATE_Attached)) {
          return -1;
        }

        if (unit->FuelRatio <= kRefuelCompleteFuelRatio || unit->Health != unit->MaxHealth) {
          return 10;
        }

        VTransform launchTransform{Wm3::Vec3f{0.0f, 0.0f, 0.0f}, Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f}};
        if (transport != nullptr) {
          transport->TransportRemoveFromStorage(unit, launchTransform);
        }

        unit->SetPendingTransform(launchTransform, 1.0f);
        unit->AdvanceCoords();
        unit->AdvanceCoords();

        const Wm3::Vec3f launchDirection = OrientationForwardAxis(launchTransform.orient_);
        const float launchSpeed = unit->GetBlueprint()->Air.MaxAirspeed;
        const Wm3::Vec3f launchVelocity{
          launchDirection.x * launchSpeed,
          launchDirection.y * launchSpeed,
          launchDirection.z * launchSpeed
        };

        if (unit->UnitMotion != nullptr) {
          unit->UnitMotion->SetImmediateVelocity(launchVelocity, launchTransform.orient_);
        }

        mTaskState = NextTaskState(mTaskState);
        return 1;
      }

      case TASKSTATE_Starting:
        // Launched. Drop the refuel flag and, if the shared command still has
        // another aircraft waiting on this carrier, clear the deck by moving
        // off; otherwise just park where we are and end the task.
        unit->UnitStateMask &= ~(1ull << UNITSTATE_Refueling);

        if (unit->IsUnitState(UNITSTATE_Patrolling) || unit->IsUnitState(UNITSTATE_Guarding)) {
          return -1;
        }

        if (unit->CommandQueue != nullptr
            && CommandHasRefuellingAirUnit(unit->CommandQueue->GetCurrentCommand(), "CARRIER")) {
          SteerTowardPlatform(*unit, *platform, true);
          return 10;
        }

        SteerTowardPlatform(*unit, *platform, false);
        return -1;

      default:
        return 1;
      }
    }

    switch (mTaskState) {
    case TASKSTATE_Preparing:
      // Ask the pad for a landing slot. `-1` lets the platform pick the hook.
      if (transport != nullptr && transport->TransportAssignSlot(unit, -1)) {
        unit->UnitStateMask &= ~(1ull << UNITSTATE_ForceSpeedThrough);
        transport->TransportAtPickupPosition();
        mTaskState = NextTaskState(mTaskState);
        mHasTransportReservation = true;
        return 0;
      }

      if (unit->IsUnitState(UNITSTATE_Patrolling) || unit->IsUnitState(UNITSTATE_Guarding)) {
        return -1;
      }

      SteerTowardPlatform(*unit, *platform, true);
      return 10;

    case TASKSTATE_Waiting: {
      // Slot granted: fly to the attach bone and adopt its height and facing.
      if (!transport) {
        return -1;
      }

      const Wm3::Vec3f attachPosition = transport->TransportGetAttachBonePosition(unit);
      const Wm3::Vec3f attachFacing = transport->TransportGetAttachFacing(unit);
      if (!IsValidVector3f(attachPosition)) {
        return -1;
      }

      SNavGoal goal = SingleCellGoalAt(attachPosition, unit->GetFootprint());
      goal.mLayer = LAYER_Land;
      NewMoveTask(goal, this, 0, nullptr, 0);

      if (unit->UnitMotion != nullptr) {
        unit->UnitMotion->mHeight = attachPosition.y;
        unit->UnitMotion->SetFacing(attachFacing);
      }

      mTaskState = NextTaskState(mTaskState);
      return 1;
    }

    case TASKSTATE_Starting: {
      // Hovering over the bone. Keep turning until the unit's forward axis is
      // aligned with the attach facing (ground units are exempt), then stop
      // steering, release the height hold, and let the pad take the unit.
      if (!transport) {
        return -1;
      }

      const Wm3::Vec3f attachFacing = transport->TransportGetAttachFacing(unit);
      if (unit->UnitMotion != nullptr) {
        unit->UnitMotion->SetFacing(attachFacing);
      }

      const float alignment = DotProduct(attachFacing, OrientationForwardAxis(unit->GetTransform().orient_));
      if (alignment > kAttachFacingAlignment || unit->mCurrentLayer == LAYER_Land) {
        if (unit->UnitMotion != nullptr) {
          unit->UnitMotion->SetFacing(Wm3::Vec3f{0.0f, 0.0f, 0.0f});
          unit->UnitMotion->mHeight = std::numeric_limits<float>::infinity();
        }

        if (transport->TransportAttachUnit(unit)) {
          mTaskState = NextTaskState(mTaskState);
          mHasTransportReservation = false;
        }
      }
      return 1;
    }

    case TASKSTATE_Processing:
      // Docked and refuelling. This is the only place the engine undocks a
      // repaired, refuelled aircraft: once both conditions hold the pad
      // detaches it and a move task lifts it back into the air layer.
      if (unit->FuelRatio > kRefuelCompleteFuelRatio && unit->Health == unit->MaxHealth) {
        if (transport != nullptr) {
          transport->TransportDetachUnit(unit);
        }

        SNavGoal goal = SingleCellGoalAt(unit->GetPosition(), unit->GetFootprint());
        goal.mLayer = LAYER_Air;
        NewMoveTask(goal, this, 0, nullptr, 0);
        mTaskState = NextTaskState(mTaskState);
      }
      return 10;

    case TASKSTATE_Complete:
      // Airborne again. Drop the refuel flag, and if the shared dock command
      // still lists another refuelling aircraft, vacate the pad for it.
      unit->UnitStateMask &= ~(1ull << UNITSTATE_Refueling);

      if (unit->IsUnitState(UNITSTATE_Patrolling) || unit->IsUnitState(UNITSTATE_Guarding)) {
        return -1;
      }

      if (unit->CommandQueue != nullptr && unit->CommandQueue->GetNextCommand() != nullptr
          && CommandHasRefuellingAirUnit(unit->CommandQueue->GetCurrentCommand(), "AIRSTAGINGPLATFORM")) {
        SteerTowardPlatform(*unit, *platform, true);
        return 10;
      }

      SteerTowardPlatform(*unit, *platform, false);
      return -1;

    default:
      return 1;
    }
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006224D0 (FUN_006224D0, gpg::RRef_CUnitRefuel)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitRefuel*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitRefuel(gpg::RRef* const outRef, moho::CUnitRefuel* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitRefuelType());
    return outRef;
  }
} // namespace gpg
