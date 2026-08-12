#include "moho/unit/tasks/CUnitCarrierLand.h"

#include <cstdint>
#include <limits>

#include "moho/ai/CAiBrain.h"
#include "moho/ai/IAiTransport.h"
#include "moho/path/SNavGoal.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/SFootprint.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace
{
  // Distance added to the reservation's drop index when placing the standoff
  // point the flyer approaches from, in world units.
  constexpr float kApproachStandoffPadding = 20.0f;

  // `EUnitMotionCarrierEvent` is an opaque reflected enum in this tree (the
  // binary registers only its size, never enumerator names), so the two values
  // the landing sequence drives are spelled as named constants — matching the
  // `kUnitMotionCarrierEventRelativeHeight` lane CUnitMotion::GetElevation
  // already reads.
  constexpr moho::EUnitMotionCarrierEvent kCarrierEventHoldRelativeHeight =
    static_cast<moho::EUnitMotionCarrierEvent>(1);
  constexpr moho::EUnitMotionCarrierEvent kCarrierEventDescendToDeck =
    static_cast<moho::EUnitMotionCarrierEvent>(2);

  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState state) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<std::int32_t>(state) + 1);
  }

  /**
   * Queues a single-cell move onto `worldPos`, measured with the moving unit's
   * own footprint. `layer` is `LAYER_None` for the approach leg (the navigator
   * keeps the unit in whatever layer it is already flying in) and `LAYER_Land`
   * for the final descent onto the deck.
   */
  void QueueMoveOnto(
    moho::CCommandTask& task,
    moho::Unit& unit,
    const Wm3::Vec3f& worldPos,
    const moho::ELayer layer
  )
  {
    moho::SNavGoal goal{unit.GetFootprint().ToCellPos(worldPos)};
    goal.mLayer = layer;
    moho::NewMoveTask(goal, &task, 0, nullptr, 0);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00607B50 (FUN_00607B50, Moho::CUnitCarrierLandTypeInfo::NewRef)
   * Address: 0x00607C30 (FUN_00607C30, Moho::CUnitCarrierLandTypeInfo::CtrRef)
   *
   * What it does:
   * Builds one unbound carrier-land task: base command task with null unit /
   * sim lanes plus a zeroed reservation payload. Both reflection construction
   * entry points inline this body in the binary.
   */
  CUnitCarrierLand::CUnitCarrierLand()
    : CCommandTask()
    , mTargetCarrier{}
    , mHasLoadedIntoCarrier(false)
    , mPad39_3B{}
    , mReservationResult(0)
    , mCarrierHeight(0.0f)
    , mCarrierAttachPos{0.0f, 0.0f, 0.0f}
    , mCarrierAttachDir{0.0f, 0.0f, 0.0f}
    , mCarrierApproachPos{0.0f, 0.0f, 0.0f}
  {
  }

  /**
   * Address: 0x00606500 (FUN_00606500, ??0CUnitCarrierLand@Moho@@QAE@@Z)
   *
   * What it does:
   * See the header. The binary inlines `Unit::SetFocusEntity`; the recovered
   * form calls it, which performs the same rebind + `OnAssignedFocusEntity`
   * dispatch + sync-dirty flag.
   */
  CUnitCarrierLand::CUnitCarrierLand(CCommandTask* const parentTask, Unit* const carrier)
    : CCommandTask(parentTask)
    , mTargetCarrier{}
    , mHasLoadedIntoCarrier(false)
    , mPad39_3B{}
    , mReservationResult(0)
    , mCarrierHeight(0.0f)
    , mCarrierAttachPos{0.0f, 0.0f, 0.0f}
    , mCarrierAttachDir{0.0f, 0.0f, 0.0f}
    , mCarrierApproachPos{0.0f, 0.0f, 0.0f}
  {
    mTargetCarrier.ResetFromObject(carrier);

    mUnit->UnitStateMask |= (1ull << UNITSTATE_TransportLoading);
    mUnit->SetFocusEntity(mTargetCarrier.GetObjectPtr());
  }

  /**
   * Address: 0x006067A0 (FUN_006067A0, ?TaskTick@CUnitCarrierLand@Moho@@UAE?AW4ETaskStatus@2@XZ)
   *
   * What it does:
   * See the header; the per-state behaviour is documented inline.
   */
  int CUnitCarrierLand::Execute()
  {
    Unit* const unit = mUnit;
    if (unit->IsDead()) {
      return -1;
    }

    CUnitMotion* const motion = unit->UnitMotion;
    if (!motion) {
      return -1;
    }

    Unit* const carrier = mTargetCarrier.GetObjectPtr();
    if (!carrier || carrier->IsDead()) {
      return -1;
    }

    if (unit->IsUnitState(UNITSTATE_Refueling)) {
      // Auto-refuel landings only proceed while the carrier is parked: it must
      // be idle and neither surfacing nor diving.
      if (!carrier->IsIdleState() || carrier->IsUnitState(UNITSTATE_MovingUp)
          || carrier->IsUnitState(UNITSTATE_MovingDown)) {
        return -1;
      }
    } else if (mTaskState >= TASKSTATE_Waiting && !carrier->IsUnitState(UNITSTATE_TransportLoading)) {
      // Ordered landings past the reservation step require the carrier to keep
      // holding its side of the load handshake.
      return -1;
    }

    IAiTransport* const transport = carrier->AiTransport;

    switch (mTaskState) {
    case TASKSTATE_Preparing: {
      // Claim a bay. The carrier answers with the attach point, the attach
      // facing, and the height to hold above it; the int result is the bay's
      // queue distance, which sets how far back the approach starts.
      if (!transport || !transport->TransportHasAvailableStorage()) {
        if (unit->ArmyRef != nullptr) {
          if (CAiBrain* const brain = unit->ArmyRef->GetArmyBrain(); brain != nullptr) {
            (void)brain->RunScript("OnTransportFull");
          }
        }
        return -1;
      }

      mReservationResult =
        transport->TransportReserveStorage(unit, mCarrierAttachPos, mCarrierAttachDir, mCarrierHeight);

      // Flatten the attach facing into the horizontal plane before using it to
      // walk the standoff point back from the attach point.
      mCarrierAttachDir.y = 0.0f;
      (void)mCarrierAttachDir.Normalize();

      const float standoff = static_cast<float>(mReservationResult) + kApproachStandoffPadding;
      mCarrierApproachPos.x = mCarrierAttachPos.x - (mCarrierAttachDir.x * standoff);
      mCarrierApproachPos.y = mCarrierAttachPos.y - (mCarrierAttachDir.y * standoff);
      mCarrierApproachPos.z = mCarrierAttachPos.z - (mCarrierAttachDir.z * standoff);

      mTaskState = NextTaskState(mTaskState);
      return 1;
    }

    case TASKSTATE_Waiting:
      // Fly to the standoff point on the attach heading, holding the reserved
      // height relative to the carrier.
      QueueMoveOnto(*this, *unit, mCarrierApproachPos, LAYER_None);
      motion->SetFacing(mCarrierAttachDir);
      motion->mCarrierEvent = kCarrierEventHoldRelativeHeight;
      motion->mHeight = mCarrierAttachPos.y;
      mTaskState = NextTaskState(mTaskState);
      return 0;

    case TASKSTATE_Starting: {
      // Hold while a submerged carrier surfaces; the deck height is not known
      // until it is on the surface.
      if (carrier->mCurrentLayer == LAYER_Sub || carrier->mCurrentLayer == LAYER_Seabed) {
        return 5;
      }

      const float carrierY = carrier->GetPosition().y;
      const int reservationDelay = mReservationResult;
      mTaskState = NextTaskState(mTaskState);
      mCarrierAttachPos.y = carrierY + mCarrierHeight;
      // Later bays in the queue wait proportionally longer before descending.
      return (reservationDelay != 0) ? reservationDelay : 1;
    }

    case TASKSTATE_Processing:
      // Descend onto the attach point itself.
      QueueMoveOnto(*this, *unit, mCarrierAttachPos, LAYER_Land);
      motion->mHeight = mCarrierAttachPos.y;
      motion->mCarrierEvent = kCarrierEventDescendToDeck;
      mTaskState = NextTaskState(mTaskState);
      return 0;

    case TASKSTATE_Complete:
      // On the deck: release the height hold and hand the unit over. The task
      // ends here, and `mHasLoadedIntoCarrier` tells the destructor the landing
      // succeeded so it must not undo the reservation.
      motion->mHeight = std::numeric_limits<float>::infinity();
      if (transport != nullptr) {
        transport->TransportAddToStorage(unit);
      }
      mHasLoadedIntoCarrier = true;
      return -1;

    default:
      return 1;
    }
  }
} // namespace moho
