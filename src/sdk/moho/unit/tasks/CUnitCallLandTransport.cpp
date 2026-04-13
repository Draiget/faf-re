#include "moho/unit/tasks/CUnitCallLandTransport.h"

#include <cmath>
#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/IAiTransport.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/math/QuaternionMath.h"
#include "moho/path/SNavGoal.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskCallLandTransportPending = 0x0000000000000100ull;
  constexpr std::uint64_t kUnitStateMaskWaitingForTransport = 0x0000000000000080ull;
  constexpr std::uint64_t kUnitStateMaskTeleporting = 0x0000000000080000ull;
  constexpr float kPi = 3.1415927f;
  constexpr std::int16_t kInvalidCellPosComponent = static_cast<std::int16_t>(0x8000);

  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState state) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<std::int32_t>(state) + 1);
  }

  [[nodiscard]] bool IsValidCellPos(const moho::SOCellPos& cellPos) noexcept
  {
    return cellPos.x != kInvalidCellPosComponent && cellPos.z != kInvalidCellPosComponent;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCallLandTransportType()
  {
    gpg::RType* type = moho::CUnitCallLandTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallLandTransport));
      moho::CUnitCallLandTransport::sType = type;
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
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVTransformType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::VTransform));
    }
    return cached;
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
  gpg::RType* CUnitCallLandTransport::sType = nullptr;

  /**
   * Address: 0x006003F0 (FUN_006003F0, ??1CUnitCallLandTransport@Moho@@QAE@@Z)
   *
   * What it does:
   * Tears down transport-call state, clears owner-unit transport flags,
   * finalizes dispatch result, and unlinks the target transport weak pointer.
   */
  CUnitCallLandTransport::~CUnitCallLandTransport()
  {
    if (mIsOccupying) {
      mUnit->FreeOgridRect();
      mIsOccupying = false;
    }

    mUnit->UnitStateMask &= ~kUnitStateMaskCallLandTransportPending;
    mUnit->UnitStateMask &= ~kUnitStateMaskWaitingForTransport;

    if (!mHasBeamupDestination) {
      if (mUnit->IsUnitState(UNITSTATE_Teleporting)) {
        (void)mUnit->RunScript("OnStopTransportBeamUp");
        mUnit->UnitStateMask &= ~kUnitStateMaskTeleporting;
      }

      if (CUnitMotion* const unitMotion = mUnit->UnitMotion; unitMotion != nullptr && mBeamupTime < 10.0f) {
        unitMotion->NotifyDetached(static_cast<Entity*>(mUnit), false);
      }

      Unit* const transportUnit = mTargetTransportUnit.GetObjectPtr();
      if (transportUnit != nullptr && transportUnit->AiTransport != nullptr && !transportUnit->IsDead()) {
        transportUnit->AiTransport->TransportRemovePickupUnit(mUnit, true);
      }
    }

    *mDispatchResult = static_cast<EAiResult>(2 - static_cast<int>(mHasBeamupDestination));
    mTargetTransportUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x00600880 (FUN_00600880, Moho::CUnitCallLandTransport::TaskTick)
   *
   * What it does:
   * Runs land-transport call task state transitions from pickup assignment,
   * through beam-up alignment, to final transport attach completion.
   */
  int CUnitCallLandTransport::Execute()
  {
    if (mUnit->IsDead()) {
      return -1;
    }

    if (mUnit->UnitMotion == nullptr) {
      return -1;
    }

    Unit* const transportUnit = mTargetTransportUnit.GetObjectPtr();
    if (transportUnit == nullptr || transportUnit->IsDead()) {
      return -1;
    }

    if (mTaskState != TASKSTATE_Preparing && !transportUnit->IsUnitState(UNITSTATE_TransportLoading)) {
      return -1;
    }

    IAiTransport* const transport = transportUnit->AiTransport;
    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        const bool transportLoading = transportUnit->IsUnitState(UNITSTATE_TransportLoading);
        const bool commandHeadsMatch =
          transportUnit->CommandQueue->GetCurrentCommand() == mUnit->CommandQueue->GetCurrentCommand();
        const bool transportAssistMoving = transportUnit->IsUnitState(UNITSTATE_AssistMoving);
        if (transportLoading && (commandHeadsMatch || transportAssistMoving)) {
          mTaskState = NextTaskState(mTaskState);
          return 3;
        }
        return 10;
      }

      case TASKSTATE_Waiting: {
        if (!transport->TransportIsUnitAssignedForPickup(mUnit)) {
          return -1;
        }

        mUnit->UnitStateMask |= kUnitStateMaskWaitingForTransport;
        if (transport->TransportIsReadyForUnit(mUnit)) {
          SOCellPos pickupCell = transportUnit->GetFootprint().ToCellPos(transportUnit->GetPosition());

          bool hasMeleeSpace = false;
          if (transportUnit->IsMobile()) {
            const SFootprint& transportFootprint = transportUnit->GetFootprint();
            std::uint8_t transportSize = transportFootprint.mSizeZ;
            if (transportFootprint.mSizeX > transportFootprint.mSizeZ) {
              transportSize = transportFootprint.mSizeX;
            }

            if (transportSize > 1u) {
              hasMeleeSpace = mUnit->HasMeleeSpaceAroundLargeTarget(transportUnit, &pickupCell, 1);
            } else {
              hasMeleeSpace = mUnit->HasMeleeSpaceAroundSmallTarget(transportUnit, &pickupCell);
            }
          } else {
            hasMeleeSpace = mUnit->HasMeleeSpaceAroundSmallTarget(transportUnit, &pickupCell);
          }

          if (!hasMeleeSpace || !IsValidCellPos(pickupCell)) {
            return -1;
          }

          const Wm3::Vector3f pickupWorldPos = COORDS_ToWorldPos(mSim->mMapData, pickupCell, mUnit->GetFootprint());
          const SCoordsVec2 pickupPosXZ{pickupWorldPos.x, pickupWorldPos.z};
          gpg::Rect2i pickupRect{};
          (void)COORDS_ToGridRect(&pickupRect, pickupPosXZ, mUnit->GetFootprint());
          mUnit->ReserveOgridRect(pickupRect);
          mTaskState = NextTaskState(mTaskState);
          mIsOccupying = true;
          NewMoveTask(SNavGoal(pickupCell), this, 0, nullptr, 0);
        }
        return 10;
      }

      case TASKSTATE_Starting: {
        if (transport->TransportIsReadyForUnit(mUnit)) {
          static constexpr Wm3::Vector3f kZeroFacing{0.0f, 0.0f, 0.0f};
          mUnit->UnitMotion->SetFacing(kZeroFacing);
          mUnit->UnitMotion->mHeight = std::numeric_limits<float>::infinity();

          mSourceTransform = mUnit->GetTransform();
          mDestinationTransform = transport->TransportGetAttachBoneTransform(mUnit);
          mUnit->StartTransportBeamUp(mTargetTransportUnit, transport->TransportGetAttachBone(mUnit));
          mUnit->UnitStateMask |= kUnitStateMaskTeleporting;
          mTaskState = NextTaskState(mTaskState);
        }
        return 1;
      }

      case TASKSTATE_Processing: {
        if (mBeamupTime > 1.0f) {
          const float blend = (std::cos(mBeamupTime * kPi * 0.1f) * 0.5f) + 0.5f;
          mDestinationTransform = transport->TransportGetAttachBoneTransform(mUnit);
          if (const RUnitBlueprint* const blueprint = mUnit->GetBlueprint(); blueprint != nullptr) {
            mDestinationTransform.pos_.y -= blueprint->mSizeY;
          }

          VTransform interpolated{};
          interpolated.pos_.x =
            mSourceTransform.pos_.x + ((mDestinationTransform.pos_.x - mSourceTransform.pos_.x) * blend);
          interpolated.pos_.y =
            mSourceTransform.pos_.y + ((mDestinationTransform.pos_.y - mSourceTransform.pos_.y) * blend);
          interpolated.pos_.z =
            mSourceTransform.pos_.z + ((mDestinationTransform.pos_.z - mSourceTransform.pos_.z) * blend);
          (void)SLERP(&mDestinationTransform.orient_, &mSourceTransform.orient_, &interpolated.orient_, blend);

          mUnit->SetPendingTransform(interpolated, 1.0f);
          mUnit->AdvanceCoords();
          mBeamupTime -= 1.0f;
          return 1;
        }

        (void)mUnit->RunScript("OnStopTransportBeamUp");
        mUnit->UnitStateMask &= ~kUnitStateMaskTeleporting;
        if (transport->TransportAttachUnit(mUnit)) {
          mHasBeamupDestination = true;
        }
        return -1;
      }

      default:
        return 1;
    }
  }

  /**
   * Address: 0x00600250 (FUN_00600250)
   *
   * What it does:
   * Initializes detached land-transport-call task state with identity
   * transforms and cleared weak-pointer/flag lanes.
   */
  CUnitCallLandTransport::CUnitCallLandTransport()
    : CCommandTask()
  {
    mTargetTransportUnit.ownerLinkSlot = nullptr;
    mTargetTransportUnit.nextInOwner = nullptr;
    mBeamupTime = 0.0f;
    mSourceTransform.orient_ = Wm3::Quatf::Identity();
    mSourceTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
    mDestinationTransform.orient_ = Wm3::Quatf::Identity();
    mDestinationTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
    mHasBeamupDestination = false;
    mIsOccupying = false;
  }

  /**
   * Address: 0x006002D0 (FUN_006002D0, Moho::CUnitCallLandTransport::CUnitCallLandTransport)
   *
   * What it does:
   * Initializes one parent-linked land-transport task, binds target transport
   * weak pointer, snapshots source/destination transforms, and sets owner-unit
   * transport-pending state.
   */
  CUnitCallLandTransport::CUnitCallLandTransport(CCommandTask* const parentTask, Unit* const transportUnit)
    : CCommandTask(parentTask)
  {
    mTargetTransportUnit.BindObjectUnlinked(transportUnit);
    (void)mTargetTransportUnit.LinkIntoOwnerChainHeadUnlinked();
    mBeamupTime = 10.0f;

    const VTransform& sourceTransform = transportUnit->GetTransform();
    mSourceTransform = sourceTransform;

    const VTransform& destinationTransform = transportUnit->GetTransform();
    mDestinationTransform = destinationTransform;

    mHasBeamupDestination = false;
    mIsOccupying = false;

    mUnit->UnitStateMask |= kUnitStateMaskCallLandTransportPending;
    if (mUnit->IsUnitState(UNITSTATE_WaitForFerry)) {
      mTaskState = TASKSTATE_Waiting;
    }
  }

  /**
   * Address: 0x00603AB0 (FUN_00603AB0)
   *
   * What it does:
   * Loads base command-task state plus land-transport serialization fields.
   */
  void CUnitCallLandTransport::MemberDeserialize(
    gpg::ReadArchive* const archive,
    CUnitCallLandTransport* const task,
    int,
    gpg::RRef*
  )
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (!archive || !task) {
      return;
    }

    gpg::RRef nullOwner{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(task), nullOwner);
    archive->Read(CachedWeakPtrUnitType(), &task->mTargetTransportUnit, nullOwner);
    archive->ReadBool(&task->mHasBeamupDestination);
    archive->ReadFloat(&task->mBeamupTime);
    archive->Read(CachedVTransformType(), &task->mSourceTransform, nullOwner);
    archive->Read(CachedVTransformType(), &task->mDestinationTransform, nullOwner);
    archive->ReadBool(&task->mIsOccupying);
  }

  /**
   * Address: 0x00603BC0 (FUN_00603BC0)
   *
   * What it does:
   * Saves base command-task state plus land-transport serialization fields.
   */
  void CUnitCallLandTransport::MemberSerialize(
    gpg::WriteArchive* const archive,
    const CUnitCallLandTransport* const task,
    int,
    gpg::RRef*
  )
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (!archive || !task) {
      return;
    }

    gpg::RRef nullOwner{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(task), nullOwner);
    archive->Write(CachedWeakPtrUnitType(), &task->mTargetTransportUnit, nullOwner);
    archive->WriteBool(task->mHasBeamupDestination);
    archive->WriteFloat(task->mBeamupTime);
    archive->Write(CachedVTransformType(), &task->mSourceTransform, nullOwner);
    archive->Write(CachedVTransformType(), &task->mDestinationTransform, nullOwner);
    archive->WriteBool(task->mIsOccupying);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00603380 (FUN_00603380, gpg::RRef_CUnitCallLandTransport)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitCallLandTransport*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitCallLandTransport(gpg::RRef* const outRef, moho::CUnitCallLandTransport* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitCallLandTransportType());
    return outRef;
  }
} // namespace gpg
