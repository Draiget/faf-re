#include "moho/unit/tasks/CUnitCallTransport.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Logging.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/IAiTransport.h"
#include "moho/math/QuaternionMath.h"
#include "moho/path/SNavGoal.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskCallTransportPending = 0x0000000000000100ull;
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

  [[nodiscard]] float HorizontalDistanceXZ(const Wm3::Vector3f& lhs, const Wm3::Vector3f& rhs) noexcept
  {
    const float dx = lhs.x - rhs.x;
    const float dz = lhs.z - rhs.z;
    return std::sqrt((dx * dx) + (dz * dz));
  }

  [[nodiscard]]
  Wm3::Quaternionf QuatLerpShortestPathNormalized(const Wm3::Quaternionf& target, const Wm3::Quaternionf& source, const float alpha)
    noexcept
  {
    float clamped = alpha;
    if (clamped > 1.0f) {
      clamped = 1.0f;
    } else if (clamped < 0.0f) {
      clamped = 0.0f;
    }

    if (moho::QuatsNearEqual(source, target)) {
      return source;
    }

    Wm3::Quaternionf signedTarget = target;
    const float dot =
      (source.x * target.x) + (source.y * target.y) + (source.z * target.z) + (source.w * target.w);
    if (dot < 0.0f) {
      signedTarget.x = -signedTarget.x;
      signedTarget.y = -signedTarget.y;
      signedTarget.z = -signedTarget.z;
      signedTarget.w = -signedTarget.w;
    }

    const float inverse = 1.0f - clamped;
    Wm3::Quaternionf blend{};
    blend.x = (source.x * inverse) + (signedTarget.x * clamped);
    blend.y = (source.y * inverse) + (signedTarget.y * clamped);
    blend.z = (source.z * inverse) + (signedTarget.z * clamped);
    blend.w = (source.w * inverse) + (signedTarget.w * clamped);
    moho::NormalizeQuatInPlace(&blend);
    return blend;
  }

  [[nodiscard]] const char* BlueprintIdOrUnknown(const moho::Unit* const unit) noexcept
  {
    if (!unit) {
      return "<unknown>";
    }

    const moho::RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (!blueprint) {
      return "<unknown>";
    }

    return blueprint->mBlueprintId.c_str();
  }

  [[nodiscard]] gpg::RType* CachedCUnitCallTransportType()
  {
    gpg::RType* type = moho::CUnitCallTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallTransport));
      moho::CUnitCallTransport::sType = type;
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
  gpg::RType* CUnitCallTransport::sType = nullptr;

  /**
   * Address: 0x005FF7F0 (FUN_005FF7F0, Moho::CUnitCallTransport::~CUnitCallTransport)
   *
   * What it does:
   * Tears down transport-call state, clears owner-unit transport flags,
   * finalizes dispatch result, and unlinks the target transport weak pointer.
   */
  CUnitCallTransport::~CUnitCallTransport()
  {
    mUnit->UnitStateMask &= ~kUnitStateMaskCallTransportPending;
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
   * Address: 0x005FFC70 (FUN_005FFC70, Moho::CUnitCallTransport::TaskTick)
   *
   * What it does:
   * Runs transport-call state transitions from pickup staging through beamup
   * interpolation and final transport attach handoff.
   */
  int CUnitCallTransport::Execute()
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
        const bool transportReadyToLoad =
          transportUnit->IsUnitState(UNITSTATE_TransportLoading) && !transportUnit->IsUnitState(UNITSTATE_HoldingPattern);
        const bool commandHeadsMatch =
          transportUnit->CommandQueue->GetCurrentCommand() == mUnit->CommandQueue->GetCurrentCommand();
        const bool transportAssistMoving = transportUnit->IsUnitState(UNITSTATE_AssistMoving);
        if (transportReadyToLoad && (commandHeadsMatch || transportAssistMoving)) {
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
        const SOCellPos targetCell =
          transport->TransportIsReadyForUnit(mUnit) ? transport->TransportGetAttachPosition(mUnit)
                                                    : transport->TransportGetPickupUnitPos(mUnit);
        if (!IsValidCellPos(targetCell)) {
          return -1;
        }

        mTaskState = NextTaskState(mTaskState);
        NewMoveTask(SNavGoal(targetCell), this, 0, nullptr, 0);
        return 1;
      }

      case TASKSTATE_Starting: {
        if (!transport->TransportIsReadyForUnit(mUnit)) {
          return 1;
        }

        const Wm3::Vector3f attachBonePosition = transport->TransportGetAttachBonePosition(mUnit);
        const float distanceToAttachPoint = HorizontalDistanceXZ(mUnit->GetPosition(), attachBonePosition);

        const SFootprint& transportFootprint = transportUnit->GetFootprint();
        const float transportExtent =
          static_cast<float>(std::max(transportFootprint.mSizeX, transportFootprint.mSizeZ));
        if (distanceToAttachPoint <= (transportExtent * 2.0f)) {
          static constexpr Wm3::Vector3f kZeroFacing{0.0f, 0.0f, 0.0f};
          mUnit->UnitMotion->SetFacing(kZeroFacing);
          mUnit->UnitMotion->mHeight = std::numeric_limits<float>::infinity();

          mSourceTransform = mUnit->GetTransform();
          mDestinationTransform = transport->TransportGetAttachBoneTransform(mUnit);
          mUnit->StartTransportBeamUp(mTargetTransportUnit, transport->TransportGetAttachBone(mUnit));
          mUnit->UnitStateMask |= kUnitStateMaskTeleporting;
          mTaskState = NextTaskState(mTaskState);
          return 1;
        }

        if (++mArrivalTickOrSequence > 5) {
          return -1;
        }

        mTaskState = static_cast<ETaskState>(static_cast<std::int32_t>(mTaskState) - 1);
        return 0;
      }

      case TASKSTATE_Processing: {
        if (mBeamupTime <= 1.0f) {
          (void)mUnit->RunScript("OnStopTransportBeamUp");
          mUnit->UnitStateMask &= ~kUnitStateMaskTeleporting;
          if (transport->TransportAttachUnit(mUnit)) {
            mHasBeamupDestination = true;
          }
          return -1;
        }

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
        interpolated.orient_ =
          QuatLerpShortestPathNormalized(mDestinationTransform.orient_, mSourceTransform.orient_, blend);

        mUnit->SetPendingTransform(interpolated, 1.0f);
        mUnit->AdvanceCoords();
        mBeamupTime -= 1.0f;
        return 1;
      }

      default:
        return 1;
    }
  }

  /**
   * Address: 0x005FF650 (FUN_005FF650)
   *
   * What it does:
   * Initializes detached transport-call task state with identity transforms
   * and cleared weak-pointer/flag lanes.
   */
  CUnitCallTransport::CUnitCallTransport()
    : CCommandTask()
  {
    mTargetTransportUnit.ownerLinkSlot = nullptr;
    mTargetTransportUnit.nextInOwner = nullptr;
    mHasBeamupDestination = false;
    mBeamupTime = 0.0f;
    mSourceTransform.orient_ = Wm3::Quatf::Identity();
    mSourceTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
    mDestinationTransform.orient_ = Wm3::Quatf::Identity();
    mDestinationTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
    mArrivalTickOrSequence = 0;
  }

  /**
   * Address: 0x005FF6D0 (FUN_005FF6D0, Moho::CUnitCallTransport::CUnitCallTransport)
   *
   * What it does:
   * Initializes one parent-linked call-transport task, binds the target
   * transport weak pointer, snapshots transport transform lanes, and sets
   * owner-unit transport-pending state.
   */
  CUnitCallTransport::CUnitCallTransport(CCommandTask* const parentTask, Unit* const transportUnit)
    : CCommandTask(parentTask)
  {
    mTargetTransportUnit.BindObjectUnlinked(transportUnit);
    (void)mTargetTransportUnit.LinkIntoOwnerChainHeadUnlinked();
    mHasBeamupDestination = false;
    mBeamupTime = 10.0f;

    if (transportUnit != nullptr) {
      const VTransform& transform = transportUnit->GetTransform();
      mSourceTransform = transform;
      mDestinationTransform = transform;
    } else {
      mSourceTransform.orient_ = Wm3::Quatf::Identity();
      mSourceTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
      mDestinationTransform.orient_ = Wm3::Quatf::Identity();
      mDestinationTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
    }

    mArrivalTickOrSequence = 0;

    if (mUnit != nullptr) {
      mUnit->UnitStateMask |= kUnitStateMaskCallTransportPending;
      if (mUnit->IsUnitState(UNITSTATE_WaitForFerry)) {
        mTaskState = TASKSTATE_Waiting;
      }
    }
  }

  /**
   * Address: 0x00603890 (FUN_00603890)
   *
   * What it does:
   * Loads base command-task state, transport weak pointer, beamup flags, and
   * two transform lanes for one `CUnitCallTransport` object.
   */
  void CUnitCallTransport::MemberDeserialize(
    gpg::ReadArchive* const archive,
    CUnitCallTransport* const task,
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
    archive->ReadInt(&task->mArrivalTickOrSequence);
  }

  /**
   * Address: 0x006039A0 (FUN_006039A0)
   *
   * What it does:
   * Saves base command-task state, transport weak pointer, beamup flags, and
   * two transform lanes for one `CUnitCallTransport` object.
   */
  void CUnitCallTransport::MemberSerialize(
    gpg::WriteArchive* const archive,
    const CUnitCallTransport* const task,
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
    archive->WriteInt(task->mArrivalTickOrSequence);
  }

  /**
   * Address: 0x00602C80 (FUN_00602C80)
   *
   * What it does:
   * Preserves one deserialize callback thunk lane for call-transport task
   * serializer registration.
   */
  [[maybe_unused]] void CUnitCallTransportMemberDeserializeAdapterLaneA(
    gpg::ReadArchive* const archive,
    CUnitCallTransport* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTransport::MemberDeserialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x00602C90 (FUN_00602C90)
   *
   * What it does:
   * Preserves one serialize callback thunk lane for call-transport task
   * serializer registration.
   */
  [[maybe_unused]] void CUnitCallTransportMemberSerializeAdapterLaneA(
    gpg::WriteArchive* const archive,
    const CUnitCallTransport* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTransport::MemberSerialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x00603060 (FUN_00603060)
   *
   * What it does:
   * Alternate deserialize callback thunk lane for call-transport task
   * serializer registration.
   */
  [[maybe_unused]] void CUnitCallTransportMemberDeserializeAdapterLaneB(
    gpg::ReadArchive* const archive,
    CUnitCallTransport* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTransport::MemberDeserialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x00603070 (FUN_00603070)
   *
   * What it does:
   * Alternate serialize callback thunk lane for call-transport task serializer
   * registration.
   */
  [[maybe_unused]] void CUnitCallTransportMemberSerializeAdapterLaneB(
    gpg::WriteArchive* const archive,
    const CUnitCallTransport* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTransport::MemberSerialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x005FFBB0 (FUN_005FFBB0, Moho::NewCallTransportCommand)
   *
   * What it does:
   * Validates one candidate transport and allocates a call-transport task when
   * legal, otherwise emits an illegal-transport warning.
   */
  void NewCallTransportCommand(CCommandTask* const parentTask, Unit* const transportUnit)
  {
    if (!transportUnit || transportUnit->IsDead()) {
      return;
    }

    if (transportUnit->AiTransport != nullptr) {
      (void)new (std::nothrow) CUnitCallTransport(parentTask, transportUnit);
      return;
    }

    gpg::Warnf("Attepted to call illegal transport %s", BlueprintIdOrUnknown(transportUnit));
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006031D0 (FUN_006031D0, gpg::RRef_CUnitCallTransport)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitCallTransport*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitCallTransport(gpg::RRef* const outRef, moho::CUnitCallTransport* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitCallTransportType());
    return outRef;
  }

  /**
   * Address: 0x00602FA0 (FUN_00602FA0)
   *
   * What it does:
   * Materializes one `RRef_CUnitCallTransport` result into a stack local and
   * copies that pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* StoreRRefCUnitCallTransportAdapter(
    moho::CUnitCallTransport* const value,
    gpg::RRef* const outRef
  )
  {
    gpg::RRef temp{};
    (void)RRef_CUnitCallTransport(&temp, value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }
} // namespace gpg
