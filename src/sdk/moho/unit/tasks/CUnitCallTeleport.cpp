#include "moho/unit/tasks/CUnitCallTeleport.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiTransport.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/path/SNavGoal.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace moho
{
  /**
   * Address: 0x0062B200 (FUN_0062B200, func_TryBuildStructureAt)
   *
   * What it does:
   * Validates one structure footprint placement around `tryPos` against map
   * bounds and occupancy constraints and optionally coerces to nearby cells.
   */
  [[nodiscard]] bool TryBuildStructureAt(
    SCoordsVec2* tryPos,
    const RUnitBlueprint* blueprint,
    Sim* sim,
    int border,
    bool wholeMap,
    bool doCoerce,
    bool useSkirt
  );

  [[nodiscard]]
  bool PrepareMove(int moveFlags, Unit* unit, Wm3::Vector3f* inOutPos, gpg::Rect2f* outSkirtRect, bool useWholeMap);
} // namespace moho

namespace
{
  constexpr std::uint64_t kUnitStateMaskTeleportPending = 0x0000000000000100ull;
  constexpr std::uint64_t kUnitStateMaskWaitingForTransport = 0x0000000000000080ull;
  constexpr std::uint64_t kUnitStateMaskTeleporting = 0x0000000000080000ull;
  constexpr std::int16_t kInvalidCellPosComponent = static_cast<std::int16_t>(0x8000);

  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState state) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<std::int32_t>(state) + 1);
  }

  [[nodiscard]] bool IsZeroVector(const Wm3::Vector3f& value) noexcept
  {
    return value.x == 0.0f && value.y == 0.0f && value.z == 0.0f;
  }

  [[nodiscard]] bool IsValidCellPos(const moho::SOCellPos& cellPos) noexcept
  {
    return cellPos.x != kInvalidCellPosComponent && cellPos.z != kInvalidCellPosComponent;
  }

  [[nodiscard]] gpg::Rect2f ZeroRect2f() noexcept
  {
    return gpg::Rect2f{0.0f, 0.0f, 0.0f, 0.0f};
  }

  [[nodiscard]] gpg::Rect2i BuildOgridRectFromWorldPos(const moho::Unit* const unit, const Wm3::Vector3f& worldPos) noexcept
  {
    const moho::SFootprint& footprint = unit->GetFootprint();
    const moho::SOCellPos cellPos = footprint.ToCellPos(worldPos);

    return gpg::Rect2i{
      static_cast<std::int32_t>(cellPos.x),
      static_cast<std::int32_t>(cellPos.z),
      static_cast<std::int32_t>(cellPos.x) + static_cast<std::int32_t>(footprint.mSizeX),
      static_cast<std::int32_t>(cellPos.z) + static_cast<std::int32_t>(footprint.mSizeZ),
    };
  }

  [[nodiscard]] int FailTeleportCallTaskTick(moho::CUnitCallTeleport* const task) noexcept
  {
    if (task != nullptr && task->mTaskState == moho::TASKSTATE_Complete) {
      task->mCompletedSuccessfully = true;
    }
    return -1;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCallTeleportType()
  {
    gpg::RType* type = moho::CUnitCallTeleport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallTeleport));
      moho::CUnitCallTeleport::sType = type;
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
  gpg::RType* CUnitCallTeleport::sType = nullptr;

  /**
   * Address: 0x005E2340 (FUN_005E2340, CUnitCallTeleport::BuildGroundTeleportTarget)
   *
   * What it does:
   * Builds one ground-target payload from world position, clears entity-link
   * lanes, and resets target-point/mobile flags.
   */
  CAiTarget CUnitCallTeleport::BuildGroundTeleportTarget(const Wm3::Vector3f& worldPos) noexcept
  {
    CAiTarget target{};
    target.targetType = EAiTargetType::AITARGET_Ground;
    target.targetEntity.ClearLinkState();
    target.position = worldPos;
    target.targetPoint = -1;
    target.targetIsMobile = false;
    return target;
  }

  /**
   * Address: 0x006013D0 (FUN_006013D0, Moho::CUnitCallTeleport::TaskTick)
   *
   * What it does:
   * Runs teleport-call state transitions between pickup staging, attach move,
   * and teleport-task spawn while keeping O-grid occupancy state.
   */
  int CUnitCallTeleport::Execute()
  {
    if (mUnit->IsDead()) {
      return FailTeleportCallTaskTick(this);
    }

    Unit* const transportUnit = mTargetTransportUnit.GetObjectPtr();
    if (transportUnit == nullptr || transportUnit->IsDead()) {
      return FailTeleportCallTaskTick(this);
    }

    if (mTaskState != TASKSTATE_Preparing && !transportUnit->IsUnitState(UNITSTATE_TransportLoading)) {
      return FailTeleportCallTaskTick(this);
    }

    IAiTransport* const transport = transportUnit->AiTransport;
    Wm3::Vector3f teleportDestination = transport->TransportGetTeleportDest();
    if (IsZeroVector(teleportDestination)) {
      return FailTeleportCallTaskTick(this);
    }

    const bool isAssignedForPickup = transport->TransportIsUnitAssignedForPickup(mUnit);
    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        if (!transportUnit->IsUnitState(UNITSTATE_TransportLoading)) {
          return 10;
        }

        if (transportUnit->CommandQueue->GetCurrentCommand() != mUnit->CommandQueue->GetCurrentCommand()) {
          return 10;
        }

        mTaskState = NextTaskState(mTaskState);
        return 3;
      }

      case TASKSTATE_Waiting: {
        if (!isAssignedForPickup) {
          Wm3::Vector3f pickupPos = transportUnit->GetPosition();
          gpg::Rect2f moveSkirt = ZeroRect2f();
          const bool useWholeMap = mUnit->ArmyRef->UseWholeMap();
          if (!PrepareMove(0, mUnit, &pickupPos, &moveSkirt, useWholeMap)) {
            return -1;
          }

          mUnit->ReserveOgridRect(BuildOgridRectFromWorldPos(mUnit, pickupPos));
          mIsOccupying = true;
          NewMoveTask(SNavGoal(mUnit->GetFootprint().ToCellPos(pickupPos)), this, 0, nullptr, 0);
        }

        mTaskState = NextTaskState(mTaskState);
        return 1;
      }

      case TASKSTATE_Starting: {
        if (mIsOccupying) {
          mUnit->FreeOgridRect();
          mIsOccupying = false;
        }

        if (!isAssignedForPickup) {
          return 1;
        }

        mUnit->UnitStateMask |= kUnitStateMaskWaitingForTransport;
        const SOCellPos attachCell = transport->TransportGetAttachPosition(mUnit);
        if (!IsValidCellPos(attachCell)) {
          return -1;
        }

        NewMoveTask(SNavGoal(attachCell), this, 0, nullptr, 0);
        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Processing: {
        if (!transport->TransportIsTeleportBeaconReady()) {
          return 10;
        }

        transport->TransportAttachUnit(mUnit);
        teleportDestination = transport->TransportGetTeleportDest();

        gpg::Rect2f moveSkirt = ZeroRect2f();
        const bool useWholeMap = mUnit->ArmyRef->UseWholeMap();
        (void)PrepareMove(0, mUnit, &teleportDestination, &moveSkirt, useWholeMap);

        mUnit->ReserveOgridRect(BuildOgridRectFromWorldPos(mUnit, teleportDestination));
        mIsOccupying = true;

        CAiTarget teleportTarget = BuildGroundTeleportTarget(teleportDestination);
        const VTransform& sourceTransform = mUnit->GetTransform();
        (void)CUnitTeleportTask::Create(&teleportTarget, this, transportUnit, &sourceTransform);

        mTaskState = NextTaskState(mTaskState);
        return 1;
      }

      default:
        return 1;
    }
  }

  /**
   * Address: 0x00600E90 (FUN_00600E90, ??0CUnitCallTeleport@Moho@@QAE@@Z)
   */
  CUnitCallTeleport::CUnitCallTeleport(CCommandTask* const parentTask, Unit* const targetUnit)
    : CCommandTask(parentTask)
  {
    mTargetTransportUnit.BindObjectUnlinked(targetUnit);
    (void)mTargetTransportUnit.LinkIntoOwnerChainHeadUnlinked();
    mCompletedSuccessfully = false;
    mIsOccupying = false;

    if (mUnit) {
      mUnit->UnitStateMask |= kUnitStateMaskTeleportPending;
    }
  }

  /**
   * Address: 0x00600EF0 (FUN_00600EF0, Moho::CUnitCallTeleport::~CUnitCallTeleport)
   *
   * What it does:
   * Clears call-teleport state flags on the owner unit, removes transport
   * waiting/pickup links when needed, publishes dispatch result, and unlinks
   * the weak transport-unit lane.
   */
  CUnitCallTeleport::~CUnitCallTeleport()
  {
    mUnit->UnitStateMask &= ~kUnitStateMaskTeleportPending;
    mUnit->UnitStateMask &= ~kUnitStateMaskWaitingForTransport;

    if (mIsOccupying) {
      mUnit->FreeOgridRect();
      mIsOccupying = false;
    }

    Unit* const transportUnit = mTargetTransportUnit.GetObjectPtr();
    if (transportUnit != nullptr && transportUnit->AiTransport != nullptr && !transportUnit->IsDead()) {
      transportUnit->AiTransport->TransportRemoveFromWaitingList(mUnit);
    }

    if (!mCompletedSuccessfully && transportUnit != nullptr && transportUnit->AiTransport != nullptr && !transportUnit->IsDead()) {
      transportUnit->AiTransport->TransportRemovePickupUnit(mUnit, true);
    }

    *mDispatchResult = static_cast<EAiResult>(2 - static_cast<int>(mCompletedSuccessfully));
    mTargetTransportUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x0060AAC0 (FUN_0060AAC0, Moho::CUnitTeleportTask::operator new)
   *
   * What it does:
   * Allocates one teleport execution task and forwards constructor arguments
   * into in-place construction.
   */
  CUnitTeleportTask* CUnitTeleportTask::Create(
    CAiTarget* const target,
    CCommandTask* const parentTask,
    Unit* const teleportBeaconUnit,
    const VTransform* const sourceTransform
  )
  {
    void* const storage = ::operator new(sizeof(CUnitTeleportTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitTeleportTask(parentTask, *target, teleportBeaconUnit, *sourceTransform);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x0060AB20 (FUN_0060AB20, Moho::CUnitTeleportTask::CUnitTeleportTask)
   *
   * What it does:
   * Initializes one teleport execution task with copied target payload,
   * weak-linked beacon lane, and source orientation snapshot.
   */
  CUnitTeleportTask::CUnitTeleportTask(
    CCommandTask* const parentTask,
    const CAiTarget& target,
    Unit* const teleportBeaconUnit,
    const VTransform& sourceTransform
  )
    : CCommandTask(parentTask)
    , mTarget(target)
    , mTeleportBeaconUnit{}
    , mOrientation(sourceTransform.orient_)
  {
    mTeleportBeaconUnit.BindObjectUnlinked(teleportBeaconUnit);
    (void)mTeleportBeaconUnit.LinkIntoOwnerChainHeadUnlinked();

    if (mUnit && mUnit->AiNavigator) {
      mUnit->AiNavigator->AbortMove();
    }
  }

  /**
   * Address: 0x0060AEC0 (FUN_0060AEC0, Moho::CUnitTeleportTask::~CUnitTeleportTask)
   *
   * What it does:
   * Clears unit teleport state, publishes dispatch result, restores motion
   * collision processing, and unlinks beacon weak references.
   */
  CUnitTeleportTask::~CUnitTeleportTask()
  {
    mUnit->UnitStateMask &= ~kUnitStateMaskTeleporting;

    if (mTaskState == TASKSTATE_Starting) {
      *mDispatchResult = static_cast<EAiResult>(1);
    } else {
      *mDispatchResult = static_cast<EAiResult>(2);
      (void)mUnit->RunScript("OnFailedTeleport");
    }

    if (CUnitMotion* const unitMotion = mUnit->UnitMotion; unitMotion != nullptr) {
      unitMotion->mProcessSurfaceCollision = true;
    }

    mTeleportBeaconUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x0060AC00 (FUN_0060AC00, Moho::CUnitTeleportTask::TaskTick)
   *
   * What it does:
   * Runs teleport execution state transitions, validating beacon readiness,
   * reserving teleport placement viability, and dispatching script callback
   * payloads for teleport application.
   */
  int CUnitTeleportTask::Execute()
  {
    if (mTaskState != TASKSTATE_Preparing) {
      if (mTaskState == TASKSTATE_Waiting) {
        Unit* const beaconUnit = mTeleportBeaconUnit.GetObjectPtr();
        if (beaconUnit != nullptr && !beaconUnit->IsDead() && !beaconUnit->IsBeingBuilt()) {
          const bool readyForFinalize =
            (mUnit == beaconUnit)
            || (beaconUnit->AiTransport == nullptr)
            || beaconUnit->AiTransport->TransportIsTeleportBeaconReady();
          if (readyForFinalize) {
            if (mUnit != nullptr && mUnit->IsUnitState(UNITSTATE_Immobile)) {
              return 1;
            }

            mTaskState = NextTaskState(mTaskState);
          }
        }
      }

      return -1;
    }

    const Wm3::Vector3f teleportTargetPos = mTarget.GetTargetPosGun(false);
    SCoordsVec2 tryPos{};
    tryPos.x = teleportTargetPos.x;
    tryPos.z = teleportTargetPos.z;

    const SFootprint& footprint = mUnit->GetFootprint();
    int border = static_cast<int>(footprint.mSizeZ);
    if (static_cast<int>(footprint.mSizeX) > border) {
      border = static_cast<int>(footprint.mSizeX);
    }

    if (!TryBuildStructureAt(&tryPos, mUnit->GetBlueprint(), mUnit->SimulationRef, border, true, false, false)) {
      return -1;
    }

    mUnit->UnitStateMask |= kUnitStateMaskTeleporting;

    Unit* const beaconUnit = mTeleportBeaconUnit.GetObjectPtr();
    if (beaconUnit == nullptr || beaconUnit->IsDead()) {
      return -1;
    }

    const LuaPlus::LuaObject orientationObject =
      SCR_ToLua<Wm3::Quaternion<float>>(mUnit->SimulationRef->mLuaState, mOrientation);

    Wm3::Vector3f teleportScriptPos{};
    teleportScriptPos.x = tryPos.x;
    teleportScriptPos.y = 0.0f;
    teleportScriptPos.z = tryPos.z;
    const LuaPlus::LuaObject positionObject =
      SCR_ToLua<Wm3::Vector3<float>>(mUnit->SimulationRef->mLuaState, teleportScriptPos);
    const LuaPlus::LuaObject beaconObject = beaconUnit->GetLuaObject();

    mUnit->RunScriptOnTeleportUnit(beaconObject, positionObject, orientationObject);
    mTaskState = NextTaskState(mTaskState);
    return 1;
  }

  /**
   * Address: 0x00603CD0 (FUN_00603CD0)
   *
   * What it does:
   * Loads base command-task state plus teleport-task weak-unit and status
   * flags from archive data.
   */
  void CUnitCallTeleport::MemberDeserialize(gpg::ReadArchive* const archive, CUnitCallTeleport* const task, int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (!archive || !task) {
      return;
    }

    gpg::RRef nullOwner{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(task), nullOwner);
    archive->Read(CachedWeakPtrUnitType(), &task->mTargetTransportUnit, nullOwner);
    archive->ReadBool(&task->mCompletedSuccessfully);
    archive->ReadBool(&task->mIsOccupying);
  }

  /**
   * Address: 0x00603D60 (FUN_00603D60)
   *
   * What it does:
   * Saves base command-task state plus teleport-task weak-unit and status
   * flags into archive data.
   */
  void CUnitCallTeleport::MemberSerialize(
    gpg::WriteArchive* const archive,
    const CUnitCallTeleport* const task,
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
    archive->WriteBool(task->mCompletedSuccessfully);
    archive->WriteBool(task->mIsOccupying);
  }

  /**
   * Address: 0x00602F00 (FUN_00602F00)
   * Address: 0x0060C580 (FUN_0060C580)
   *
   * What it does:
   * Preserves one deserialize callback thunk lane for call-teleport task
   * serializer registration.
   */
  [[maybe_unused]] void CUnitCallTeleportMemberDeserializeAdapterLaneA(
    gpg::ReadArchive* const archive,
    CUnitCallTeleport* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTeleport::MemberDeserialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x00602F10 (FUN_00602F10)
   *
   * What it does:
   * Preserves one serialize callback thunk lane for call-teleport task
   * serializer registration.
   */
  [[maybe_unused]] void CUnitCallTeleportMemberSerializeAdapterLaneA(
    gpg::WriteArchive* const archive,
    const CUnitCallTeleport* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTeleport::MemberSerialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x00603190 (FUN_00603190)
   *
   * What it does:
   * Alternate deserialize callback thunk lane for call-teleport task serializer
   * registration.
   */
  [[maybe_unused]] void CUnitCallTeleportMemberDeserializeAdapterLaneB(
    gpg::ReadArchive* const archive,
    CUnitCallTeleport* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTeleport::MemberDeserialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x006031A0 (FUN_006031A0)
   *
   * What it does:
   * Alternate serialize callback thunk lane for call-teleport task serializer
   * registration.
   */
  [[maybe_unused]] void CUnitCallTeleportMemberSerializeAdapterLaneB(
    gpg::WriteArchive* const archive,
    const CUnitCallTeleport* const task,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTeleport::MemberSerialize(archive, task, version, ownerRef);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00603530 (FUN_00603530, gpg::RRef_CUnitCallTeleport)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitCallTeleport*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitCallTeleport(gpg::RRef* const outRef, moho::CUnitCallTeleport* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitCallTeleportType());
    return outRef;
  }

  /**
   * Address: 0x00603000 (FUN_00603000)
   *
   * What it does:
   * Materializes one `RRef_CUnitCallTeleport` result into a stack local and
   * copies that pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* StoreRRefCUnitCallTeleportAdapter(
    moho::CUnitCallTeleport* const value,
    gpg::RRef* const outRef
  )
  {
    gpg::RRef temp{};
    (void)RRef_CUnitCallTeleport(&temp, value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }
} // namespace gpg
