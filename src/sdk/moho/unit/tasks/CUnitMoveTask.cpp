#include "moho/unit/tasks/CUnitMoveTask.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/containers/Rect2.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/SFootprint.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitCallTransport.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSNavGoalType()
  {
    gpg::RType* type = moho::SNavGoal::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SNavGoal));
      moho::SNavGoal::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrCUnitCommandType()
  {
    gpg::RType* type = moho::WeakPtr<moho::CUnitCommand>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::CUnitCommand>));
      moho::WeakPtr<moho::CUnitCommand>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCUnitMoveTaskType()
  {
    gpg::RType* type = moho::CUnitMoveTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitMoveTask));
      moho::CUnitMoveTask::sType = type;
    }
    return type;
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
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

  void ReadBoolIntoByteLane(gpg::ReadArchive* const archive, std::uint8_t& laneValue)
  {
    bool value = false;
    archive->ReadBool(&value);
    laneValue = value ? 1u : 0u;
  }

  [[nodiscard]] moho::Unit* ResolveAssignedTransportUnit(moho::Unit* const unit) noexcept
  {
    if (!unit) {
      return nullptr;
    }

    return unit->AssignedTransportRef.ResolveObjectPtr<moho::Unit>();
  }

  [[nodiscard]] bool IsZeroVector(const Wm3::Vector3f& value) noexcept
  {
    return value.x == 0.0f && value.y == 0.0f && value.z == 0.0f;
  }

  [[nodiscard]] moho::SOCellPos ToCellPos(const Wm3::Vector3f& position, const moho::SFootprint& footprint) noexcept
  {
    moho::SOCellPos cell{};
    cell.x = static_cast<std::int16_t>(position.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    cell.z = static_cast<std::int16_t>(position.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));
    return cell;
  }

  [[nodiscard]] moho::Broadcaster* NavigatorListenerHead(moho::IAiNavigator* const navigator) noexcept
  {
    if (!navigator) {
      return nullptr;
    }

    return reinterpret_cast<moho::Broadcaster*>(&navigator->mListenerNode);
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitMoveTask::sType = nullptr;

  /**
   * Address: 0x00618C30 (FUN_00618C30, nullsub_54)
   *
   * What it does:
   * Preserves the `Listener<EFormationdStatus>` callback lane used by
   * `CUnitMoveTask`; this callback is intentionally a no-op.
   */
  void __stdcall CUnitMoveTaskFormationStatusListenerNoOp(void* const)
  {}

  /**
   * Address: 0x006189C0 (FUN_006189C0, Moho::CommandIsInstant)
   *
   * What it does:
   * Returns whether one command type is considered instant for move-task
   * chain decisions (no queued motion duration lane).
   */
  bool CommandIsInstant(const EUnitCommandType commandType) noexcept
  {
    switch (commandType) {
      case EUnitCommandType::UNITCOMMAND_None:
      case EUnitCommandType::UNITCOMMAND_Stop:
      case EUnitCommandType::UNITCOMMAND_Dive:
      case EUnitCommandType::UNITCOMMAND_BuildMobile:
      case EUnitCommandType::UNITCOMMAND_Nuke:
      case EUnitCommandType::UNITCOMMAND_Tactical:
      case EUnitCommandType::UNITCOMMAND_Teleport:
      case EUnitCommandType::UNITCOMMAND_Reclaim:
      case EUnitCommandType::UNITCOMMAND_Capture:
      case EUnitCommandType::UNITCOMMAND_DetachFromTransport:
      case EUnitCommandType::UNITCOMMAND_Upgrade:
      case EUnitCommandType::UNITCOMMAND_KillSelf:
      case EUnitCommandType::UNITCOMMAND_DestroySelf:
        return true;

      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_BuildSiloTactical:
      case EUnitCommandType::UNITCOMMAND_BuildSiloNuke:
      case EUnitCommandType::UNITCOMMAND_BuildFactory:
      case EUnitCommandType::UNITCOMMAND_BuildAssist:
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
      case EUnitCommandType::UNITCOMMAND_Guard:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_Ferry:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_Repair:
      case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
      case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits:
      case EUnitCommandType::UNITCOMMAND_TransportUnloadUnits:
      case EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits:
      case EUnitCommandType::UNITCOMMAND_Script:
      case EUnitCommandType::UNITCOMMAND_AssistCommander:
      default:
        return false;
    }
  }

  /**
   * Address: 0x00618030 (FUN_00618030, Moho::CUnitMoveTask::CUnitMoveTask)
   *
   * What it does:
   * Initializes one detached move-task with self-linked listener nodes and
   * empty dispatch/goal/command lanes.
   */
  CUnitMoveTask::CUnitMoveTask()
    : CCommandTask()
    , mUnknown0030(0)
    , mNavigatorListenerVftable(0)
    , mNavigatorListenerLink{}
    , mUnknown0040(0)
    , mFormationStatusListenerVftable(0)
    , mFormationStatusListenerLink{}
    , mUnknown0050(0)
    , mCommandEventListenerVftable(0)
    , mCommandEventListenerLink{}
    , mDispatchTask(nullptr)
    , mMoveGoal()
    , mCommandRef{}
    , mNextCmdIsInstant(1)
    , mRequiresTransportCategoryCheck(0)
    , mIsOccupying(0)
    , mTransportDispatchIssued(0)
    , mMoveVariant(0)
    , mHasPreparedDynamicGoal(0)
    , mPad_0096_0098{0, 0}
  {}

  /**
   * Address: 0x0061A750 (FUN_0061A750)
   *
   * What it does:
   * Deserializes move-task runtime state in binary read order: base command
   * task payload, dispatch pointer, move goal, command weak link, and
   * command-lane state bytes read as booleans.
   */
  void CUnitMoveTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    gpg::RRef dispatchTaskRef{};
    archive->ReadPointer_CCommandTask(&mDispatchTask, &dispatchTaskRef);

    const gpg::RRef moveGoalOwnerRef{};
    archive->Read(CachedSNavGoalType(), &mMoveGoal, moveGoalOwnerRef);

    const gpg::RRef commandOwnerRef{};
    archive->Read(CachedWeakPtrCUnitCommandType(), &mCommandRef, commandOwnerRef);

    ReadBoolIntoByteLane(archive, mNextCmdIsInstant);
    ReadBoolIntoByteLane(archive, mRequiresTransportCategoryCheck);
    ReadBoolIntoByteLane(archive, mIsOccupying);
    ReadBoolIntoByteLane(archive, mTransportDispatchIssued);
    ReadBoolIntoByteLane(archive, mMoveVariant);
    ReadBoolIntoByteLane(archive, mHasPreparedDynamicGoal);
  }

  /**
   * Address: 0x0061A880 (FUN_0061A880)
   *
   * What it does:
   * Serializes move-task runtime state in binary write order: base command
   * task payload, dispatch pointer, move goal, command weak link, and
   * command-lane state bytes emitted as booleans.
   */
  void CUnitMoveTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);

    gpg::RRef dispatchTaskRef{};
    (void)gpg::RRef_CCommandTask(&dispatchTaskRef, mDispatchTask);
    gpg::WriteRawPointer(archive, dispatchTaskRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedSNavGoalType(), &mMoveGoal, ownerRef);
    archive->Write(CachedWeakPtrCUnitCommandType(), &mCommandRef, ownerRef);

    archive->WriteBool(mNextCmdIsInstant != 0u);
    archive->WriteBool(mRequiresTransportCategoryCheck != 0u);
    archive->WriteBool(mIsOccupying != 0u);
    archive->WriteBool(mTransportDispatchIssued != 0u);
    archive->WriteBool(mMoveVariant != 0u);
    archive->WriteBool(mHasPreparedDynamicGoal != 0u);
  }

  /**
   * Address: 0x0061A1A0 (FUN_0061A1A0)
   *
   * What it does:
   * Serializer-save thunk lane forwarding one `(task, archive)` pair into
   * `CUnitMoveTask::MemberSerialize`.
   */
  [[maybe_unused]] void CUnitMoveTaskMemberSerializeThunk(
    const CUnitMoveTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    if (task != nullptr) {
      task->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x0061A3C0 (FUN_0061A3C0)
   *
   * What it does:
   * Thin alias lane that forwards one `(task, archive)` pair into
   * `CUnitMoveTask::MemberSerialize`.
   */
  void CUnitMoveTaskMemberSerializeAlias(
    const CUnitMoveTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x00618A00 (FUN_00618A00, sub_618A00)
   *
   * What it does:
   * Returns true when this move task is the unit's only active command and
   * the command lane allows target-position derived movement.
   */
  bool CUnitMoveTask::ShouldUseCurrentCommandTargetPosition() const
  {
    if (!mUnit) {
      return false;
    }

    if (mUnit->IsUnitState(UNITSTATE_WaitForFerry)) {
      return false;
    }
    if (mUnit->IsUnitState(UNITSTATE_LandingOnPlatform)) {
      return false;
    }
    if (mUnit->IsUnitState(UNITSTATE_Attached)) {
      return false;
    }

    CUnitCommandQueue* const commandQueue = mUnit->CommandQueue;
    if (!commandQueue) {
      return false;
    }

    CUnitCommand* const currentCommand = commandQueue->GetCurrentCommand();
    if (!currentCommand) {
      return false;
    }

    if (!currentCommand->mUnknownFlag142) {
      return false;
    }

    return commandQueue->GetNextCommand() == nullptr;
  }

  /**
   * Address: 0x00618BB0 (FUN_00618BB0)
   *
   * What it does:
   * Applies navigator-event result transitions, clears instant-command lane,
   * and resumes owner-thread execution immediately.
   */
  void CUnitMoveTask::HandleNavigatorEvent(
    const EAiNavigatorEvent event
  )
  {
    switch (event) {
      case AINAVEVENT_Failed:
      case AINAVEVENT_Aborted:
        if (mDispatchResult != nullptr) {
          *mDispatchResult = static_cast<EAiResult>(2);
        }
        break;

      case AINAVEVENT_Succeeded:
        if (mDispatchResult != nullptr) {
          *mDispatchResult = static_cast<EAiResult>(1);
        }
        break;

      case AINAVEVENT_ResumeTask:
        if (mTransportDispatchIssued == 0u) {
          return;
        }
        if (mDispatchResult != nullptr) {
          *mDispatchResult = static_cast<EAiResult>(1);
        }
        break;

      default:
        break;
    }

    mNextCmdIsInstant = 0u;

    if (mOwnerThread == nullptr) {
      return;
    }

    mOwnerThread->mPendingFrames = 0;
    if (mOwnerThread->mStaged) {
      mOwnerThread->Unstage();
    }
  }

  /**
   * Address: 0x006180E0 (FUN_006180E0, Moho::CUnitMoveTask::CUnitMoveTask)
   *
   * What it does:
   * Initializes move-task listener/dispatch lanes, seeds command weak-link
   * ownership, and derives an initial move goal from command target context.
   */
  CUnitMoveTask::CUnitMoveTask(
    CCommandTask* const dispatchTask,
    const SNavGoal& moveGoal,
    const std::uint8_t requiresTransportCategoryCheck,
    CUnitCommand* const sourceCommand,
    const std::uint8_t moveVariant
  )
    : CCommandTask(dispatchTask)
    , mUnknown0030(0)
    , mNavigatorListenerVftable(0)
    , mNavigatorListenerLink{}
    , mUnknown0040(0)
    , mFormationStatusListenerVftable(0)
    , mFormationStatusListenerLink{}
    , mUnknown0050(0)
    , mCommandEventListenerVftable(0)
    , mCommandEventListenerLink{}
    , mDispatchTask(dispatchTask)
    , mMoveGoal(moveGoal)
    , mCommandRef{}
    , mNextCmdIsInstant(1)
    , mRequiresTransportCategoryCheck(requiresTransportCategoryCheck)
    , mIsOccupying(0)
    , mTransportDispatchIssued(0)
    , mMoveVariant(moveVariant)
    , mHasPreparedDynamicGoal(0)
    , mPad_0096_0098{0, 0}
  {
    mCommandRef.BindObjectUnlinked(sourceCommand);
    (void)mCommandRef.LinkIntoOwnerChainHeadUnlinked();

    if (!mUnit) {
      return;
    }

    mUnit->UnitStateMask |= 0x0000000000000004ull;

    if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
      if (Broadcaster* const listenerHead = NavigatorListenerHead(navigator); listenerHead != nullptr) {
        mNavigatorListenerLink.ListLinkBefore(listenerHead);
      }
    }

    CUnitCommand* command = mCommandRef.GetObjectPtr();
    if (!command) {
      if (CUnitCommandQueue* const commandQueue = mUnit->CommandQueue; commandQueue != nullptr) {
        command = commandQueue->GetCurrentCommand();
        mCommandRef.ResetFromObject(command);
      }
    }

    if (command) {
      if (ShouldUseCurrentCommandTargetPosition()) {
        const Wm3::Vector3f targetPosition = command->mTarget.GetTargetPosGun(false);
        if (!IsZeroVector(targetPosition)) {
          const SOCellPos targetCell = ToCellPos(targetPosition, mUnit->GetFootprint());
          mMoveGoal = SNavGoal(targetCell);
          mMoveGoal.mLayer = moveGoal.mLayer;

          if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
            navigator->SetGoal(mMoveGoal);
          }

          const gpg::Rect2i reservedRect{
            mMoveGoal.mPos1.x0,
            mMoveGoal.mPos1.z0,
            mMoveGoal.mPos1.x1,
            mMoveGoal.mPos1.z1,
          };
          mUnit->ReserveOgridRect(reservedRect);
          mIsOccupying = 1;
          mHasPreparedDynamicGoal = 1;
        }
      } else {
        SOCellPos commandCell{};
        (void)CUnitCommand::GetPosition(command, mUnit, &commandCell);
        mMoveGoal = SNavGoal(commandCell);
        mMoveGoal.mLayer = moveGoal.mLayer;
        if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
          navigator->SetGoal(mMoveGoal);
        }
      }
    }

    if (mUnit->IsUnitState(UNITSTATE_Immobile)) {
      if (const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
          blueprint != nullptr && blueprint->AI.NeedUnpack && mUnit->AiAttacker != nullptr) {
        CAiTarget stopTarget{};
        mUnit->AiAttacker->SetDesiredTarget(&stopTarget);
      }
    }

    mUnit->UpdateSpeedThroughStatus();

    if (mOwnerThread != nullptr && !mOwnerThread->mStaged) {
      mOwnerThread->Stage();
    }
  }

  /**
   * Address: 0x00618A70 (FUN_00618A70, Moho::CUnitMoveTask::OnEvent)
   *
   * What it does:
   * Issues one transport-call command for the assigned ferry transport when
   * transport-category gating passes, then marks dispatch complete.
   */
  int CUnitMoveTask::Execute()
  {
    if (mTransportDispatchIssued != 0u) {
      return -1;
    }

    bool shouldIssueTransportCall = false;
    if (mRequiresTransportCategoryCheck != 0u) {
      Unit* const transportUnit = ResolveAssignedTransportUnit(mUnit);
      if (transportUnit != nullptr && transportUnit->IsInCategory("TRANSPORTATION")) {
        shouldIssueTransportCall = true;
      }
    }

    if (!shouldIssueTransportCall) {
      return -1;
    }

    if (mUnit->AiNavigator != nullptr) {
      mNavigatorListenerLink.ListUnlink();
    }

    Unit* const transportUnit = ResolveAssignedTransportUnit(mUnit);
    NewCallTransportCommand(mDispatchTask, transportUnit);
    mTransportDispatchIssued = 1u;
    return 1;
  }

  /**
   * Address: 0x006190A0 (FUN_006190A0, Moho::NewMoveTask)
   *
   * What it does:
   * Sets one navigator goal for the dispatch unit and allocates one
   * `CUnitMoveTask` child command task when navigator state is present.
   */
  void NewMoveTask(
    const SNavGoal& goal,
    CCommandTask* const dispatchTask,
    const std::uint8_t requiresTransportCategoryCheck,
    CUnitCommand* const sourceCommand,
    const std::uint8_t moveVariant
  )
  {
    if (!dispatchTask || !dispatchTask->mUnit) {
      return;
    }

    IAiNavigator* const navigator = dispatchTask->mUnit->AiNavigator;
    if (!navigator) {
      return;
    }

    navigator->SetGoal(goal);
    (void)new (std::nothrow)
      CUnitMoveTask(dispatchTask, goal, requiresTransportCategoryCheck, sourceCommand, moveVariant);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0061A3F0 (FUN_0061A3F0, gpg::RRef_CUnitMoveTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitMoveTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitMoveTask(gpg::RRef* const outRef, moho::CUnitMoveTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitMoveTaskType());
    return outRef;
  }

  /**
   * Address: 0x0061A350 (FUN_0061A350)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitMoveTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitMoveTaskRef(gpg::RRef* const outRef, moho::CUnitMoveTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)RRef_CUnitMoveTask(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg

namespace
{
  gpg::SerSaveLoadHelperListRuntime gCUnitMoveTaskSerializer{};

  /**
   * Address: 0x00619040 (FUN_00619040)
   *
   * What it does:
   * Unlinks `CUnitMoveTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitMoveTaskSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitMoveTaskSerializer);
  }

  /**
   * Address: 0x00619070 (FUN_00619070)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitMoveTaskSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitMoveTaskSerializerNodeSecondary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitMoveTaskSerializer);
  }
} // namespace
