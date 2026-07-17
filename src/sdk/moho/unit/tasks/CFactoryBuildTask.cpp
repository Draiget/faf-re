#include "moho/unit/tasks/CFactoryBuildTask.h"

#include <typeinfo>
#include <new>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/command/SSTITarget.h"
#include "moho/entity/Entity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitCommandWeakPtrReflection.h"

namespace
{
  [[nodiscard]] gpg::RType* ResolveCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveCBuildTaskHelperType()
  {
    static gpg::RType* type = nullptr;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CBuildTaskHelper));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrCUnitCommandType()
  {
    gpg::RType* type = moho::WeakPtr<moho::CUnitCommand>::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::CUnitCommand>));
      moho::WeakPtr<moho::CUnitCommand>::sType = type;
    }
    return type;
  }

  constexpr std::uint64_t kUnitStateBuildingMask = (1ull << static_cast<std::uint32_t>(moho::UNITSTATE_Building));
  constexpr std::uint64_t kUnitStateBusyMask = (1ull << static_cast<std::uint32_t>(moho::UNITSTATE_Busy));

  /**
   * Address: 0x005FD420 (FUN_005FD420, func_RTypeAddBaseCCommandTask)
   *
   * What it does:
   * Resolves `CCommandTask` RTTI and registers it as a zero-offset reflection
   * base lane for task-derived type-info owners.
   */
  [[maybe_unused]] void AddBaseCCommandTask(gpg::RType* const typeInfo)
  {
    if (typeInfo == nullptr) {
      return;
    }

    gpg::RType* const baseType = ResolveCCommandTaskType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F9EB0 (FUN_005F9EB0, Moho::CFactoryBuildTask::CFactoryBuildTask)
   *
   * What it does:
   * Initializes one detached factory-build task with empty dispatch, blueprint,
   * helper, rally-point, and command lanes.
   */
  CFactoryBuildTask::CFactoryBuildTask()
    : CCommandTask()
    , mDispatch(nullptr)
    , mBlueprint(nullptr)
    , mBuildHelper()
    , mRallyPointUnit{}
    , mBuildCount(0)
    , mHasCommand(false)
    , mPad89{}
    , mCommand{}
  {}

  /**
   * Address: 0x005F9F20 (FUN_005F9F20)
   * Mangled: ??0CFactoryBuildTask@Moho@@QAE@@Z_0
   *
   * What it does:
   * Initializes one dispatch-bound factory build task, linking blueprint,
   * rally point unit weak pointer, and originating command weak pointer.
   */
  CFactoryBuildTask::CFactoryBuildTask(
    CCommandTask* const dispatchTask,
    const RUnitBlueprint* const blueprint,
    CUnitCommand* const command,
    Unit* const rallyPointUnit
  )
    : CCommandTask(dispatchTask)
    , mDispatch(static_cast<IAiCommandDispatchImpl*>(dispatchTask))
    , mBlueprint(blueprint)
    , mBuildHelper("FactoryBuild", dispatchTask ? dispatchTask->mUnit : nullptr)
    , mRallyPointUnit{}
    , mBuildCount(0)
    , mHasCommand(false)
    , mPad89{}
    , mCommand{}
  {
    // Link rally point unit weak pointer into owner chain.
    mRallyPointUnit.BindObjectUnlinked(rallyPointUnit);
    if (rallyPointUnit != nullptr) {
      (void)mRallyPointUnit.LinkIntoOwnerChainHeadUnlinked();
    }

    // Link originating command weak pointer into owner chain.
    mCommand.BindObjectUnlinked(command);
    if (command != nullptr) {
      (void)mCommand.LinkIntoOwnerChainHeadUnlinked();
    }

    // If the command object exists (non-null, non-sentinel), mark that we have one.
    if (mCommand.GetObjectPtr() != nullptr) {
      mHasCommand = true;
    }
  }

  /**
   * Address: 0x005FA010 (FUN_005FA010, Moho::CFactoryBuildTask::~CFactoryBuildTask)
   * Thunk entry: 0x005FA110 (FUN_005FA110, scalar deleting destructor thunk)
   *
   * What it does:
   * Clears owner build/busy unit-state bits, resets work progress, dispatches
   * build stop + result lanes, and unlinks both weak-pointer member lanes.
   */
  CFactoryBuildTask::~CFactoryBuildTask()
  {
    mUnit->UnitStateMask &= ~(kUnitStateBuildingMask | kUnitStateBusyMask);
    mUnit->WorkProgress = 0.0f;

    if (mTaskState == TASKSTATE_Complete) {
      mBuildHelper.OnStopBuild(true);
      *mDispatchResult = static_cast<EAiResult>(1);
    } else {
      mBuildHelper.OnStopBuild(false);
      *mDispatchResult = static_cast<EAiResult>(2);
    }

    mCommand.UnlinkFromOwnerChain();
    mRallyPointUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x005FF020 (FUN_005FF020, Moho::CFactoryBuildTask::MemberDeserialize)
   *
   * What it does:
   * Deserializes factory-build task state in binary lane order: base command
   * task, dispatch pointer lane, blueprint pointer lane, build helper lane,
   * rally weak lane, build count, command-present flag, then command weak lane.
   */
  void CFactoryBuildTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(ResolveCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    CCommandTask* dispatchTask = nullptr;
    archive->ReadPointer_CCommandTask(&dispatchTask, &ownerRef);
    mDispatch = static_cast<IAiCommandDispatchImpl*>(dispatchTask);

    RUnitBlueprint* blueprint = nullptr;
    archive->ReadPointer_RUnitBlueprint(&blueprint, &ownerRef);
    mBlueprint = blueprint;

    archive->Read(ResolveCBuildTaskHelperType(), &mBuildHelper, ownerRef);
    archive->Read(ResolveWeakPtrUnitType(), &mRallyPointUnit, ownerRef);
    archive->ReadInt(&mBuildCount);
    archive->ReadBool(&mHasCommand);
    archive->Read(ResolveWeakPtrCUnitCommandType(), &mCommand, ownerRef);
  }

  /**
   * Address: 0x005FF160 (FUN_005FF160, Moho::CFactoryBuildTask::MemberSerialize)
   *
   * What it does:
   * Serializes factory-build task state in binary lane order: base command
   * task, dispatch pointer lane, blueprint pointer lane, build helper lane,
   * rally weak lane, build count, command-present flag, then command weak lane.
   */
  void CFactoryBuildTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(ResolveCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);

    gpg::RRef dispatchRef{};
    (void)gpg::RRef_CCommandTask(&dispatchRef, static_cast<CCommandTask*>(mDispatch));
    gpg::WriteRawPointer(archive, dispatchRef, gpg::TrackedPointerState::Unowned, ownerRef);

    gpg::RRef blueprintRef{};
    (void)gpg::RRef_RUnitBlueprint(&blueprintRef, const_cast<RUnitBlueprint*>(mBlueprint));
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(ResolveCBuildTaskHelperType(), &mBuildHelper, ownerRef);
    archive->Write(ResolveWeakPtrUnitType(), &mRallyPointUnit, ownerRef);
    archive->WriteInt(mBuildCount);
    archive->WriteBool(mHasCommand);
    archive->Write(ResolveWeakPtrCUnitCommandType(), &mCommand, ownerRef);
  }

  /**
   * Address: 0x005FAD00 (FUN_005FAD00, ??2CFactoryBuildTask@Moho@@QAE@@Z_0)
   *
   * IDA signature:
   * Moho::CFactoryBuildTask *__cdecl Moho::CFactoryBuildTask::operator new(
   *   Moho::IAiCommandDispatchImpl *dispatch, Moho::REntityBlueprint *bp,
   *   Moho::CUnitCommand *cmd, int rallyUnit);
   *
   * What it does:
   * Allocates one CFactoryBuildTask (0x94 bytes) and runs the dispatch-bound
   * constructor in place, returning the constructed task (or nullptr when the
   * allocation fails).
   */
  CFactoryBuildTask* CFactoryBuildTask::Create(
    CCommandTask* const dispatchTask,
    const RUnitBlueprint* const blueprint,
    CUnitCommand* const command,
    Unit* const rallyPointUnit
  )
  {
    auto* const result = static_cast<CFactoryBuildTask*>(::operator new(sizeof(CFactoryBuildTask)));
    if (result == nullptr) {
      return nullptr;
    }
    return new (result) CFactoryBuildTask(dispatchTask, blueprint, command, rallyPointUnit);
  }

  namespace
  {
    // Copies the factory builder's command queue into `commands` (replaced by
    // the rally-point unit's builder queue when present), matching the shared
    // head of sub_5FA340 / InheritCommandsTo.
    void SnapshotFactoryCommandQueue(
      Unit* const factoryUnit, WeakPtr<Unit>& rallyPointUnit,
      msvc8::vector<WeakPtr<CUnitCommand>>& commands)
    {
      CopyWeakPtrCUnitCommandVector(factoryUnit->AiBuilder->BuilderGetFactoryCommandQueue(), commands);
      if (Unit* const rallyUnit = rallyPointUnit.GetObjectPtr();
          rallyUnit != nullptr && rallyUnit->AiBuilder != nullptr) {
        ResetWeakPtrCUnitCommandVectorStorage(commands);
        CopyWeakPtrCUnitCommandVector(rallyUnit->AiBuilder->BuilderGetFactoryCommandQueue(), commands);
      }
    }
  } // namespace

  /**
   * Address: 0x005FA340 (FUN_005FA340, Moho::CFactoryBuildTask::InheritQueuedCommandsTo)
   *
   * IDA signature:
   * void __thiscall sub_5FA340(CFactoryBuildTask *this, Moho::Entity *builtUnit);
   *
   * What it does:
   * Re-queues the factory's pending builder commands onto the newly built unit,
   * dropping TransportLoadUnits commands when the built unit is AIR or NAVAL.
   * No leading-Move suppression (the no-transport-guard path).
   */
  void CFactoryBuildTask::InheritQueuedCommandsTo(Entity* const builtUnit)
  {
    Unit* const factoryUnit = mUnit;
    if (factoryUnit->AiBuilder == nullptr || factoryUnit->IsMobile()) {
      return;
    }

    msvc8::vector<WeakPtr<CUnitCommand>> commands{};
    SnapshotFactoryCommandQueue(factoryUnit, mRallyPointUnit, commands);

    for (const WeakPtr<CUnitCommand>& commandLink : commands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      if (command == nullptr) {
        continue;
      }
      if (command->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_TransportLoadUnits &&
          (builtUnit->IsInCategory("AIR") || builtUnit->IsInCategory("NAVAL"))) {
        continue;
      }
      static_cast<Unit*>(builtUnit)->CommandQueue->AddCommandToQueue(command);
    }
  }

  /**
   * Address: 0x005FA550 (FUN_005FA550, Moho::CFactoryBuildTask::InheritCommandsTo)
   *
   * IDA signature:
   * void __thiscall Moho::CFactoryBuildTask::InheritCommandsTo(
   *   CFactoryBuildTask *this, Moho::Unit *builtUnit);
   *
   * What it does:
   * As InheritQueuedCommandsTo, but suppresses the leading run of Move commands
   * (until the first non-Move command is queued) so a transport-loaded unit does
   * not drive off before loading.
   */
  void CFactoryBuildTask::InheritCommandsTo(Unit* const builtUnit)
  {
    Unit* const factoryUnit = mUnit;
    if (factoryUnit->AiBuilder == nullptr || factoryUnit->IsMobile()) {
      return;
    }

    msvc8::vector<WeakPtr<CUnitCommand>> commands{};
    SnapshotFactoryCommandQueue(factoryUnit, mRallyPointUnit, commands);

    bool suppressLeadingMove = true;
    for (const WeakPtr<CUnitCommand>& commandLink : commands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      if (command == nullptr) {
        continue;
      }
      if (command->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_TransportLoadUnits) {
        if (builtUnit->IsInCategory("AIR") || builtUnit->IsInCategory("NAVAL")) {
          continue;
        }
      }
      if (command->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_Move && suppressLeadingMove) {
        continue;
      }
      suppressLeadingMove = false;
      builtUnit->CommandQueue->AddCommandToQueue(command);
    }
  }

  /**
   * Address: 0x005FA790 (FUN_005FA790, Moho::CFactoryBuildTask::Execute / TaskTick)
   *
   * IDA signature:
   * int __thiscall Moho::CFactoryBuildTask::TaskTick(CFactoryBuildTask *this);
   *
   * VFTable SLOT: 1
   *
   * What it does:
   * Factory build-task state machine: prepares/spawns the target unit (shuffling
   * blockers via SIM_TryToBuild when the site is occupied), advances work
   * progress, and on completion hands the unit to a TRANSPORTATION guard (issuing
   * a load command) or inherits the queued commands directly.
   */
  int CFactoryBuildTask::Execute()
  {
    if (mHasCommand && mCommand.GetObjectPtr() == nullptr) {
      return -1;
    }

    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        if (!mUnit->CanBuild(mBlueprint)) {
          return -1;
        }
        if (!mUnit->CanStartBuilding(mBlueprint->Economy.BuildCostEnergy, mBlueprint->Economy.BuildCostMass)) {
          return 1;
        }
        if (mUnit->IsPaused) {
          return 10;
        }

        const Wm3::Vec3f& factoryPos = mUnit->GetPosition();
        const SCoordsVec2 factoryCoords{factoryPos.x, factoryPos.z};
        gpg::Rect2i footprintRect = mUnit->GetBlueprint()->GetFootprintRect(factoryCoords);

        if (!Sim::LocationIsFree(mSim, mUnit, &footprintRect, 1)) {
          SIM_TryToBuild(mSim, mUnit->ArmyRef, &footprintRect, 1);
          return 50;
        }

        const std::int32_t layerArg = mBlueprint->Air.CanFly;
        static TSimConVar<bool> sAiInstaBuild(false, "ai_InstaBuild", false);
        CSimConVarInstanceBase* const instaBuildVar = mSim->GetSimVar(&sAiInstaBuild);
        void* const instaBuildStorage = instaBuildVar != nullptr ? instaBuildVar->GetValueStorage() : nullptr;
        const bool instaBuild =
          instaBuildStorage != nullptr && (*reinterpret_cast<const std::uint8_t*>(instaBuildStorage) != 0u);

        const Wm3::Vec3f& spawnPos = mUnit->GetPosition();
        SUnitConstructionParams params(layerArg, spawnPos, mUnit->ArmyRef, mBlueprint, mUnit, instaBuild);

        Unit* const newUnit = mSim->CreateUnitForScript(params, true);
        if (newUnit == nullptr) {
          return 10;
        }

        newUnit->SetFireState(mUnit->FireState);
        mBuildHelper.SetFocus(newUnit);
        mUnit->UnitStateMask |= (1ull << static_cast<std::uint32_t>(UNITSTATE_Building));
        mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
      }
        [[fallthrough]];

      case TASKSTATE_Waiting: {
        if (!mBuildHelper.IsGood()) {
          mBuildHelper.OnStopBuild(false);
          mTaskState = TASKSTATE_Preparing;
          return 10;
        }
        if (!mBuildHelper.UpdateWorkProgress()) {
          return 1;
        }

        Unit* const newUnit = mBuildHelper.mFocus.GetObjectPtr();
        mBuildHelper.OnStopBuild(true);
        mUnit->UnitStateMask &= ~(1ull << static_cast<std::uint32_t>(UNITSTATE_Building));

        // Walk the guard chain to the terminal guarded unit.
        Unit* terminalGuarded = mUnit;
        Unit* previousGuarded = nullptr;
        for (;;) {
          Unit* const next = terminalGuarded->GetGuardedUnit();
          if (next == nullptr || next == mUnit || next == previousGuarded) {
            break;
          }
          previousGuarded = terminalGuarded;
          terminalGuarded = next;
        }

        // Select a TRANSPORTATION guard that is ferrying, preferring one that is
        // not currently moving; stop at the first stationary transport.
        Unit* selectedTransport = nullptr;
        const gpg::fastvector_runtime_view<SGuardedByWeakOwnerSlot> guardSlots =
          terminalGuarded->GuardedByList.mSlots;
        for (const SGuardedByWeakOwnerSlot* slot = guardSlots.begin; slot != guardSlots.end; ++slot) {
          const std::uintptr_t encoded = reinterpret_cast<std::uintptr_t>(slot->ownerLinkSlot);
          if (encoded == 0) {
            break;
          }
          if (encoded <= 0x8u) {
            continue;
          }
          Unit* const guardUnit = reinterpret_cast<Unit*>(encoded - 0x8u);
          if (!guardUnit->IsInCategory("TRANSPORTATION") || !guardUnit->IsUnitState(UNITSTATE_Ferrying)) {
            continue;
          }
          if (selectedTransport == nullptr || !guardUnit->IsUnitState(UNITSTATE_Moving)) {
            selectedTransport = guardUnit;
          }
          if (!selectedTransport->IsUnitState(UNITSTATE_Moving)) {
            break;
          }
        }

        if (selectedTransport != nullptr) {
          SEntitySetTemplateUnit dispatchSet{};
          (void)dispatchSet.AddUnit(selectedTransport);

          CAiTarget aiTarget{};
          aiTarget.UpdateTarget(selectedTransport);
          SSTITarget encodedTarget{};
          aiTarget.EncodeToSSTITarget(encodedTarget);

          SSTICommandIssueData issueData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
          issueData.mTarget = encodedTarget;

          (void)IssueCommandToSelectedUnits(mUnit->SimulationRef, dispatchSet, issueData, false);
          InheritCommandsTo(newUnit);
        } else {
          InheritQueuedCommandsTo(newUnit);
        }
        return 0;
      }

      case TASKSTATE_Starting:
        if (mLinkResult == static_cast<EAiResult>(2)) {
          mTaskState = TASKSTATE_Preparing;
          return 0;
        }
        mUnit->WorkProgress = 0.0f;
        mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
        return 1;

      case TASKSTATE_Processing:
        if (mUnit->IsUnitState(UNITSTATE_Busy)) {
          return 10;
        }
        mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
        return -1;

      default:
        gpg::HandleAssertFailure(
          "Reached the supposably unreachable.",
          1713,
          "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitBuild.cpp");
        return -1;
    }
  }

  /**
   * Address: 0x005FD490 (FUN_005FD490)
   *
   * What it does:
   * Preserves one serializer-save thunk lane for `CFactoryBuildTask`.
   */
  [[maybe_unused]] void CFactoryBuildTaskMemberSerializeAdapterLaneA(
    const CFactoryBuildTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x005FDC80 (FUN_005FDC80)
   *
   * What it does:
   * Alternate serializer-save thunk lane for `CFactoryBuildTask`.
   */
  [[maybe_unused]] void CFactoryBuildTaskMemberSerializeAdapterLaneB(
    const CFactoryBuildTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }
} // namespace moho
