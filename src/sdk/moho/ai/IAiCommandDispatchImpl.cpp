#include "moho/ai/IAiCommandDispatchImpl.h"

#include <algorithm>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiTransport.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/path/SNavGoal.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/sim/Sim.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitGetBuiltTask.h"
#include "moho/unit/tasks/CUnitCallAirStagingPlatform.h"
#include "moho/unit/tasks/CUnitCallLandTransport.h"
#include "moho/unit/tasks/CUnitCallTeleport.h"
#include "moho/unit/tasks/CUnitRefuel.h"

#include <cstring>

#include "moho/lua/SCR_ToLua.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/SFootprint.h"
#include "moho/unit/tasks/CFactoryBuildTask.h"
#include "moho/unit/tasks/CUnitAssistMoveTask.h"
#include "moho/unit/tasks/CUnitAttackTargetTask.h"
#include "moho/unit/tasks/CUnitCallTransport.h"
#include "moho/unit/tasks/CUnitCaptureTask.h"
#include "moho/unit/tasks/CUnitCarrierLaunch.h"
#include "moho/unit/tasks/CUnitCarrierRetrieve.h"
#include "moho/unit/tasks/CUnitFerryTask.h"
#include "moho/unit/tasks/CUnitFireAtTask.h"
#include "moho/unit/tasks/CUnitFormAndMoveTask.h"
#include "moho/unit/tasks/CUnitGuardTask.h"
#include "moho/unit/tasks/CUnitLoadUnits.h"
#include "moho/unit/tasks/CUnitMobileBuildTask.h"
#include "moho/unit/tasks/CUnitMoveTask.h"
#include "moho/unit/tasks/CUnitPatrolTask.h"
#include "moho/unit/tasks/CUnitPodAssist.h"
#include "moho/unit/tasks/CUnitRepairTask.h"
#include "moho/unit/tasks/CUnitSacrificeTask.h"
#include "moho/unit/tasks/CUnitUnloadUnits.h"
#include "moho/unit/tasks/CUnitUpgradeTask.h"
#include "moho/unit/tasks/CUnitWaitForFerryTask.h"
#include "moho/script/CUnitScriptTask.h"

using namespace moho;

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  class IAiCommandDispatchImplConstructed final : public IAiCommandDispatchImpl
  {
  public:
    using IAiCommandDispatchImpl::IAiCommandDispatchImpl;

    int Execute() override
    {
      return static_cast<int>(TaskTick());
    }
  };

  static_assert(
    sizeof(IAiCommandDispatchImplConstructed) == sizeof(IAiCommandDispatchImpl),
    "IAiCommandDispatchImplConstructed size must match IAiCommandDispatchImpl"
  );

  [[nodiscard]] gpg::RType* CachedIAiCommandDispatchImplType()
  {
    gpg::RType* type = IAiCommandDispatchImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiCommandDispatchImpl));
      IAiCommandDispatchImpl::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CCommandTask));
      CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandQueueType()
  {
    gpg::RType* type = CUnitCommandQueue::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CUnitCommandQueue));
      CUnitCommandQueue::sType = type;
    }
    return type;
  }

  /**
    * Alias of FUN_00409A40 (non-canonical helper lane).
   *
   * What it does:
   * Allocates one task-thread on `stage` and links `dispatch` as thread-top
   * task while preserving prior top linkage.
   */
  [[nodiscard]] CTaskThread* CreateTaskThreadForDispatch(CTask* const dispatch, CTaskStage* const stage, const bool autoDelete)
  {
    if (!dispatch || !stage) {
      return nullptr;
    }

    auto* const taskThread = new CTaskThread(stage);
    dispatch->mAutoDelete = autoDelete;
    dispatch->mOwnerThread = taskThread;
    dispatch->mSubtask = taskThread->mTaskTop;
    taskThread->mTaskTop = dispatch;
    return taskThread;
  }

  [[nodiscard]] gpg::RRef MakeDispatchObjectRef(IAiCommandDispatchImpl* const object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedIAiCommandDispatchImplType();
    return ref;
  }

  [[nodiscard]] CUnitCommandQueue* ReadCommandQueuePointer(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const expectedType = CachedCUnitCommandQueueType();
    if (!expectedType || !tracked.type) {
      return static_cast<CUnitCommandQueue*>(tracked.object);
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<CUnitCommandQueue*>(upcast.mObj);
    }

    const char* const expected = expectedType->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "CUnitCommandQueue",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(message.c_str());
  }

  [[nodiscard]] gpg::RRef MakeCommandQueueRef(CUnitCommandQueue* const queue)
  {
    gpg::RRef out{};
    gpg::RType* const staticType = CachedCUnitCommandQueueType();
    out.mObj = nullptr;
    out.mType = staticType;
    if (!queue || !staticType) {
      out.mObj = queue;
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*queue));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!isDerived) {
      out.mObj = queue;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(queue) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] const char* BlueprintIdOrUnknown(const Unit* const unit) noexcept
  {
    if (!unit) {
      return "<unknown>";
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (!blueprint) {
      return "<unknown>";
    }

    return blueprint->mBlueprintId.c_str();
  }

  /**
   * Address: 0x0060B8B0 (FUN_0060B8B0)
   *
   * What it does:
   * Resolves one target entity to `Unit*` and, when this dispatch unit has
   * transport AI state, applies that unit as teleport destination.
   */
  [[maybe_unused]] Entity* TrySetTransportTeleportDestinationFromTarget(
    IAiCommandDispatchImpl* const dispatch,
    CAiTarget* const target
  )
  {
    if (!dispatch || !dispatch->mUnit || !target) {
      return nullptr;
    }

    Entity* const targetEntity = target->GetEntity();
    Unit* const targetUnit = targetEntity ? targetEntity->IsUnit() : nullptr;
    if (!targetUnit) {
      return targetEntity;
    }

    IAiTransport* const transportAi = dispatch->mUnit->AiTransport;
    if (transportAi != nullptr) {
      transportAi->TranspotSetTeleportDest(targetUnit);
    }

    return targetEntity;
  }

  /**
   * Address: 0x0060B900 (FUN_0060B900)
   *
   * What it does:
   * Runs lower-bound lookup by unit entity id over one sorted `Entity*` lane
   * and writes either exact slot or `end` cursor into `outSlot`.
   */
  [[maybe_unused]] Entity*** FindUnitSlotInSortedEntityRange(
    Entity** const begin,
    Entity** const end,
    Entity*** const outSlot,
    Unit* const unit
  )
  {
    if (!outSlot) {
      return outSlot;
    }

    if (!begin || !end || !unit) {
      *outSlot = end;
      return outSlot;
    }

    Entity* const unitEntity = static_cast<Entity*>(unit);
    const std::uint32_t unitId = static_cast<std::uint32_t>(unitEntity->id_);
    Entity** const found = std::lower_bound(begin, end, unitId, [](const Entity* const candidate, const std::uint32_t key) {
      const std::uint32_t candidateId = candidate ? static_cast<std::uint32_t>(candidate->id_) : 0u;
      return candidateId < key;
    });
    *outSlot = (found != end && *found == unitEntity) ? found : end;
    return outSlot;
  }

  /**
   * Address: 0x00626A90 (FUN_00626A90)
   *
   * What it does:
   * Resolves current transport owner of this dispatch unit and asks that
   * transport to detach the unit when both lanes are valid.
   */
  [[maybe_unused]] int DetachDispatchUnitFromTransport(IAiCommandDispatchImpl* const dispatch)
  {
    if (!dispatch || !dispatch->mUnit) {
      return 0;
    }

    Unit* const unit = dispatch->mUnit;
    Unit* const transportOwner = unit->GetTransportedBy();
    if (!transportOwner) {
      return 0;
    }

    IAiTransport* const transportAi = transportOwner->AiTransport;
    if (!transportAi) {
      return 0;
    }

    return transportAi->TransportDetachUnit(unit) ? 1 : 0;
  }

  /**
   * Recovered runtime carrier-land task object used by IssueCarrierLandTask.
   *
   * This models the observed constructor-side state writes in
   * `FUN_00606500` (weak carrier link, focus/entity-state priming, and
   * zero-initialized movement lanes).
   */
  class CUnitCarrierLandDispatchTask final : public CCommandTask
  {
  public:
    CUnitCarrierLandDispatchTask(CCommandTask* const parentTask, Unit* const carrierUnit)
      : CCommandTask(parentTask)
      , mCarrierUnit()
      , mHasLandingOrder(false)
      , mPad39_3B{}
      , mPendingLandingTicks(0)
      , mHeight(0.0f)
      , mPos{0.0f, 0.0f, 0.0f}
      , mDir{0.0f, 0.0f, 0.0f}
      , mLastPos{0.0f, 0.0f, 0.0f}
    {
      mCarrierUnit.ResetFromObject(carrierUnit);

      if (mUnit != nullptr) {
        mUnit->UnitStateMask |= 0x100ull;
        mUnit->FocusEntityRef.ResetObjectPtr<Entity>(carrierUnit);
        if (carrierUnit != nullptr) {
          (void)mUnit->RunScript("OnAssignedFocusEntity");
        }
        mUnit->NeedSyncGameData = true;
      }
    }

    int Execute() override
    {
      return -1;
    }

  private:
    WeakPtr<Unit> mCarrierUnit; // +0x30
    bool mHasLandingOrder; // +0x38
    std::uint8_t mPad39_3B[3];
    std::int32_t mPendingLandingTicks; // +0x3C
    float mHeight; // +0x40
    Wm3::Vec3f mPos; // +0x44
    Wm3::Vec3f mDir; // +0x50
    Wm3::Vec3f mLastPos; // +0x5C
  };
  static_assert(sizeof(CUnitCarrierLandDispatchTask) == 0x68, "CUnitCarrierLandDispatchTask size must be 0x68");

  /**
   * Recovered runtime reclaim-task object used by IssueReclaimTask.
   *
   * This mirrors constructor-side target snapshot and economy/request lane
   * zero-initialization observed in `FUN_0061EB60`.
   */
  class CUnitReclaimDispatchTask final : public CCommandTask
  {
  public:
    CUnitReclaimDispatchTask(
      CCommandTask* const parentTask,
      Entity* const targetEntity,
      const Wm3::Vec3f& targetPos
    )
      : CCommandTask(parentTask)
      , mListenerRuntimePad{}
      , mCurrentCommand(nullptr)
      , mTargetEntity()
      , mTargetPos(targetPos)
      , mHasStarted(false)
      , mPad5D_5F{}
      , mConsumptionData(nullptr)
      , mReclaimRate(0.0f)
      , mReclaimEnergyPerSecond(0.0f)
      , mReclaimMassPerSecond(0.0f)
    {
      mTargetEntity.ResetFromObject(targetEntity);
    }

    int Execute() override
    {
      return -1;
    }

  private:
    std::uint8_t mListenerRuntimePad[0x10]; // +0x30
    CUnitCommand* mCurrentCommand; // +0x40
    WeakPtr<Entity> mTargetEntity; // +0x44
    Wm3::Vec3f mTargetPos; // +0x4C
    bool mHasStarted; // +0x58
    std::uint8_t mPad5D_5F[3];
    void* mConsumptionData; // +0x5C
    float mReclaimRate; // +0x60
    float mReclaimEnergyPerSecond; // +0x64
    float mReclaimMassPerSecond; // +0x68
  };
  static_assert(sizeof(CUnitReclaimDispatchTask) == 0x6C, "CUnitReclaimDispatchTask size must be 0x6C");

  /**
   * Address: 0x00608EF0 (FUN_00608EF0, Moho::IAiCommandDispatchImpl::DispatchTask)
   *
   * IDA signature:
   * void __cdecl Moho::IAiCommandDispatchImpl::DispatchTask(
   *   Moho::IAiCommandDispatchImpl *dispatch, Moho::CUnitCommand *a2);
   *
   * What it does:
   * Central command-head dispatcher. Keyed on the queued command's real
   * EUnitCommandType, it spawns the matching unit task (move / attack / build /
   * transport / upgrade / ...) bound to this dispatch context. Mirrors the
   * binary `switch (command->mVarDat.mCmdType - 1)` ladder (the decompiler's
   * shifted case labels are corrected to the real enum here).
   */
  void DispatchQueuedCommand(IAiCommandDispatchImpl* const dispatch, CUnitCommand* const command)
  {
    Unit* const unit = dispatch->mUnit;

    // Binary does an RTTI-checked upcast (gpg::RRef_REntityBlueprint +
    // REF_UpcastPtr(RUnitBlueprint::sType2)); build-dispatch blueprints are unit
    // blueprints (RUnitBlueprint derives from REntityBlueprint), so the checked
    // cast resolves to a static upcast for the reachable inputs.
    REntityBlueprint* const entityBlueprint = command->mConstDat.blueprint;
    const RUnitBlueprint* const unitBlueprint = static_cast<const RUnitBlueprint*>(entityBlueprint);

    switch (command->mVarDat.mCmdType) {
      case EUnitCommandType::UNITCOMMAND_Stop: {
        dispatch->Stop();
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Move: {
        CUnitCommand::Move(unit, command);
        SOCellPos cell;
        const SNavGoal goal(*CUnitCommand::GetPosition(command, unit, &cell));
        NewMoveTask(goal, dispatch, 0, nullptr, 0);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Dive: {
        const ELayer layer = unit->mCurrentLayer;
        const SFootprint& footprint = unit->GetFootprint();
        const SOCellPos cell = footprint.ToCellPos(unit->GetPosition());
        SNavGoal goal(cell);
        goal.aux0 = 4 * (layer == LAYER_Sub) + 4;
        dispatch->SetNewTargetLayer(goal);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_FormMove: {
        CUnitCommand::Move(unit, command);
        if (CAiFormationInstance* const formation = CUnitCommand::InFormation(unit, command)) {
          SOCellPos cell;
          const SNavGoal goal(*CUnitCommand::GetPosition(command, unit, &cell));
          CUnitFormAndMoveTask::Create(formation, dispatch);
        } else {
          SOCellPos cell;
          const SNavGoal goal(*CUnitCommand::GetPosition(command, unit, &cell));
          NewMoveTask(goal, dispatch, 0, nullptr, 0);
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_BuildFactory: {
        if (entityBlueprint) {
          const LuaPlus::LuaObject blueprintLua =
            unitBlueprint->GetLuaBlueprint(dispatch->mSim->mLuaState);
          if (unit->RunScript("CheckBuildRestriction", blueprintLua).GetBoolean()) {
            CFactoryBuildTask::Create(dispatch, unitBlueprint, command, nullptr);
          }
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_BuildMobile: {
        if (entityBlueprint) {
          // The binary inlines Unit::CanBuild (army-buildable categories, minus the
          // unit's build restrictions, tested against the blueprint's ordinal bit);
          // the 2007 source called CanBuild and the compiler inlined it here.
          if (unit->CanBuild(unitBlueprint)) {
            const LuaPlus::LuaObject blueprintLua =
              unitBlueprint->GetLuaBlueprint(dispatch->mSim->mLuaState);
            if (unit->RunScript("CheckBuildRestriction", blueprintLua).GetBoolean()) {
              const Wm3::Vector3f buildDirection = command->mVarDat.mTarget2.mPos;
              const Wm3::Quatf buildOrientation = command->mConstDat.origin;
              const Wm3::Vector3f buildPosition = command->mTarget.GetTargetPosGun(false);
              CUnitMobileBuildTask::Create(dispatch, unitBlueprint, buildPosition, buildOrientation, buildDirection);
            }
          }
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_BuildAssist: {
        gpg::Logf("UNITCOMMAND_BuildAssist not implemented");
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Attack: {
        CUnitCommand::Move(unit, command);
        CAiFormationInstance* const formation = CUnitCommand::InFormation(unit, command);
        CAttackTargetTask::Create(dispatch, &command->mTarget, formation);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_FormAttack: {
        CUnitCommand::Move(unit, command);
        CAiFormationInstance* const formation = CUnitCommand::InFormation(unit, command);
        CAttackTargetTask::CreateRespectFormation(dispatch, &command->mTarget, formation, false);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Nuke: {
        CUnitFireAtTask::Create(dispatch, &command->mTarget, 1);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Tactical: {
        CUnitFireAtTask::Create(dispatch, &command->mTarget, 0);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Teleport: {
        CUnitTeleportTask::Create(&command->mTarget, dispatch, unit, &unit->GetTransform());
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Guard: {
        if (command->mTarget.HasTarget()) {
          if (command->mTarget.GetEntity() == nullptr) {
            CUnitCommand::Move(unit, command);
          }
          CUnitGuardTask::Create(dispatch, &command->mTarget);
        } else {
          dispatch->Stop();
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Patrol: {
        SOCellPos cell;
        const SNavGoal goal(*CUnitCommand::GetPosition(command, unit, &cell));
        CUnitPatrolTask::Create(dispatch, &goal, false);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Ferry: {
        CUnitFerryTask::CreateFromDispatch(dispatch, unit->GetPosition());
        return;
      }

      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove: {
        CUnitCommand::Move(unit, command);
        SOCellPos cell;
        const SNavGoal goal(*CUnitCommand::GetPosition(command, unit, &cell));
        CAiFormationInstance* const formation = CUnitCommand::InFormation(unit, command);
        CUnitPatrolTask::Create(dispatch, &goal, formation != nullptr);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Reclaim: {
        dispatch->IssueReclaimTask(command->mTarget);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Repair: {
        Entity* const focus = CUnitCommand::GetFocus(command);
        if (!focus) {
          return;
        }
        Unit* creator = nullptr;
        if (Unit* const focusUnit = focus->IsUnit()) {
          creator = focusUnit;
        } else if (ReconBlip* const blip = focus->IsReconBlip()) {
          creator = blip->GetCreator();
        } else {
          return;
        }
        if (creator) {
          (void)new (std::nothrow) CUnitRepairTask(dispatch, creator, false);
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Capture: {
        CUnitCaptureTask::Create(dispatch, &command->mTarget);
        return;
      }

      // Shared body (.c case Capture/SpecialAction @ 344-512): the transport gather.
      case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
      case EUnitCommandType::UNITCOMMAND_Dock: {
        Unit* const target = CUnitCommand::GetTarget(command);

        bool routeToFerry = false;
        if (target != nullptr) {
          if (target->IsInCategory("FERRYBEACON")) {
            routeToFerry = true;
          } else if (target->IsInCategory("FACTORY")) {
            routeToFerry = target->IsInCategory("AIRSTAGINGPLATFORM") || target->IsInCategory("TELEPORTATION");
          }
        }

        if (routeToFerry) {
          CUnitCommand::Move(unit, command);
          SOCellPos cell;
          const SNavGoal goal(*CUnitCommand::GetPosition(command, unit, &cell));
          Unit* const ferryTarget = CUnitCommand::GetTarget(command);
          CUnitWaitForFerryTask::Create(dispatch, goal, ferryTarget);
          return;
        }

        if (CUnitCommand::GetTarget(command) == unit) {
          SEntitySetTemplateUnit workingSet;
          for (CScriptObject* const entry : command->mUnitSet.mVec) {
            if (!SCommandUnitSet::IsUsableEntry(entry)) {
              continue;
            }
            if (Unit* const setUnit = SCommandUnitSet::UnitFromEntry(entry)) {
              (void)workingSet.AddUnit(setUnit);
            }
          }
          (void)workingSet.RemoveUnit(unit);

          if (unit->IsInCategory("CARRIER")) {
            if (command->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_TransportLoadUnits) {
              CUnitCarrierRetrieve::Create(dispatch, workingSet);
            } else if (IAiTransport* const transport = unit->AiTransport) {
              transport->TransportResetReservation();
            }
          } else {
            for (auto it = workingSet.mVec.begin(); it != workingSet.mVec.end();) {
              Entity* const entity = *it;
              Unit* const setUnit = entity ? entity->IsUnit() : nullptr;
              if (setUnit != nullptr && setUnit->GetTransportedBy() != nullptr) {
                (void)workingSet.RemoveUnit(setUnit);
                it = workingSet.mVec.begin(); // RemoveUnit compacts mVec; re-seek from head
              } else {
                ++it;
              }
            }
            if (!unit->IsInCategory("AIRSTAGINGPLATFORM")) {
              CUnitLoadUnits::Create(dispatch, &workingSet);
            }
          }
          return;
        }

        if (target != nullptr) {
          if (target->IsInCategory("CARRIER")) {
            if (command->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_TransportLoadUnits) {
              dispatch->IssueCarrierLandTask(target);
            } else {
              dispatch->IssueRefuelTask(target);
            }
          } else if (target->IsInCategory("AIRSTAGINGPLATFORM")) {
            dispatch->IssueRefuelTask(target);
          } else if (target->IsInCategory("TELEPORTATION")) {
            dispatch->IssueCallTeleportTask(target);
          } else if (target->mIsAir) {
            NewCallTransportCommand(dispatch, target);
          } else {
            dispatch->IssueCallLandTransportTask(target);
          }
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits: {
        if (CUnitCommand::GetTarget(command) != unit) {
          if (!unit->AiTransport || !CUnitCommand::GetTarget(command)) {
            return;
          }
          SEntitySetTemplateUnit loadSet;
          (void)loadSet.AddUnit(CUnitCommand::GetTarget(command));
          if (unit->IsInCategory("CARRIER")) {
            CUnitCarrierRetrieve::Create(dispatch, loadSet);
            return;
          }
          CUnitLoadUnits::Create(dispatch, &loadSet);
          return;
        }

        Unit* first = nullptr;
        for (CScriptObject* const entry : command->mUnitSet.mVec) {
          if (!SCommandUnitSet::IsUsableEntry(entry)) {
            continue;
          }
          Unit* const setUnit = SCommandUnitSet::UnitFromEntry(entry);
          if (setUnit == nullptr || setUnit == unit) {
            continue;
          }
          first = setUnit;
          break;
        }
        if (first == nullptr) {
          return;
        }
        if (first->IsInCategory("CARRIER")) {
          dispatch->IssueCarrierLandTask(first);
        } else if (first->IsInCategory("AIRSTAGINGPLATFORM")) {
          dispatch->IssueCallAirStagingPlatformTask(first);
        } else if (first->IsInCategory("TELEPORTATION")) {
          dispatch->IssueCallTeleportTask(first);
        } else if (first->mIsAir) {
          NewCallTransportCommand(dispatch, first);
        } else {
          dispatch->IssueCallLandTransportTask(first);
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_TransportUnloadUnits:
      case EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits: {
        IAiTransport* const transport = unit->AiTransport;
        if (!transport) {
          return;
        }
        if (transport->TransportIsTeleporter() && command->mTarget.GetEntity()) {
          transport->TransportResetReservation();
          return;
        }
        const EntitySetTemplate<Unit> loaded = transport->TransportGetLoadedUnits(false);
        if (loaded.Empty()) {
          return;
        }
        if (transport->TransportIsAirStagingPlatform()) {
          const Wm3::Vec3f targetPos = command->mTarget.GetTargetPosGun(false);
          const SOCellPos cell = unit->GetFootprint().ToCellPos(targetPos);
          const SNavGoal goal(cell);
          if (unit->IsInCategory("CARRIER")) {
            CUnitCarrierLaunch::Create(dispatch, &goal, &command->mUnitSet);
          } else {
            CUnitUnloadUnits::Create(dispatch, &goal, &command->mUnitSet, nullptr);
          }
        } else {
          CUnitCommand::Move(unit, command);
          SOCellPos cell;
          const SNavGoal goal(*CUnitCommand::GetPosition(command, unit, &cell));
          CUnitUnloadUnits::Create(dispatch, &goal, &command->mUnitSet, nullptr);
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_DetachFromTransport: {
        DetachDispatchUnitFromTransport(dispatch);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Upgrade: {
        const RUnitBlueprint* const targetBp = unitBlueprint;
        if (!targetBp) {
          return;
        }
        const RUnitBlueprint* const selfBp = unit->GetBlueprint();
        if (!targetBp->General.UpgradesFrom.name.empty()) {
          if (_stricmp(selfBp->mBlueprintId.c_str(), targetBp->General.UpgradesFrom.name.c_str()) != 0) {
            return;
          }
        } else {
          if (_stricmp(selfBp->General.UpgradesTo.name.c_str(), targetBp->mBlueprintId.c_str()) == 0) {
            CUnitUpgradeTask::Create(dispatch, targetBp);
            return;
          }
          if (_stricmp(selfBp->mBlueprintId.c_str(), targetBp->mBlueprintId.c_str()) != 0) {
            return;
          }
        }
        CUnitUpgradeTask::Create(dispatch, targetBp);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Script: {
        CUnitScriptTask::Create(dispatch, &command->mArgs);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_AssistCommander: {
        CUnitPodAssist::Create(dispatch);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_KillSelf: {
        dispatch->KillSelf();
        return;
      }

      case EUnitCommandType::UNITCOMMAND_DestroySelf: {
        unit->Destroy();
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Sacrifice: {
        Unit* const target = CUnitCommand::GetTarget(command);
        if (!target) {
          return;
        }
        if (target->IsBeingBuilt() || target->IsUnitState(UNITSTATE_Upgrading) ||
            target->MaxHealth > target->Health) {
          CUnitSacrificeTask::Create(dispatch, target);
        } else if (target->IsUnitState(UNITSTATE_Building)) {
          if (Entity* const focusEntity = target->GetFocusEntity();
              focusEntity != nullptr && static_cast<std::uint32_t>(focusEntity->id_) != 0) {
            CUnitSacrificeTask::Create(dispatch, target);
          }
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_Pause: {
        unit->SetPaused(!unit->IsPaused);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_OverCharge: {
        if (Entity* const targetEntity = command->mTarget.GetEntity()) {
          CArmyImpl* const targetArmy = targetEntity->ArmyRef;
          if (targetArmy == nullptr ||
              unit->ArmyRef->GetAllianceWith(targetArmy) != EAlliance::ALLIANCE_Ally) {
            CAttackTargetTask::CreateRespectFormation(dispatch, &command->mTarget, nullptr, true);
          }
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_AggressiveMove: {
        CUnitCommand::Move(unit, command);
        SOCellPos cell;
        const SNavGoal goal(*CUnitCommand::GetPosition(command, unit, &cell));
        CUnitPatrolTask::Create(dispatch, &goal, true);
        return;
      }

      case EUnitCommandType::UNITCOMMAND_AssistMove: {
        // .c FormAggressiveMove label @ 752-777 + 789-877 (real enum = AssistMove):
        // partition the command unit-set into transports vs mobile-land units; when
        // both are non-empty, dispatch an assist-move (transport) or a move variant.
        CUnitCommand::Move(unit, command);

        SEntitySetTemplateUnit transportSet;
        SEntitySetTemplateUnit mobileLandSet;
        for (CScriptObject* const entry : command->mUnitSet.mVec) {
          if (!SCommandUnitSet::IsUsableEntry(entry)) {
            continue;
          }
          Unit* const setUnit = SCommandUnitSet::UnitFromEntry(entry);
          if (setUnit == nullptr) {
            continue;
          }
          if (setUnit->IsInCategory("TRANSPORTATION")) {
            (void)transportSet.AddUnit(setUnit);
          } else if (setUnit->IsInCategory("MOBILE") && setUnit->IsInCategory("LAND")) {
            (void)mobileLandSet.AddUnit(setUnit);
          }
        }

        if (!transportSet.Empty() && !mobileLandSet.Empty()) {
          SOCellPos cell;
          const SNavGoal goal(*CUnitCommand::GetPosition(command, unit, &cell));
          if (unit->IsInCategory("TRANSPORTATION")) {
            CUnitAssistMoveTask::Create(dispatch, &goal);
          } else {
            NewMoveTask(goal, dispatch, 1, nullptr, 0);
          }
        }
        return;
      }

      case EUnitCommandType::UNITCOMMAND_SpecialAction: {
        // .c AssistMove label @ 778-785 (real enum = SpecialAction).
        const Wm3::Vec3f actionPos = command->mTarget.GetTargetPosGun(false);
        const LuaPlus::LuaObject actionArg = SCR_ToLua<Wm3::Vector3<float>>(dispatch->mSim->mLuaState, actionPos);
        unit->RunScript("OnSpecialAction", actionArg);
        return;
      }

      default:
        return;
    }
  }
} // namespace

gpg::RType* IAiCommandDispatchImpl::sType = nullptr;

/**
 * Address: 0x00599470 (FUN_00599470, ?AI_CreateCommandDispatch@Moho@@YAPAVIAiCommandDispatch@1@PAVUnit@1@_N@Z)
 *
 * What it does:
 * Allocates one command-dispatch implementation lane for `unit`, then runs
 * the startup built-task child allocation lane used by command queue dispatch
 * initialization.
 */
IAiCommandDispatch* moho::AI_CreateCommandDispatch(Unit* const unit)
{
  auto* const dispatch = new (std::nothrow) IAiCommandDispatchImplConstructed(unit);
  (void)new (std::nothrow) CUnitGetBuiltTask(static_cast<CCommandTask*>(dispatch));
  return dispatch ? static_cast<IAiCommandDispatch*>(dispatch) : nullptr;
}

/**
 * Address: 0x005990B0 (FUN_005990B0, ??0IAiCommandDispatchImpl@Moho@@AAE@XZ)
 */
IAiCommandDispatchImpl::IAiCommandDispatchImpl()
  : CCommandTask()
  , IAiCommandDispatch()
  , Listener<EUnitCommandQueueStatus>()
  , mState(0)
  , mPadding41{}
  , mCommandQueue(nullptr)
{}

/**
 * Address: 0x00598D00 (FUN_00598D00, ??0IAiCommandDispatchImpl@Moho@@QAE@PAVUnit@1@PAVCTaskThread@1@PAW4EAiResult@1@@Z)
 */
IAiCommandDispatchImpl::IAiCommandDispatchImpl(Unit* const unit)
  : CCommandTask(unit, unit ? unit->SimulationRef : nullptr)
  , IAiCommandDispatch()
  , Listener<EUnitCommandQueueStatus>()
  , mState(0)
  , mPadding41{}
  , mCommandQueue(unit ? unit->CommandQueue : nullptr)
{
  if (mSim != nullptr) {
    (void)CreateTaskThreadForDispatch(static_cast<CTask*>(this), &mSim->mTaskStageA, false);
  }

  if (mCommandQueue != nullptr) {
    mListenerLink.ListLinkBefore(static_cast<Broadcaster*>(mCommandQueue));
  }
}

/**
 * Address: 0x005990F0 (FUN_005990F0, scalar deleting thunk)
 * Address: 0x00598DD0 (FUN_00598DD0, non-deleting body)
 */
IAiCommandDispatchImpl::~IAiCommandDispatchImpl()
{
  mListenerLink.ListUnlink();

  CTaskThread* const taskThread = mOwnerThread;
  if (taskThread != nullptr) {
    (void)taskThread->Destroy();
  }

  mListenerLink.ListUnlink();
}

/**
 * Address: 0x00599030 (FUN_00599030, ?OnEvent@IAiCommandDispatchImpl@Moho@@UAEXW4EUnitCommandQueueStatus@2@@Z)
 */
void IAiCommandDispatchImpl::OnEvent(const EUnitCommandQueueStatus event)
{
  if (event == EUnitCommandQueueStatus::UCQS_CommandInserted) {
    if (mUnit != nullptr) {
      mUnit->UpdateSpeedThroughStatus();
    }
    return;
  }

  if (event > EUnitCommandQueueStatus::UCQS_Changed && event <= EUnitCommandQueueStatus::UCQS_NeedsRefresh) {
    if (mOwnerThread != nullptr) {
      mOwnerThread->mPendingFrames = 0;
      if (mOwnerThread->mStaged) {
        mOwnerThread->Unstage();
      }
      TaskInterruptSubtasks();
    }
    mState = 0u;
  }
}

/**
 * Address: 0x0060A490 (FUN_0060A490, Moho::IAiCommandDispatchImpl::Stop)
 *
 * What it does:
 * Stops the unit's AI-side attack/silo work, requests a UI refresh, and marks
 * the dispatch result as stopped.
 */
int IAiCommandDispatchImpl::Stop()
{
  if (mUnit->AiAttacker != nullptr) {
    mUnit->AiAttacker->Stop();
  }

  if (mUnit->AiSiloBuild != nullptr) {
    mUnit->AiSiloBuild->SiloStopBuild();
  }

  mUnit->VarDat().mDidRefresh = true;
  mLinkResult = static_cast<EAiResult>(1);
  return 1;
}

/**
 * Address: 0x0060B850 (FUN_0060B850, Moho::IAiCommandDispatchImpl::KillSelf)
 *
 * What it does:
 * Routes the owned unit through the standard entity kill path using the
 * recovered `"Damage"` reason lane.
 */
int IAiCommandDispatchImpl::KillSelf()
{
  mUnit->Kill(mUnit, "Damage", 0.0f);
  return 1;
}

/**
 * Address: 0x0060B890 (FUN_0060B890, Moho::IAiCommandDispatchImpl::SetNewTargetLayer)
 *
 * What it does:
 * Applies the recovered navigation goal layer to the unit motion controller.
 */
void IAiCommandDispatchImpl::SetNewTargetLayer(const SNavGoal& goal)
{
  mUnit->UnitMotion->SetNewTargetLayer(goal.mLayer);
}

/**
 * Address: 0x00606D80 (FUN_00606D80, Moho::IAiCommandDispatchImpl::IssueCarrierLandTask)
 *
 * What it does:
 * Validates a carrier target, warns on illegal carriers, and schedules the
 * recovered carrier-land task lane.
 */
void IAiCommandDispatchImpl::IssueCarrierLandTask(Unit* const unit)
{
  if (!unit || unit->IsDead()) {
    return;
  }

  if (unit->AiTransport == nullptr) {
    gpg::Die("Attepted to load on illegal carrier %s", BlueprintIdOrUnknown(unit));
  }

  (void)new (std::nothrow) CUnitCarrierLandDispatchTask(this, unit);
}

/**
 * Address: 0x0061EF60 (FUN_0061EF60, Moho::IAiCommandDispatchImpl::IssueReclaimTask)
 *
 * What it does:
 * Validates the target entity lane, then schedules the recovered reclaim task
 * using the target's gun position.
 */
void IAiCommandDispatchImpl::IssueReclaimTask(const CAiTarget& target)
{
  Entity* const targetEntity = target.GetEntity();
  if (targetEntity == nullptr) {
    mLinkResult = static_cast<EAiResult>(2);
    return;
  }

  const Wm3::Vec3f targetPos = const_cast<CAiTarget&>(target).GetTargetPosGun(false);
  (void)new (std::nothrow) CUnitReclaimDispatchTask(this, targetEntity, targetPos);
}

/**
 * Address: 0x00598E80 (FUN_00598E80, ?TaskTick@IAiCommandDispatchImpl@Moho@@UAE?AW4ETaskStatus@2@XZ)
 *
 * What it does:
 * Advances the command-dispatch state machine. When idle, it waits for the
 * unit to be able to consume queue work and then hands the current head
 * command to the dispatch shim. When a linked command has completed, it folds
 * the queue state back into the current command, rotates or removes entries as
 * needed, and then re-enters the dispatch-ready check.
 */
ETaskStatus IAiCommandDispatchImpl::TaskTick()
{
  auto tryDispatchHead = [this]() -> ETaskStatus {
    if (mUnit == nullptr || mCommandQueue == nullptr) {
      return static_cast<ETaskStatus>(1);
    }

    if (mUnit->IsBeingBuilt() || mUnit->IsDead() || mUnit->IsUnitState(UNITSTATE_Attached) ||
        mUnit->IsUnitState(UNITSTATE_BlockCommandQueue)) {
      return static_cast<ETaskStatus>(1);
    }

    if (mCommandQueue->Finished()) {
      return static_cast<ETaskStatus>(1);
    }

    CUnitCommand* const currentCommand = mCommandQueue->GetCurrentCommand();
    if (!currentCommand) {
      return static_cast<ETaskStatus>(1);
    }

    mState = 1u;
    mLinkResult = static_cast<EAiResult>(0);
    DispatchQueuedCommand(this, currentCommand);
    return static_cast<ETaskStatus>(0);
  };

  if (mState == 0u) {
    return tryDispatchHead();
  }

  CUnitCommandQueue* const commandQueue = mCommandQueue;
  CUnitCommand* const currentCommand = commandQueue != nullptr ? commandQueue->GetCurrentCommand() : nullptr;
  mState = 0u;

  if (currentCommand == nullptr || commandQueue == nullptr) {
    return tryDispatchHead();
  }

  if (mLinkResult == static_cast<EAiResult>(2)) {
    const EUnitCommandType commandType = currentCommand->mVarDat.mCmdType;
    if (commandType == EUnitCommandType::UNITCOMMAND_Patrol || commandType == EUnitCommandType::UNITCOMMAND_FormPatrol) {
      commandQueue->MoveFirstCommandToBackOfQueue();
    } else {
      commandQueue->RemoveFirstCommandFromQueue();
    }

    return tryDispatchHead();
  }

  if (currentCommand->mVarDat.mCount > 1) {
    currentCommand->mVarDat.mCount -= 1;
    currentCommand->mNeedsUpdate = true;
    return tryDispatchHead();
  }

  if (mUnit != nullptr && mUnit->RepeatQueueEnabled != 0 &&
      currentCommand->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_BuildFactory) {
    currentCommand->mVarDat.mCount = currentCommand->mVarDat.mMaxCount;
    currentCommand->mNeedsUpdate = true;
    commandQueue->MoveFirstCommandToBackOfQueue();
    return static_cast<ETaskStatus>(1);
  }

  if (currentCommand->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_Attack) {
    if (currentCommand->mTarget.targetType != EAiTargetType::AITARGET_Ground) {
      commandQueue->RemoveFirstCommandFromQueue();
      return tryDispatchHead();
    }
  } else if (currentCommand->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_Patrol &&
             currentCommand->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_FormPatrol) {
    commandQueue->RemoveFirstCommandFromQueue();
    return tryDispatchHead();
  }

  if (commandQueue->GetNextCommand() != nullptr) {
    CUnitCommand::FormRemoveUnit(mUnit, currentCommand);
    commandQueue->MoveFirstCommandToBackOfQueue();
  } else {
    commandQueue->RemoveFirstCommandFromQueue();
  }

  return tryDispatchHead();
}

/**
 * Address: 0x006012B0 (FUN_006012B0, Moho::IAiCommandDispatchImpl::IssueCallTeleportTask)
 */
void IAiCommandDispatchImpl::IssueCallTeleportTask(Unit* const unit)
{
  if (!unit || unit->IsDead()) {
    return;
  }

  if (!unit->IsInCategory("TELEPORTATION")) {
    gpg::Warnf("Attepted to call illegal teleport %s", BlueprintIdOrUnknown(unit));
    return;
  }

  (void)new (std::nothrow) CUnitCallTeleport(this, unit);
}

/**
 * Address: 0x00601CE0 (FUN_00601CE0, Moho::IAiCommandDispatchImpl::IssueCallAirStagingPlatformTask)
 */
void IAiCommandDispatchImpl::IssueCallAirStagingPlatformTask(Unit* const unit)
{
  if (!unit || unit->IsDead()) {
    return;
  }

  if (!unit->IsInCategory("AIRSTAGINGPLATFORM")) {
    gpg::Warnf("Attepted to call illegal air staging platform %s", BlueprintIdOrUnknown(unit));
    return;
  }

  (void)new (std::nothrow) CUnitCallAirStagingPlatform(this, unit);
}

/**
 * Address: 0x006007C0 (FUN_006007C0, Moho::IAiCommandDispatchImpl::IssueCallLandTransportTask)
 */
void IAiCommandDispatchImpl::IssueCallLandTransportTask(Unit* const unit)
{
  if (!unit || unit->IsDead()) {
    return;
  }

  if (unit->AiTransport != nullptr) {
    (void)new (std::nothrow) CUnitCallLandTransport(this, unit);
    return;
  }

  gpg::Warnf("Attepted to call illegal transport %s", BlueprintIdOrUnknown(unit));
}

/**
 * Address: 0x00622110 (FUN_00622110, Moho::IAiCommandDispatchImpl::IssueRefuelTask)
 */
void IAiCommandDispatchImpl::IssueRefuelTask(Unit* const unit)
{
  if (!unit || unit->IsDead() || unit->IsBeingBuilt()) {
    return;
  }

  IAiTransport* const transport = unit->AiTransport;
  if (!transport || !transport->TransportIsAirStagingPlatform()) {
    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    const char* const blueprintId = (blueprint != nullptr) ? blueprint->mBlueprintId.c_str() : "<unknown>";
    gpg::Die("Attepted to call illegal refuel on non-air staging platform %s", blueprintId);
  }

  (void)new (std::nothrow) CUnitRefuel(unit, this);
}

/**
 * Address: 0x00599330 (FUN_00599330, Moho::IAiCommandDispatchImpl::MemberConstruct)
 */
void IAiCommandDispatchImpl::MemberConstruct(
  gpg::ReadArchive* const,
  const int,
  const int,
  gpg::SerConstructResult* const result
)
{
  if (!result) {
    return;
  }

  IAiCommandDispatchImpl* const object = new (std::nothrow) IAiCommandDispatchImplConstructed();
  result->SetUnowned(MakeDispatchObjectRef(object), 0u);
}

/**
 * Address: 0x00599C80 (FUN_00599C80, Moho::IAiCommandDispatchImpl::MemberDeserialize)
 */
void IAiCommandDispatchImpl::MemberDeserialize(gpg::ReadArchive* const archive, IAiCommandDispatchImpl* const object)
{
  if (!archive || !object) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Read(CachedCCommandTaskType(), object, ownerRef);

  bool state = false;
  archive->ReadBool(&state);
  object->mState = state ? 1u : 0u;

  object->mCommandQueue = ReadCommandQueuePointer(archive, ownerRef);
}

/**
 * Address: 0x00599A30 (FUN_00599A30)
 *
 * What it does:
 * Serializer bridge thunk that forwards to `IAiCommandDispatchImpl::MemberDeserialize`.
 */
[[maybe_unused]] void IAiCommandDispatchImplMemberDeserializeBridgeA(
  gpg::ReadArchive* const archive,
  IAiCommandDispatchImpl* const object
)
{
  IAiCommandDispatchImpl::MemberDeserialize(archive, object);
}

/**
 * Address: 0x00599C60 (FUN_00599C60)
 *
 * What it does:
 * Serializer bridge thunk that forwards to `IAiCommandDispatchImpl::MemberDeserialize`.
 */
[[maybe_unused]] void IAiCommandDispatchImplMemberDeserializeBridgeB(
  gpg::ReadArchive* const archive,
  IAiCommandDispatchImpl* const object
)
{
  IAiCommandDispatchImpl::MemberDeserialize(archive, object);
}

/**
 * Address: 0x00599CF0 (FUN_00599CF0, Moho::IAiCommandDispatchImpl::MemberSerialize)
 */
void IAiCommandDispatchImpl::MemberSerialize(const IAiCommandDispatchImpl* const object, gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Write(CachedCCommandTaskType(), object, ownerRef);
  archive->WriteBool(object && object->mState != 0u);

  const gpg::RRef queueRef = MakeCommandQueueRef(object ? object->mCommandQueue : nullptr);
  gpg::WriteRawPointer(archive, queueRef, gpg::TrackedPointerState::Unowned, ownerRef);
}
