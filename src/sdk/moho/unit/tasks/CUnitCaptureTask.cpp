#include "moho/unit/tasks/CUnitCaptureTask.h"

#include <algorithm>
#include <cmath>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"
#include "moho/render/camera/VTransform.h"

namespace moho
{
  [[nodiscard]]
  bool PrepareMove(int moveFlags, Unit* unit, Wm3::Vector3f* inOutPos, gpg::Rect2f* outSkirtRect, bool useWholeMap);
} // namespace moho

namespace
{
  gpg::SerSaveLoadHelperListRuntime gCUnitCaptureTaskSerializer{};

  /**
   * Address: 0x00604300 (FUN_00604300)
   *
   * What it does:
   * Unlinks `CUnitCaptureTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCaptureTaskSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitCaptureTaskSerializer);
  }

  /**
   * Address: 0x00604330 (FUN_00604330)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitCaptureTaskSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCaptureTaskSerializerNodeSecondary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitCaptureTaskSerializer);
  }
} // namespace

namespace
{
  constexpr const char* kOnAssignedFocusEntityScript = "OnAssignedFocusEntity";
  constexpr const char* kOnStartBeingCapturedScript = "OnStartBeingCaptured";
  constexpr const char* kOnStartCaptureScript = "OnStartCapture";
  constexpr const char* kOnFailedBeingCapturedScript = "OnFailedBeingCaptured";
  constexpr const char* kOnFailedCaptureScript = "OnFailedCapture";
  constexpr const char* kOnStopCaptureScript = "OnStopCapture";
  constexpr const char* kOnStopBeingCapturedScript = "OnStopBeingCaptured";
  constexpr const char* kOnCapturedScript = "OnCaptured";
  constexpr const char* kGetCaptureCostsScript = "GetCaptureCosts";
  constexpr const char* kCaptureCostsError = "Failed to get valid capture costs from the target";

  struct CUnitCommandCommandEventLinkView
  {
    std::uint8_t pad_0000_0034[0x34];
    moho::Broadcaster mCommandEventListenerHead;
  };

  static_assert(
    offsetof(CUnitCommandCommandEventLinkView, mCommandEventListenerHead) == 0x34,
    "CUnitCommandCommandEventLinkView::mCommandEventListenerHead offset must be 0x34"
  );

  [[nodiscard]] moho::Broadcaster* CommandEventListenerHead(moho::CUnitCommand* const command) noexcept
  {
    if (!command) {
      return nullptr;
    }

    auto* const view = reinterpret_cast<CUnitCommandCommandEventLinkView*>(command);
    return &view->mCommandEventListenerHead;
  }

  [[nodiscard]] moho::Entity* ResolveCaptureTargetEntity(const moho::CAiTarget* const commandTarget) noexcept
  {
    if (commandTarget == nullptr) {
      return nullptr;
    }

    return commandTarget->targetEntity.GetObjectPtr();
  }

  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState current) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<int>(current) + 1);
  }

  void WakeTaskThreadForImmediateTick(moho::CTaskThread* const ownerThread)
  {
    if (ownerThread == nullptr) {
      return;
    }

    ownerThread->mPendingFrames = 0;
    if (ownerThread->mStaged) {
      ownerThread->Unstage();
    }
  }

  void DestroyEconomyRequestPointer(moho::CEconRequest*& request)
  {
    if (request == nullptr) {
      return;
    }

    request->mNode.ListUnlink();
    delete request;
    request = nullptr;
  }

  void ReplaceEconomyRequestPointer(moho::CEconRequest*& request, moho::CEconRequest* const replacement)
  {
    DestroyEconomyRequestPointer(request);
    request = replacement;
  }

  [[nodiscard]] moho::CEconRequest* CreateEconomyRequest(
    const moho::SEconValue& requested,
    moho::CSimArmyEconomyInfo* const economy
  )
  {
    auto* const request = new moho::CEconRequest{};
    request->mRequested = requested;
    request->mGranted.energy = 0.0f;
    request->mGranted.mass = 0.0f;

    if (economy != nullptr) {
      request->mNode.ListLinkBefore(&economy->registrationNode);
    }
    return request;
  }

  [[nodiscard]] moho::SEconValue TakeGrantedResourcesAndReset(moho::CEconRequest* const request) noexcept
  {
    moho::SEconValue out{};
    out.energy = request->mGranted.energy;
    out.mass = request->mGranted.mass;
    request->mGranted.energy = 0.0f;
    request->mGranted.mass = 0.0f;
    return out;
  }

  [[nodiscard]] int MaxFootprintExtent(const moho::SFootprint& footprint) noexcept
  {
    return std::max(static_cast<int>(footprint.mSizeX), static_cast<int>(footprint.mSizeZ));
  }

  [[nodiscard]] float HorizontalDistanceToCaptureContact(const moho::Unit& unit, const moho::Entity& targetEntity)
  {
    const auto& unitPosition = unit.GetPosition();
    const auto& targetPosition = targetEntity.GetPositionWm3();

    const float dx = targetPosition.x - unitPosition.x;
    const float dz = targetPosition.z - unitPosition.z;
    const float rawDistance = std::sqrt((dx * dx) + (dz * dz));

    const int unitExtent = MaxFootprintExtent(unit.GetFootprint());
    const int targetExtent = MaxFootprintExtent(targetEntity.GetFootprint());
    return rawDistance - static_cast<float>(unitExtent) - static_cast<float>(targetExtent);
  }

  [[nodiscard]] bool IsTargetCaptureCapable(const moho::Entity* const targetEntity, const moho::Unit* const targetUnit)
  {
    if (targetEntity == nullptr) {
      return false;
    }

    if (targetUnit == nullptr) {
      return true;
    }

    return targetUnit->GetAttributes().mCapturable;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrEntityType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Entity>::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Entity>));
      moho::WeakPtr<moho::Entity>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    gpg::RType* type = moho::SEconValue::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::SEconValue));
      moho::SEconValue::sType = type;
    }
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00603F40 (FUN_00603F40, Moho::CUnitCaptureTask::CUnitCaptureTask)
   *
   * What it does:
   * Initializes capture-task command/listener slices and zeroes capture
   * bookkeeping/economy lanes.
   */
  CUnitCaptureTask::CUnitCaptureTask()
    : CCommandTask()
    , CUnitCaptureTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mCommand(nullptr)
    , mTargetEntity{}
    , mHasStarted(false)
    , mPad4D{0, 0, 0}
    , mCaptureProgress(0)
    , mCaptureTime(0)
    , mConsumptionData(nullptr)
    , mCaptureRate{0.0f, 0.0f}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mTargetEntity.ClearLinkState();
  }

  /**
   * Address: 0x00603F90 (FUN_00603F90, ??0CUnitCaptureTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one capture-task lane from parent dispatch context, binds
   * target/listener ownership links, and seeds owner focus/target blip state.
   */
  CUnitCaptureTask::CUnitCaptureTask(CCommandTask* const parentTask, Entity* const targetEntity)
    : CCommandTask(parentTask)
    , CUnitCaptureTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mCommand(nullptr)
    , mTargetEntity{}
    , mHasStarted(false)
    , mPad4D{0, 0, 0}
    , mCaptureProgress(0)
    , mCaptureTime(0)
    , mConsumptionData(nullptr)
    , mCaptureRate{0.0f, 0.0f}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mTargetEntity.ResetFromObject(targetEntity);

    if (mUnit != nullptr) {
      CAiTarget updatedTarget{};
      updatedTarget.UpdateTarget(targetEntity);
      mUnit->FocusEntityRef.ResetObjectPtr<Entity>(updatedTarget.GetEntity());
      if (mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
        mUnit->RunScript(kOnAssignedFocusEntityScript);
      }
      mUnit->NeedSyncGameData = true;

      Entity* const targetBlip = (targetEntity != nullptr) ? targetEntity->IsReconBlip() : nullptr;
      mUnit->TargetBlipEntityRef.ResetObjectPtr<Entity>(targetBlip);
      mUnit->NeedSyncGameData = true;
    }

    if (mUnit != nullptr && mUnit->CommandQueue != nullptr) {
      mCommand = mUnit->CommandQueue->GetCurrentCommand();
      if (Broadcaster* const commandListenerHead = CommandEventListenerHead(mCommand); commandListenerHead != nullptr) {
        mListenerLink.ListLinkBefore(commandListenerHead);
      }
    }
  }

  /**
   * Address: 0x00604360 (FUN_00604360, ??2CUnitCaptureTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Resolves one capture target from command payload, writes dispatch failure
   * result when absent, and allocates/constructs one capture-task object.
   */
  CUnitCaptureTask* CUnitCaptureTask::Create(CCommandTask* const parentTask, CAiTarget* const commandTarget)
  {
    Entity* const targetEntity = ResolveCaptureTargetEntity(commandTarget);
    if (targetEntity == nullptr) {
      if (parentTask != nullptr) {
        parentTask->mLinkResult = static_cast<EAiResult>(2);
      }
      return nullptr;
    }

    void* const storage = ::operator new(sizeof(CUnitCaptureTask));
    if (storage == nullptr) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitCaptureTask(parentTask, targetEntity);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x006043E0 (FUN_006043E0, Moho::CUnitCaptureTask::TaskTick)
   *
   * What it does:
   * Runs capture-task state transitions from range/setup through capture-cost
   * budgeting, economy-consumption progress, and final capture callbacks.
   */
  int CUnitCaptureTask::TaskTick()
  {
    Entity* targetEntity = mTargetEntity.GetObjectPtr();
    Unit* targetUnit = (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;
    if (!IsTargetCaptureCapable(targetEntity, targetUnit)) {
      mUnit->RunScriptUnit(kOnStopCaptureScript, mUnit);
      *mDispatchResult = static_cast<EAiResult>(1);
      return -1;
    }

    if (
      targetEntity->ArmyRef == nullptr || targetEntity->mCurrentLayer == LAYER_Air
      || targetEntity->ArmyRef->GetAllianceWith(mUnit->ArmyRef) == ALLIANCE_Ally
    ) {
      *mDispatchResult = static_cast<EAiResult>(2);
      return -1;
    }

    const float distance = HorizontalDistanceToCaptureContact(*mUnit, *targetEntity);
    if (
      targetEntity->mMotor != nullptr && targetUnit != nullptr && targetUnit->IsUnitState(UNITSTATE_BeingCaptured)
      && distance > 10.0f
    ) {
      *mDispatchResult = static_cast<EAiResult>(2);
      return -1;
    }

    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        if (distance > 5.0f) {
          Wm3::Vec3f targetPosition = targetEntity->GetTransformWm3().pos_;
          if (!mUnit->mIsAir) {
            gpg::Rect2f moveSkirt{0.0f, 0.0f, 0.0f, 0.0f};
            if (Unit* const unitTarget = targetEntity->IsUnit(); unitTarget != nullptr) {
              moveSkirt = unitTarget->GetSkirtRect();
            }

            const bool useWholeMap = (mUnit->ArmyRef != nullptr) ? mUnit->ArmyRef->UseWholeMap() : false;
            (void)PrepareMove(1, mUnit, &targetPosition, &moveSkirt, useWholeMap);

            const SCoordsVec2 targetPos2d{targetPosition.x, targetPosition.z};
            gpg::Rect2i reserveRect{};
            (void)COORDS_ToGridRect(&reserveRect, targetPos2d, mUnit->GetFootprint());
            mUnit->ReserveOgridRect(reserveRect);
          }

          const SOCellPos targetCell = mUnit->GetFootprint().ToCellPos(targetPosition);
          NewMoveTask(SNavGoal(targetCell), this, 0, nullptr, 0);
        }

        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Waiting: {
        if (distance > 10.0f) {
          *mDispatchResult = static_cast<EAiResult>(2);
          return -1;
        }

        if (ReconBlip* const reconBlip = targetEntity->IsReconBlip(); reconBlip != nullptr) {
          Unit* const creator = reconBlip->GetCreator();
          mTargetEntity.Set(static_cast<Entity*>(creator));
          targetEntity = mTargetEntity.GetObjectPtr();
          targetUnit = (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;
        }

        if (targetEntity == nullptr || targetUnit == nullptr || targetUnit->IsDead() || targetUnit->DestroyQueued()) {
          return -1;
        }

        if (mUnit->AiBuilder != nullptr) {
          const VTransform targetTransform = targetEntity->GetBoneWorldTransform(-1);
          mUnit->AiBuilder->BuilderSetAimTarget(targetTransform.pos_);
        }

        mUnit->UnitStateMask |= (1ull << UNITSTATE_Capturing);
        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Starting: {
        if (targetEntity == nullptr) {
          return -1;
        }

        gpg::core::FastVector<LuaPlus::LuaObject> captureCostResults;
        LuaPlus::LuaObject arg2{};
        LuaPlus::LuaObject arg3{};
        LuaPlus::LuaObject arg4{};
        LuaPlus::LuaObject arg5{};
        if (
          !mUnit->RunScriptMultiRet(
            kGetCaptureCostsScript,
            captureCostResults,
            targetEntity->mLuaObj,
            arg2,
            arg3,
            arg4,
            arg5
          )
          || captureCostResults.size() != 3
        ) {
          gpg::Warnf(kCaptureCostsError);
          return -1;
        }

        mCaptureTime += static_cast<int>(std::max(1.0f, static_cast<float>(captureCostResults[0].ToNumber() * 10.0)));
        float energyCost = captureCostResults[1].ToNumber();
        float massCost = captureCostResults[2].ToNumber();

        const msvc8::vector<Entity*>& attachedEntities = targetEntity->GetAttachedEntities();
        for (Entity* const attachedEntity : attachedEntities) {
          Unit* const attachedUnit = (attachedEntity != nullptr) ? attachedEntity->IsUnit() : nullptr;
          if (attachedUnit == nullptr || attachedUnit->IsDead()) {
            continue;
          }

          gpg::core::FastVector<LuaPlus::LuaObject> attachedCaptureCosts;
          LuaPlus::LuaObject attachedArg2{};
          LuaPlus::LuaObject attachedArg3{};
          LuaPlus::LuaObject attachedArg4{};
          LuaPlus::LuaObject attachedArg5{};
          if (
            !mUnit->RunScriptMultiRet(
              kGetCaptureCostsScript,
              attachedCaptureCosts,
              attachedUnit->mLuaObj,
              attachedArg2,
              attachedArg3,
              attachedArg4,
              attachedArg5
            )
            || attachedCaptureCosts.size() != 3
          ) {
            continue;
          }

          mCaptureTime += static_cast<int>(std::max(1.0f, static_cast<float>(attachedCaptureCosts[0].ToNumber() * 10.0)));
          energyCost += attachedCaptureCosts[1].ToNumber();
          massCost += attachedCaptureCosts[2].ToNumber();
        }

        if (energyCost < 0.0f) {
          energyCost = 0.0f;
        }
        if (massCost < 0.0f) {
          massCost = 0.0f;
        }

        const float captureTimeAsFloat = static_cast<float>(mCaptureTime);
        mCaptureRate.energy = energyCost / captureTimeAsFloat;
        mCaptureRate.mass = massCost / captureTimeAsFloat;

        CSimArmyEconomyInfo* const economyInfo = mUnit->ArmyRef->GetEconomy();
        ReplaceEconomyRequestPointer(mConsumptionData, CreateEconomyRequest(mCaptureRate, economyInfo));

        DoCallback(true);
        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Processing: {
        if (mConsumptionData->mGranted.energy >= mCaptureRate.energy && mConsumptionData->mGranted.mass >= mCaptureRate.mass) {
          const SEconValue granted = TakeGrantedResourcesAndReset(mConsumptionData);
          mUnit->mBeatResourceAccumulators.resourcesSpentEnergy += granted.energy;
          mUnit->mBeatResourceAccumulators.resourcesSpentMass += granted.mass;

          targetEntity = mTargetEntity.GetObjectPtr();
          targetUnit = (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;
          if (targetUnit != nullptr) {
            int captureProgress = mCaptureProgress + targetUnit->CaptorCount;
            if (captureProgress > mCaptureTime) {
              captureProgress = mCaptureTime;
            }
            mCaptureProgress = captureProgress;
            mUnit->WorkProgress = static_cast<float>(mCaptureProgress) / static_cast<float>(mCaptureTime);
          }
        }

        if (mCaptureProgress < mCaptureTime) {
          return 1;
        }

        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Complete: {
        mUnit->RunScriptWeakEntity(kOnStopCaptureScript, mTargetEntity);

        targetEntity = mTargetEntity.GetObjectPtr();
        if (targetEntity != nullptr) {
          targetEntity->RunScriptUnit(kOnStopBeingCapturedScript, mUnit);
          targetEntity->RunScriptUnit(kOnCapturedScript, mUnit);
        }

        return -1;
      }

      default:
        gpg::HandleAssertFailure(
          "Reached the supposably unreachable.",
          276,
          "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitCapture.cpp"
        );
        return 1;
    }
  }

  int CUnitCaptureTask::Execute()
  {
    return TaskTick();
  }

  /**
   * Address: 0x00605BA0 (FUN_00605BA0, Moho::CUnitCaptureTask::MemberSerialize)
   *
   * What it does:
   * Saves base command-task state plus capture-task command/target/economy
   * ownership lanes and capture progress/rate values.
   */
  void CUnitCaptureTask::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    gpg::RRef commandRef{};
    (void)gpg::RRef_CUnitCommand(&commandRef, mCommand);
    gpg::WriteRawPointer(archive, commandRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedWeakPtrEntityType(), &mTargetEntity, ownerRef);
    archive->WriteBool(mHasStarted);
    archive->WriteInt(mCaptureProgress);
    archive->WriteInt(mCaptureTime);

    gpg::RRef economyRequestRef{};
    (void)gpg::RRef_CEconRequest(&economyRequestRef, mConsumptionData);
    gpg::WriteRawPointer(archive, economyRequestRef, gpg::TrackedPointerState::Owned, ownerRef);

    archive->Write(CachedSEconValueType(), &mCaptureRate, ownerRef);
  }

  /**
   * Address: 0x006050F0 (FUN_006050F0, ??1CUnitCaptureTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks command/listener lanes, clears capture state from owner/target,
   * flushes economy request ownership, and tears down weak-target links.
   */
  CUnitCaptureTask::~CUnitCaptureTask()
  {
    mListenerLink.ListUnlink();

    if (mUnit != nullptr) {
      mUnit->FocusEntityRef.ResetObjectPtr<Entity>(nullptr);
      if (mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
        mUnit->RunScript(kOnAssignedFocusEntityScript);
      }
      mUnit->NeedSyncGameData = true;

      mUnit->TargetBlipEntityRef.ResetObjectPtr<Entity>(nullptr);
      mUnit->NeedSyncGameData = true;

      mUnit->UnitStateMask &= ~(1ull << UNITSTATE_Capturing);
      mUnit->WorkProgress = 0.0f;
    }

    DoCallback(false);

    if (mUnit != nullptr) {
      if (mUnit->AiBuilder != nullptr) {
        mUnit->AiBuilder->BuilderSetAimTarget(Wm3::Vector3f::Zero());
      }

      mUnit->FreeOgridRect();
    }

    DestroyEconomyRequestPointer(mConsumptionData);
    mTargetEntity.UnlinkFromOwnerChain();
    mListenerLink.ListUnlink();
  }

  /**
   * Address: 0x00604E10 (FUN_00604E10, Moho::CUnitCaptureTask::DoCallback)
   *
   * What it does:
   * Toggles target capture-state/captor-count bookkeeping and dispatches
   * start/failed capture script callbacks on owner and target lanes.
   */
  void CUnitCaptureTask::DoCallback(const bool start)
  {
    if (start == mHasStarted) {
      return;
    }

    mHasStarted = start;

    Entity* const targetEntity = mTargetEntity.GetObjectPtr();
    Unit* const targetUnit = (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;
    if (start) {
      if (targetUnit == nullptr || mUnit == nullptr) {
        return;
      }

      targetUnit->UnitStateMask |= (1ull << UNITSTATE_BeingCaptured);
      ++targetUnit->CaptorCount;

      targetUnit->RunScriptUnit(kOnStartBeingCapturedScript, mUnit);
      mUnit->RunScriptWeakEntity(kOnStartCaptureScript, mTargetEntity);
      return;
    }

    if (targetUnit == nullptr || mUnit == nullptr) {
      return;
    }

    if (targetUnit->IsBeingBuilt() || targetUnit->DestroyQueued()) {
      return;
    }

    targetUnit->DecrementCapturers();
    if (targetUnit->IsUnitState(UNITSTATE_BeingCaptured) && targetUnit->CaptorCount == 0) {
      targetUnit->UnitStateMask &= ~(1ull << UNITSTATE_BeingCaptured);
    }

    targetUnit->RunScriptUnit(kOnFailedBeingCapturedScript, mUnit);
    mUnit->RunScriptWeakEntity(kOnFailedCaptureScript, mTargetEntity);
  }

  /**
   * Address: 0x00604FC0 (FUN_00604FC0, Moho::CUnitCaptureTask::Receive)
   *
   * What it does:
   * Refreshes target/focus links from current command payload, resets capture
   * progress/economy lanes, and wakes owner task thread for immediate retick.
   */
  void CUnitCaptureTask::OnEvent(ECommandEvent)
  {
    DoCallback(false);

    Entity* const commandTargetEntity = mCommand->mTarget.GetEntity();
    Entity* const rawTargetEntity = mCommand->mTarget.targetEntity.GetObjectPtr();
    Entity* const commandTargetBlip = (rawTargetEntity != nullptr) ? rawTargetEntity->IsReconBlip() : nullptr;
    mTargetEntity.Set(commandTargetEntity);

    mUnit->FocusEntityRef.ResetObjectPtr<Entity>(commandTargetEntity);
    if (mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
      mUnit->RunScript(kOnAssignedFocusEntityScript);
    }
    mUnit->NeedSyncGameData = true;

    mUnit->TargetBlipEntityRef.ResetObjectPtr<Entity>(commandTargetBlip);
    mUnit->NeedSyncGameData = true;
    mUnit->WorkProgress = 0.0f;

    DestroyEconomyRequestPointer(mConsumptionData);
    mCaptureProgress = 0;
    mCaptureTime = 0;
    mTaskState = TASKSTATE_Preparing;
    WakeTaskThreadForImmediateTick(mOwnerThread);
  }
} // namespace moho
