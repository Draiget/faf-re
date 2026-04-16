#include "moho/unit/tasks/CUnitReclaimTask.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/entity/Prop.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CEconomy.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace moho
{
  [[nodiscard]]
  bool PrepareMove(int moveFlags, Unit* unit, Wm3::Vector3f* inOutPos, gpg::Rect2f* outSkirtRect, bool useWholeMap);
} // namespace moho

namespace
{
  constexpr const char* kOnAssignedFocusEntityScript = "OnAssignedFocusEntity";
  constexpr const char* kReclaimableCategoryName = "RECLAIMABLE";
  constexpr const char* kOnReclaimedScript = "OnReclaimed";
  constexpr const char* kGetReclaimCostsScript = "GetReclaimCosts";
  constexpr const char* kFailedReclaimCostWarning = "Failed to get valid reclaim costs from the target";
  constexpr const char* kInvalidReclaimCostWarning = "Invalid reclaim costs from the target";

  constexpr moho::EAiResult kAiResultInvalidTarget = static_cast<moho::EAiResult>(1);
  constexpr moho::EAiResult kAiResultRetryOrRetarget = static_cast<moho::EAiResult>(2);

  constexpr std::uint64_t kUnitStateNoReclaimMask = 0x0000000000008000ull;
  constexpr std::uint64_t kUnitStateReclaimingMask = 0x0000000010000000ull;

  static_assert(
    sizeof(moho::CEconomy) == sizeof(moho::CSimArmyEconomyInfo),
    "CEconomy and CSimArmyEconomyInfo layout must stay equivalent"
  );

  struct ReclaimCostInfo
  {
    float reclaimTime = 1.0f;
    float reclaimEnergy = 0.0f;
    float reclaimMass = 0.0f;
  };

  struct PausedPropReclaimOverride
  {
    bool active = false;
    float savedReclaimRate = 0.0f;
    moho::SEconValue savedReclaimPerSecond{0.0f, 0.0f};
  };

  struct CUnitReclaimTaskSerializerStartupNode
  {
    void* mVtable = nullptr;                    // +0x00
    gpg::SerHelperBase* mHelperNext = nullptr; // +0x04
    gpg::SerHelperBase* mHelperPrev = nullptr; // +0x08
    gpg::RType::load_func_t mLoad = nullptr;   // +0x0C
    gpg::RType::save_func_t mSave = nullptr;   // +0x10
  };

  static_assert(
    offsetof(CUnitReclaimTaskSerializerStartupNode, mHelperNext) == 0x04,
    "CUnitReclaimTaskSerializerStartupNode::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitReclaimTaskSerializerStartupNode, mHelperPrev) == 0x08,
    "CUnitReclaimTaskSerializerStartupNode::mHelperPrev offset must be 0x08"
  );
  static_assert(
    sizeof(CUnitReclaimTaskSerializerStartupNode) == 0x14,
    "CUnitReclaimTaskSerializerStartupNode size must be 0x14"
  );

  CUnitReclaimTaskSerializerStartupNode gCUnitReclaimTaskSerializerStartupNode{};

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(CUnitReclaimTaskSerializerStartupNode& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(CUnitReclaimTaskSerializerStartupNode& serializer) noexcept
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

  [[nodiscard]] constexpr moho::ETaskState NextTaskState(const moho::ETaskState current) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<int>(current) + 1);
  }

  [[nodiscard]] constexpr int MaxFootprintExtent(const moho::SFootprint& footprint) noexcept
  {
    return (footprint.mSizeX >= footprint.mSizeZ) ? static_cast<int>(footprint.mSizeX) : static_cast<int>(footprint.mSizeZ);
  }

  [[nodiscard]] moho::SFootprint FallbackReclaimFootprint() noexcept
  {
    moho::SFootprint footprint{};
    footprint.mSizeX = 2;
    footprint.mSizeZ = 2;
    footprint.mOccupancyCaps = static_cast<moho::EOccupancyCaps>(0);
    footprint.mFlags = static_cast<moho::EFootprintFlags>(0);
    footprint.mMaxSlope = 0.0f;
    footprint.mMinWaterDepth = 0.0f;
    footprint.mMaxWaterDepth = 0.0f;
    return footprint;
  }

  [[nodiscard]] bool QueryReclaimCosts(moho::Unit* const unit, moho::Entity* const targetEntity, ReclaimCostInfo& outCosts)
  {
    if (unit == nullptr || targetEntity == nullptr) {
      return false;
    }

    gpg::core::FastVector<LuaPlus::LuaObject> reclaimResults;
    LuaPlus::LuaObject arg2{};
    LuaPlus::LuaObject arg3{};
    LuaPlus::LuaObject arg4{};
    LuaPlus::LuaObject arg5{};
    if (
      !unit->RunScriptMultiRet(
        kGetReclaimCostsScript,
        reclaimResults,
        targetEntity->mLuaObj,
        arg2,
        arg3,
        arg4,
        arg5
      )
      || reclaimResults.size() != 3
    ) {
      return false;
    }

    outCosts.reclaimTime = static_cast<float>(reclaimResults[0].ToNumber() * 10.0);
    if (outCosts.reclaimTime < 1.0f) {
      outCosts.reclaimTime = 1.0f;
    }

    outCosts.reclaimEnergy = static_cast<float>(reclaimResults[1].ToNumber());
    outCosts.reclaimMass = static_cast<float>(reclaimResults[2].ToNumber());
    return true;
  }

  [[nodiscard]] moho::CEconomy* ResolveArmyEconomy(moho::Unit* const unit) noexcept
  {
    if (unit == nullptr || unit->ArmyRef == nullptr) {
      return nullptr;
    }

    moho::CSimArmyEconomyInfo* const economyInfo = unit->ArmyRef->GetEconomy();
    if (economyInfo == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<moho::CEconomy*>(economyInfo);
  }

  void AwardReclaimedResources(
    moho::Unit* const unit,
    const float appliedFractionDelta,
    const float reclaimRate,
    const moho::SEconValue& reclaimPerSecond
  )
  {
    moho::CEconomy* const economy = ResolveArmyEconomy(unit);
    if (economy == nullptr) {
      return;
    }

    const float multiplier = appliedFractionDelta / reclaimRate;
    const float reclaimedEnergy = reclaimPerSecond.energy * multiplier;
    const float reclaimedMass = reclaimPerSecond.mass * multiplier;

    economy->mResources.energy += reclaimedEnergy;
    economy->mResources.mass += reclaimedMass;
    economy->mTotals.mReclaimed.ENERGY += reclaimedEnergy;
    economy->mTotals.mReclaimed.MASS += reclaimedMass;
  }

  [[nodiscard]] gpg::RType* CachedCUnitReclaimTaskType()
  {
    gpg::RType* type = moho::CUnitReclaimTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitReclaimTask));
      moho::CUnitReclaimTask::sType = type;
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

  [[nodiscard]] gpg::RType* CachedWeakPtrEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::Entity>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    gpg::RType* type = moho::SEconValue::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SEconValue));
      moho::SEconValue::sType = type;
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
} // namespace

namespace moho
{
  gpg::RType* CUnitReclaimTask::sType = nullptr;

  /**
   * Address: 0x0061EB00 (FUN_0061EB00, sub_61EB00)
   *
   * What it does:
   * Initializes reclaim-task command/listener base slices and resets task
   * runtime lanes used by reflection allocation paths.
   */
  CUnitReclaimTask::CUnitReclaimTask()
    : CCommandTask()
    , CUnitReclaimTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mCommand(nullptr)
    , mTargetEntity{}
    , mTargetHasNoMotor(false)
    , mPad4D{0, 0, 0}
    , mTargetPosition{}
    , mHasStarted(false)
    , mPad5D{0, 0, 0}
    , mConsumptionData(nullptr)
    , mReclaimRate(0.0f)
    , mReclaimPerSecond{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mTargetEntity.ClearLinkState();
    mTargetPosition.x = 0.0f;
    mTargetPosition.y = 0.0f;
    mTargetPosition.z = 0.0f;
    mReclaimPerSecond.energy = 0.0f;
    mReclaimPerSecond.mass = 0.0f;
  }

  /**
   * Address: 0x0061EB60 (FUN_0061EB60, Moho::CUnitReclaimTask::CUnitReclaimTask)
   *
   * What it does:
   * Initializes one reclaim task from dispatch context, target entity, and
   * target position snapshot, then seeds economy/request and command-listener
   * lanes.
   */
  CUnitReclaimTask::CUnitReclaimTask(
    CCommandTask* const parentTask,
    Entity* const targetEntity,
    const Wm3::Vector3f& targetPos
  )
    : CCommandTask(parentTask)
    , CUnitReclaimTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mCommand(nullptr)
    , mTargetEntity{}
    , mTargetHasNoMotor(false)
    , mPad4D{0, 0, 0}
    , mTargetPosition(targetPos)
    , mHasStarted(false)
    , mPad5D{0, 0, 0}
    , mConsumptionData(nullptr)
    , mReclaimRate(0.0f)
    , mReclaimPerSecond{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();

    mTargetEntity.ResetFromObject(targetEntity);

    mConsumptionData = new (std::nothrow) CEconRequest{};
    if (mConsumptionData != nullptr) {
      mConsumptionData->mRequested.energy = 0.0f;
      mConsumptionData->mRequested.mass = 0.0f;
      mConsumptionData->mGranted.energy = 0.0f;
      mConsumptionData->mGranted.mass = 0.0f;

      if (mUnit != nullptr && mUnit->ArmyRef != nullptr) {
        if (CSimArmyEconomyInfo* const economyInfo = mUnit->ArmyRef->GetEconomy(); economyInfo != nullptr) {
          mConsumptionData->mNode.ListLinkBefore(&economyInfo->registrationNode);
        }
      }
    }

    mReclaimRate = 0.0f;
    mReclaimPerSecond.energy = 0.0f;
    mReclaimPerSecond.mass = 0.0f;

    if (mUnit != nullptr && mUnit->CommandQueue != nullptr) {
      mCommand = mUnit->CommandQueue->GetCurrentCommand();
    }
    if (mCommand != nullptr) {
      mListenerLink.ListLinkBefore(static_cast<Broadcaster*>(mCommand));
    }

    if (mUnit != nullptr && mUnit->AiNavigator != nullptr) {
      mUnit->AiNavigator->AbortMove();
    }

    mTargetHasNoMotor = (mTargetEntity.GetObjectPtr() == nullptr);
  }

  /**
   * Address: 0x00620280 (FUN_00620280, Moho::CUnitReclaimTask::~CUnitReclaimTask)
   *
   * What it does:
   * Unlinks reclaim listeners/requests, clears reclaim/focus runtime state on
   * owner and target units, and tears down task/listener base slices.
   */
  CUnitReclaimTask::~CUnitReclaimTask()
  {
    mListenerLink.ListUnlink();

    if (Entity* const targetEntity = mTargetEntity.GetObjectPtr(); targetEntity != nullptr) {
      if (Unit* const targetUnit = targetEntity->IsUnit(); targetUnit != nullptr) {
        targetUnit->UnitStateMask &= ~kUnitStateNoReclaimMask;
      }
    }

    if (mUnit != nullptr && mUnit->AiBuilder != nullptr) {
      mUnit->AiBuilder->BuilderSetAimTarget(Wm3::Vector3f::Zero());
    }

    SetReclaimScriptActive(false);

    if (mUnit != nullptr) {
      mUnit->FocusEntityRef.ResetObjectPtr<Entity>(nullptr);
      if (mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
        (void)mUnit->RunScript(kOnAssignedFocusEntityScript);
      }
      mUnit->NeedSyncGameData = true;
      mUnit->UnitStateMask &= ~kUnitStateReclaimingMask;
      mUnit->WorkProgress = 0.0f;
    }

    DestroyEconomyRequestPointer(mConsumptionData);
    mTargetEntity.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x00620160 (FUN_00620160, listener callback lane)
   *
   * What it does:
   * Refreshes reclaim target from current command payload, rebinds unit focus
   * target, clears per-task progress state, and wakes owner task thread.
   */
  void CUnitReclaimTask::OnEvent(ECommandEvent)
  {
    SetReclaimScriptActive(false);

    Entity* commandTargetEntity = nullptr;
    if (mCommand != nullptr) {
      commandTargetEntity = mCommand->mTarget.targetEntity.GetObjectPtr();
      mTargetEntity.Set(commandTargetEntity);
      mTargetPosition = mCommand->mTarget.GetTargetPosGun(false);
    } else {
      mTargetEntity.Set(nullptr);
    }

    if (mUnit != nullptr) {
      mUnit->FocusEntityRef.ResetObjectPtr<Entity>(commandTargetEntity);
      if (mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
        (void)mUnit->RunScript(kOnAssignedFocusEntityScript);
      }
      mUnit->NeedSyncGameData = true;
      mUnit->WorkProgress = 0.0f;
    }

    mTargetHasNoMotor = (commandTargetEntity == nullptr);
    mTaskState = TASKSTATE_Preparing;
    WakeTaskThreadForImmediateTick(mOwnerThread);
  }

  /**
   * Address: 0x0061EF00 (FUN_0061EF00, cleanup_CUnitReclaimTaskSerializerStartupThunkA)
   *
   * What it does:
   * Unlinks one startup helper lane for the `CUnitReclaimTask` serializer
   * helper node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CUnitReclaimTaskSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(gCUnitReclaimTaskSerializerStartupNode);
  }

  /**
   * Address: 0x0061EF30 (FUN_0061EF30, cleanup_CUnitReclaimTaskSerializerStartupThunkB)
   *
   * What it does:
   * Unlinks the mirrored startup helper lane for the `CUnitReclaimTask`
   * serializer helper node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CUnitReclaimTaskSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(gCUnitReclaimTaskSerializerStartupNode);
  }

  /**
   * Address: 0x0061F000 (FUN_0061F000, Moho::CUnitReclaimTask::TaskTick)
   *
   * What it does:
   * Runs reclaim task state transitions: validates target lanes, handles
   * approach/setup, evaluates reclaim costs, applies per-tick reclaim
   * materialization, and credits reclaimed resources to army economy totals.
   */
  int CUnitReclaimTask::TaskTick()
  {
    Entity* targetEntity = mTargetEntity.GetObjectPtr();
    Unit* targetUnit = (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;

    if (!mTargetHasNoMotor) {
      if (targetUnit != nullptr && targetEntity->IsBeingBuilt() && targetUnit->IsUnitState(UNITSTATE_NoReclaim)) {
        if (mHasStarted) {
          SetReclaimScriptActive(false);
        }
        *mDispatchResult = kAiResultRetryOrRetarget;
        return -1;
      }

      if (
        targetEntity == nullptr || targetEntity->DestroyQueuedFlag != 0u
        || (targetUnit != nullptr && !targetUnit->GetAttributes().mReclaimable)
      ) {
        if (mHasStarted) {
          SetReclaimScriptActive(false);
        }
        *mDispatchResult = (targetEntity != nullptr) ? kAiResultRetryOrRetarget : kAiResultInvalidTarget;
        return -1;
      }

      if (!targetEntity->IsBeingBuilt() && targetEntity->mCurrentLayer == LAYER_Air) {
        *mDispatchResult = kAiResultRetryOrRetarget;
        return -1;
      }
    } else if (mUnit != nullptr && mUnit->ArmyRef != nullptr) {
      if (CAiReconDBImpl* const reconDB = mUnit->ArmyRef->GetReconDB(); reconDB != nullptr) {
        if (reconDB->ReconCanDetect(mTargetPosition, RECON_LOSNow) != RECON_None) {
          if (mHasStarted) {
            SetReclaimScriptActive(false);
          }
          *mDispatchResult = kAiResultRetryOrRetarget;
          return -1;
        }
      }
    }

    targetEntity = mTargetEntity.GetObjectPtr();
    targetUnit = (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;

    const Wm3::Vector3f targetPosition = (targetEntity != nullptr) ? targetEntity->GetPositionWm3() : mTargetPosition;
    const SFootprint targetFootprint = (targetEntity != nullptr) ? targetEntity->GetFootprint() : FallbackReclaimFootprint();

    const Wm3::Vector3f& unitPosition = mUnit->GetPosition();
    const float distanceX = unitPosition.x - targetPosition.x;
    const float distanceZ = unitPosition.z - targetPosition.z;
    const float rawDistance = std::sqrt((distanceX * distanceX) + (distanceZ * distanceZ));

    const int unitFootprintExtent = MaxFootprintExtent(mUnit->GetFootprint());
    const int targetFootprintExtent = MaxFootprintExtent(targetFootprint);
    const float contactDistance =
      rawDistance - static_cast<float>(unitFootprintExtent) - static_cast<float>(targetFootprintExtent);

    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        if (targetEntity != nullptr && !targetEntity->IsBeingBuilt()) {
          bool invalidCategory = true;
          if (targetEntity->IsInCategory(kReclaimableCategoryName)) {
            invalidCategory = (targetEntity == static_cast<Entity*>(mUnit));
          }

          if (invalidCategory) {
            *mDispatchResult = kAiResultRetryOrRetarget;
            return -1;
          }
        }

        Wm3::Vector3f moveTargetPosition = targetPosition;
        const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
        if (contactDistance > blueprint->Economy.MaxBuildDistance || rawDistance < 1.0f) {
          const SCoordsVec2 goalXZ{moveTargetPosition.x, moveTargetPosition.z};
          gpg::Rect2i reserveRect{};
          (void)COORDS_ToGridRect(&reserveRect, goalXZ, targetFootprint);

          const bool useWholeMap = (mUnit->ArmyRef != nullptr) ? mUnit->ArmyRef->UseWholeMap() : false;
          gpg::Rect2f moveSkirt{
            static_cast<float>(reserveRect.x0),
            static_cast<float>(reserveRect.z0),
            static_cast<float>(reserveRect.x1),
            static_cast<float>(reserveRect.z1),
          };
          (void)PrepareMove(1, mUnit, &moveTargetPosition, &moveSkirt, useWholeMap);

          const SOCellPos targetCell = mUnit->GetFootprint().ToCellPos(moveTargetPosition);
          NewMoveTask(SNavGoal(targetCell), this, 0, nullptr, 0);
        }

        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Waiting: {
        if (mTargetHasNoMotor) {
          *mDispatchResult = kAiResultRetryOrRetarget;
          return -1;
        }

        const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
        float maxReclaimDistance = blueprint->Economy.MaxBuildDistance;
        if (mUnit->IsUnitState(UNITSTATE_Patrolling)) {
          maxReclaimDistance = std::max(maxReclaimDistance, blueprint->AI.GuardScanRadius);
        }

        if (contactDistance > maxReclaimDistance) {
          if (mHasStarted) {
            SetReclaimScriptActive(false);
          }
          *mDispatchResult = kAiResultRetryOrRetarget;
          return -1;
        }

        if (targetEntity != nullptr) {
          if (ReconBlip* const reconBlip = targetEntity->IsReconBlip(); reconBlip != nullptr) {
            Unit* const creator = reconBlip->GetCreator();
            mTargetEntity.Set(static_cast<Entity*>(creator));
            targetEntity = mTargetEntity.GetObjectPtr();
            targetUnit = (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;
            if (targetEntity == nullptr) {
              return -1;
            }
          }
        }

        if (IAiBuilder* const builder = mUnit->AiBuilder; builder != nullptr && targetEntity != nullptr) {
          builder->BuilderSetAimTarget(targetEntity->GetPositionWm3());
        }

        SetReclaimScriptActive(true);
        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Starting: {
        targetEntity = mTargetEntity.GetObjectPtr();
        targetUnit = (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;
        if (targetEntity == nullptr || targetUnit == nullptr || targetEntity->IsBeingBuilt()) {
          mTaskState = NextTaskState(mTaskState);
          return 1;
        }

        if (IAiBuilder* const builder = mUnit->AiBuilder; builder != nullptr && rawDistance > 1.0f) {
          if (!builder->BuilderGetOnTarget()) {
            return 1;
          }
        }

        if (contactDistance > mUnit->GetBlueprint()->Economy.MaxBuildDistance) {
          return -1;
        }

        ReclaimCostInfo reclaimCosts{};
        if (!QueryReclaimCosts(mUnit, targetEntity, reclaimCosts)) {
          gpg::Warnf(kFailedReclaimCostWarning);
          return -1;
        }

        mUnit->UnitStateMask |= kUnitStateReclaimingMask;
        mUnit->SetFocusEntity(targetEntity);

        float reclaimHealthDelta = targetEntity->MaxHealth / reclaimCosts.reclaimTime;
        if (targetUnit->GetAttributes().regenRate > 0.0f) {
          reclaimHealthDelta += targetUnit->GetAttributes().regenRate * 0.1f;
        }

        if (targetEntity->Health <= reclaimHealthDelta) {
          if (!mUnit->IsUnitState(UNITSTATE_Guarding) && !mUnit->IsUnitState(UNITSTATE_AssistingCommander)) {
            targetEntity->RunScriptUnit(kOnReclaimedScript, mUnit);

            LuaPlus::LuaObject newEntityObject = targetEntity->RunScriptCreateWreckageProp(0.0f);
            targetEntity->Destroy();
            if (newEntityObject.IsNil()) {
              mTargetEntity.Set(nullptr);
            } else {
              mTargetEntity.Set(SCR_FromLua_EntityOpt(newEntityObject));
              mUnit->SetFocusEntity(mTargetEntity.GetObjectPtr());
            }

            mTaskState = NextTaskState(mTaskState);
          }
        } else {
          targetEntity->AdjustHealth(nullptr, -reclaimHealthDelta);
          if (targetUnit != nullptr) {
            targetUnit->UnitStateMask |= kUnitStateNoReclaimMask;
          }
        }

        return 1;
      }

      case TASKSTATE_Processing: {
        if (IAiBuilder* const builder = mUnit->AiBuilder; builder != nullptr && rawDistance > 1.0f) {
          if (!builder->BuilderGetOnTarget()) {
            return 1;
          }
        }

        targetEntity = mTargetEntity.GetObjectPtr();
        if (targetEntity == nullptr) {
          return -1;
        }

        ReclaimCostInfo reclaimCosts{};
        if (!QueryReclaimCosts(mUnit, targetEntity, reclaimCosts)) {
          gpg::Warnf(kFailedReclaimCostWarning);
          targetEntity->RunScriptUnit(kOnReclaimedScript, mUnit);
          return -1;
        }

        const float reclaimRate = 1.0f / reclaimCosts.reclaimTime;
        mReclaimRate = -reclaimRate;
        if (reclaimCosts.reclaimEnergy >= 0.0f && reclaimCosts.reclaimMass >= 0.0f) {
          mReclaimPerSecond.energy = std::max(reclaimCosts.reclaimEnergy, 0.0f) * reclaimRate;
          mReclaimPerSecond.mass = std::max(reclaimCosts.reclaimMass, 0.0f) * reclaimRate;

          mTaskState = NextTaskState(mTaskState);
          mUnit->UnitStateMask |= kUnitStateReclaimingMask;

          const float previousFraction = targetEntity->FractionCompleted;
          const float completionFromHealth = targetEntity->Health / targetEntity->MaxHealth;
          const float clampedCompletion = std::min(completionFromHealth, previousFraction);
          (void)targetEntity->UpdateFractionComplete(clampedCompletion - previousFraction);
          return 1;
        }

        gpg::Warnf(kInvalidReclaimCostWarning);
        targetEntity->RunScriptUnit(kOnReclaimedScript, mUnit);
        return -1;
      }

      case TASKSTATE_Complete: {
        targetEntity = mTargetEntity.GetObjectPtr();
        targetUnit = (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;
        if (targetUnit != nullptr && contactDistance > mUnit->GetBlueprint()->Economy.MaxBuildDistance) {
          if (mHasStarted) {
            SetReclaimScriptActive(false);
          }
          *mDispatchResult = kAiResultRetryOrRetarget;
          return -1;
        }

        SetReclaimScriptActive(true);

        const float limitingRate = mConsumptionData->LimitingRate();
        float appliedFractionDelta = 0.0f;
        float reclaimWorkProgress = mUnit->WorkProgress;
        PausedPropReclaimOverride pausedOverride{};
        if (targetUnit != nullptr) {
          appliedFractionDelta = targetEntity->Materialize(mReclaimRate * limitingRate);

          const float completionFromHealth = targetEntity->Health / targetEntity->MaxHealth;
          const float clampedCompletion = std::min(targetEntity->FractionCompleted, completionFromHealth);
          const float clampedHealth = targetEntity->MaxHealth * clampedCompletion;
          if (clampedHealth != targetEntity->Health) {
            targetEntity->SetHealth(clampedHealth);
          }

          reclaimWorkProgress = 1.0f - targetEntity->FractionCompleted;
        } else if (targetEntity != nullptr) {
          if (Prop* const propTarget = targetEntity->IsProp(); propTarget != nullptr) {
            if (mUnit->IsPaused) {
              pausedOverride.active = true;
              pausedOverride.savedReclaimRate = mReclaimRate;
              pausedOverride.savedReclaimPerSecond = mReclaimPerSecond;
              mReclaimRate = -0.0000000099999999f;
              mReclaimPerSecond.energy = 0.0f;
              mReclaimPerSecond.mass = 0.0f;
            }

            appliedFractionDelta = propTarget->Materialize(mReclaimRate * limitingRate);
            reclaimWorkProgress = 1.0f - targetEntity->FractionCompleted;
          }
        }

        mUnit->WorkProgress = reclaimWorkProgress;
        AwardReclaimedResources(mUnit, appliedFractionDelta, mReclaimRate, mReclaimPerSecond);

        if (pausedOverride.active) {
          mReclaimRate = pausedOverride.savedReclaimRate;
          mReclaimPerSecond = pausedOverride.savedReclaimPerSecond;
          return 1;
        }

        return 1;
      }

      default:
        gpg::HandleAssertFailure(
          "Reached the supposably unreachable.",
          427,
          "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitReclaim.cpp"
        );
        return 1;
    }
  }

  int CUnitReclaimTask::Execute()
  {
    return TaskTick();
  }

  /**
   * Address: 0x00620C60 (FUN_00620C60, Moho::CUnitReclaimTask::MemberDeserialize)
   *
   * What it does:
   * Loads base command-task state and reclaim-task payload lanes, then
   * swaps owned economy request pointer ownership from archive state.
   */
  void CUnitReclaimTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), nullOwner);
    archive->ReadPointer_CUnitCommand(&mCommand, &nullOwner);
    archive->Read(CachedWeakPtrEntityType(), &mTargetEntity, nullOwner);
    archive->ReadBool(&mTargetHasNoMotor);
    archive->Read(CachedVector3fType(), &mTargetPosition, nullOwner);
    archive->ReadBool(&mHasStarted);

    CEconRequest* loadedRequest = nullptr;
    archive->ReadPointerOwned_CEconRequest(&loadedRequest, &nullOwner);

    CEconRequest* previousRequest = mConsumptionData;
    mConsumptionData = loadedRequest;
    DestroyEconomyRequestPointer(previousRequest);

    archive->ReadFloat(&mReclaimRate);
    archive->Read(CachedSEconValueType(), &mReclaimPerSecond, nullOwner);
  }

  /**
   * Address: 0x00620DD0 (FUN_00620DD0, Moho::CUnitReclaimTask::MemberSerialize)
   *
   * What it does:
   * Saves base command-task state and reclaim-task payload lanes including
   * tracked pointer ownership for command and economy request references.
   */
  void CUnitReclaimTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), nullOwner);

    gpg::RRef commandRef{};
    (void)gpg::RRef_CUnitCommand(&commandRef, mCommand);
    gpg::WriteRawPointer(archive, commandRef, gpg::TrackedPointerState::Unowned, nullOwner);

    archive->Write(CachedWeakPtrEntityType(), &mTargetEntity, nullOwner);
    archive->WriteBool(mTargetHasNoMotor);
    archive->Write(CachedVector3fType(), &mTargetPosition, nullOwner);
    archive->WriteBool(mHasStarted);

    gpg::RRef requestRef{};
    (void)gpg::RRef_CEconRequest(&requestRef, mConsumptionData);
    gpg::WriteRawPointer(archive, requestRef, gpg::TrackedPointerState::Owned, nullOwner);

    archive->WriteFloat(mReclaimRate);
    archive->Write(CachedSEconValueType(), &mReclaimPerSecond, nullOwner);
  }

  /**
   * Address: 0x00620750 (FUN_00620750, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards one CUnitReclaimTask serializer-save thunk alias into
   * `CUnitReclaimTask::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCUnitReclaimTaskThunkVariantA(
    CUnitReclaimTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x006209D0 (FUN_006209D0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards a second CUnitReclaimTask serializer-save thunk alias into
   * `CUnitReclaimTask::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCUnitReclaimTaskThunkVariantB(
    CUnitReclaimTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x00620110 (FUN_00620110, sub_620110)
   *
   * What it does:
   * Toggles reclaim-script active state and dispatches
   * `OnStartReclaim`/`OnStopReclaim` callbacks when state changes.
   */
  void CUnitReclaimTask::SetReclaimScriptActive(const bool active)
  {
    if (mHasStarted == active) {
      return;
    }

    mHasStarted = active;
    if (mUnit == nullptr) {
      return;
    }

    mUnit->RunScriptWeakEntity(active ? "OnStartReclaim" : "OnStopReclaim", mTargetEntity);
  }

} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0060D610 (FUN_0060D610, reflection pair-pack thunk alias)
   *
   * What it does:
   * Builds one `EAiResult` reflection reference then writes the pair into
   * caller-provided `RRef` storage.
   */
  [[maybe_unused]] gpg::RRef* PackEAiResultRefPair(
    moho::EAiResult* const value,
    gpg::RRef* const outPair
  )
  {
    gpg::RRef typedRef{};
    (void)gpg::RRef_EAiResult(&typedRef, value);
    *outPair = typedRef;
    return outPair;
  }

  /**
   * Address: 0x00620990 (FUN_00620990, reflection pair-pack thunk alias)
   *
   * What it does:
   * Builds one `CUnitReclaimTask` reflection reference then writes the pair
   * into caller-provided `RRef` storage.
   */
  [[maybe_unused]] gpg::RRef* PackCUnitReclaimTaskRefPair(
    moho::CUnitReclaimTask* const value,
    gpg::RRef* const outPair
  )
  {
    gpg::RRef typedRef{};
    (void)gpg::RRef_CUnitReclaimTask(&typedRef, value);
    *outPair = typedRef;
    return outPair;
  }

  /**
   * Address: 0x00620AB0 (FUN_00620AB0, gpg::RRef_CUnitReclaimTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitReclaimTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitReclaimTask(gpg::RRef* const outRef, moho::CUnitReclaimTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitReclaimTaskType());
    return outRef;
  }
} // namespace gpg
