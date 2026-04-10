#include "moho/unit/tasks/CUnitUpgradeTask.h"

#include <new>

#include "gpg/core/utils/Global.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/entity/EntityId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SFootprint.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/SUnitConstructionParams.h"

namespace
{
  constexpr std::uint64_t kUpgradeOwnerLowMask = 0x0000000000000040ull;
  constexpr std::uint64_t kUpgradeOwnerHighMask = 0x0000020000000000ull;
  constexpr std::uint64_t kUpgradeTargetHighMask = 0x0000002000000000ull;

  [[nodiscard]] moho::ETaskState AdvanceTaskState(const moho::ETaskState current) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<int>(current) + 1);
  }

  [[nodiscard]] bool ReadInstaBuildFlag(moho::Sim* const sim)
  {
    static moho::TSimConVar<bool> sAiInstaBuild(false, "ai_InstaBuild", false);

    moho::CSimConVarInstanceBase* const instance = sim ? sim->GetSimVar(&sAiInstaBuild) : nullptr;
    void* const valueStorage = instance ? instance->GetValueStorage() : nullptr;
    return valueStorage != nullptr && (*reinterpret_cast<const std::uint8_t*>(valueStorage) != 0u);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F83D0 (FUN_005F83D0, ??0CUnitUpgradeTask@Moho@@QAE@@Z)
   */
  CUnitUpgradeTask::CUnitUpgradeTask()
    : CCommandTask()
    , mToBlueprint(nullptr)
    , mBuildHelper()
    , mUpgradedUnit{}
  {}

  /**
   * Address: 0x005F8420 (FUN_005F8420, ??0CUnitUpgradeTask@Moho@@QAE@@Z_0)
   */
  CUnitUpgradeTask::CUnitUpgradeTask(CCommandTask* const dispatchTask, const RUnitBlueprint* const toBlueprint)
    : CCommandTask(dispatchTask)
    , mToBlueprint(toBlueprint)
    , mBuildHelper("Upgrade", dispatchTask ? dispatchTask->mUnit : nullptr)
    , mUpgradedUnit{}
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask |= kUpgradeOwnerLowMask;
      mUnit->WorkProgress = 0.0f;
    }
  }

  /**
   * Address: 0x005F84C0 (FUN_005F84C0, ??1CUnitUpgradeTask@Moho@@QAE@@Z)
   */
  CUnitUpgradeTask::~CUnitUpgradeTask()
  {
    if (mUnit != nullptr) {
      mUnit->FocusEntityRef.ResetObjectPtr<Entity>(nullptr);
      if (mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
        mUnit->RunScript("OnAssignedFocusEntity");
      }
      mUnit->NeedSyncGameData = true;

      mUnit->UnitStateMask &= ~kUpgradeOwnerLowMask;
      mUnit->UnitStateMask &= ~kUpgradeOwnerHighMask;
      mUnit->WorkProgress = 0.0f;
    }

    Unit* const upgradedUnit = mUpgradedUnit.GetObjectPtr();
    if (mTaskState == TASKSTATE_Processing) {
      if (mUnit != nullptr) {
        mUnit->FootprintDown = false;
      }
      if (upgradedUnit != nullptr) {
        upgradedUnit->UnitStateMask &= ~kUpgradeTargetHighMask;
      }
      mBuildHelper.OnStopBuild(true);
      if (mDispatchResult != nullptr) {
        *mDispatchResult = static_cast<EAiResult>(1);
      }
    } else {
      if (upgradedUnit != nullptr) {
        // Non-1:1 lane: 0x006A7AB0 (`Unit::ReleaseOccupyGround`) is still
        // pending symbolic lift; use recovered occupancy-release helper.
        upgradedUnit->FreeOgridRect();
        upgradedUnit->Destroy();
      }

      if (mUnit != nullptr) {
        mUnit->ExecuteOccupyGround();
        mUnit->UpgradedToEntityId = static_cast<EntId>(ToRaw(EEntityIdSentinel::Invalid));
      }

      mBuildHelper.OnStopBuild(false);
      if (mDispatchResult != nullptr) {
        *mDispatchResult = static_cast<EAiResult>(2);
      }
    }

    mUpgradedUnit.UnlinkFromOwnerChain();
    mUpgradedUnit.ClearLinkState();
  }

  /**
   * Address: 0x005F8890 (FUN_005F8890, Moho::CUnitUpgradeTask::TaskTick)
   */
int CUnitUpgradeTask::TaskTick()
  {
    auto finishOrContinueBuild = [this]() -> int {
      Unit* const focusUnit = mBuildHelper.mFocus.GetObjectPtr();

      // FAF Binary Patch (non-1:1 with original binary):
      // Retail code reaches 0x005F8B20 and reads a vtable through a decoded
      // weak-focus pointer without guarding sentinel/cleared lanes. Under the
      // restricted-upgrade path (notably restricted mex tier-up), this can
      // become a null-vtable dereference and CTD.
      // Fixed behavior: resolve `WeakPtr<Unit>` first and bail out on null.
      // Related: https://github.com/FAForever/FA-Binary-Patches/issues/125
      if (focusUnit == nullptr || focusUnit->IsDead()) {
        mBuildHelper.OnStopBuild(false);
        mTaskState = TASKSTATE_Preparing;
        return 10;
      }

      if (mBuildHelper.UpdateWorkProgress()) {
        mTaskState = AdvanceTaskState(mTaskState);
        return -1;
      }

      return 1;
    };

    switch (mTaskState) {
      case TASKSTATE_Preparing:
        if (mUnit != nullptr && mUnit->IsMobile() && Wm3::Vector3f::Compare(&mUnit->Position, &mUnit->PrevPosition)) {
          if (mUnit->AiNavigator != nullptr) {
            mUnit->AiNavigator->AbortMove();
            return 1;
          }
        }
        mTaskState = AdvanceTaskState(mTaskState);
        break;

      case TASKSTATE_Waiting:
        break;

      case TASKSTATE_Starting:
        return finishOrContinueBuild();

      default:
        gpg::HandleAssertFailure(
          "Reached the supposably unreachable.",
          1032,
          "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitBuild.cpp"
        );
        return finishOrContinueBuild();
    }

    if (mUnit == nullptr || mUnit->IsPaused) {
      return 10;
    }

    const SFootprint& footprint = mUnit->GetFootprint();
    Wm3::Vector3f position = mUnit->GetPosition();
    position.x -= static_cast<float>(footprint.mSizeX) * 0.5f;
    position.z -= static_cast<float>(footprint.mSizeZ) * 0.5f;

    mUnit->UnitStateMask |= kUpgradeOwnerHighMask;

    SUnitConstructionParams params{};
    params.mArmy = mUnit->ArmyRef;
    params.mBlueprint = mToBlueprint;
    params.mTransform.pos_ = position;
    params.mUseLayerOverride = 0;
    params.mFixElevation = 0;
    params.mLayer = static_cast<std::int32_t>(mUnit->mCurrentLayer);
    params.mLinkSourceUnit = mUnit;
    params.mComplete = ReadInstaBuildFlag(mSim) ? 1u : 0u;

    Unit* upgradedUnit = nullptr;
    if (mSim != nullptr && mToBlueprint != nullptr) {
      // Non-1:1 lane: binary path constructs `Unit` directly via ctor
      // 0x006A53F0. Current source routes through `Sim::CreateUnit()` while
      // that constructor body remains under recovery.
      upgradedUnit = mSim->CreateUnitForScript(params, false);
    }

    mUpgradedUnit.ResetFromObject(upgradedUnit);
    if (upgradedUnit == nullptr) {
      return -1;
    }

    mUnit->UpgradedToEntityId = upgradedUnit->id_;
    mUnit->FocusEntityRef.ResetObjectPtr<Entity>(upgradedUnit);
    if (mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
      mUnit->RunScript("OnAssignedFocusEntity");
    }
    mUnit->NeedSyncGameData = true;

    if (upgradedUnit->FireState != mUnit->FireState) {
      upgradedUnit->FireState = mUnit->FireState;
      upgradedUnit->NeedSyncGameData = true;
    }

    upgradedUnit->UnitStateMask |= kUpgradeTargetHighMask;
    mBuildHelper.SetFocus(upgradedUnit);
    mTaskState = AdvanceTaskState(mTaskState);

    return finishOrContinueBuild();
  }

  /**
   * Address: 0x005F8B80 (FUN_005F8B80, ??2CUnitUpgradeTask@Moho@@QAE@@Z_0)
   */
  CUnitUpgradeTask* CUnitUpgradeTask::Create(CCommandTask* const dispatchTask, const RUnitBlueprint* const toBlueprint)
  {
    return new (std::nothrow) CUnitUpgradeTask(dispatchTask, toBlueprint);
  }

  int CUnitUpgradeTask::Execute()
  {
    return TaskTick();
  }
} // namespace moho
