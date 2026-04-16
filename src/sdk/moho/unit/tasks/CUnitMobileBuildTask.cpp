#include "moho/unit/tasks/CUnitMobileBuildTask.h"

#include <memory>
#include <new>

#include "moho/ai/IAiBuilder.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateBuildingMask = (1ull << moho::UNITSTATE_Building);
  constexpr std::uint64_t kUnitStateNoReclaimMask = (1ull << moho::UNITSTATE_NoReclaim);

  struct CUnitCommandEventBroadcasterRuntimeView
  {
    std::byte mPad00_33[0x34];
    moho::Broadcaster mEventBroadcaster;
  };

  static_assert(
    offsetof(CUnitCommandEventBroadcasterRuntimeView, mEventBroadcaster) == 0x34,
    "CUnitCommandEventBroadcasterRuntimeView::mEventBroadcaster offset must be 0x34"
  );

  [[nodiscard]] moho::Broadcaster* ResolveCommandEventBroadcaster(moho::CUnitCommand* const command)
  {
    if (command == nullptr) {
      return nullptr;
    }

    auto* const runtimeView = reinterpret_cast<CUnitCommandEventBroadcasterRuntimeView*>(command);
    return &runtimeView->mEventBroadcaster;
  }

  [[nodiscard]] moho::CUnitCommand* ResolveQueueHeadCommand(moho::Unit* const unit)
  {
    if (unit == nullptr || unit->CommandQueue == nullptr || unit->CommandQueue->mCommandVec.empty()) {
      return nullptr;
    }

    return unit->CommandQueue->mCommandVec.front().GetObjectPtr();
  }

  [[nodiscard]] moho::SOCellPos BuildPlacementCellFromTargetPosition(
    const Wm3::Vector3f& targetPosition,
    const moho::RUnitBlueprint* const blueprint
  )
  {
    moho::SOCellPos buildCell{};
    if (blueprint == nullptr) {
      return buildCell;
    }

    const float halfSizeX = static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f;
    const float halfSizeZ = static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f;
    buildCell.x = static_cast<std::int16_t>(static_cast<int>(targetPosition.x - halfSizeX));
    buildCell.z = static_cast<std::int16_t>(static_cast<int>(targetPosition.z - halfSizeZ));
    return buildCell;
  }

  [[nodiscard]] Wm3::Vector3f ResolveBuildPlacementPosition(
    const moho::Sim* const sim,
    const moho::RUnitBlueprint* const blueprint,
    const Wm3::Vector3f& targetPosition
  )
  {
    if (sim == nullptr || sim->mMapData == nullptr || blueprint == nullptr) {
      return targetPosition;
    }

    const moho::SOCellPos buildCell = BuildPlacementCellFromTargetPosition(targetPosition, blueprint);
    return moho::COORDS_ToWorldPos(sim->mMapData, buildCell, blueprint->mFootprint);
  }

  [[nodiscard]] gpg::Rect2i BuildRectFromPlacementPosition(
    const Wm3::Vector3f& placementPosition,
    const moho::RUnitBlueprint* const blueprint
  )
  {
    gpg::Rect2i buildRect{};
    if (blueprint == nullptr) {
      return buildRect;
    }

    buildRect.x0 =
      static_cast<int>(placementPosition.x - static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f);
    buildRect.z0 =
      static_cast<int>(placementPosition.z - static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f);
    buildRect.x1 = buildRect.x0 + static_cast<int>(blueprint->mFootprint.mSizeX);
    buildRect.z1 = buildRect.z0 + static_cast<int>(blueprint->mFootprint.mSizeZ);
    return buildRect;
  }

  [[nodiscard]] gpg::Rect2f BuildSkirtFromPlacementPosition(
    const Wm3::Vector3f& placementPosition,
    const moho::RUnitBlueprint* const blueprint
  )
  {
    if (blueprint == nullptr) {
      return {};
    }

    return blueprint->GetSkirtRect(moho::SCoordsVec2{placementPosition.x, placementPosition.z});
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F6400 (FUN_005F6400, ??0CUnitMobileBuildTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes detached mobile-build-task storage for reflection lanes:
   * command/listener subobjects, build-helper defaults, and build target
   * placement/runtime weak-link state.
   */
  CUnitMobileBuildTask::CUnitMobileBuildTask()
    : CCommandTask()
    , CUnitMobileBuildTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mBuildHelper()
    , mCommand(nullptr)
    , mBlueprint(nullptr)
    , mBuildPosition(Wm3::Vector3f{0.0f, 0.0f, 1.0f})
    , mBuildOrientation(Wm3::Quatf{0.0f, 0.0f, 0.0f, 0.0f})
    , mBuildDirection(Wm3::Vector3f::Zero())
    , mPlacementRetryCount(0)
    , mBuildUnit{}
    , mPendingBuildEntity{}
    , mBuildRect{}
    , mBuildSkirt{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mBuildUnit.ClearLinkState();
    mPendingBuildEntity.ClearLinkState();
  }

  /**
   * Address: 0x005F6520 (FUN_005F6520, ??0CUnitMobileBuildTask@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Initializes one dispatch-bound mobile-build task, binds command-listener
   * lanes, resolves build placement from footprint/cell coordinates, and
   * primes runtime build-area/skirt caches.
   */
  CUnitMobileBuildTask::CUnitMobileBuildTask(
    CCommandTask* const dispatchTask,
    const RUnitBlueprint* const blueprint,
    const Wm3::Vector3f& buildPosition,
    const Wm3::Quatf& buildOrientation,
    const Wm3::Vector3f& buildDirection
  )
    : CCommandTask(dispatchTask)
    , CUnitMobileBuildTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mBuildHelper("MobileBuild", dispatchTask != nullptr ? dispatchTask->mUnit : nullptr)
    , mCommand(nullptr)
    , mBlueprint(blueprint)
    , mBuildPosition(buildPosition)
    , mBuildOrientation(buildOrientation)
    , mBuildDirection(buildDirection)
    , mPlacementRetryCount(0)
    , mBuildUnit{}
    , mPendingBuildEntity{}
    , mBuildRect{}
    , mBuildSkirt{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mBuildUnit.ClearLinkState();
    mPendingBuildEntity.ClearLinkState();

    mCommand = ResolveQueueHeadCommand(mUnit);
    if (mCommand != nullptr) {
      if (Broadcaster* const eventBroadcaster = ResolveCommandEventBroadcaster(mCommand); eventBroadcaster != nullptr) {
        mListenerLink.ListLinkBefore(eventBroadcaster);
      }
    }

    mBuildPosition = ResolveBuildPlacementPosition(mSim, mBlueprint, mBuildPosition);
    mBuildRect = BuildRectFromPlacementPosition(mBuildPosition, mBlueprint);
    mBuildSkirt = BuildSkirtFromPlacementPosition(mBuildPosition, mBlueprint);
  }

  /**
   * Address: 0x00605CD0 (FUN_00605CD0)
   *
   * What it does:
   * Stores one blueprint pointer lane and returns this task.
   */
  CUnitMobileBuildTask* CUnitMobileBuildTask::SetBlueprint(const RUnitBlueprint* const blueprint) noexcept
  {
    mBlueprint = blueprint;
    return this;
  }

  /**
   * Address: 0x005F6AC0 (FUN_005F6AC0, ??1CUnitMobileBuildTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Clears owner/build-unit state bits, commits dispatch result lane for
   * failed/interrupted completion, and tears down helper + weak-link lanes.
   */
  CUnitMobileBuildTask::~CUnitMobileBuildTask()
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~kUnitStateBuildingMask;
      if (mUnit->AiBuilder != nullptr) {
        mUnit->AiBuilder->BuilderSetAimTarget(Wm3::Vector3f::Zero());
      }
    }

    if (Unit* const buildUnit = mBuildUnit.GetObjectPtr(); buildUnit != nullptr) {
      buildUnit->UnitStateMask &= ~kUnitStateNoReclaimMask;
    }

    mBuildHelper.OnStopBuild(true);

    if (mDispatchResult != nullptr) {
      if (mTaskState == TASKSTATE_5) {
        *mDispatchResult = static_cast<EAiResult>(1);
      } else {
        if (mUnit != nullptr) {
          mUnit->RunScript("OnFailedToBuild");
        }
        *mDispatchResult = static_cast<EAiResult>(2);
      }
    }

    if (mUnit != nullptr) {
      mUnit->FreeOgridRect();
    }

    mPendingBuildEntity.UnlinkFromOwnerChain();
    mPendingBuildEntity.ClearLinkState();
    mBuildUnit.UnlinkFromOwnerChain();
    mBuildUnit.ClearLinkState();

    if (!mListenerLink.ListIsSingleton()) {
      mListenerLink.ListUnlink();
    }
    mListenerLink.ListResetLinks();
  }

  /**
   * Address: 0x005F8370 (FUN_005F8370, ??2CUnitMobileBuildTask@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Allocates one mobile-build task object and forwards arguments into
   * dispatch-bound in-place construction.
   */
  CUnitMobileBuildTask* CUnitMobileBuildTask::Create(
    CCommandTask* const dispatchTask,
    const RUnitBlueprint* const blueprint,
    const Wm3::Vector3f& buildPosition,
    const Wm3::Quatf& buildOrientation,
    const Wm3::Vector3f& buildDirection
  )
  {
    auto* const raw = static_cast<CUnitMobileBuildTask*>(::operator new(sizeof(CUnitMobileBuildTask), std::nothrow));
    if (raw == nullptr) {
      return nullptr;
    }

    auto guard = std::unique_ptr<CUnitMobileBuildTask, void (*)(CUnitMobileBuildTask*)>(raw, [](CUnitMobileBuildTask* p) {
      ::operator delete(p);
    });

    return std::construct_at(guard.release(), dispatchTask, blueprint, buildPosition, buildOrientation, buildDirection);
  }
} // namespace moho
