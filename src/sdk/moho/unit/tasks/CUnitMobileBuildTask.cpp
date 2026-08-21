#include "moho/unit/tasks/CUnitMobileBuildTask.h"

#include <memory>
#include <new>
#include <typeinfo>

#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include <cmath>
#include <limits>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/command/SSTITarget.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/math/MathReflection.h"
#include "moho/misc/WeakPtr.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/tasks/CUnitMoveTask.h"
#include "moho/task/CCommandTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateBuildingMask = (1ull << moho::UNITSTATE_Building);
  constexpr std::uint64_t kUnitStateNoReclaimMask = (1ull << moho::UNITSTATE_NoReclaim);

  // Reflection-type caches used by the archive load/save lanes. The binary
  // caches each reflected `gpg::RType*` in a dedicated global initialized on
  // first use via `gpg::LookupRType(typeid(...))`. Where the type owns a
  // class-static `sType` (CCommandTask, WeakPtr<T>, gpg::Rect2<T>) we mirror
  // that lane; where it does not (CBuildTaskHelper, Wm3::Vector3f,
  // Wm3::Quaternionf) we mirror the binary's file-level `Xxx__sType` global
  // with a file-static cache, exactly as the sibling CUnitPatrolTask does for
  // `Wm3::Box3f`.

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCBuildTaskHelperType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CBuildTaskHelper));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Quaternion<float>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrEntityType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Entity>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Entity>));
      moho::WeakPtr<moho::Entity>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRect2iType()
  {
    gpg::RType* type = gpg::Rect2i::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2<int>));
      gpg::Rect2i::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRect2fType()
  {
    gpg::RType* type = gpg::Rect2f::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2<float>));
      gpg::Rect2f::sType = type;
    }
    return type;
  }

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
   * Address: 0x005F6C70 (FUN_005F6C70, sub_5F6C70)
   *
   * Sphere-queries units near the build site (radius = larger footprint extent
   * of the target blueprint) and returns the first live, being-built unit that
   * is XZ-coincident with the build position and whose blueprint id matches.
   */
  Unit* CUnitMobileBuildTask::FindExistingSeedUnitOnSite() const
  {
    const std::uint8_t sizeX = mBlueprint->mFootprint.mSizeX;
    const std::uint8_t sizeZ = mBlueprint->mFootprint.mSizeZ;
    const float queryRadius = static_cast<float>(sizeX > sizeZ ? sizeX : sizeZ);

    const Wm3::Sphere3f querySphere{mBuildPosition, queryRadius};
    CollisionResultFastVectorN10 collisions{};
    mSim->mOGrid->ForAllEntitiesIterator(collisions, ENTITYTYPE_Unit, querySphere);

    for (const CollisionResult& hit : collisions) {
      Entity* const entity = hit.sourceEntity;
      if (entity == nullptr) {
        continue;
      }
      Unit* const unit = entity->IsUnit();
      if (unit == nullptr || unit->IsDead() || !unit->IsBeingBuilt()) {
        continue;
      }

      const Wm3::Vec3f& unitPos = unit->GetPosition();
      const float deltaX = unitPos.x - mBuildPosition.x;
      const float deltaZ = unitPos.z - mBuildPosition.z;
      if (std::sqrt(deltaX * deltaX + deltaZ * deltaZ) > 0.0f) {
        continue;
      }

      if (_stricmp(unit->GetBlueprint()->mBlueprintId.c_str(), mBlueprint->mBlueprintId.c_str()) != 0) {
        continue;
      }
      return unit;
    }
    return nullptr;
  }

  /**
   * Address: 0x005F6EA0 (FUN_005F6EA0, sub_5F6EA0)
   *
   * Finds the nearest ObstructsBuild prop over the target footprint; on a
   * RebuildBonus id match (coincident) records the rebuild fraction + binds the
   * pending-build entity (returns null), else returns the nearest prop.
   */
  Entity* CUnitMobileBuildTask::FindObstructingPropToReclaim()
  {
    const EntityCategorySet* const obstructsBuild = mSim->mRules->GetEntityCategory("ObstructsBuild");

    const std::uint8_t sizeX = mBlueprint->mFootprint.mSizeX;
    const std::uint8_t sizeZ = mBlueprint->mFootprint.mSizeZ;
    const int minX = static_cast<int>(mBuildPosition.x - static_cast<float>(sizeX) * 0.5f);
    const int minZ = static_cast<int>(mBuildPosition.z - static_cast<float>(sizeZ) * 0.5f);
    const int maxX = minX + static_cast<int>(sizeX);
    const int maxZ = minZ + static_cast<int>(sizeZ);

    Wm3::Vector3f boxCenter{static_cast<float>(maxX + minX) * 0.5f, mBuildPosition.y,
                            static_cast<float>(maxZ + minZ) * 0.5f};
    Wm3::Vector3f boxExtents{static_cast<float>(maxX - minX) * 0.5f, 1000.0f,
                             static_cast<float>(maxZ - minZ) * 0.5f};
    const VAxes3 boxAxes{Wm3::Quaternionf(1.0f, 0.0f, 0.0f, 0.0f)};
    const Wm3::Box3f queryBox{boxCenter, &boxAxes.vX, &boxExtents.x};

    CollisionResultFastVectorN10 collisions{};
    mSim->mOGrid->CollectEntitiesInBox(collisions, ENTITYTYPE_Prop, queryBox);

    Entity* nearest = nullptr;
    float nearestDistSq = std::numeric_limits<float>::infinity();
    const Wm3::Vec3f& builderPos = mUnit->GetPosition();
    for (const CollisionResult& hit : collisions) {
      Entity* const entity = hit.sourceEntity;
      if (entity == nullptr || entity->IsProp() == nullptr) {
        continue;
      }
      const REntityBlueprint* const propBp = entity->BluePrint;
      if (propBp == nullptr || !EntityCategory::HasBlueprint(propBp, obstructsBuild)) {
        continue;
      }
      const Wm3::Vec3f& propPos = entity->GetPositionWm3();
      const float dx = builderPos.x - propPos.x;
      const float dy = builderPos.y - propPos.y;
      const float dz = builderPos.z - propPos.z;
      const float distSq = dx * dx + dy * dy + dz * dz;
      if (distSq < nearestDistSq) {
        nearestDistSq = distSq;
        nearest = entity;
      }
    }

    if (nearest == nullptr || nearest->IsProp() == nullptr) {
      return nearest;
    }

    LuaPlus::LuaObject associatedBp{};
    nearest->FindScript(&associatedBp, "AssociatedBP");
    if (!associatedBp.IsString()) {
      return nearest;
    }

    for (const msvc8::string& rebuildId : mBlueprint->Economy.RebuildBonusIds) {
      if (_stricmp(associatedBp.GetString(), rebuildId.c_str()) != 0) {
        continue;
      }
      const Wm3::Vec3f& propPos = nearest->GetPositionWm3();
      const float cdx = mBuildPosition.x - propPos.x;
      const float cdz = mBuildPosition.z - propPos.z;
      if ((cdx * cdx + cdz * cdz) >= 0.000001f) {
        break;
      }

      gpg::core::FastVector<LuaPlus::LuaObject> results{};
      const LuaPlus::LuaObject bpLua = mBlueprint->GetLuaBlueprint(mSim->mLuaState);
      const LuaPlus::LuaObject e1{};
      const LuaPlus::LuaObject e2{};
      const LuaPlus::LuaObject e3{};
      const LuaPlus::LuaObject e4{};
      if (!nearest->RunScriptMultiRet("GetRebuildBonus", results, bpLua, e1, e2, e3, e4) ||
          (results.end() - results.begin()) != 1) {
        gpg::Warnf("Failed to get valid rebuild bonus from the script");
        return nullptr;
      }
      const float fractionComplete = nearest->FractionCompleted;
      const float rebuildBonus = static_cast<float>(results.begin()->ToNumber());
      mBuildHelper.mUnknown18 = rebuildBonus * fractionComplete;
      mPendingBuildEntity.Set(nearest);
      return nullptr;
    }
    return nearest;
  }

  /**
   * Address: 0x005F7440 (FUN_005F7440, Moho::CUnitMobileBuildTask::TaskTick)
   *
   * VFTable SLOT: 1
   *
   * What it does:
   * Mobile engineer build-task state machine; see header.
   */
  int CUnitMobileBuildTask::Execute()
  {
    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        if (!CheckBuildRestriction(mBlueprint, &mBuildRect, &mBuildHelper)) {
          return -1;
        }
        if (Entity* const obstruction = FindObstructingPropToReclaim(); obstruction != nullptr) {
          CAiTarget reclaimTarget{};
          reclaimTarget.UpdateTarget(obstruction);
          reinterpret_cast<IAiCommandDispatchImpl*>(this)->IssueReclaimTask(reclaimTarget);
          return 1;
        }
        if (mUnit->IsMobile()) {
          const Wm3::Vec3f& startPos = mUnit->GetPosition();
          const SCoordsVec2 startCoords{startPos.x, startPos.z};
          const bool fits =
            mUnit->GetFootprint().FitsAt(startCoords, *mSim->mOGrid) != static_cast<EOccupancyCaps>(0u);

          const Wm3::Vec3f& builderPos = mUnit->GetPosition();
          const float ddx = builderPos.x - mBuildPosition.x;
          const float ddz = builderPos.z - mBuildPosition.z;
          const SFootprint& fp = mUnit->GetFootprint();
          const std::uint8_t maxFp = fp.mSizeX > fp.mSizeZ ? fp.mSizeX : fp.mSizeZ;
          const float skX = mBlueprint->Physics.SkirtSizeX;
          const float skZ = mBlueprint->Physics.SkirtSizeZ;
          const float maxSkirt = skZ > skX ? skZ : skX;
          const float range = (std::sqrt(ddx * ddx + ddz * ddz) - static_cast<float>(maxFp)) - maxSkirt;

          const gpg::Rect2f builderSkirt = mUnit->GetSkirtRect();
          const bool outOfRange = range > mUnit->GetBlueprint()->Economy.MaxBuildDistance;
          const bool overlaps = mBuildSkirt.OverlapsInclusive(builderSkirt);
          if (!fits || outOfRange || overlaps) {
            gpg::Rect2f moveSkirt = mBuildSkirt;
            moveSkirt.z0 = moveSkirt.z0 - 1.0f;
            moveSkirt.x1 = moveSkirt.x1 + 1.0f;
            Wm3::Vector3f moveTarget{mBuildPosition.x, mBuildPosition.y, mBuildPosition.z};
            const bool useWholeMap = mUnit->ArmyRef->UseWholeMap();
            (void)mUnit->PrepareMove(1, &moveTarget, &moveSkirt, useWholeMap);
            const SCoordsVec2 moveCoords{moveTarget.x, moveTarget.z};
            const SFootprint& moveFp = mUnit->GetFootprint();
            gpg::Rect2i reserveRect{};
            COORDS_ToGridRect(&reserveRect, moveCoords, moveFp.mSizeX, moveFp.mSizeZ);
            mUnit->ReserveOgridRect(reserveRect);
            const SOCellPos goalCell = mUnit->GetFootprint().ToCellPos(moveTarget);
            NewMoveTask(SNavGoal(goalCell), this, 0, nullptr, 0);
          }
        }
        mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
        return 1;
      }

      case TASKSTATE_Waiting: {
        const Wm3::Vec3f& builderPos = mUnit->GetPosition();
        const float ddx = builderPos.x - mBuildPosition.x;
        const float ddz = builderPos.z - mBuildPosition.z;
        const SFootprint& fp = mUnit->GetFootprint();
        const std::uint8_t maxFp = fp.mSizeX > fp.mSizeZ ? fp.mSizeX : fp.mSizeZ;
        const float skX = mBlueprint->Physics.SkirtSizeX;
        const float skZ = mBlueprint->Physics.SkirtSizeZ;
        const float maxSkirt = skZ > skX ? skZ : skX;
        const float range = (std::sqrt(ddx * ddx + ddz * ddz) - static_cast<float>(maxFp)) - maxSkirt;
        if (range > mUnit->GetBlueprint()->Economy.MaxBuildDistance ||
            !CheckBuildRestriction(mBlueprint, &mBuildRect, &mBuildHelper)) {
          return -1;
        }
        if (IAiBuilder* const builder = mUnit->AiBuilder; builder != nullptr) {
          const float aimY = (mBlueprint->Physics.SkirtSizeX * 0.5f) + mBlueprint->Physics.SkirtSizeZ + mBuildPosition.y;
          builder->BuilderSetAimTarget(Wm3::Vector3f{mBuildPosition.x, aimY, mBuildPosition.z});
        }
        mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
        mUnit->UnitStateMask |= kUnitStateBuildingMask;
        return 0;
      }

      case TASKSTATE_Starting: {
        if (!mUnit->GetBlueprint()->Economy.NeedToFaceTargetToBuild) {
          mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
          return 0;
        }
        const VTransform& transform = mUnit->GetTransform();
        const VAxes3 axes{transform.orient_};
        Wm3::Vector3f forward{axes.vX.x, 0.0f, axes.vX.z};
        (void)forward.Normalize();
        const Wm3::Vec3f& builderPos = mUnit->GetPosition();
        Wm3::Vector3f toTarget{mBuildPosition.x - builderPos.x, 0.0f, mBuildPosition.z - builderPos.z};
        (void)toTarget.Normalize();
        const float dot = forward.x * toTarget.x + forward.y * toTarget.y + forward.z * toTarget.z;
        const Wm3::Vector3f zeroFacing{0.0f, 0.0f, 0.0f};
        if (dot > 0.94999999f) {
          mUnit->UnitMotion->SetFacing(zeroFacing);
          mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
          return 0;
        }
        mUnit->UnitMotion->SetFacing(toTarget);
        return 1;
      }

      case TASKSTATE_Processing: {
        if (mPlacementRetryCount > 10 || !CheckBuildRestriction(mBlueprint, &mBuildRect, &mBuildHelper)) {
          return -1;
        }
        if (Unit* const seed = FindExistingSeedUnitOnSite(); seed != nullptr) {
          if (!seed->IsBeingBuilt()) {
            return -1;
          }
          mBuildUnit.Set(seed);
          mBuildHelper.SetFocus(mBuildUnit.GetObjectPtr());
          mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
          return 0;
        }

        SOccupationResult occupation{};
        const SCoordsVec2 buildCoords{mBuildPosition.x, mBuildPosition.z};
        if (!func_LocationIsFree(*mBlueprint, *mSim->mOGrid, buildCoords, occupation)) {
          return -1;
        }
        if (!Sim::LocationIsFree(mSim, mUnit, &mBuildRect, 0)) {
          gpg::Rect2i footprintRect = mBlueprint->GetFootprintRect(buildCoords);
          footprintRect.z0 -= 1;
          footprintRect.x1 += 1;
          SIM_TryToBuild(mSim, mUnit->ArmyRef, &footprintRect, 0);
          ++mPlacementRetryCount;
          return 50;
        }
        if (IAiBuilder* const builder = mUnit->AiBuilder; builder != nullptr && !builder->BuilderGetOnTarget()) {
          return 1;
        }
        if (mUnit->IsPaused) {
          return 10;
        }

        const RUnitBlueprint* spawnBlueprint = mBlueprint;
        if (!mBlueprint->General.SeedUnit.name.empty()) {
          spawnBlueprint = mSim->mRules->GetUnitBlueprint(RResId{mBlueprint->General.SeedUnit.name});
        }

        static TSimConVar<bool> sAiInstaBuild(false, "ai_InstaBuild", false);
        CSimConVarInstanceBase* const instaBuildVar = mSim->GetSimVar(&sAiInstaBuild);
        void* const instaBuildStorage = instaBuildVar != nullptr ? instaBuildVar->GetValueStorage() : nullptr;
        const bool instaBuild =
          instaBuildStorage != nullptr && (*reinterpret_cast<const std::uint8_t*>(instaBuildStorage) != 0u);

        const std::int32_t layer = mUnit->mCurrentLayer;
        const VTransform spawnTransform{mBuildPosition, mBuildOrientation};
        SUnitConstructionParams params(layer, spawnTransform, mUnit->ArmyRef, spawnBlueprint, mUnit, instaBuild);
        Unit* const newUnit = mSim->CreateUnitForScript(params, true);
        mBuildUnit.Set(newUnit);
        Unit* const spawned = mBuildUnit.GetObjectPtr();
        if (spawned == nullptr) {
          return 10;
        }
        spawned->UnitStateMask |= kUnitStateNoReclaimMask;

        if (Entity* const pending = mPendingBuildEntity.GetObjectPtr(); pending != nullptr) {
          pending->Destroy();
          mPendingBuildEntity.Set(nullptr);
        }
        if (!mBlueprint->General.SeedUnit.name.empty()) {
          const char* seedName = mBlueprint->General.SeedUnit.name.c_str();
          spawned->CallbackStr("OnSeedUnitBuilt", &seedName);
        }
        mBuildHelper.SetFocus(spawned);
        mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
        return 1;
      }

      case TASKSTATE_Complete: {
        if (!mBuildHelper.IsGood()) {
          return -1;
        }
        if (mUnit->IsPaused) {
          return 10;
        }
        if (!mBuildHelper.UpdateWorkProgress()) {
          return 1;
        }
        Unit* const builtUnit = mBuildUnit.GetObjectPtr();
        const Wm3::Vector3f zeroDir{0.0f, 0.0f, 0.0f};
        if (builtUnit != nullptr && !mBlueprint->General.SeedUnit.name.empty()) {
          SEntitySetTemplateUnit dispatchSet{};
          (void)dispatchSet.AddUnit(builtUnit);
          SSTICommandIssueData issueData(EUnitCommandType::UNITCOMMAND_Upgrade);
          issueData.mBlueprint = const_cast<RUnitBlueprint*>(mBlueprint);
          (void)IssueCommandToSelectedUnits(mSim, dispatchSet, issueData, true);
        } else if (builtUnit != nullptr && builtUnit->AiBuilder != nullptr &&
                   builtUnit->AiBuilder->BuilderIsFactory() &&
                   Wm3::Vector3f::Compare(&mBuildDirection, &zeroDir)) {
          SEntitySetTemplateUnit dispatchSet{};
          (void)dispatchSet.AddUnit(builtUnit);
          const Wm3::Vec3f& unitPos = builtUnit->GetPosition();
          const Wm3::Vector3f rallyPos{unitPos.x + mBuildDirection.x, unitPos.y + mBuildDirection.y,
                                       unitPos.z + mBuildDirection.z};
          SSTICommandIssueData moveData(EUnitCommandType::UNITCOMMAND_Move);
          moveData.mTarget.mType = EAiTargetType::AITARGET_Ground;
          moveData.mTarget.mEnt = -268435456;
          moveData.mTarget.mPos = rallyPos;
          (void)IssueCommandToSelectedUnits(mSim, dispatchSet, moveData, true);
        }
        if (builtUnit != nullptr) {
          builtUnit->UnitStateMask &= ~kUnitStateNoReclaimMask;
        }
        mBuildUnit.UnlinkFromOwnerChain();
        mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
        return -1;
      }

      default:
        gpg::HandleAssertFailure(
          "Reached the supposably unreachable.", 856, "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitBuild.cpp");
        return -1;
    }
  }

  /**
   * Address: 0x005F6AC0 (FUN_005F6AC0, ??1CUnitMobileBuildTask@Moho@@QAE@@Z)
   * Address: 0x005F6880 (FUN_005F6880, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
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
   * Address: 0x005F80C0 (FUN_005F80C0, Moho::CUnitMobileBuildTask::OnEvent)
   * Mangled: ?OnEvent@CUnitMobileBuildTask@Moho@@UAEXW4ECommandEvent@2@@Z
   *
   * VFTable SLOT: 0 of the `Listener<ECommandEvent>` sub-object at +0x34.
   *
   * What it does:
   * See the declaration. `this` is the listener sub-object, so every field
   * displacement in the shipped body is 0x34 below the complete-object offset
   * (`[ebp-18h]` = `mUnit` at +0x1C, `[ebp+84h]` = `mBuildUnit` at +0xB8, and
   * so on). The `Sim*` at `[mUnit+0x150]` is `Entity::SimulationRef`: `Unit`
   * is `IUnit`-primary and carries its `Entity` sub-object at `Unit+0x08`
   * (`lea edi,[esi+8]` before the `Entity::Entity` call at 0x006A5082), so
   * `Unit+0x150` is `Entity+0x148`. The task deliberately goes through the
   * unit rather than its own `CCommandTask::mSim`.
   */
  void CUnitMobileBuildTask::OnEvent(const ECommandEvent event)
  {
    (void)event;

    // 0x005F80CF..0x005F8170: tear down a build already in flight. Guarded on
    // the weak link being live (`!= 0` and `!= 4`, the `WeakPtr<Unit>`
    // sentinel), so a re-seat before the seed unit exists skips it entirely.
    if (mBuildUnit.HasValue()) {
      // 0x005F80FD: the shipped code loads the low half of the 64-bit state
      // mask and stores it back untouched because only the high half carries
      // the bit - `and [unit+4A4h], 0FFFFFEFFh` clears bit 8 of the high
      // dword, i.e. bit 40, `UNITSTATE_NoReclaim`.
      mBuildUnit.GetObjectPtr()->UnitStateMask &= ~kUnitStateNoReclaimMask;

      // 0x005F811E: no null check on `mUnit` here, unlike the destructor -
      // a listener event can only arrive on a task that still has its builder.
      mUnit->WorkProgress = 0.0f;
      mBuildHelper.OnStopBuild(true);

      mBuildUnit.UnlinkFromOwnerChain();
      mPendingBuildEntity.UnlinkFromOwnerChain();
    }

    // 0x005F8173..0x005F8222: re-derive the build placement from the command's
    // current gun target. The target world position is snapped back to the
    // footprint's origin cell, then re-expanded to a world position on the
    // sim map so the build lands on the grid.
    const RUnitBlueprint& blueprint = *mBlueprint;
    const SFootprint& footprint = blueprint.mFootprint;
    const Wm3::Vec3f targetPos = mCommand->mTarget.GetTargetPosGun(false);

    const SOCellPos originCell{
      static_cast<std::int16_t>(static_cast<std::int32_t>(targetPos.x - (static_cast<float>(footprint.mSizeX) * 0.5f))),
      static_cast<std::int16_t>(static_cast<std::int32_t>(targetPos.z - (static_cast<float>(footprint.mSizeZ) * 0.5f)))
    };

    mBuildPosition = COORDS_ToWorldPos(
      mUnit->SimulationRef->mMapData,
      originCell,
      static_cast<ELayer>(footprint.mOccupancyCaps),
      footprint.mSizeX,
      footprint.mSizeZ
    );

    // 0x005F8250..0x005F82D3: the occupancy rectangle, re-snapped from the
    // *new* build position rather than reusing `originCell` - the shipped body
    // reloads the blueprint and both footprint bytes for this second pass.
    const auto rectX0 = static_cast<std::int32_t>(
      static_cast<std::int16_t>(static_cast<std::int32_t>(
        mBuildPosition.x - (static_cast<float>(footprint.mSizeX) * 0.5f)))
    );
    const auto rectZ0 = static_cast<std::int32_t>(
      static_cast<std::int16_t>(static_cast<std::int32_t>(
        mBuildPosition.z - (static_cast<float>(footprint.mSizeZ) * 0.5f)))
    );

    mBuildRect.x0 = rectX0;
    mBuildRect.z0 = rectZ0;
    mBuildRect.x1 = rectX0 + footprint.mSizeX;
    mBuildRect.z1 = rectZ0 + footprint.mSizeZ;

    // 0x005F82D9..0x005F831B: the skirt rectangle for the same position.
    const SCoordsVec2 skirtOrigin{mBuildPosition.x, mBuildPosition.z};
    mBuildSkirt = blueprint.GetSkirtRect(skirtOrigin);

    // 0x005F8321..0x005F835D: rewind the state machine and put the owning
    // thread back on its stage's ready list so it re-runs next frame.
    mTaskState = TASKSTATE_Preparing;
    if (CTaskThread* const ownerThread = mOwnerThread; ownerThread != nullptr) {
      ownerThread->mPendingFrames = 0;
      ownerThread->Unstage();
    }
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

  /**
   * Address: 0x005FE710 (FUN_005FE710, Moho::CUnitMobileBuildTask::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall MemberDeserialize(CUnitCommand** this@<ecx>, gpg::ReadArchive* archive@<eax>);
   *
   * What it does:
   * Restores mobile-build-task state from an archive, lane by lane in binary
   * order (12 reads). The transform / rect / weak-link / helper lanes flow
   * through the reflected `Read`; the two tracked pointer lanes through the
   * typed `ReadPointer_*` slots; the placement-retry counter through the
   * virtual `ReadInt` slot.
   */
  void CUnitMobileBuildTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    // The binary reuses one zero-initialized owner-ref record across every
    // reflected `Read` (each call re-zeroes it before use); mirror that with a
    // single fresh, empty owner-ref.
    const gpg::RRef ownerRef{};

    // 1. base CCommandTask sub-object (offset 0x00).
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    // 2. embedded build helper (offset 0x40).
    archive->Read(CachedCBuildTaskHelperType(), &mBuildHelper, ownerRef);

    // 3. command pointer lane (offset 0x84).
    archive->ReadPointer_CUnitCommand(&mCommand, &ownerRef);

    // 4. blueprint pointer lane (offset 0x88). ReadPointer_RUnitBlueprint wants
    //    a non-const `RUnitBlueprint**`; round-trip through a mutable local.
    RUnitBlueprint* blueprint = const_cast<RUnitBlueprint*>(mBlueprint);
    archive->ReadPointer_RUnitBlueprint(&blueprint, &ownerRef);
    mBlueprint = blueprint;

    // 5-7. build transform payloads (offsets 0x8C / 0x98 / 0xA8).
    archive->Read(CachedVector3fType(), &mBuildPosition, ownerRef);
    archive->Read(CachedQuaternionfType(), &mBuildOrientation, ownerRef);
    archive->Read(CachedVector3fType(), &mBuildDirection, ownerRef);

    // 8. placement-retry counter (offset 0xB4) via the virtual ReadInt slot.
    archive->ReadInt(&mPlacementRetryCount);

    // 9-10. runtime weak links (offsets 0xB8 / 0xC0).
    archive->Read(CachedWeakPtrUnitType(), &mBuildUnit, ownerRef);
    archive->Read(CachedWeakPtrEntityType(), &mPendingBuildEntity, ownerRef);

    // 11-12. build area / skirt rects (offsets 0xC8 / 0xD8).
    archive->Read(CachedRect2iType(), &mBuildRect, ownerRef);
    archive->Read(CachedRect2fType(), &mBuildSkirt, ownerRef);
  }

  /**
   * Address: 0x005FE950 (FUN_005FE950, Moho::CUnitMobileBuildTask::MemberSerialize)
   *
   * IDA signature:
   * void __usercall MemberSerialize(CUnitMobileBuildTask* this@<eax>, gpg::WriteArchive* archive@<esi>);
   *
   * What it does:
   * Line-for-line write mirror of `MemberDeserialize` over the identical field
   * set and order (12 writes). The reflected `Write` lanes carry an empty owner
   * ref; the two tracked pointer lanes build a typed `RRef_*` and emit it as an
   * unowned raw pointer; the placement-retry counter is written through the
   * virtual `WriteInt` slot.
   */
  void CUnitMobileBuildTask::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};

    // 1. base CCommandTask sub-object (offset 0x00).
    archive->Write(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    // 2. embedded build helper (offset 0x40).
    archive->Write(CachedCBuildTaskHelperType(), &mBuildHelper, ownerRef);

    // 3. command pointer lane (offset 0x84): typed RRef then unowned raw pointer.
    gpg::RRef pointerRef{};
    (void)gpg::RRef_CUnitCommand(&pointerRef, mCommand);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    // 4. blueprint pointer lane (offset 0x88).
    (void)gpg::RRef_RUnitBlueprint(&pointerRef, const_cast<RUnitBlueprint*>(mBlueprint));
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    // 5-7. build transform payloads (offsets 0x8C / 0x98 / 0xA8).
    archive->Write(CachedVector3fType(), &mBuildPosition, ownerRef);
    archive->Write(CachedQuaternionfType(), &mBuildOrientation, ownerRef);
    archive->Write(CachedVector3fType(), &mBuildDirection, ownerRef);

    // 8. placement-retry counter (offset 0xB4) via the virtual WriteInt slot.
    archive->WriteInt(mPlacementRetryCount);

    // 9-10. runtime weak links (offsets 0xB8 / 0xC0).
    archive->Write(CachedWeakPtrUnitType(), &mBuildUnit, ownerRef);
    archive->Write(CachedWeakPtrEntityType(), &mPendingBuildEntity, ownerRef);

    // 11-12. build area / skirt rects (offsets 0xC8 / 0xD8).
    archive->Write(CachedRect2iType(), &mBuildRect, ownerRef);
    archive->Write(CachedRect2fType(), &mBuildSkirt, ownerRef);
  }
} // namespace moho
