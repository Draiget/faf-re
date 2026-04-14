#include "moho/unit/tasks/CUnitUnloadUnits.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <new>

#include "gpg/core/containers/Rect2.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiTransport.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/containers/BVSet.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace moho
{
  /**
   * Address: 0x0062B780 (FUN_0062B780, Moho::PrepareMove)
   *
   * What it does:
   * Coerces one world-space move destination into a valid passable location for
   * one unit.
   */
  [[nodiscard]]
  bool PrepareMove(int moveFlags, Unit* unit, Wm3::Vector3f* inOutPos, gpg::Rect2f* outSkirtRect, bool useWholeMap);
} // namespace moho

namespace
{
  constexpr std::uint64_t kUnitStateMaskTransportUnloading = (1ull << moho::UNITSTATE_TransportUnloading);
  constexpr std::uintptr_t kEntitySetInvalidEntry = 0x8u;
  constexpr std::int16_t kInvalidCellPosComponent = static_cast<std::int16_t>(0x8000);
  constexpr std::uint32_t kGroundTargetEntityIdTag = 0xF0000000u;

  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState state) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<std::int32_t>(state) + 1);
  }

  [[nodiscard]] bool IsUsableDetachedUnit(const moho::Unit* const unit) noexcept
  {
    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(unit);
    return raw != 0u && raw != kEntitySetInvalidEntry;
  }

  [[nodiscard]]
  moho::BVSet<moho::EntId, moho::EntIdUniverse> BuildSelectedEntitySetFromUnits(
    const moho::EntitySetTemplate<moho::Unit>& units
  )
  {
    moho::BVSet<moho::EntId, moho::EntIdUniverse> selected{};
    for (moho::Unit* const unit : units) {
      if (!IsUsableDetachedUnit(unit)) {
        continue;
      }
      (void)selected.mBits.Add(static_cast<unsigned int>(unit->id_));
    }
    return selected;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00625E80 (FUN_00625E80, Moho::CUnitUnloadUnits::CUnitUnloadUnits)
   *
   * What it does:
   * Initializes one detached unload-units task with cleared goal/set/link
   * lanes.
   */
  CUnitUnloadUnits::CUnitUnloadUnits()
    : CCommandTask()
    , mUnloadGoal{}
    , mIsStagingPlatform(false)
    , mHasEligibleLoadedUnits(false)
    , mPad56_57{}
    , mLoadedUnits()
    , mOwnerCommandLinkLane{}
  {}

  /**
   * Address: 0x00626070 (FUN_00626070, Moho::CUnitUnloadUnits::~CUnitUnloadUnits)
   *
   * What it does:
   * Clears owner-unit unload state, requests variable-data refresh, and unlinks
   * the owner weak-link lane before member/base teardown.
   */
  CUnitUnloadUnits::~CUnitUnloadUnits()
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~kUnitStateMaskTransportUnloading;
      mUnit->NeedSyncGameData = true;
    }

    mOwnerCommandLinkLane.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x00625EE0 (FUN_00625EE0, Moho::CUnitUnloadUnits::CUnitUnloadUnits)
   *
   * What it does:
   * Initializes one unload-units task from dispatch context, copies unload
   * goal rectangle state, collects eligible transported units, links the
   * loaded-unit set into EntityDB, and updates owner unit unload state.
   */
  CUnitUnloadUnits::CUnitUnloadUnits(
    CUnitCommand* const ownerCommand,
    CCommandTask* const dispatchTask,
    const SNavGoal& unloadGoal,
    const SCommandUnitSet& commandUnits
  )
    : CCommandTask(dispatchTask)
    , mUnloadGoal(unloadGoal)
    , mIsStagingPlatform(false)
    , mHasEligibleLoadedUnits(false)
    , mPad56_57{}
    , mLoadedUnits()
    , mOwnerCommandLinkLane{}
  {
    mOwnerCommandLinkLane.ResetFromObject(ownerCommand);
    mUnit->SimulationRef->mEntityDB->RegisterEntitySet(mLoadedUnits);

    for (CScriptObject* const entry : commandUnits.mVec) {
      if (!SCommandUnitSet::IsUsableEntry(entry)) {
        continue;
      }

      Unit* const candidate = SCommandUnitSet::UnitFromEntry(entry);
      if (candidate == nullptr || candidate->IsDead() || candidate == mUnit) {
        continue;
      }

      Unit* const transportOwner = candidate->GetTransportedBy();
      if (!transportOwner) {
        continue;
      }

      mHasEligibleLoadedUnits = true;
      if (transportOwner == mUnit) {
        (void)mLoadedUnits.AddUnit(candidate);
      }
    }

    mUnit->UnitStateMask |= kUnitStateMaskTransportUnloading;
    mIsStagingPlatform = mUnit->AiTransport->TransportIsAirStagingPlatform();

    if (mUnit->IsMobile()) {
      IAiNavigator* const navigator = mUnit->AiNavigator;
      if (navigator != nullptr) {
        navigator->AbortMove();
      }
    }
  }

  /**
   * Address: 0x00626390 (FUN_00626390, Moho::CUnitUnloadUnits::TaskTick)
   *
   * What it does:
   * Executes one unload-units task tick across prepare/wait/start/process
   * states, detaches loaded units, repositions them, and issues follow-up
   * move commands when required.
   */
  int CUnitUnloadUnits::Execute()
  {
    const msvc8::vector<Entity*>& attachedEntities = mUnit->GetAttachedEntities();
    if (attachedEntities.begin() == nullptr || attachedEntities.begin() == attachedEntities.end()) {
      return -1;
    }

    if (mHasEligibleLoadedUnits && mLoadedUnits.Empty()) {
      return -1;
    }

    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
        if (
          blueprint != nullptr
          && blueprint->Physics.MotionType == RULEUMT_SurfacingSub
          && mUnit->mCurrentLayer == LAYER_Sub
        ) {
          SNavGoal surfacingGoal(mUnit->GetFootprint().ToCellPos(mUnit->GetPosition()));
          surfacingGoal.mLayer = LAYER_Water;
          if (mUnit->AiCommandDispatch != nullptr) {
            mUnit->AiCommandDispatch->SetNewTargetLayer(surfacingGoal);
          }
          mTaskState = NextTaskState(mTaskState);
          return 1;
        }

        mTaskState = TASKSTATE_Starting;
        return 0;
      }

      case TASKSTATE_Waiting:
        if (mUnit->mCurrentLayer != LAYER_Water) {
          return 1;
        }
        mTaskState = TASKSTATE_Starting;
        return 0;

      case TASKSTATE_Starting: {
        if (!mIsStagingPlatform && mUnit->IsMobile()) {
          mUnloadGoal.aux4 = static_cast<std::int32_t>(LAYER_Land);
          NewMoveTask(mUnloadGoal, this, 0, mOwnerCommandLinkLane.GetObjectPtr(), 0);
        }

        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Processing: {
        EntitySetTemplate<Unit> detachedUnits{};
        if (mLoadedUnits.Empty()) {
          detachedUnits = mUnit->AiTransport->TransportDetachAllUnits(false);
        } else {
          for (Entity* const entry : mLoadedUnits.mVec) {
            Unit* const candidate = SEntitySetTemplateUnit::UnitFromEntry(entry);
            if (!IsUsableDetachedUnit(candidate)) {
              continue;
            }

            if (mUnit->AiTransport->TransportDetachUnit(candidate)) {
              (void)detachedUnits.Add(candidate);
            }
          }
        }

        if (!mIsStagingPlatform && mUnit->mIsAir) {
          if (CUnitMotion* const motion = mUnit->UnitMotion; motion != nullptr) {
            const Wm3::Vector3f zeroSteering{0.0f, 0.0f, 0.0f};
            motion->SetTarget(mUnit->GetPosition(), zeroSteering, LAYER_Air);
          }

          mTaskState = NextTaskState(mTaskState);
          return 0;
        }

        for (Unit* detachedUnit : detachedUnits) {
          if (!IsUsableDetachedUnit(detachedUnit)) {
            continue;
          }

          if (mIsStagingPlatform) {
            if (detachedUnit->mIsAir && detachedUnit->UnitMotion != nullptr) {
              detachedUnit->UnitMotion->mHeight = std::numeric_limits<float>::infinity();
            }
            continue;
          }

          const VTransform transportTransform = mUnit->GetTransform();
          SOCellPos unloadCell{kInvalidCellPosComponent, kInvalidCellPosComponent};

          bool foundMeleeSpace = false;
          if (mUnit->IsMobile()) {
            const SFootprint& transportFootprint = mUnit->GetFootprint();
            const int transportSize = std::max<int>(transportFootprint.mSizeX, transportFootprint.mSizeZ);

            if (transportSize > 1) {
              const SFootprint& unloadedFootprint = detachedUnit->GetFootprint();
              const int unloadedSize = std::max<int>(unloadedFootprint.mSizeX, unloadedFootprint.mSizeZ);
              foundMeleeSpace = detachedUnit->HasMeleeSpaceAroundLargeTarget(mUnit, &unloadCell, 2 * unloadedSize);
            } else {
              foundMeleeSpace = detachedUnit->HasMeleeSpaceAroundSmallTarget(mUnit, &unloadCell);
            }
          } else {
            foundMeleeSpace = detachedUnit->HasMeleeSpaceAroundSmallTarget(mUnit, &unloadCell);
          }

          Wm3::Vector3f unloadWorldPos{};
          if (foundMeleeSpace) {
            unloadWorldPos = COORDS_ToWorldPos(mUnit->SimulationRef->mMapData, unloadCell, detachedUnit->GetFootprint());
          } else {
            unloadWorldPos = detachedUnit->GetPosition();
            gpg::Rect2f moveSkirt{0.0f, 0.0f, 0.0f, 0.0f};
            const bool useWholeMap = mUnit->ArmyRef != nullptr && mUnit->ArmyRef->UseWholeMap();
            (void)PrepareMove(1, detachedUnit, &unloadWorldPos, &moveSkirt, useWholeMap);
          }

          VTransform unloadTransform = transportTransform;
          unloadTransform.pos_ = unloadWorldPos;

          if (CUnitMotion* const unitMotion = detachedUnit->UnitMotion; unitMotion != nullptr) {
            unitMotion->Warp(unloadTransform);
          }

          const SCoordsVec2 unloadCenter{unloadWorldPos.x, unloadWorldPos.z};
          gpg::Rect2i reservationRect{};
          (void)COORDS_ToGridRect(&reservationRect, unloadCenter, detachedUnit->GetFootprint());
          detachedUnit->ReserveOgridRect(reservationRect);
        }

        if (!mIsStagingPlatform) {
          for (Unit* detachedUnit : detachedUnits) {
            if (IsUsableDetachedUnit(detachedUnit)) {
              detachedUnit->FreeOgridRect();
            }
          }
        }

        if (mIsStagingPlatform || !mUnit->IsMobile()) {
          const SOCellPos unloadCell{
            static_cast<std::int16_t>(mUnloadGoal.minX),
            static_cast<std::int16_t>(mUnloadGoal.minZ),
          };
          const SFootprint& footprint = mUnit->GetFootprint();
          const Wm3::Vector3f unloadWorldPos = COORDS_ToWorldPos(
            mUnit->SimulationRef->mMapData,
            unloadCell,
            static_cast<ELayer>(footprint.mOccupancyCaps),
            static_cast<int>(footprint.mSizeX),
            static_cast<int>(footprint.mSizeZ)
          );

          SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Move);
          commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
          commandIssueData.mTarget.mEntityId = kGroundTargetEntityIdTag;
          commandIssueData.mTarget.mPos = unloadWorldPos;

          const BVSet<EntId, EntIdUniverse> selectedUnits = BuildSelectedEntitySetFromUnits(detachedUnits);
          if (selectedUnits.mBits.Count() != 0u) {
            mUnit->SimulationRef->IssueCommand(selectedUnits, commandIssueData, true);
          }
        }

        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Complete:
        return -1;

      default:
        return 1;
    }
  }

  /**
   * Address: 0x00626330 (FUN_00626330, Moho::CUnitUnloadUnits::operator new)
   *
   * What it does:
   * Allocates one unload-units task and forwards constructor arguments into
   * in-place construction.
   */
  CUnitUnloadUnits* CUnitUnloadUnits::Create(
    CCommandTask* const dispatchTask,
    const SNavGoal* const unloadGoal,
    const SCommandUnitSet* const commandUnits,
    CUnitCommand* const ownerCommand
  )
  {
    void* const storage = ::operator new(sizeof(CUnitUnloadUnits));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitUnloadUnits(ownerCommand, dispatchTask, *unloadGoal, *commandUnits);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }
} // namespace moho
