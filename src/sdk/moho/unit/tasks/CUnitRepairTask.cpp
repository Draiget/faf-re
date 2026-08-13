#include "moho/unit/tasks/CUnitRepairTask.h"

#include <cmath>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/math/MathReflection.h"
#include "moho/path/SNavGoal.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/render/camera/VTransform.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"
#include "Wm3Vector3.h"

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

  [[nodiscard]] gpg::RType* CachedCBuildTaskHelperType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CBuildTaskHelper));
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
} // namespace

namespace moho
{
  /**
   * Address: 0x005FED70 (FUN_005FED70, Moho::CUnitRepairTask::MemberDeserialize)
   *
   * What it does:
   * Deserializes repair-task runtime state in binary lane order: command-task
   * base, build-helper lane, command raw pointer, weak target lanes, then flags.
   */
  void CUnitRepairTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);
    archive->Read(CachedCBuildTaskHelperType(), &mBuildHelper, ownerRef);
    archive->ReadPointer_CUnitCommand(&mCommand, &ownerRef);
    archive->Read(CachedWeakPtrUnitType(), &mTargetUnit, ownerRef);
    archive->Read(CachedWeakPtrUnitType(), &mBuildTargetUnit, ownerRef);
    archive->ReadBool(&mInPosition);
    archive->ReadBool(&mIsSilo);
    archive->ReadBool(&mGuardAssistMode);
    archive->ReadBool(&mInheritingWork);
  }

  /**
   * Address: 0x005FEEC0 (FUN_005FEEC0)
   *
   * What it does:
   * Serializes repair-task runtime state in binary lane order: command-task
   * base, build-helper lane, command raw pointer, target weak lanes, then flags.
   */
  void CUnitRepairTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);
    archive->Write(CachedCBuildTaskHelperType(), &mBuildHelper, ownerRef);

    gpg::RRef commandRef{};
    (void)gpg::RRef_CUnitCommand(&commandRef, mCommand);
    gpg::WriteRawPointer(archive, commandRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedWeakPtrUnitType(), &mTargetUnit, ownerRef);
    archive->Write(CachedWeakPtrUnitType(), &mBuildTargetUnit, ownerRef);

    archive->WriteBool(mInPosition);
    archive->WriteBool(mIsSilo);
    archive->WriteBool(mGuardAssistMode);
    archive->WriteBool(mInheritingWork);
  }

  /**
   * Address: 0x005F8C80 (FUN_005F8C80, ??0CUnitRepairTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Builds the repair-task command/listener subobjects, initializes the shared
   * build helper, binds the target weak lane, and primes the repair mode flags.
   */
  CUnitRepairTask::CUnitRepairTask(IAiCommandDispatchImpl* const dispatchTask, Unit* const targetUnit, const bool isSiloBuild)
    : CCommandTask(static_cast<CCommandTask*>(dispatchTask))
    , Listener<ECommandEvent>()
    , mBuildHelper("Repair", mUnit)
    , mCommand(nullptr)
    , mTargetUnit{}
    , mBuildTargetUnit{}
    , mInPosition(false)
    , mIsSilo(isSiloBuild)
    , mGuardAssistMode(false)
    , mInheritingWork(false)
  {
    mListenerLink.ListResetLinks();

    if (dispatchTask != nullptr && dispatchTask->mUnit != nullptr && dispatchTask->mUnit->CommandQueue != nullptr) {
      mCommand = dispatchTask->mUnit->CommandQueue->GetCurrentCommand();
      if (mCommand != nullptr) {
        mListenerLink.ListLinkBefore(static_cast<Broadcaster*>(mCommand));
      }
    }

    mTargetUnit.ResetFromObject(targetUnit);
    mBuildTargetUnit.ClearLinkState();

    if (mUnit != nullptr) {
      if (Unit* const target = mTargetUnit.GetObjectPtr(); target != nullptr && target->IsUnitState(UNITSTATE_Enhancing)) {
        mUnit->RunScriptWeakUnit("InheritWork", mTargetUnit);
        mInheritingWork = true;
      }
    }

    mGuardAssistMode = mUnit != nullptr
      && (mUnit->IsUnitState(UNITSTATE_Guarding) || mUnit->IsUnitState(UNITSTATE_AssistingCommander));
  }

  /**
   * Address: 0x005F9E50 (FUN_005F9E50, Moho::CUnitRepairTask::operator new)
   *
   * IDA signature:
   * int *__cdecl Moho::CUnitRepairTask::operator new(
   *     Moho::IAiCommandDispatchImpl *dispatch, Moho::Unit *target, bool isSilo);
   *
   * What it does:
   * Allocates 0x9C bytes through the plain global `operator new`, constructs a
   * repair task in that storage when the allocation succeeded, and returns it.
   *
   * Note this is the throwing `operator new` with an explicit null check, not
   * the `std::nothrow` overload: the binary calls `??2@YAPAXI@Z` and branches
   * on the result. All five creation sites share this one out-of-line copy.
   */
  CUnitRepairTask* CUnitRepairTask::Allocate(
    IAiCommandDispatchImpl* const dispatchTask,
    Unit* const targetUnit,
    const bool isSiloBuild
  )
  {
    void* const storage = ::operator new(sizeof(CUnitRepairTask));
    if (storage == nullptr) {
      return nullptr;
    }

    return ::new (storage) CUnitRepairTask(dispatchTask, targetUnit, isSiloBuild);
  }

  /**
   * Address: 0x005F8E20 (FUN_005F8E20, ??1CUnitRepairTask@Moho@@QAE@@Z body)
   * Scalar deleting dtor thunk: 0x005F8FE0 (FUN_005F8FE0, vtable slot 0)
   *
   * IDA signature:
   * int __stdcall Moho::CUnitRepairTask::~CUnitRepairTask(Moho::CUnitRepairTask *this);
   *
   * What it does:
   * Runs the "ClearWork" unit script, detaches the embedded command-event
   * listener, clears the owner unit's repairing state bit, zeros its work
   * progress and builder aim target, releases the reserved ogrid footprint
   * when still held mid-prep, clears the build-target unit's no-reclaim bit,
   * stops the shared build helper, records the task's dispatch result, and
   * unlinks the build-target/target weak lanes. The primary/Listener vftable
   * resets and the CBuildTaskHelper/CCommandTask sub-object teardowns are
   * emitted by the compiler and are not written here.
   */
  CUnitRepairTask::~CUnitRepairTask()
  {
    // Notify the unit script that the active repair work is being torn down.
    // The binary dereferences mUnit unconditionally here (no null guard).
    mUnit->RunScript("ClearWork");

    // Detach the embedded command-event listener from whatever broadcaster
    // ring it currently sits in and reset it to a self-linked singleton.
    mListenerLink.ListUnlinkSelf();

    // Drop the repairing state bit this task owns on the owner unit.
    mUnit->UnitStateMask &= ~(1ull << UNITSTATE_Repairing);

    // Clear the owner unit's cached work-progress and builder aim target.
    mUnit->WorkProgress = 0.0f;
    if (IAiBuilder* const builder = mUnit->AiBuilder; builder != nullptr) {
      builder->BuilderSetAimTarget(Wm3::Vector3f::Zero());
    }

    // Release the reserved ogrid footprint if we were still preparing and had
    // not yet reached the repair position (TASKSTATE_Waiting == 1).
    if (mTaskState == TASKSTATE_Waiting && !mInPosition) {
      mUnit->FreeOgridRect();
    }

    // Clear the no-reclaim protection bit on the unit we were building/assisting.
    if (Unit* const buildTarget = mBuildTargetUnit.GetObjectPtr(); buildTarget != nullptr) {
      buildTarget->UnitStateMask &= ~(1ull << UNITSTATE_NoReclaim);
    }

    // Stop the shared build helper (failed == true), matching the binary.
    mBuildHelper.OnStopBuild(true);

    // Publish the dispatch result: 1 when the task finished in TASKSTATE_5,
    // otherwise 2. EAiResult has no lexical labels in the recovered RTTI.
    *mDispatchResult = static_cast<EAiResult>(mTaskState == TASKSTATE_5 ? 1 : 2);

    // Unlink both weak lanes from their owner chains (declaration-reverse order
    // in the binary: build-target then target). WeakPtr<T>'s generic destructor
    // is trivial in our model, so these detaches are explicit.
    mBuildTargetUnit.UnlinkFromOwnerChain();
    mTargetUnit.UnlinkFromOwnerChain();

    // Final explicit Listener sub-object detach (trivially-destructible in our
    // model, so the compiler does not emit it): unlink and reset to singleton.
    mListenerLink.ListUnlinkSelf();
  }

  /**
   * Address: 0x005FD410 (FUN_005FD410)
   *
   * What it does:
   * Preserves one serializer-save thunk lane for `CUnitRepairTask`.
   */
  [[maybe_unused]] void CUnitRepairTaskMemberSerializeAdapterLaneA(
    const CUnitRepairTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x005FDC60 (FUN_005FDC60)
   *
   * What it does:
   * Alternate serializer-save thunk lane for `CUnitRepairTask`.
   */
  [[maybe_unused]] void CUnitRepairTaskMemberSerializeAdapterLaneB(
    const CUnitRepairTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  namespace
  {
    constexpr int kRepairTaskAssertLine = 1388;
    constexpr char kAiUnitBuildSource[] = "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitBuild.cpp";

    // Larger XZ footprint extent of the owner unit (max(mSizeX, mSizeZ)).
    [[nodiscard]] float LargerFootprintExtent(const SFootprint& footprint) noexcept
    {
      const std::uint8_t sizeX = footprint.mSizeX;
      const std::uint8_t sizeZ = footprint.mSizeZ;
      return static_cast<float>(sizeX > sizeZ ? sizeX : sizeZ);
    }

    // Larger skirt extent of the target blueprint (max(SkirtSizeX, SkirtSizeZ)).
    [[nodiscard]] float LargerSkirtExtent(const RUnitBlueprint& blueprint) noexcept
    {
      const float skirtX = blueprint.Physics.SkirtSizeX;
      const float skirtZ = blueprint.Physics.SkirtSizeZ;
      return skirtZ > skirtX ? skirtZ : skirtX;
    }

    // Horizontal (XZ) distance between two world positions, minus the owner's
    // footprint extent and the target blueprint's skirt extent (the binary's
    // "build gap" used against Economy.MaxBuildDistance).
    [[nodiscard]] float BuildRangeGap(
      const Wm3::Vec3f& builderPos,
      const Wm3::Vec3f& targetPos,
      const SFootprint& builderFootprint,
      const RUnitBlueprint& targetBlueprint) noexcept
    {
      const float dx = builderPos.x - targetPos.x;
      const float dz = builderPos.z - targetPos.z;
      const float planarDist = std::sqrt(dx * dx + dz * dz);
      return (planarDist - LargerFootprintExtent(builderFootprint)) - LargerSkirtExtent(targetBlueprint);
    }
  } // namespace

  /**
   * Address: 0x005F9230 (FUN_005F9230, Moho::CUnitRepairTask::CanRepair)
   *
   * What it does:
   * Returns whether the target may currently be repaired: false when the target
   * needs refuel (fuel-using blueprint below full fuel) or is a SHIELD whose
   * shielded focus is itself damaged; true otherwise (including no target).
   */
  bool CUnitRepairTask::CanRepair()
  {
    Unit* const target = mTargetUnit.GetObjectPtr();
    if (target == nullptr) {
      return true;
    }

    if (target->GetBlueprint()->Physics.FuelUseTime > 0.0f && target->FuelRatio < 1.0f) {
      return false;
    }

    if (target->IsInCategory("SHIELD")) {
      if (Entity* const focus = target->FocusEntityRef.ResolveObjectPtr<Entity>(); focus != nullptr) {
        if (focus->MaxHealth > focus->Health) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Address: 0x005F9370 (FUN_005F9370, Moho::CUnitRepairTask::TaskTick)
   *
   * VFTABLE SLOT: 1
   *
   * What it does:
   * Repair/assist build-task state machine; see header. Target-unit field reads
   * that IDA rendered on an IUnit-view pointer (Entity sub-object at +8) resolve
   * to typed Entity/Unit members here; the uniform +8 offset is the decompiler's
   * weak-view artifact.
   */
  int CUnitRepairTask::Execute()
  {
    Unit* target = mTargetUnit.GetObjectPtr();
    if (target == nullptr || target == mUnit) {
      return -1;
    }

    // Fully healed: if nothing else keeps us busy and CanRepair() clears us, stop.
    if (target->Health == target->MaxHealth) {
      if (mGuardAssistMode) {
        if (mTaskState < TASKSTATE_Complete && !mIsSilo &&
            !target->IsUnitState(UNITSTATE_Upgrading) && CanRepair()) {
          return -1;
        }
      } else if ((!target->IsBeingBuilt() || target->FractionCompleted == 1.0f) && CanRepair()) {
        return -1;
      }
    }

    // Grounded / being-built targets that have not moved this frame are idle;
    // an airborne flyer on the AIR layer cannot be repaired in place.
    if (!target->GetBlueprint()->Air.CanFly || target->IsBeingBuilt()) {
      if (Wm3::Vector3f::Compare(&target->Position, &target->PrevPosition)) {
        return -1;
      }
    } else if (target->mCurrentLayer == LAYER_Air) {
      return -1;
    }

    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        // Off-map targets are unreachable unless this army uses the whole map.
        if (!mUnit->ArmyRef->UseWholeMap()) {
          STIMap* const mapData = mUnit->SimulationRef->mMapData;
          if (!mapData->IsWithin(target->GetPosition(), 0.0f, false)) {
            return 1;
          }
        }

        // In guard/assist mode, re-home onto the FACTORY that is building the
        // target, or onto the focus of an upgrading target.
        if (mGuardAssistMode) {
          bool retargetCreator = false;
          if (target->IsBeingBuilt() && target->GetCreator() != nullptr) {
            if (target->GetCreator()->IsInCategory("FACTORY")) {
              retargetCreator = true;
            }
          }

          if (retargetCreator) {
            target = target->GetCreator();
          } else if (target->IsUnitState(UNITSTATE_Upgrading)) {
            if (Entity* const focus = target->GetFocusEntity(); focus != nullptr) {
              if (Unit* const focusUnit = focus->IsUnit(); focusUnit != nullptr) {
                mTargetUnit.ResetFromObject(focusUnit);
                target = mTargetUnit.GetObjectPtr();
              }
            }
          }
        }

        // If not yet in position, reserve the build footprint and, when the site
        // does not fit or the target is out of build range, path into range.
        if (!mInPosition && target != nullptr) {
          const Wm3::Vec3f& builderPos = mUnit->GetPosition();
          const SCoordsVec2 builderCoords{builderPos.x, builderPos.z};
          const bool fits =
            mUnit->GetFootprint().FitsAt(builderCoords, *mUnit->SimulationRef->mOGrid) != static_cast<EOccupancyCaps>(0u);

          const RUnitBlueprint* const targetBlueprint = target->GetBlueprint();
          const float rangeGap =
            BuildRangeGap(mUnit->GetPosition(), target->GetPosition(), mUnit->GetFootprint(), *targetBlueprint);

          if (!fits || rangeGap > mUnit->GetBlueprint()->Economy.MaxBuildDistance) {
            gpg::Rect2f skirt = target->GetSkirtRect();
            skirt.x0 -= 1.0f;
            skirt.z0 -= 1.0f;
            skirt.x1 += 1.0f;
            skirt.z1 += 1.0f;

            const Wm3::Vec3f& targetPos = target->GetPosition();
            Wm3::Vector3f moveTarget{targetPos.x, targetPos.y, targetPos.z};
            const bool useWholeMap = mUnit->ArmyRef->UseWholeMap();
            (void)mUnit->PrepareMove(1, &moveTarget, &skirt, useWholeMap);

            const SCoordsVec2 reserveCoords{moveTarget.x, moveTarget.z};
            gpg::Rect2i reserveRect{};
            COORDS_ToGridRect(&reserveRect, reserveCoords, mUnit->GetFootprint());
            mUnit->ReserveOgridRect(reserveRect);

            const SOCellPos goalCell = mUnit->GetFootprint().ToCellPos(moveTarget);
            NewMoveTask(SNavGoal(goalCell), this, 0, nullptr, 0);
          }
        }

        mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
        return 0;
      }

      case TASKSTATE_Waiting: {
        const bool wasMoving = !mInPosition;
        mTaskState = TASKSTATE_Starting;

        if (wasMoving) {
          mUnit->FreeOgridRect();

          bool retargetCreator = false;
          if (target->IsBeingBuilt() && target->GetCreator() != nullptr) {
            if (target->GetCreator()->IsInCategory("FACTORY")) {
              retargetCreator = true;
            }
          }
          if (retargetCreator) {
            target = target->GetCreator();
          }

          const RUnitBlueprint* const targetBlueprint = target->GetBlueprint();
          const float rangeGap =
            BuildRangeGap(mUnit->GetPosition(), target->GetPosition(), mUnit->GetFootprint(), *targetBlueprint);
          if (rangeGap > mUnit->GetBlueprint()->Economy.MaxBuildDistance) {
            return -1;
          }
        }

        if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
          navigator->AbortMove();
        }

        mBuildTargetUnit.ResetFromObject(mTargetUnit.GetObjectPtr());

        if (IAiBuilder* const builder = mUnit->AiBuilder; builder != nullptr) {
          Unit* const buildTarget = mBuildTargetUnit.GetObjectPtr();
          const VTransform boneTransform = buildTarget->GetBoneWorldTransform(-1);
          builder->BuilderSetAimTarget(boneTransform.pos_);
        }
      }
        [[fallthrough]];

      case TASKSTATE_Starting: {
        if (!mUnit->GetBlueprint()->Economy.NeedToFaceTargetToBuild) {
          mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
          return 0;
        }

        const VTransform& transform = mUnit->GetTransform();
        const VAxes3 axes{transform.orient_};
        Wm3::Vector3f forward{axes.vZ.x, 0.0f, axes.vZ.z};
        (void)forward.Normalize();

        const Wm3::Vec3f& builderPos = mUnit->GetPosition();
        const Wm3::Vec3f& targetPos = target->GetPosition();
        Wm3::Vector3f toTarget{targetPos.x - builderPos.x, 0.0f, targetPos.z - builderPos.z};
        (void)toTarget.Normalize();

        const float dot = (forward.x * toTarget.x) + (forward.y * toTarget.y) + (forward.z * toTarget.z);
        if (dot > 0.94999999f) {
          mUnit->UnitMotion->SetFacing(Wm3::Vector3f::Zero());
          mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
          return 0;
        }
        mUnit->UnitMotion->SetFacing(toTarget);
        return 1;
      }

      case TASKSTATE_Processing: {
        if (IAiBuilder* const builder = mUnit->AiBuilder; builder != nullptr && !builder->BuilderGetOnTarget()) {
          return 1;
        }
        if (mUnit->IsPaused) {
          return 10;
        }

        if (Unit* const buildTarget = mBuildTargetUnit.GetObjectPtr(); buildTarget != nullptr) {
          buildTarget->UnitStateMask |= (1ull << static_cast<std::uint32_t>(UNITSTATE_NoReclaim));
          mBuildHelper.SetFocus(buildTarget);
        } else {
          mBuildHelper.SetFocus(nullptr);
        }
        mBuildHelper.mIsSilo = mIsSilo;

        mUnit->UnitStateMask |= (1ull << static_cast<std::uint32_t>(UNITSTATE_Repairing));
        mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
        return 0;
      }

      case TASKSTATE_Complete: {
        // Attached targets skip the range gate (they cannot drift away).
        if (!target->IsUnitState(UNITSTATE_Attached)) {
          const RUnitBlueprint* const targetBlueprint = target->GetBlueprint();
          const float rangeGap =
            BuildRangeGap(mUnit->GetPosition(), target->GetPosition(), mUnit->GetFootprint(), *targetBlueprint);
          if (rangeGap > (mUnit->GetBlueprint()->Economy.MaxBuildDistance * 2.0f)) {
            return -1;
          }
        }

        if (!mBuildHelper.UpdateWorkProgress()) {
          // Not finished: keep waiting unless we are inheriting an enhancement
          // whose subject has since gone away or stopped enhancing.
          if (!mInheritingWork) {
            return 1;
          }
          Unit* const buildTarget = mBuildTargetUnit.GetObjectPtr();
          if (buildTarget == nullptr || !buildTarget->IsUnitState(UNITSTATE_Enhancing)) {
            return 1;
          }
        }

        mTaskState = static_cast<ETaskState>(static_cast<int>(mTaskState) + 1);
        return -1;
      }

      default:
        gpg::HandleAssertFailure("Reached the supposably unreachable.", kRepairTaskAssertLine, kAiUnitBuildSource);
        return -1;
    }
  }

  /**
   * Address: 0x005F9D60 (FUN_005F9D60, Moho::CUnitRepairTask::OnEvent)
   *
   * VFTABLE SLOT: 0 (Listener<ECommandEvent> sub-object vtable)
   *
   * What it does:
   * Cancels the active repair on any command event: clears the build-target's
   * NoReclaim bit, zeros owner work progress, stops the build helper, unlinks the
   * build-target lane, rebinds the target lane from the command's focus unit,
   * resets state to Preparing, and resumes the owning task thread.
   */
  void CUnitRepairTask::OnEvent(ECommandEvent /*event*/)
  {
    if (Unit* const buildTarget = mBuildTargetUnit.GetObjectPtr(); buildTarget != nullptr) {
      buildTarget->UnitStateMask &= ~(1ull << static_cast<std::uint32_t>(UNITSTATE_NoReclaim));
      mUnit->WorkProgress = 0.0f;
      mBuildHelper.OnStopBuild(true);
      mBuildTargetUnit.UnlinkFromOwnerChain();
    }

    mTargetUnit.ResetFromObject(mCommand != nullptr ? CUnitCommand::GetTarget(mCommand) : nullptr);
    mInPosition = false;
    mTaskState = TASKSTATE_Preparing;
    TaskResume(false, 0);
  }
} // namespace moho
