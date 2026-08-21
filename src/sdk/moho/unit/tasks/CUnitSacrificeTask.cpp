#include "moho/unit/tasks/CUnitSacrificeTask.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/path/SNavGoal.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace
{
  // Category a still-under-construction recipient's creator must carry before
  // the approach is redirected onto that creator (0x005FB676).
  constexpr const char* kFactoryCategoryName = "FACTORY";

  // Script hooks fired on entering and leaving the paying phase
  // (0x005FB5F3 / 0x005FB478).
  constexpr const char* kOnStartSacrificeScript = "OnStartSacrifice";
  constexpr const char* kOnStopSacrificeScript = "OnStopSacrifice";

  // Script-side enhancement bookkeeping read/written while the recipient is
  // enhancing (0x005FB28F, 0x005FB2B2, 0x005FB304, 0x005FB37B).
  constexpr const char* kWorkProgressKey = "WorkProgress";
  constexpr const char* kWorkItemBuildCostMassKey = "WorkItemBuildCostMass";
  constexpr const char* kWorkItemBuildCostEnergyKey = "WorkItemBuildCostEnergy";

  // gpg assert lane taken when `mTaskState` is outside the three sacrifice
  // phases (0x005FB1FC-0x005FB20B).
  constexpr const char* kUnreachableStateText = "Reached the supposably unreachable.";
  constexpr int kUnreachableStateLine = 1896; // push 768h @ 0x005FB201
  constexpr const char* kAiUnitBuildSourcePath = "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitBuild.cpp";

  // Fraction substituted whenever a cost divisor is not positive
  // (flt_E4F724 = 0.5f, loaded at 0x005FB2F3/0x005FB33C/0x005FB3E5/0x005FB424).
  constexpr float kUnknownCostFraction = 0.5f;
  // Enhancement progress saturates here (a7 = 1.0f at 0x00DFEC20, 0x005FB358).
  constexpr float kCompleteWorkProgress = 1.0f;

  /**
   * Build-range tests measure the gap between footprint edges, so each unit
   * contributes its widest side (0x005FB4F4-0x005FB518).
   */
  [[nodiscard]] float FootprintExtent(const moho::SFootprint& footprint) noexcept
  {
    return static_cast<float>(std::max(footprint.mSizeX, footprint.mSizeZ));
  }

  /**
   * Share of `value` one unit of `cost` buys. A recipient with no recorded
   * cost yields the binary's fixed half-step instead of dividing by zero.
   */
  [[nodiscard]] float CostFraction(const float value, const float cost) noexcept
  {
    return (cost > 0.0f) ? (value / cost) : kUnknownCostFraction;
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

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

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
} // namespace

namespace moho
{
  /**
   * Address: 0x005FAD60 (FUN_005FAD60, Moho::CUnitSacrificeTask::CUnitSacrificeTask)
   *
   * What it does:
   * Initializes one detached sacrifice-task lane with default listener-link,
   * null current-command pointer, and cleared weak target lane.
   */
  CUnitSacrificeTask::CUnitSacrificeTask()
    : CCommandTask()
    , CUnitSacrificeTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mCommand(nullptr)
    , mTargetUnit{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mTargetUnit.ownerLinkSlot = nullptr;
    mTargetUnit.nextInOwner = nullptr;
  }

  /**
   * Address: 0x005FAD90 (FUN_005FAD90, Moho::CUnitSacrificeTask::CUnitSacrificeTask)
   *
   * What it does:
   * Initializes one sacrifice-task lane from parent command-task and command
   * payload ownership context.
   */
  CUnitSacrificeTask::CUnitSacrificeTask(CCommandTask* const parentTask, Unit* const targetUnit)
    : CCommandTask(parentTask)
    , CUnitSacrificeTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mCommand(nullptr)
    , mTargetUnit{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mTargetUnit.ResetFromObject(targetUnit);

    if (mUnit != nullptr && mUnit->CommandQueue != nullptr) {
      mCommand = mUnit->CommandQueue->GetCurrentCommand();
      if (Broadcaster* const commandListenerHead = CommandEventListenerHead(mCommand); commandListenerHead != nullptr) {
        mListenerLink.ListLinkBefore(commandListenerHead);
      }
    }
  }

  /**
   * Address: 0x005FAE40 (FUN_005FAE40, Moho::CUnitSacrificeTask::~CUnitSacrificeTask)
   * Address: 0x005FAF40 (FUN_005FAF40, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   *
   * What it does:
   * Unlinks command/listener lanes, clears repairing-state ownership bits,
   * writes dispatch result state, and tears down weak-target ownership links.
   */
  CUnitSacrificeTask::~CUnitSacrificeTask()
  {
    mListenerLink.ListUnlink();

    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~(1ull << UNITSTATE_Repairing);

      if (mTaskState == TASKSTATE_Waiting) {
        mUnit->FreeOgridRect();
      }

      if (mDispatchResult != nullptr) {
        if (mTaskState == TASKSTATE_Starting) {
          *mDispatchResult = static_cast<EAiResult>(1);
          static_cast<Entity*>(mUnit)->Destroy();
        } else {
          *mDispatchResult = static_cast<EAiResult>(2);
        }
      }
    }

    mTargetUnit.UnlinkFromOwnerChain();
    mListenerLink.ListUnlink();
  }

  /**
   * Address: 0x005FB8B0 (FUN_005FB8B0, Moho::CUnitSacrificeTask::operator new)
   *
   * What it does:
   * Allocates one sacrifice-task object and forwards constructor arguments
   * into in-place construction.
   */
  CUnitSacrificeTask* CUnitSacrificeTask::Create(CCommandTask* const parentTask, Unit* const targetUnit)
  {
    void* const storage = ::operator new(sizeof(CUnitSacrificeTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitSacrificeTask(parentTask, targetUnit);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x005FB830 (FUN_005FB830, listener callback lane)
   *
   * What it does:
   * Refreshes sacrifice target weak-unit ownership from current command target
   * payload, resets task state to preparing, and wakes owner task thread.
   */
  void CUnitSacrificeTask::OnEvent(ECommandEvent)
  {
    if (mTaskState >= TASKSTATE_Starting) {
      return;
    }

    Unit* commandTargetUnit = nullptr;
    if (mCommand != nullptr) {
      Entity* const commandTargetEntity = mCommand->mTarget.targetEntity.GetObjectPtr();
      commandTargetUnit = (commandTargetEntity != nullptr) ? commandTargetEntity->IsUnit() : nullptr;
    }

    mTargetUnit.Set(commandTargetUnit);
    mTaskState = TASKSTATE_Preparing;
    WakeTaskThreadForImmediateTick(mOwnerThread);
  }

  /**
   * Address: 0x005FF2C0 (FUN_005FF2C0, Moho::CUnitSacrificeTask::MemberDeserialize)
   *
   * What it does:
   * Deserializes sacrifice-task runtime state in binary lane order: command-task
   * base, current command pointer lane, then target weak unit lane.
   */
  void CUnitSacrificeTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);
    archive->ReadPointer_CUnitCommand(&mCommand, &ownerRef);
    archive->Read(CachedWeakPtrUnitType(), &mTargetUnit, ownerRef);
  }

  /**
   * Address: 0x005FF360 (FUN_005FF360)
   *
   * What it does:
   * Serializes sacrifice-task runtime state in binary lane order: command-task
   * base, current command raw pointer lane, then target weak unit lane.
   */
  void CUnitSacrificeTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);

    gpg::RRef commandRef{};
    (void)gpg::RRef_CUnitCommand(&commandRef, mCommand);
    gpg::WriteRawPointer(archive, commandRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedWeakPtrUnitType(), &mTargetUnit, ownerRef);
  }

  /**
   * Address: 0x005FB180 (FUN_005FB180, Moho::CUnitSacrificeTask::TaskTick)
   * VFTable SLOT: 1 (CTask::Execute), ??_7CUnitSacrificeTask@Moho@@6B@ + 0x04
   *
   * IDA signature:
   * int __thiscall Moho::CUnitSacrificeTask::TaskTick(Moho::CUnitSacrificeTask *this);
   *
   * What it does:
   * Sacrifice state machine. See the header for the phase summary; the
   * per-phase behaviour is documented inline below. Return values: -1 abort,
   * 0 reschedule, 10 idle delay.
   *
   * Asm-verified field/dispatch evidence:
   * - Recipient lane `mTargetUnit` at `[this+44h]` (lea ebx, 0x005FB1A9),
   *   decoded with the standard null / sentinel-4 pair (0x005FB1B0-0x005FB1BF).
   * - Air recipients rejected via Entity `mCurrentLayer` at `[unit+120h]`
   *   compared against 0x10 = LAYER_Air (0x005FB1C5).
   * - Owner unit `[this+1Ch]`, task state `[this+24h]` (0x005FB1E3).
   * - IUnit vtbl: IsDead `+0x28`, GetPosition `+0x14`, GetBlueprint `+0x1C`,
   *   IsBeingBuilt `+0x34`, IsUnitState `+0x3C`; Entity vtbl: IsUnit `+0x10`,
   *   Materialize `+0x74`; IArmy vtbl UseWholeMap `+0xB8`; IAiBuilder vtbl
   *   BuilderSetAimTarget `+0x3C` fed the zero vector `vec0` at 0x00F3D21C
   *   (0x005FB628-0x005FB65C).
   * - Blueprint economy: BuildCostEnergy `+0x4E8`, BuildCostMass `+0x4EC`,
   *   SacrificeMassMult `+0x55C`, SacrificeEnergyMult `+0x560`,
   *   MaxBuildDistance `+0x564` (0x005FB221-0x005FB25A, 0x005FB54C).
   * - Unit state ids: 0x26 = UNITSTATE_Enhancing (0x005FB280, 0x005FB56B),
   *   6 = UNITSTATE_Upgrading (0x005FB6E8).
   * - Enhancement gate reads `IsPaused` at `[unit+2A0h]` (0x005FB580) and the
   *   requested econ rates through `mConsumptionData` at `[unit+534h]`,
   *   energy `+0x08` / mass `+0x0C` (0x005FB59A-0x005FB5A3).
   * - Owner army `ArmyRef` at `[unit+154h]` (0x005FB747).
   */
  int CUnitSacrificeTask::Execute()
  {
    // A recipient that vanished, died, or took to the air can no longer be
    // sacrificed into.
    Unit* const target = mTargetUnit.GetObjectPtr();
    if (target == nullptr || target->mCurrentLayer == LAYER_Air || target->IsDead()) {
      return -1;
    }

    // Every phase dereferences the owning unit unguarded in the binary; a
    // command task without one never reaches a tick.
    Unit& owner = *mUnit;

    switch (mTaskState) {
    case TASKSTATE_Preparing: {
      // Drop any aim the build arm still holds, then walk to the recipient.
      if (IAiBuilder* const builder = owner.AiBuilder; builder != nullptr) {
        builder->BuilderSetAimTarget(Wm3::Vector3f(0.0f, 0.0f, 0.0f));
      }

      Unit* approachTarget = target;
      if (target->IsBeingBuilt() && target->GetCreator() != nullptr
          && target->GetCreator()->IsInCategory(kFactoryCategoryName)) {
        // Still on the factory pad: stand at the factory, not inside it.
        approachTarget = target->GetCreator();
      } else if (target->IsUnitState(UNITSTATE_Upgrading) && target->GetFocusEntity() != nullptr
                 && target->GetFocusEntity()->IsUnit() != nullptr) {
        // An upgrading recipient hands the sacrifice on to the unit it is
        // becoming; that unit is adopted as the task target for good.
        mTargetUnit.Set(target->GetFocusEntity()->IsUnit());
        approachTarget = mTargetUnit.GetObjectPtr();
      }

      // PrepareMove nudges the destination onto a cell the owner may legally
      // occupy, keeping clear of the recipient's skirt.
      Wm3::Vector3f movePos = approachTarget->GetPosition();
      const bool useWholeMap = owner.ArmyRef->UseWholeMap();
      gpg::Rect2f skirtRect = approachTarget->GetSkirtRect();
      (void)owner.PrepareMove(1, &movePos, &skirtRect, useWholeMap);

      // Hold the destination cells so nothing else builds into them while the
      // owner is still walking over.
      const SCoordsVec2 moveCoords{movePos.x, movePos.z};
      gpg::Rect2i reservedRect{};
      (void)COORDS_ToGridRect(&reservedRect, moveCoords, owner.GetFootprint());
      owner.ReserveOgridRect(reservedRect);

      NewMoveTask(SNavGoal(owner.GetFootprint().ToCellPos(movePos)), this, 0, nullptr, 0);
      mTaskState = TASKSTATE_Waiting;
      return 0;
    }

    case TASKSTATE_Waiting: {
      // Range is measured edge to edge, so both footprints come off the
      // centre-to-centre distance.
      const Wm3::Vec3f& targetPos = target->GetPosition();
      const Wm3::Vec3f& ownerPos = owner.GetPosition();
      const float deltaX = ownerPos.x - targetPos.x;
      const float deltaZ = ownerPos.z - targetPos.z;
      const float gap = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ))
                        - FootprintExtent(owner.GetFootprint())
                        - FootprintExtent(target->GetFootprint());

      if (gap > owner.GetBlueprint()->Economy.MaxBuildDistance) {
        return -1;
      }

      // A recipient mid-enhancement only has somewhere to put the donation
      // while the enhancement is actually running and drawing resources.
      if (target->IsUnitState(UNITSTATE_Enhancing)) {
        if (target->IsPaused) {
          return -1;
        }

        // Unguarded in the binary: an enhancing unit always owns a request.
        const SEconValue& request = target->mConsumptionData->mRequested;
        if (std::max(request.energy, request.mass) <= 0.0f) {
          return -1;
        }
      }

      // The binary runs the identical range test a second time here
      // (0x005FB54C and 0x005FB5DE), re-reading the blueprint; kept 1:1.
      if (gap > owner.GetBlueprint()->Economy.MaxBuildDistance) {
        return -1;
      }

      mTaskState = TASKSTATE_Starting;
      owner.RunScriptWeakUnit(kOnStartSacrificeScript, mTargetUnit);
      return 10;
    }

    default:
      // Out-of-range state: the binary asserts and then falls straight into
      // the paying phase (0x005FB1FC assert, 0x005FB213 trap, body at
      // 0x005FB214), i.e. this is a state assertion and not a guarded branch.
      gpg::HandleAssertFailure(kUnreachableStateText, kUnreachableStateLine, kAiUnitBuildSourcePath);
      [[fallthrough]];

    case TASKSTATE_Starting: {
      // The donation is the owner's own build cost scaled by its sacrifice
      // multipliers.
      const RUnitBlueprintEconomy& ownerEconomy = owner.GetBlueprint()->Economy;
      const float massValue = ownerEconomy.BuildCostMass * ownerEconomy.SacrificeMassMult;
      const float energyValue = ownerEconomy.BuildCostEnergy * ownerEconomy.SacrificeEnergyMult;

      if (target->IsUnitState(UNITSTATE_Enhancing)) {
        // Enhancing recipients bank the donation in the script-side work item
        // rather than in their own construction progress. Whichever resource
        // buys less decides the step, and progress saturates at 1.
        const float progress = target->GetLuaValue(kWorkProgressKey);
        const float massFraction = CostFraction(massValue, target->GetLuaValue(kWorkItemBuildCostMassKey));
        const float energyFraction = CostFraction(energyValue, target->GetLuaValue(kWorkItemBuildCostEnergyKey));

        const float advanced = progress + std::min(massFraction, energyFraction);
        target->SetLuaValue(kWorkProgressKey, std::min(advanced, kCompleteWorkProgress));
      } else {
        // Everything else takes the donation as construction progress, again
        // limited by the scarcer of the two resources.
        const RUnitBlueprintEconomy& targetEconomy = target->GetBlueprint()->Economy;
        const float massFraction = CostFraction(massValue, targetEconomy.BuildCostMass);
        const float energyFraction = CostFraction(energyValue, targetEconomy.BuildCostEnergy);

        (void)target->Materialize(std::min(massFraction, energyFraction));
      }

      owner.RunScriptWeakUnit(kOnStopSacrificeScript, mTargetUnit);
      return -1;
    }
    }
  }

  /**
   * Address: 0x005FD570 (FUN_005FD570)
   *
   * What it does:
   * Preserves one serializer-save thunk lane for `CUnitSacrificeTask`.
   */
  [[maybe_unused]] void CUnitSacrificeTaskMemberSerializeAdapterLaneA(
    const CUnitSacrificeTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x005FDCA0 (FUN_005FDCA0)
   *
   * What it does:
   * Alternate serializer-save thunk lane for `CUnitSacrificeTask`.
   */
  [[maybe_unused]] void CUnitSacrificeTaskMemberSerializeAdapterLaneB(
    const CUnitSacrificeTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }
} // namespace moho

namespace
{
  // The binary global is 0x14 bytes (vtable + mNext/mPrev + load/save
  // callback lanes, matching every other SerHelperBase-derived serializer in
  // this codebase).
  struct CUnitSacrificeTaskSerializerHelperNode
  {
    gpg::SerSaveLoadHelperListRuntime mListLinks{};
    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(
    offsetof(CUnitSacrificeTaskSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "CUnitSacrificeTaskSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitSacrificeTaskSerializerHelperNode, mSerSaveFunc) == 0x10,
    "CUnitSacrificeTaskSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(CUnitSacrificeTaskSerializerHelperNode) == 0x14,
    "CUnitSacrificeTaskSerializerHelperNode size must be 0x14"
  );

  CUnitSacrificeTaskSerializerHelperNode gCUnitSacrificeTaskSerializer{};

  /**
   * Unlinks `CUnitSacrificeTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitSacrificeTaskSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitSacrificeTaskSerializer.mListLinks);
  }

  /**
   * Address: 0x005FB0D0 (FUN_005FB0D0, Moho::CUnitSacrificeTaskSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `CUnitSacrificeTask`. Forwards the
   * reflected object pointer to `CUnitSacrificeTask::MemberDeserialize`
   * (FUN_005FF2C0 body); `version` and the owner-ref lane are unused by the
   * member (mirrors the binary tail call).
   */
  void DeserializeCUnitSacrificeTaskSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitSacrificeTask*>(objectPtr);
    if (task == nullptr) {
      return;
    }
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x005FB0E0 (FUN_005FB0E0, Moho::CUnitSacrificeTaskSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `CUnitSacrificeTask`. Forwards the
   * reflected object pointer to `CUnitSacrificeTask::MemberSerialize`
   * (FUN_005FF360 body); `version` and the owner-ref lane are unused by the
   * member (mirrors the binary tail call).
   */
  void SerializeCUnitSacrificeTaskSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const task = reinterpret_cast<const moho::CUnitSacrificeTask*>(objectPtr);
    if (task == nullptr) {
      return;
    }
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BF9570 (FUN_00BF9570, Moho::CUnitSacrificeTaskSerializer::~CUnitSacrificeTaskSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the `CUnitSacrificeTaskSerializer` helper
   * node, matching the sibling unlink lanes used across other serializer
   * registrars.
   */
  void cleanup_CUnitSacrificeTaskSerializer_atexit()
  {
    (void)UnlinkCUnitSacrificeTaskSerializerNodePrimary();
  }

  /**
   * Address: 0x00BCFA10 (FUN_00BCFA10, register_CUnitSacrificeTaskSerializer)
   *
   * What it does:
   * Initializes the global `CUnitSacrificeTask` serializer helper's
   * load/save callback lanes (self-linking the intrusive helper node) and
   * installs process-exit cleanup via `atexit`.
   */
  void register_CUnitSacrificeTaskSerializer()
  {
    (void)UnlinkCUnitSacrificeTaskSerializerNodePrimary();
    gCUnitSacrificeTaskSerializer.mSerLoadFunc = &DeserializeCUnitSacrificeTaskSerializerCallback;
    gCUnitSacrificeTaskSerializer.mSerSaveFunc = &SerializeCUnitSacrificeTaskSerializerCallback;
    (void)std::atexit(&cleanup_CUnitSacrificeTaskSerializer_atexit);
  }

  struct CUnitSacrificeTaskSerializerStartupBootstrap
  {
    CUnitSacrificeTaskSerializerStartupBootstrap()
    {
      register_CUnitSacrificeTaskSerializer();
    }
  };

  [[maybe_unused]] CUnitSacrificeTaskSerializerStartupBootstrap gCUnitSacrificeTaskSerializerStartupBootstrap;
} // namespace
