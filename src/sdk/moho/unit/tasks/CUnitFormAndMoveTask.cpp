#include "moho/unit/tasks/CUnitFormAndMoveTask.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/IFormationInstanceCountedPtrReflection.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

namespace
{
  struct CUnitCommandCommandEventLinkView
  {
    std::uint8_t pad_0000_0034[0x34];
    moho::Broadcaster mCommandEventListenerHead;
  };

  static_assert(
    offsetof(CUnitCommandCommandEventLinkView, mCommandEventListenerHead) == 0x34,
    "CUnitCommandCommandEventLinkView::mCommandEventListenerHead offset must be 0x34"
  );

  struct CAiFormationInstanceStatusListenerHeadView
  {
    std::uint8_t pad_0000_0008[0x08];
    moho::Broadcaster mFormationStatusListenerHead;
  };

  static_assert(
    offsetof(CAiFormationInstanceStatusListenerHeadView, mFormationStatusListenerHead) == 0x08,
    "CAiFormationInstanceStatusListenerHeadView::mFormationStatusListenerHead offset must be 0x08"
  );

  [[nodiscard]] moho::Broadcaster* CommandEventListenerHead(moho::CUnitCommand* const command) noexcept
  {
    if (!command) {
      return nullptr;
    }

    auto* const view = reinterpret_cast<CUnitCommandCommandEventLinkView*>(command);
    return &view->mCommandEventListenerHead;
  }

  [[nodiscard]] moho::Broadcaster* FormationStatusListenerHead(moho::CAiFormationInstance* const formation) noexcept
  {
    if (!formation) {
      return nullptr;
    }

    auto* const view = reinterpret_cast<CAiFormationInstanceStatusListenerHeadView*>(formation);
    return &view->mFormationStatusListenerHead;
  }

  [[nodiscard]] moho::Broadcaster* NavigatorListenerHead(moho::IAiNavigator* const navigator) noexcept
  {
    if (!navigator) {
      return nullptr;
    }

    return reinterpret_cast<moho::Broadcaster*>(&navigator->mListenerNode);
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

  [[nodiscard]] gpg::RType* CachedCUnitFormAndMoveTaskType()
  {
    gpg::RType* type = moho::CUnitFormAndMoveTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitFormAndMoveTask));
      moho::CUnitFormAndMoveTask::sType = type;
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
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

} // namespace

namespace moho
{
  gpg::RType* CUnitFormAndMoveTask::sType = nullptr;

  /**
   * Address: 0x006191F0 (FUN_006191F0, ctor helper lane)
   *
   * What it does:
   * Initializes one detached form-move task with self-linked listener lanes.
   */
  CUnitFormAndMoveTask::CUnitFormAndMoveTask()
    : CCommandTask()
    , CUnitFormAndMoveTaskReservedSlot30()
    , Listener<EAiNavigatorEvent>()
    , CUnitFormAndMoveTaskReservedSlot40()
    , Listener<EFormationdStatus>()
    , CUnitFormAndMoveTaskReservedSlot50()
    , Listener<ECommandEvent>()
    , mFormation(nullptr)
    , mFormationArrivalSatisfied(0)
    , mPad0065_0068{0, 0, 0}
  {}

  /**
   * Address: 0x00619A90 (FUN_00619A90, ??2CUnitFormAndMoveTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Allocates one form-move task when formation and dispatch navigator lanes
   * are valid, then forwards into constructor logic.
   */
  CUnitFormAndMoveTask* CUnitFormAndMoveTask::Create(
    CAiFormationInstance* const formation,
    IAiCommandDispatchImpl* const dispatchTask
  )
  {
    if (!formation || !dispatchTask || !dispatchTask->mUnit || !dispatchTask->mUnit->AiNavigator) {
      return nullptr;
    }

    void* const storage = ::operator new(sizeof(CUnitFormAndMoveTask), std::nothrow);
    if (storage == nullptr) {
      return nullptr;
    }

    return new (storage) CUnitFormAndMoveTask(static_cast<CCommandTask*>(dispatchTask), formation);
  }

  /**
   * Address: 0x00619250 (FUN_00619250, ??0CUnitFormAndMoveTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one form-move task from dispatch/formation context, seeds
   * the current formation-adjusted navigator goal, and links listener lanes.
   */
  CUnitFormAndMoveTask::CUnitFormAndMoveTask(
    CCommandTask* const dispatchTask,
    CAiFormationInstance* const formation
  )
    : CCommandTask(dispatchTask)
    , CUnitFormAndMoveTaskReservedSlot30()
    , Listener<EAiNavigatorEvent>()
    , CUnitFormAndMoveTaskReservedSlot40()
    , Listener<EFormationdStatus>()
    , CUnitFormAndMoveTaskReservedSlot50()
    , Listener<ECommandEvent>()
    , mFormation(formation)
    , mFormationArrivalSatisfied(0)
    , mPad0065_0068{0, 0, 0}
  {
    if (!mUnit) {
      return;
    }

    mUnit->UnitStateMask |= 0x0000000000000004ull;

    if (CUnitCommandQueue* const queue = mUnit->CommandQueue; queue != nullptr) {
      if (CUnitCommand* const currentCommand = queue->GetCurrentCommand(); currentCommand != nullptr) {
        if (Broadcaster* const commandListenerHead = CommandEventListenerHead(currentCommand); commandListenerHead != nullptr) {
          Listener<ECommandEvent>::mListenerLink.ListLinkBefore(commandListenerHead);
        }
      }
    }

    if (Broadcaster* const formationListenerHead = FormationStatusListenerHead(mFormation); formationListenerHead != nullptr) {
      Listener<EFormationdStatus>::mListenerLink.ListLinkBefore(formationListenerHead);
    }

    ApplyFormationGoalFromCurrentUnit();
    mTaskState = TASKSTATE_Waiting;

    if (mUnit->IsUnitState(UNITSTATE_Immobile)) {
      if (const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
          blueprint != nullptr && blueprint->AI.NeedUnpack && mUnit->AiAttacker != nullptr) {
        CAiTarget stopTarget{};
        stopTarget.targetPoint = -1;
        stopTarget.targetIsMobile = false;
        mUnit->AiAttacker->SetDesiredTarget(&stopTarget);
      }
    }

    mUnit->UpdateSpeedThroughStatus();

    if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
      if (Broadcaster* const navigatorListenerHead = NavigatorListenerHead(navigator); navigatorListenerHead != nullptr) {
        Listener<EAiNavigatorEvent>::mListenerLink.ListLinkBefore(navigatorListenerHead);
      }
    }

    if (mOwnerThread != nullptr && !mOwnerThread->mStaged) {
      mOwnerThread->Stage();
    }
  }

  /**
   * Address: 0x006194E0 (FUN_006194E0, ??1CUnitFormAndMoveTask@Moho@@QAE@@Z)
   * Address: 0x00619830 (FUN_00619830, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   *
   * What it does:
   * Unlinks all listener lanes, aborts navigator movement, clears unit
   * form-move state bit, and tears down command-task ownership.
   */
  CUnitFormAndMoveTask::~CUnitFormAndMoveTask()
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~0x0000000000000004ull;
    }

    if (mUnit != nullptr && mUnit->CommandQueue != nullptr && mUnit->CommandQueue->GetCurrentCommand() != nullptr) {
      Listener<ECommandEvent>::mListenerLink.ListUnlink();
    }

    if (mFormation != nullptr) {
      Listener<EFormationdStatus>::mListenerLink.ListUnlink();
    }

    if (mUnit != nullptr) {
      if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
        Listener<EAiNavigatorEvent>::mListenerLink.ListUnlink();
        navigator->AbortMove();
      }
    }

    Listener<ECommandEvent>::mListenerLink.ListResetLinks();
    Listener<EFormationdStatus>::mListenerLink.ListResetLinks();
    Listener<EAiNavigatorEvent>::mListenerLink.ListResetLinks();
  }

  /**
   * Address: 0x00619650 (FUN_00619650, Moho::CUnitFormAndMoveTask::TaskTick)
   *
   * What it does:
   * Returns active-task status when formation lane is valid and the unit has
   * not yet consumed cached formation-speed data.
   */
  int CUnitFormAndMoveTask::Execute()
  {
    if (mFormationArrivalSatisfied != 0u || mFormation == nullptr || mUnit == nullptr || mUnit->mInfoCache.mHasFormationSpeedData) {
      return -1;
    }

    return 1;
  }

  /**
   * Address: 0x0061A9C0 (FUN_0061A9C0)
   *
   * What it does:
   * Deserializes base command-task state, weak formation pointer lane, and
   * the arrival-satisfied flag for one form-move task.
   */
  void CUnitFormAndMoveTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), owner);

    IFormationInstance* formationBase = static_cast<IFormationInstance*>(mFormation);
    archive->ReadPointer_IFormationInstance(&formationBase, &owner);
    mFormation = static_cast<CAiFormationInstance*>(formationBase);

    bool arrivalSatisfied = (mFormationArrivalSatisfied != 0u);
    archive->ReadBool(&arrivalSatisfied);
    mFormationArrivalSatisfied = arrivalSatisfied ? 1u : 0u;
  }

  /**
   * Address: 0x0061AA30 (FUN_0061AA30)
   *
   * What it does:
   * Serializes base command-task state, weak formation pointer lane, and the
   * arrival-satisfied flag for one form-move task.
   */
  void CUnitFormAndMoveTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(CachedCCommandTaskType(), const_cast<CCommandTask*>(static_cast<const CCommandTask*>(this)), owner);

    gpg::RRef formationRef{};
    gpg::RRef_IFormationInstance(&formationRef, mFormation);
    gpg::WriteRawPointer(archive, formationRef, gpg::TrackedPointerState::Unowned, owner);

    archive->WriteBool(mFormationArrivalSatisfied != 0u);
  }

  /**
   * Address: 0x0061A340 (FUN_0061A340)
   *
   * What it does:
   * Thin alias lane that forwards one `(task, archive)` pair into
   * `CUnitFormAndMoveTask::MemberSerialize`.
   */
  [[maybe_unused]] void CUnitFormAndMoveTaskMemberSerializeAliasThunk(
    const CUnitFormAndMoveTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    if (task != nullptr) {
      task->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x0061A3E0 (FUN_0061A3E0)
   *
   * What it does:
   * Thin alias lane that forwards one `(task, archive)` pair into
   * `CUnitFormAndMoveTask::MemberSerialize`.
   */
  void CUnitFormAndMoveTaskMemberSerializeAlias(
    const CUnitFormAndMoveTask* const task,
    gpg::WriteArchive* const archive
  )
  {
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x00619680 (FUN_00619680, Moho::CUnitFormAndMoveTask::OnEvent)
   * Primary vtable: `Listener<EAiNavigatorEvent>` secondary slot 0
   * (`??_7CUnitFormAndMoveTask@Moho@@6B?$Listener@W4EAiNavigatorEvent@Moho@@@Moho@@@`).
   *
   * What it does:
   * Applies navigator event state transitions and resumes owner thread
   * processing.
   */
  void CUnitFormAndMoveTask::OnEvent(const EAiNavigatorEvent event)
  {
    if (event == AINAVEVENT_Failed || event == AINAVEVENT_Aborted) {
      mTaskState = TASKSTATE_Starting;
    } else if (event == AINAVEVENT_Succeeded) {
      mTaskState = TASKSTATE_Waiting;
    }

    ResumeOwnerThreadNow();
  }

  /**
   * Address: 0x006196F0 (FUN_006196F0, Moho::CUnitFormAndMoveTask::OnEvent)
   * Primary vtable: `Listener<ECommandEvent>` secondary slot 0
   * (`??_7CUnitFormAndMoveTask@Moho@@6B?$Listener@W4ECommandEvent@Moho@@@Moho@@@`).
   *
   * What it does:
   * Re-applies current formation-adjusted navigator goal when command
   * dispatch payload changes.
   */
  void CUnitFormAndMoveTask::OnEvent(const ECommandEvent)
  {
    ApplyFormationGoalFromCurrentUnit();
  }

  /**
   * Address: 0x00619770 (FUN_00619770, Moho::CUnitFormAndMoveTask::OnEvent)
   * Primary vtable: `Listener<EFormationdStatus>` secondary slot 0
   * (`??_7CUnitFormAndMoveTask@Moho@@6B?$Listener@W4EFormationdStatus@Moho@@@Moho@@@`).
   *
   * What it does:
   * Handles formation status transitions by refreshing current formation goal
   * or marking form-move completion when the unit reaches valid formation lane.
   */
  void CUnitFormAndMoveTask::OnEvent(const EFormationdStatus status)
  {
    if (status == FORMATIONSTATUS_FormationUpdated) {
      ApplyFormationGoalFromCurrentUnit();
      return;
    }

    if (status != FORMATIONSTATUS_FormationAtGoal) {
      return;
    }

    if (mFormation == nullptr || mUnit == nullptr) {
      return;
    }

    if (!mFormation->Func21(mUnit)) {
      return;
    }

    mFormationArrivalSatisfied = 1u;
    ResumeOwnerThreadNow();
  }

  void CUnitFormAndMoveTask::ApplyFormationGoalFromCurrentUnit()
  {
    if (mFormation == nullptr || mUnit == nullptr) {
      return;
    }

    IAiNavigator* const navigator = mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    SOCellPos formationCell{};
    (void)mFormation->GetAdjustedFormationPosition(&formationCell, mUnit, nullptr);
    navigator->SetGoal(SNavGoal(formationCell));
  }

  void CUnitFormAndMoveTask::ResumeOwnerThreadNow()
  {
    if (mOwnerThread == nullptr) {
      return;
    }

    mOwnerThread->mPendingFrames = 0;
    if (mOwnerThread->mStaged) {
      mOwnerThread->Unstage();
    }
  }
} // namespace moho

namespace moho
{
  /**
   * VFTABLE: 0x00E206F8 (`??_7CUnitFormAndMoveTaskSerializer@Moho@@6B@`)
   *
   * Demangled base: gpg::SerSaveLoadHelper<class Moho::CUnitFormAndMoveTask>
   * (base VFTABLE: 0x00E20700, `??_7?$SerSaveLoadHelper@VCUnitFormAndMoveTask@Moho@@@gpg@@6B@`)
   *
   * Confirmed empty derived class -- NOT a `using` alias (same nuance as
   * `CEfxTrailEmitterSerializer`, see `Reflection.h`). Both vtables carry
   * the *same* Init() address (0x00619CE0): `CUnitFormAndMoveTaskSerializer`
   * overrides nothing from the base template. The binary still emits two
   * distinct vtable symbols 8 bytes apart in `.rdata` (0x00E206F8 and
   * 0x00E20700), which only happens for two distinct C++ types -- a
   * same-address `using CUnitFormAndMoveTaskSerializer =
   * SerSaveLoadHelper<CUnitFormAndMoveTask>;` alias can only ever produce
   * one vtable symbol, not two, so that shape does not fit this class.
   *
   * `CUnitFormAndMoveTask::MemberDeserialize(ReadArchive*)`/
   * `MemberSerialize(WriteArchive*) const` are ordinary instance methods
   * matching the template's expected shape exactly, so the base template's
   * generic `Deserialize`/`Serialize` static methods apply unmodified.
   *
   * Per-instantiation addresses (T = CUnitFormAndMoveTask):
   *  - ctor / compiler dynamic-initializer: 0x00BD10B0, global storage
   *    0x010B1904. `vtable_writers` shows exactly one writer for the
   *    0x00E206F8 vtable head (no dead-duplicate twin).
   *  - dtor / atexit unlink target: 0x00BFA0D0 (standard `ResetLinks()`
   *    unlink-then-self-link shape). The real ctor's tail is a plain
   *    `return atexit(sub_BFA0D0);` -- the compiler's own registration for
   *    this global's non-trivial destructor, inherited unchanged from
   *    `SerSaveLoadHelper<T>::~SerSaveLoadHelper()` -- so no destructor is
   *    declared here. `FUN_00619A30` and `FUN_00619A60` are duplicate-emission
   *    twins of that exact unlink/reset lane (same `ResetLinks()` shape,
   *    folded to separate addresses); they have no distinct source-level
   *    body of their own.
   *  - Init(): 0x00619CE0 (shared with the base template, not overridden).
   *  - Deserialize() thunk: 0x006199D0, tail-jumps into
   *    `CUnitFormAndMoveTask::MemberDeserialize` at 0x0061A9C0. (Formerly
   *    mis-modeled in this file as a standalone free function
   *    `CUnitFormAndMoveTaskMemberDeserializeThunk`; it is actually this
   *    template instantiation's own compiler-emitted `Deserialize` body.)
   *  - Serialize() thunk: 0x006199E0, tail-calls
   *    `CUnitFormAndMoveTask::MemberSerialize` at 0x0061AA30. (Same
   *    correction as above, formerly `CUnitFormAndMoveTaskMemberSerializeThunk`.)
   */
  class CUnitFormAndMoveTaskSerializer : public gpg::SerSaveLoadHelper<CUnitFormAndMoveTask>
  {
  };
  static_assert(
    sizeof(CUnitFormAndMoveTaskSerializer) == 0x14, "CUnitFormAndMoveTaskSerializer size must be 0x14"
  );
} // namespace moho

namespace
{
  // Address: 0x010B1904 -- process-global `CUnitFormAndMoveTaskSerializer`
  // singleton. Constructing it runs the compiler-emitted
  // `register_CUnitFormAndMoveTaskSerializer`-equivalent dynamic initializer
  // (0x00BD10B0), which splices this helper into
  // `gpg::SerHelperBase::sNewHelpers`; `gpg::SerHelperBase::InitNewHelpers()`
  // later dispatches `Init()` on it from within the first
  // `ReadArchive`/`WriteArchive` construction.
  moho::CUnitFormAndMoveTaskSerializer gCUnitFormAndMoveTaskSerializer;
} // namespace

namespace gpg
{
  /**
   * Address: 0x0061A5A0 (FUN_0061A5A0, gpg::RRef_CUnitFormAndMoveTask)
   *
   * What it does:
   * Builds one typed reflection reference for
   * `moho::CUnitFormAndMoveTask*`, preserving dynamic-derived ownership and
   * base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitFormAndMoveTask(gpg::RRef* const outRef, moho::CUnitFormAndMoveTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitFormAndMoveTaskType());
    return outRef;
  }

  /**
   * Address: 0x0061A380 (FUN_0061A380)
   *
   * What it does:
   * Wrapper lane that materializes one temporary
   * `RRef_CUnitFormAndMoveTask` and copies object/type fields into the
   * destination reference record.
   */
  gpg::RRef* AssignCUnitFormAndMoveTaskRef(gpg::RRef* const outRef, moho::CUnitFormAndMoveTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)RRef_CUnitFormAndMoveTask(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg
