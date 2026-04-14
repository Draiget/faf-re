#include "moho/unit/tasks/CUnitAttackTargetTask.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <new>

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/math/Vector3f.h"
#include "moho/path/SNavGoal.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/task/CCommandTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CUnitMeleeAttackTargetTask.h"

namespace
{
  struct CUnitAttackTargetTaskRuntimeView
  {
    std::uint8_t mCommandTaskStorage[sizeof(moho::CCommandTask)]{}; // +0x00
    std::uint32_t mUnknown0030{};                                   // +0x30
    std::uint32_t mAiAttackerListenerVftable{};                     // +0x34
    moho::Broadcaster mAiAttackerListenerLink{};                    // +0x38
    std::uint8_t mUnknown40To5F[0x20]{};                            // +0x40
    moho::CAiTarget mTarget{};                                      // +0x60
    Wm3::Vector3f mPos{};                                           // +0x80
    std::uint8_t mUnknown8CTo8F[0x04]{};                            // +0x8C
  };

  static_assert(
    sizeof(CUnitAttackTargetTaskRuntimeView) == sizeof(moho::CUnitAttackTargetTask),
    "CUnitAttackTargetTaskRuntimeView size must match CUnitAttackTargetTask"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mCommandTaskStorage) == 0x00,
    "CUnitAttackTargetTaskRuntimeView::mCommandTaskStorage offset must be 0x00"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mUnknown0030) == 0x30,
    "CUnitAttackTargetTaskRuntimeView::mUnknown0030 offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mAiAttackerListenerVftable) == 0x34,
    "CUnitAttackTargetTaskRuntimeView::mAiAttackerListenerVftable offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mAiAttackerListenerLink) == 0x38,
    "CUnitAttackTargetTaskRuntimeView::mAiAttackerListenerLink offset must be 0x38"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mUnknown40To5F) == 0x40,
    "CUnitAttackTargetTaskRuntimeView::mUnknown40To5F offset must be 0x40"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mTarget) == 0x60,
    "CUnitAttackTargetTaskRuntimeView::mTarget offset must be 0x60"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mPos) == 0x80,
    "CUnitAttackTargetTaskRuntimeView::mPos offset must be 0x80"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mUnknown8CTo8F) == 0x8C,
    "CUnitAttackTargetTaskRuntimeView::mUnknown8CTo8F offset must be 0x8C"
  );

  [[nodiscard]] CUnitAttackTargetTaskRuntimeView* AsRuntimeView(
    moho::CUnitAttackTargetTask* const task
  ) noexcept
  {
    return reinterpret_cast<CUnitAttackTargetTaskRuntimeView*>(task);
  }

  [[nodiscard]] moho::CCommandTask* AsCommandTask(CUnitAttackTargetTaskRuntimeView* const runtime) noexcept
  {
    return reinterpret_cast<moho::CCommandTask*>(runtime->mCommandTaskStorage);
  }

  [[nodiscard]] int RoundToCellCoord(const float value) noexcept
  {
    return static_cast<int>(std::lrintf(value));
  }

  struct CAiAttackerEventLinkView
  {
    std::uint8_t pad_0000_0004[0x04];
    moho::Broadcaster mAiAttackerEventHead;
  };

  static_assert(
    offsetof(CAiAttackerEventLinkView, mAiAttackerEventHead) == 0x04,
    "CAiAttackerEventLinkView::mAiAttackerEventHead offset must be 0x04"
  );

  [[nodiscard]] moho::Broadcaster* AiAttackerListenerHead(moho::CAiAttackerImpl* const attacker) noexcept
  {
    auto* const attackerView = reinterpret_cast<CAiAttackerEventLinkView*>(attacker);
    return &attackerView->mAiAttackerEventHead;
  }

  struct UnitAttackTaskStateGate
  {
    virtual void Reserved00() = 0;
    virtual void Reserved04() = 0;
    virtual void Reserved08() = 0;
    virtual void Reserved0C() = 0;
    virtual void Reserved10() = 0;
    virtual void Reserved14() = 0;
    virtual void Reserved18() = 0;
    virtual void Reserved1C() = 0;
    virtual void Reserved20() = 0;
    virtual void Reserved24() = 0;
    virtual void Reserved28() = 0;
    virtual void Reserved2C() = 0;
    virtual bool IsAttackTaskStateReady() = 0; // +0x30
  };

  [[nodiscard]] bool IsOwnerAttackTaskStateReady(moho::Unit* const unit) noexcept
  {
    return reinterpret_cast<UnitAttackTaskStateGate*>(unit)->IsAttackTaskStateReady();
  }

  void WakeOwnerThreadForImmediateTick(moho::CCommandTask* const commandTask)
  {
    if (commandTask == nullptr || commandTask->mOwnerThread == nullptr) {
      return;
    }

    moho::CTaskThread* const ownerThread = commandTask->mOwnerThread;
    ownerThread->mPendingFrames = 0;
    if (ownerThread->mStaged) {
      ownerThread->Unstage();
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F27D0 (FUN_005F27D0, Moho::CAttackTargetTask::operator new)
   *
   * What it does:
   * Chooses melee-vs-ranged attack task allocation from dispatch unit state,
   * then forwards into the corresponding dispatch-bound constructor lane.
   */
  CAttackTargetTask* CAttackTargetTask::Create(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    CAiFormationInstance* const formation
  )
  {
    if (dispatchTask != nullptr && dispatchTask->mUnit != nullptr && dispatchTask->mUnit->mIsMelee) {
      return CUnitMeleeAttackTargetTask::Create(dispatchTask, target, formation);
    }

    void* const storage = ::operator new(sizeof(CUnitAttackTargetTask), std::nothrow);
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitAttackTargetTask(dispatchTask, target, formation, true, false);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x005F2750 (FUN_005F2750, Moho::CAttackTargetTask::operator new `_0` overload)
   * Mangled: ??2CAttackTargetTask@Moho@@QAE@@Z_0
   *
   * What it does:
   * Formation-respecting dispatch: melee units go through
   * `CUnitMeleeAttackTargetTask::CreateRespectFormation`; ranged units get a
   * `CUnitAttackTargetTask` with `ignoreFormation=false` and the caller's
   * overcharge-weapon toggle.
   */
  CAttackTargetTask* CAttackTargetTask::CreateRespectFormation(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    CAiFormationInstance* const formation,
    const bool enableOverchargeWeapon
  )
  {
    if (dispatchTask != nullptr && dispatchTask->mUnit != nullptr && dispatchTask->mUnit->mIsMelee) {
      return CUnitMeleeAttackTargetTask::CreateRespectFormation(dispatchTask, target, formation);
    }

    void* const storage = ::operator new(sizeof(CUnitAttackTargetTask), std::nothrow);
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitAttackTargetTask(dispatchTask, target, formation, false, enableOverchargeWeapon);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x005F2CE0 (FUN_005F2CE0, Moho::CUnitAttackTargetTask::SetWeaponGoal)
   *
   * What it does:
   * Builds one rectangular navigator goal centered on target position and
   * half-weapon-radius extents, then dispatches it through the owner
   * `IAiNavigator`.
   */
  void CUnitAttackTargetTask::SetWeaponGoal(const Wm3::Vector3f& targetPosition, UnitWeapon* const weapon)
  {
    IAiNavigator* const navigator = AsCommandTask(AsRuntimeView(this))->mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    const int maxRadius = static_cast<int>(weapon->mWeaponBlueprint->MaxRadius);
    const float halfRadius = static_cast<float>(maxRadius) * 0.5f;

    const int minX = static_cast<std::int16_t>(RoundToCellCoord(targetPosition.x - halfRadius));
    const int minZ = static_cast<std::int16_t>(RoundToCellCoord(targetPosition.z - halfRadius));

    SAiNavigatorGoal goal{};
    goal.mPos1.x0 = minX;
    goal.mPos1.z0 = minZ;
    goal.mPos1.x1 = minX + maxRadius;
    goal.mPos1.z1 = minZ + maxRadius;
    goal.mPos2 = gpg::Rect2i{};
    goal.mLayer = static_cast<ELayer>(0);
    navigator->SetGoal(goal);
  }

  /**
   * Address: 0x005F2D90 (FUN_005F2D90, Moho::CUnitAttackTargetTask::SetPosGoal)
   *
   * What it does:
   * Builds one single-cell navigator goal around the provided map cell and
   * dispatches it through the owner unit navigator.
   */
  void CUnitAttackTargetTask::SetPosGoal(const SOCellPos& targetCell)
  {
    IAiNavigator* const navigator = AsCommandTask(AsRuntimeView(this))->mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    SAiNavigatorGoal goal{};
    const int x = targetCell.x;
    const int z = targetCell.z;
    goal.mPos1.x0 = x;
    goal.mPos1.z0 = z;
    goal.mPos1.x1 = x + 1;
    goal.mPos1.z1 = z + 1;
    navigator->SetGoal(goal);
  }

  /**
   * Address: 0x005F2E90 (FUN_005F2E90, Moho::CUnitAttackTargetTask::UpdatePos)
   *
   * What it does:
   * Refreshes cached attack-target world position from current `mTarget`,
   * then falls back to owner-unit position when the cached vector is invalid.
   */
  void CUnitAttackTargetTask::UpdatePos()
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    if (runtime->mTarget.HasTarget()) {
      runtime->mPos = runtime->mTarget.GetTargetPosGun(false);
    }

    if (!IsValidVector3f(runtime->mPos)) {
      runtime->mPos = AsCommandTask(runtime)->mUnit->GetPosition();
    }
  }

  /**
   * Address: 0x005F3EE0 (FUN_005F3EE0, Moho::Listener_AiAttackerEvent_CUnitAttackTargetTask::Receive)
   *
   * What it does:
   * Handles attacker-event state transitions for ranged attack-target tasks,
   * updates dispatch-result output lanes where required, and wakes the owner
   * task thread for immediate state-machine execution.
   */
  void CUnitAttackTargetTask::HandleAiAttackerEvent(const EAiAttackerEvent event)
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    if (commandTask->mTaskState == TASKSTATE_5) {
      return;
    }

    auto ownerStateReady = [&commandTask]() -> bool {
      return IsOwnerAttackTaskStateReady(commandTask->mUnit);
    };

    if (runtime->mTarget.HasTarget()) {
      switch (static_cast<std::int32_t>(event)) {
        case 1:
          commandTask->mTaskState = TASKSTATE_Complete;
          break;

        case 2:
        case 4:
          if (ownerStateReady()) {
            commandTask->mTaskState = TASKSTATE_Waiting;
          } else {
            *commandTask->mDispatchResult = static_cast<EAiResult>(2);
            commandTask->mTaskState = TASKSTATE_5;
          }
          break;

        case 3:
          if (ownerStateReady()) {
            *commandTask->mDispatchResult = static_cast<EAiResult>(2);
            commandTask->mTaskState = TASKSTATE_5;
          } else {
            commandTask->mTaskState = TASKSTATE_Complete;
          }
          break;

        case 5:
          *commandTask->mDispatchResult = static_cast<EAiResult>(2);
          commandTask->mTaskState = TASKSTATE_5;
          break;

        case 6:
          commandTask->mTaskState = TASKSTATE_Waiting;
          break;

        case 7:
          if (ownerStateReady()) {
            commandTask->mTaskState = TASKSTATE_Starting;
          } else {
            *commandTask->mDispatchResult = static_cast<EAiResult>(2);
            commandTask->mTaskState = TASKSTATE_5;
          }
          break;

        case 8:
          *commandTask->mDispatchResult = static_cast<EAiResult>(1);
          commandTask->mTaskState = TASKSTATE_5;
          break;

        default:
          break;
      }
    } else {
      commandTask->mTaskState = ownerStateReady() ? TASKSTATE_Processing : TASKSTATE_5;
    }

    WakeOwnerThreadForImmediateTick(commandTask);
  }

  /**
   * Address: 0x005F3450 (FUN_005F3450, Moho::CUnitAttackTargetTask::UpdateAttacker)
   *
   * What it does:
   * Updates owner attacker desired-target payload and relinks this task into
   * the attacker event-list lane when the entity target changed.
   */
  bool CUnitAttackTargetTask::UpdateAttacker(CAiTarget* const desiredTarget)
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CAiAttackerImpl* const attacker = AsCommandTask(runtime)->mUnit->AiAttacker;
    if (attacker == nullptr) {
      return false;
    }

    CAiTarget* const currentDesiredTarget = attacker->GetDesiredTarget();
    const auto* const desiredEntityTarget =
      desiredTarget != nullptr ? desiredTarget->targetEntity.GetObjectPtr() : nullptr;
    const auto* const currentEntityTarget =
      currentDesiredTarget != nullptr ? currentDesiredTarget->targetEntity.GetObjectPtr() : nullptr;
    if (desiredEntityTarget == currentEntityTarget) {
      attacker->ResetReportingState();
      return false;
    }

    attacker->SetDesiredTarget(desiredTarget);
    runtime->mAiAttackerListenerLink.ListLinkBefore(AiAttackerListenerHead(attacker));
    return true;
  }
} // namespace moho
