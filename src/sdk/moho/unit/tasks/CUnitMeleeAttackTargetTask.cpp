#include "moho/unit/tasks/CUnitMeleeAttackTargetTask.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/math/Vector3f.h"
#include "moho/path/SNavGoal.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/task/CCommandTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"

namespace moho
{
  class CUnitCommand;
}

namespace
{
  struct CUnitMeleeAttackTargetTaskRuntimeView
  {
    std::uint8_t mCommandTaskStorage[sizeof(moho::CCommandTask)]{}; // +0x00
    std::uint32_t mUnknown0030{};                                    // +0x30
    std::uint32_t mAiAttackerListenerVftable{};                      // +0x34
    moho::Broadcaster mAiAttackerListenerLink{};                     // +0x38
    std::uint32_t mUnknown0040{};                                    // +0x40
    std::uint32_t mCommandEventListenerVftable{};                    // +0x44
    moho::Broadcaster mCommandEventListenerLink{};                   // +0x48
    moho::CCommandTask* mDispatchTask{};                             // +0x50
    moho::CUnitCommand* mCommand{};                                  // +0x54
    moho::CAiFormationInstance* mFormation{};                        // +0x58
    moho::CAiTarget mTarget{};                                       // +0x5C
    Wm3::Vector3f mTargetPosition{};                                 // +0x7C
    moho::SOCellPos mDestination{};                                  // +0x88
    bool mHasMobileTarget{};                                         // +0x8C
    bool mIgnoreFormationUpdates{};                                  // +0x8D
    bool mNeedsNavigatorGoalUpdate{};                                // +0x8E
    bool mPlanted{};                                                 // +0x8F
  };

  static_assert(
    sizeof(CUnitMeleeAttackTargetTaskRuntimeView) == sizeof(moho::CUnitMeleeAttackTargetTask),
    "CUnitMeleeAttackTargetTaskRuntimeView size must match CUnitMeleeAttackTargetTask"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mCommandTaskStorage) == 0x00,
    "CUnitMeleeAttackTargetTaskRuntimeView::mCommandTaskStorage offset must be 0x00"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mAiAttackerListenerVftable) == 0x34,
    "CUnitMeleeAttackTargetTaskRuntimeView::mAiAttackerListenerVftable offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mUnknown0040) == 0x40,
    "CUnitMeleeAttackTargetTaskRuntimeView::mUnknown0040 offset must be 0x40"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mCommandEventListenerVftable) == 0x44,
    "CUnitMeleeAttackTargetTaskRuntimeView::mCommandEventListenerVftable offset must be 0x44"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mCommandEventListenerLink) == 0x48,
    "CUnitMeleeAttackTargetTaskRuntimeView::mCommandEventListenerLink offset must be 0x48"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mDispatchTask) == 0x50,
    "CUnitMeleeAttackTargetTaskRuntimeView::mDispatchTask offset must be 0x50"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mCommand) == 0x54,
    "CUnitMeleeAttackTargetTaskRuntimeView::mCommand offset must be 0x54"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mFormation) == 0x58,
    "CUnitMeleeAttackTargetTaskRuntimeView::mFormation offset must be 0x58"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mTarget) == 0x5C,
    "CUnitMeleeAttackTargetTaskRuntimeView::mTarget offset must be 0x5C"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mTargetPosition) == 0x7C,
    "CUnitMeleeAttackTargetTaskRuntimeView::mTargetPosition offset must be 0x7C"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mDestination) == 0x88,
    "CUnitMeleeAttackTargetTaskRuntimeView::mDestination offset must be 0x88"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mHasMobileTarget) == 0x8C,
    "CUnitMeleeAttackTargetTaskRuntimeView::mHasMobileTarget offset must be 0x8C"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mIgnoreFormationUpdates) == 0x8D,
    "CUnitMeleeAttackTargetTaskRuntimeView::mIgnoreFormationUpdates offset must be 0x8D"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mNeedsNavigatorGoalUpdate) == 0x8E,
    "CUnitMeleeAttackTargetTaskRuntimeView::mNeedsNavigatorGoalUpdate offset must be 0x8E"
  );
  static_assert(
    offsetof(CUnitMeleeAttackTargetTaskRuntimeView, mPlanted) == 0x8F,
    "CUnitMeleeAttackTargetTaskRuntimeView::mPlanted offset must be 0x8F"
  );

  [[nodiscard]] CUnitMeleeAttackTargetTaskRuntimeView* AsRuntimeView(moho::CUnitMeleeAttackTargetTask* const task
  ) noexcept
  {
    return reinterpret_cast<CUnitMeleeAttackTargetTaskRuntimeView*>(task);
  }

  [[nodiscard]] moho::CCommandTask* AsCommandTask(CUnitMeleeAttackTargetTaskRuntimeView* const runtime) noexcept
  {
    return reinterpret_cast<moho::CCommandTask*>(runtime->mCommandTaskStorage);
  }

  [[nodiscard]] gpg::RType* CachedCUnitMeleeAttackTargetTaskType()
  {
    gpg::RType* type = moho::CUnitMeleeAttackTargetTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitMeleeAttackTargetTask));
      moho::CUnitMeleeAttackTargetTask::sType = type;
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
    const bool derived =
      dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] std::int16_t RoundToCellCoord(const float value) noexcept
  {
    return static_cast<std::int16_t>(std::lrintf(value));
  }

  [[nodiscard]] Wm3::Box3f BuildAxisAlignedCollisionProbe(
    const Wm3::Vector3f& center,
    const float extentX,
    const float extentZ
  ) noexcept
  {
    Wm3::Box3f probe{};
    probe.Center[0] = center.x;
    probe.Center[1] = center.y;
    probe.Center[2] = center.z;

    probe.Axis[0][0] = 1.0f;
    probe.Axis[0][1] = 0.0f;
    probe.Axis[0][2] = 0.0f;
    probe.Axis[1][0] = 0.0f;
    probe.Axis[1][1] = 1.0f;
    probe.Axis[1][2] = 0.0f;
    probe.Axis[2][0] = 0.0f;
    probe.Axis[2][1] = 0.0f;
    probe.Axis[2][2] = 1.0f;

    probe.Extent[0] = extentX;
    probe.Extent[1] = 1000.0f;
    probe.Extent[2] = extentZ;
    return probe;
  }

  [[nodiscard]] bool HasPositionChanged(const moho::Entity& entity) noexcept
  {
    return entity.Position.x != entity.PrevPosition.x || entity.Position.y != entity.PrevPosition.y
      || entity.Position.z != entity.PrevPosition.z;
  }

  constexpr const char* kOnAssignedFocusEntityScript = "OnAssignedFocusEntity";
  constexpr const char* kMeleeTaskAssertText = "Reached the supposably unreachable.";
  constexpr const char* kMeleeTaskSourcePath = "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitMeleeAttack.cpp";
  constexpr int kMeleeTaskAssertLine = 747;

  [[nodiscard]] moho::SOCellPos ComputeDestinationCellFromUnitGoalOrPosition(const moho::Unit& targetUnit) noexcept
  {
    const moho::SFootprint& footprint = targetUnit.GetFootprint();

    Wm3::Vector3f center = targetUnit.GetPosition();
    if (HasPositionChanged(targetUnit) && targetUnit.AiNavigator != nullptr) {
      center = targetUnit.AiNavigator->GetGoalPos();
    }

    moho::SOCellPos destination{};
    destination.x =
      static_cast<std::int16_t>(static_cast<int>(center.x - (static_cast<float>(footprint.mSizeX) * 0.5f)));
    destination.z =
      static_cast<std::int16_t>(static_cast<int>(center.z - (static_cast<float>(footprint.mSizeZ) * 0.5f)));
    return destination;
  }

  [[nodiscard]] moho::SOCellPos
  ComputeMeleeMidpointDestinationCell(const moho::Unit& ownerUnit, const moho::Unit& targetUnit) noexcept
  {
    const Wm3::Vector3f ownerPos = ownerUnit.GetPosition();
    const Wm3::Vector3f targetPos = targetUnit.GetPosition();
    const moho::SFootprint& ownerFootprint = ownerUnit.GetFootprint();

    moho::SOCellPos destination{};
    destination.x = static_cast<std::int16_t>(
      static_cast<int>(
        ((targetPos.x + ownerPos.x) * 0.5f) - (static_cast<float>(ownerFootprint.mSizeX) * 0.5f)
      )
    );
    destination.z = static_cast<std::int16_t>(
      static_cast<int>(
        ((targetPos.z + ownerPos.z) * 0.5f) - (static_cast<float>(ownerFootprint.mSizeZ) * 0.5f)
      )
    );
    return destination;
  }

  [[nodiscard]] bool QueryMeleeSpaceForTarget(
    moho::Unit& ownerUnit,
    moho::Unit& targetUnit,
    moho::SOCellPos* const inOutDestination
  )
  {
    if (inOutDestination == nullptr) {
      return false;
    }

    if (targetUnit.IsMobile()) {
      const moho::SFootprint& targetFootprint = targetUnit.GetFootprint();
      const std::uint8_t maxSide = (targetFootprint.mSizeX > targetFootprint.mSizeZ)
        ? targetFootprint.mSizeX
        : targetFootprint.mSizeZ;
      if (maxSide > 1u) {
        return ownerUnit.HasMeleeSpaceAroundLargeTarget(&targetUnit, inOutDestination, 1);
      }
    }

    return ownerUnit.HasMeleeSpaceAroundSmallTarget(&targetUnit, inOutDestination);
  }

  [[nodiscard]] bool IsAtFootprintOriginCell(const moho::Unit& unit, const Wm3::Vector3f& worldPos) noexcept
  {
    const moho::SFootprint& footprint = unit.GetFootprint();
    const Wm3::Vector3f unitPos = unit.GetPosition();

    const int unitCellX = static_cast<int>(unitPos.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    const int unitCellZ = static_cast<int>(unitPos.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));
    const int targetCellX = static_cast<int>(worldPos.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    const int targetCellZ = static_cast<int>(worldPos.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));

    return static_cast<std::uint16_t>(unitCellX) == static_cast<std::uint16_t>(targetCellX)
      && static_cast<std::uint16_t>(unitCellZ) == static_cast<std::uint16_t>(targetCellZ);
  }

  void SetUnitFocusEntity(moho::Unit& unit, moho::Entity* const focusEntity)
  {
    unit.FocusEntityRef.ResetObjectPtr<moho::Entity>(focusEntity);
    if (unit.FocusEntityRef.ResolveObjectPtr<moho::Entity>() != nullptr) {
      (void)unit.RunScript(kOnAssignedFocusEntityScript);
    }
    unit.NeedSyncGameData = true;
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

  void GatherUnitEntitiesAroundPoint(
    moho::EntityGatherVector& outEntities,
    moho::COGrid& ogrid,
    const Wm3::Vector3f& center,
    const float radius
  )
  {
    gpg::Rect2f queryRect{};
    queryRect.x0 = center.x - radius;
    queryRect.z0 = center.z - radius;
    queryRect.x1 = center.x + radius;
    queryRect.z1 = center.z + radius;

    moho::CollisionDBRect collisionRect{};
    moho::func_Rect2fToInt16(&collisionRect, queryRect);
    (void)ogrid.mEntityOccupationManager.GatherUnmarkedEntities(
      outEntities,
      collisionRect,
      moho::EEntityType::ENTITYTYPE_Unit
    );
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
    if (command == nullptr) {
      return nullptr;
    }

    auto* const commandView = reinterpret_cast<CUnitCommandCommandEventLinkView*>(command);
    return &commandView->mCommandEventListenerHead;
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
    if (attacker == nullptr) {
      return nullptr;
    }

    auto* const attackerView = reinterpret_cast<CAiAttackerEventLinkView*>(attacker);
    return &attackerView->mAiAttackerEventHead;
  }

  [[nodiscard]] moho::CUnitCommand* GetCurrentCommand(moho::Unit* const unit) noexcept
  {
    if (unit == nullptr || unit->CommandQueue == nullptr) {
      return nullptr;
    }

    return unit->CommandQueue->GetCurrentCommand();
  }

  [[nodiscard]] moho::CUnitMeleeAttackTargetTask* CreateMeleeAttackTargetTask(
    moho::CCommandTask* const dispatchTask,
    moho::CAiTarget* const target,
    moho::CAiFormationInstance* const formation,
    const bool ignoreFormation
  )
  {
    void* const storage = ::operator new(sizeof(moho::CUnitMeleeAttackTargetTask), std::nothrow);
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) moho::CUnitMeleeAttackTargetTask(dispatchTask, target, formation, ignoreFormation);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitMeleeAttackTargetTask::sType = nullptr;

  /**
   * Address: 0x00615570 (FUN_00615570, Moho::CUnitMeleeAttackTargetTask::CUnitMeleeAttackTargetTask)
   *
   * What it does:
   * Initializes one detached melee attack-target task with self-linked listener
   * nodes, empty dispatch/formation lanes, and default target/cache state.
   */
  CUnitMeleeAttackTargetTask::CUnitMeleeAttackTargetTask()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    (void)new (runtime->mCommandTaskStorage) CCommandTask();

    runtime->mUnknown0030 = 0;
    runtime->mAiAttackerListenerVftable = 0;
    runtime->mAiAttackerListenerLink.ListResetLinks();
    runtime->mUnknown0040 = 0;
    runtime->mCommandEventListenerVftable = 0;
    runtime->mCommandEventListenerLink.ListResetLinks();

    runtime->mDispatchTask = nullptr;
    runtime->mCommand = nullptr;
    runtime->mFormation = nullptr;

    runtime->mTarget.targetType = EAiTargetType::AITARGET_Entity;
    runtime->mTarget.targetEntity.ClearLinkState();
    runtime->mTarget.targetPoint = -1;
    runtime->mTarget.targetIsMobile = false;
    runtime->mTarget.PickTargetPoint();

    runtime->mTargetPosition = Wm3::Vector3f::Zero();
    runtime->mDestination.x = static_cast<std::int16_t>(-0x8000);
    runtime->mDestination.z = static_cast<std::int16_t>(-0x8000);
    runtime->mHasMobileTarget = false;
    runtime->mIgnoreFormationUpdates = false;
    runtime->mNeedsNavigatorGoalUpdate = true;
    runtime->mPlanted = false;
  }

  /**
   * Address: 0x00615690 (FUN_00615690, Moho::CUnitMeleeAttackTargetTask::CUnitMeleeAttackTargetTask)
   *
   * What it does:
   * Initializes one melee attack-target task from dispatch context and target
   * payload, then binds command/listener lanes and seeds initial attacker state.
   */
  CUnitMeleeAttackTargetTask::CUnitMeleeAttackTargetTask(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    CAiFormationInstance* const formation,
    const bool ignoreFormation
  )
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    (void)new (runtime->mCommandTaskStorage) CCommandTask(dispatchTask);

    runtime->mUnknown0030 = 0;
    runtime->mAiAttackerListenerVftable = 0;
    runtime->mAiAttackerListenerLink.ListResetLinks();
    runtime->mUnknown0040 = 0;
    runtime->mCommandEventListenerVftable = 0;
    runtime->mCommandEventListenerLink.ListResetLinks();

    runtime->mDispatchTask = dispatchTask;
    runtime->mCommand = nullptr;
    runtime->mFormation = formation;

    runtime->mTarget.targetType = EAiTargetType::AITARGET_None;
    runtime->mTarget.targetEntity.ClearLinkState();
    runtime->mTarget.position = Wm3::Vector3f::Zero();
    runtime->mTarget.targetPoint = -1;
    runtime->mTarget.targetIsMobile = false;
    if (target != nullptr) {
      runtime->mTarget.targetType = target->targetType;
      runtime->mTarget.targetEntity.ResetFromOwnerLinkSlot(target->targetEntity.ownerLinkSlot);
      runtime->mTarget.position = target->position;
      runtime->mTarget.targetPoint = target->targetPoint;
      runtime->mTarget.targetIsMobile = target->targetIsMobile;
    }

    runtime->mTargetPosition = Wm3::Vector3f::Zero();
    runtime->mDestination.x = static_cast<std::int16_t>(-0x8000);
    runtime->mDestination.z = static_cast<std::int16_t>(-0x8000);
    runtime->mHasMobileTarget = false;
    runtime->mIgnoreFormationUpdates = ignoreFormation;
    runtime->mNeedsNavigatorGoalUpdate = true;
    runtime->mPlanted = false;

    CCommandTask* const commandTask = AsCommandTask(runtime);
    Unit* const unit = commandTask->mUnit;
    if (unit != nullptr) {
      unit->UnitStateMask |= (1ull << UNITSTATE_Attacking);

      if (!runtime->mIgnoreFormationUpdates) {
        if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
          navigator->IgnoreFormation(true);
        }
      }

      runtime->mCommand = GetCurrentCommand(unit);
      if (CUnitCommand* const command = runtime->mCommand; command != nullptr) {
        command->mUnknownFlag154 = true;
        if (Broadcaster* const commandListenerHead = CommandEventListenerHead(command); commandListenerHead != nullptr) {
          runtime->mCommandEventListenerLink.ListLinkBefore(commandListenerHead);
        }
      }

      if (!unit->IsMobile()) {
        runtime->mFormation = nullptr;
      }

      CAiAttackerImpl* const attacker = unit->AiAttacker;
      if (attacker != nullptr) {
        runtime->mAiAttackerListenerLink.ListUnlink();
      }

      runtime->mHasMobileTarget =
        runtime->mTarget.targetEntity.GetObjectPtr() != nullptr && runtime->mTarget.targetIsMobile;

      UpdatePosition();

      if (
        unit->IsUnitState(UNITSTATE_Immobile) && unit->GetBlueprint()->AI.NeedUnpack && attacker != nullptr
      ) {
        CAiTarget desiredTarget{};
        desiredTarget.targetType = EAiTargetType::AITARGET_None;
        desiredTarget.targetEntity.ClearLinkState();
        desiredTarget.position = Wm3::Vector3f::Zero();
        desiredTarget.targetPoint = -1;
        desiredTarget.targetIsMobile = false;
        attacker->SetDesiredTarget(&desiredTarget);
      }
    }

    commandTask->mTaskState = TASKSTATE_Preparing;
  }

  /**
   * Address: 0x00617580 (FUN_00617580, Moho::CUnitMeleeAttackTargetTask::~CUnitMeleeAttackTargetTask)
   *
   * What it does:
   * Clears focus/target weak links, detaches listener lanes, resets attacking
   * unit-state bits, and destroys the embedded command-task base slice.
   */
  CUnitMeleeAttackTargetTask::~CUnitMeleeAttackTargetTask()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    Unit* const unit = commandTask->mUnit;

    if (runtime->mPlanted && unit != nullptr) {
      unit->FreeOgridRect();
      runtime->mPlanted = false;
    }

    if (unit != nullptr) {
      unit->UnitStateMask &= ~(1ull << UNITSTATE_Attacking);

      unit->FocusEntityRef.ResetObjectPtr<Entity>(nullptr);
      if (unit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
        (void)unit->RunScript("OnAssignedFocusEntity");
      }
      unit->NeedSyncGameData = true;
    }

    runtime->mCommandEventListenerLink.ListUnlink();

    if (unit != nullptr) {
      if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
        navigator->IgnoreFormation(false);
      }

      if (CAiAttackerImpl* const attacker = unit->AiAttacker; attacker != nullptr) {
        runtime->mAiAttackerListenerLink.ListUnlink();
        attacker->Stop();
      }

      if (runtime->mPlanted) {
        unit->FreeOgridRect();
        runtime->mPlanted = false;
      }

      if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
        navigator->AbortMove();
      }
    }

    runtime->mTarget.targetEntity.UnlinkFromOwnerChain();
    runtime->mTarget.targetEntity.ClearLinkState();
    runtime->mCommandEventListenerLink.ListResetLinks();
    runtime->mAiAttackerListenerLink.ListResetLinks();

    commandTask->~CCommandTask();
  }

  /**
   * Address: 0x006154B0 (FUN_006154B0, Moho::CUnitMeleeAttackTargetTask::operator new)
   *
   * What it does:
   * Allocates one melee attack-target task and forwards into dispatch-bound
   * constructor lane with formation-ignore disabled.
   */
  CUnitMeleeAttackTargetTask* CUnitMeleeAttackTargetTask::CreateRespectFormation(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    CAiFormationInstance* const formation
  )
  {
    return CreateMeleeAttackTargetTask(dispatchTask, target, formation, false);
  }

  /**
   * Address: 0x00615510 (FUN_00615510, Moho::CUnitMeleeAttackTargetTask::operator new)
   *
   * What it does:
   * Allocates one melee attack-target task and forwards into dispatch-bound
   * constructor lane with formation-ignore enabled.
   */
  CUnitMeleeAttackTargetTask* CUnitMeleeAttackTargetTask::Create(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    CAiFormationInstance* const formation
  )
  {
    return CreateMeleeAttackTargetTask(dispatchTask, target, formation, true);
  }

  /**
   * Address: 0x00615980 (FUN_00615980)
   *
   * What it does:
   * Builds one-cell navigator goal bounds from `destinationCell`, pushes the
   * goal to the owner navigator, and caches the destination cell lane.
   */
  void CUnitMeleeAttackTargetTask::SetDestinationCellGoal(const SOCellPos& destinationCell)
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    IAiNavigator* const navigator = AsCommandTask(runtime)->mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    SAiNavigatorGoal goal{};
    goal.mPos1.x0 = static_cast<std::int32_t>(destinationCell.x);
    goal.mPos1.z0 = static_cast<std::int32_t>(destinationCell.z);
    goal.mPos1.x1 = goal.mPos1.x0 + 1;
    goal.mPos1.z1 = goal.mPos1.z0 + 1;
    goal.mPos2 = gpg::Rect2i{};
    goal.mLayer = static_cast<ELayer>(0);
    navigator->SetGoal(goal);

    runtime->mDestination = destinationCell;
  }

  /**
   * Address: 0x00615920 (FUN_00615920)
   *
   * What it does:
   * Rebuilds one-cell navigator goal bounds from cached `mDestination`
   * without modifying task destination state.
   */
  void CUnitMeleeAttackTargetTask::RefreshDestinationCellGoal()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    IAiNavigator* const navigator = AsCommandTask(runtime)->mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    const SOCellPos& destinationCell = runtime->mDestination;
    SAiNavigatorGoal goal{};
    goal.mPos1.x0 = static_cast<std::int32_t>(destinationCell.x);
    goal.mPos1.z0 = static_cast<std::int32_t>(destinationCell.z);
    goal.mPos1.x1 = goal.mPos1.x0 + 1;
    goal.mPos1.z1 = goal.mPos1.z0 + 1;
    goal.mPos2 = gpg::Rect2i{};
    goal.mLayer = static_cast<ELayer>(0);
    navigator->SetGoal(goal);
  }

  /**
   * Address: 0x006159F0 (FUN_006159F0)
   *
   * What it does:
   * Converts one world-space destination to footprint-origin cell
   * coordinates, then routes through `SetDestinationCellGoal`.
   */
  void CUnitMeleeAttackTargetTask::SetDestinationGoalFromWorldPosition(const Wm3::Vector3f& worldPosition)
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    const SFootprint& footprint = AsCommandTask(runtime)->mUnit->GetFootprint();

    SOCellPos destinationCell{};
    destinationCell.x = RoundToCellCoord(worldPosition.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    destinationCell.z = RoundToCellCoord(worldPosition.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));
    SetDestinationCellGoal(destinationCell);
  }

  /**
   * Address: 0x00615A70 (FUN_00615A70, Moho::CUnitMeleeAttackTargetTask::SetDestUnit)
   *
   * What it does:
   * Sets navigator destination-unit follow lane and refreshes the cached
   * destination cell from target footprint-centered world position.
   */
  void CUnitMeleeAttackTargetTask::SetDestUnit(Entity* const destinationEntity)
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    IAiNavigator* const navigator = AsCommandTask(runtime)->mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    navigator->SetDestUnit(static_cast<Unit*>(destinationEntity));
    if (destinationEntity == nullptr) {
      return;
    }

    const SFootprint& footprint = destinationEntity->GetFootprint();
    SOCellPos destinationCell{};
    destinationCell.x =
      RoundToCellCoord(destinationEntity->Position.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    destinationCell.z =
      RoundToCellCoord(destinationEntity->Position.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));
    runtime->mDestination = destinationCell;
  }

  /**
   * Address: 0x00615EF0 (FUN_00615EF0, Moho::CUnitMeleeAttackTargetTask::UpdateTarget)
   *
   * What it does:
   * Refreshes melee destination from formation-adjusted target position when
   * in formation mode, otherwise from live entity target weak-link state.
   */
  void CUnitMeleeAttackTargetTask::UpdateTarget()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    if (runtime->mFormation != nullptr) {
      const Wm3::Vector3f targetPos = runtime->mTarget.GetTargetPosGun(false);
      SCoordsVec2 formationCenter{};
      formationCenter.x = targetPos.x;
      formationCenter.z = targetPos.z;
      runtime->mFormation->Func3(formationCenter);

      SOCellPos adjustedPosition{};
      runtime->mFormation->GetAdjustedFormationPosition(&adjustedPosition, AsCommandTask(runtime)->mUnit, nullptr);
      SetDestinationCellGoal(adjustedPosition);
      return;
    }

    if (!runtime->mTarget.HasTarget()) {
      return;
    }

    if (runtime->mTarget.targetEntity.ownerLinkSlot == nullptr || runtime->mTarget.targetEntity.IsSentinel()) {
      return;
    }

    SetDestUnit(runtime->mTarget.targetEntity.GetObjectPtr());
  }

  /**
   * Address: 0x00615B10 (FUN_00615B10, Moho::CUnitMeleeAttackTargetTask::UpdatePosition)
   *
   * What it does:
   * Refreshes cached target world position from current target payload and
   * falls back to owner unit position when result is invalid.
   */
  void CUnitMeleeAttackTargetTask::UpdatePosition()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    if (runtime->mTarget.HasTarget()) {
      runtime->mTargetPosition = runtime->mTarget.GetTargetPosGun(false);
    }

    if (!IsValidVector3f(runtime->mTargetPosition)) {
      runtime->mTargetPosition = AsCommandTask(runtime)->mUnit->GetPosition();
    }
  }

  /**
   * Address: 0x00615B80 (FUN_00615B80, Moho::CUnitMeleeAttackTargetTask::InRange)
   *
   * What it does:
   * Returns whether owner unit is within melee guard-scan radius of current
   * target (or cached target position when no target exists).
   */
  bool CUnitMeleeAttackTargetTask::InRange()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    Unit* const unit = AsCommandTask(runtime)->mUnit;
    const Wm3::Vector3f unitPosition = unit->GetPosition();

    float deltaX = 0.0f;
    float deltaZ = 0.0f;
    if (runtime->mTarget.HasTarget()) {
      const Wm3::Vector3f targetPosition = runtime->mTarget.GetTargetPosGun(false);
      deltaX = unitPosition.x - targetPosition.x;
      deltaZ = unitPosition.z - targetPosition.z;
    } else {
      deltaX = unitPosition.x - runtime->mTargetPosition.x;
      deltaZ = unitPosition.z - runtime->mTargetPosition.z;
    }

    const float planarDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
    return unit->GetBlueprint()->AI.GuardScanRadius > planarDistance;
  }

  /**
   * Address: 0x00615C30 (FUN_00615C30)
   *
   * What it does:
   * Returns true when this task is formation-bound and the formation lead
   * unit currently has one desired attacker target.
   */
  bool CUnitMeleeAttackTargetTask::HasFormationLeadDesiredTarget()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    if (!runtime->mIgnoreFormationUpdates || runtime->mFormation == nullptr) {
      return false;
    }

    Unit* const formationLead = AsCommandTask(runtime)->mUnit->mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
    if (formationLead == nullptr) {
      return false;
    }

    CAiAttackerImpl* const attacker = formationLead->AiAttacker;
    if (attacker == nullptr) {
      return false;
    }

    CAiTarget* const desiredTarget = attacker->GetDesiredTarget();
    return desiredTarget != nullptr && desiredTarget->HasTarget();
  }

  /**
   * Address: 0x00615FB0 (FUN_00615FB0, Moho::CUnitMeleeAttackTargetTask::FreeSpot)
   *
   * What it does:
   * Releases planted O-grid reservation and aborts active navigator move.
   */
  void CUnitMeleeAttackTargetTask::FreeSpot()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    Unit* const unit = AsCommandTask(runtime)->mUnit;
    if (runtime->mPlanted) {
      unit->FreeOgridRect();
      runtime->mPlanted = false;
    }

    if (unit->AiNavigator != nullptr) {
      unit->AiNavigator->AbortMove();
    }
  }

  /**
   * Address: 0x00616020 (FUN_00616020)
   *
   * What it does:
   * Returns true when the current destination cell still contacts the target
   * footprint/collision shell for melee engagement.
   */
  bool CUnitMeleeAttackTargetTask::IsDestinationCellInMeleeContactRange()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    if (!runtime->mTarget.HasTarget()) {
      return false;
    }

    Entity* const targetEntity = runtime->mTarget.GetEntity();
    Unit* const targetUnit = targetEntity ? targetEntity->IsUnit() : nullptr;
    if (targetUnit == nullptr) {
      return false;
    }

    Unit* const ownerUnit = AsCommandTask(runtime)->mUnit;
    const SFootprint& ownerFootprint = ownerUnit->GetFootprint();
    const SFootprint& targetFootprint = targetEntity->GetFootprint();

    const std::uint8_t targetMaxSide = (targetFootprint.mSizeX > targetFootprint.mSizeZ)
      ? targetFootprint.mSizeX
      : targetFootprint.mSizeZ;
    if (targetUnit->IsMobile() && targetMaxSide > 1u) {
      if (targetEntity->CollisionExtents == nullptr) {
        return false;
      }

      const Wm3::Vector3f destinationCenter{
        static_cast<float>(runtime->mDestination.x) + (static_cast<float>(ownerFootprint.mSizeX) * 0.5f),
        0.0f,
        static_cast<float>(runtime->mDestination.z) + (static_cast<float>(ownerFootprint.mSizeZ) * 0.5f),
      };
      const float halfSizeX = static_cast<float>(ownerFootprint.mSizeX) * 0.5f;
      const float halfSizeZ = static_cast<float>(ownerFootprint.mSizeZ) * 0.5f;
      const Wm3::Box3f outerProbe =
        BuildAxisAlignedCollisionProbe(destinationCenter, halfSizeX + 1.0f, halfSizeZ + 1.0f);
      const Wm3::Box3f innerProbe = BuildAxisAlignedCollisionProbe(destinationCenter, halfSizeX, halfSizeZ);

      CollisionResult collisionResult{};
      return targetEntity->CollisionExtents->CollideBox(&outerProbe, &collisionResult)
        && !targetEntity->CollisionExtents->CollideBox(&innerProbe, &collisionResult);
    }

    SCoordsVec2 targetCenterXZ{};
    if (HasPositionChanged(*targetEntity) && targetUnit->AiNavigator != nullptr) {
      const Wm3::Vector3f targetGoalPos = targetUnit->AiNavigator->GetGoalPos();
      targetCenterXZ.x = targetGoalPos.x;
      targetCenterXZ.z = targetGoalPos.z;
    } else {
      const Wm3::Vector3f targetPosition = targetUnit->GetPosition();
      targetCenterXZ.x = targetPosition.x;
      targetCenterXZ.z = targetPosition.z;
    }

    gpg::Rect2i targetRect{};
    COORDS_ToGridRect(&targetRect, targetCenterXZ, targetFootprint);

    SCoordsVec2 destinationCenterXZ{};
    destinationCenterXZ.x =
      static_cast<float>(runtime->mDestination.x) + (static_cast<float>(ownerFootprint.mSizeX) * 0.5f);
    destinationCenterXZ.z =
      static_cast<float>(runtime->mDestination.z) + (static_cast<float>(ownerFootprint.mSizeZ) * 0.5f);

    gpg::Rect2i destinationRect{};
    COORDS_ToGridRect(&destinationRect, destinationCenterXZ, ownerFootprint);
    return destinationRect.Touches(targetRect);
  }

  /**
   * Address: 0x00615FE0 (FUN_00615FE0)
   *
   * What it does:
   * Applies a new desired attacker target when it differs by entity;
   * otherwise resets attacker reporting state.
   */
  bool CUnitMeleeAttackTargetTask::UpdateDesiredTarget(CAiTarget* const desiredTarget)
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CAiAttackerImpl* const attacker = AsCommandTask(runtime)->mUnit->AiAttacker;
    if (attacker == nullptr) {
      return false;
    }

    CAiTarget* const currentDesiredTarget = attacker->GetDesiredTarget();
    Entity* const desiredEntityTarget = desiredTarget ? desiredTarget->targetEntity.GetObjectPtr() : nullptr;
    Entity* const currentEntityTarget = currentDesiredTarget ? currentDesiredTarget->targetEntity.GetObjectPtr() : nullptr;
    if (desiredEntityTarget != currentEntityTarget) {
      attacker->SetDesiredTarget(desiredTarget);
      return true;
    }

    attacker->ResetReportingState();
    return false;
  }

  /**
   * Address: 0x00615CA0 (FUN_00615CA0)
   *
   * What it does:
   * Reconciles formation/target state and refreshes melee navigator goals
   * from either formation-adjusted cells or current cached target position.
   */
  void CUnitMeleeAttackTargetTask::RefreshMeleeNavigationGoal()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    Unit* const unit = commandTask->mUnit;

    // Clear desired target while unpacking so attacker lanes do not hold stale target payload.
    if (unit->IsUnitState(UNITSTATE_Immobile) && unit->GetBlueprint()->AI.NeedUnpack && unit->AiAttacker != nullptr) {
      CAiTarget desiredTarget{};
      desiredTarget.targetType = EAiTargetType::AITARGET_None;
      desiredTarget.targetEntity.ClearLinkState();
      desiredTarget.position = Wm3::Vector3f::Zero();
      desiredTarget.targetPoint = -1;
      desiredTarget.targetIsMobile = false;
      unit->AiAttacker->SetDesiredTarget(&desiredTarget);
    }

    if (runtime->mFormation != nullptr) {
      if (runtime->mHasMobileTarget) {
        UpdatePosition();
        const Wm3::Vector3f targetPos = runtime->mTarget.GetTargetPosGun(false);
        runtime->mFormation->Func3(SCoordsVec2{targetPos.x, targetPos.z});
      } else {
        if (!runtime->mFormation->Func17(unit, true)) {
          gpg::Warnf(" formation does not contain attackin unit! ");
          gpg::Warnf(" -- Unit id = (%d) -- ", unit->id_);
        }

        const SFootprint& footprint = unit->GetFootprint();
        SOCellPos adjustedPosition{};
        runtime->mFormation->GetAdjustedFormationPosition(&adjustedPosition, unit, nullptr);
        runtime->mTargetPosition = COORDS_ToWorldPos(
          unit->SimulationRef->mMapData,
          adjustedPosition,
          static_cast<ELayer>(static_cast<std::uint8_t>(footprint.mOccupancyCaps)),
          static_cast<int>(footprint.mSizeX),
          static_cast<int>(footprint.mSizeZ)
        );
        if (!IsValidVector3f(runtime->mTargetPosition)) {
          runtime->mTargetPosition = unit->GetPosition();
        }
      }

      if (runtime->mNeedsNavigatorGoalUpdate) {
        SOCellPos adjustedPosition{};
        runtime->mFormation->GetAdjustedFormationPosition(&adjustedPosition, unit, nullptr);
        SetDestinationCellGoal(adjustedPosition);
        runtime->mNeedsNavigatorGoalUpdate = false;
        return;
      }
    } else {
      UpdatePosition();
      if (runtime->mNeedsNavigatorGoalUpdate) {
        SetDestinationGoalFromWorldPosition(runtime->mTargetPosition);
        runtime->mNeedsNavigatorGoalUpdate = false;
        return;
      }
    }

    if (runtime->mTarget.HasTarget() && runtime->mPlanted) {
      RefreshDestinationCellGoal();
    } else {
      SetDestinationGoalFromWorldPosition(runtime->mTargetPosition);
    }

    runtime->mNeedsNavigatorGoalUpdate = false;
  }

  /**
   * Address: 0x00617510 (FUN_00617510, listener callback lane)
   *
   * What it does:
   * Syncs command-target payload on event `0` and advances task state from
   * waiting to starting.
   */
  void CUnitMeleeAttackTargetTask::HandleCommandEvent(const ECommandEvent event)
  {
    if (static_cast<std::int32_t>(event) != 0) {
      return;
    }

    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    runtime->mTarget = runtime->mCommand->mTarget;
    commandTask->mTaskState = TASKSTATE_Starting;
    WakeOwnerThreadForImmediateTick(commandTask);
  }

  /**
   * Address: 0x006172C0 (FUN_006172C0, listener callback lane)
   *
   * What it does:
   * Handles attacker-event transitions for melee task state flow, including
   * target refresh/replant when new melee contact room opens around focus
   * target.
   */
  void CUnitMeleeAttackTargetTask::HandleAiAttackerEvent(const EAiAttackerEvent event)
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    Unit* const unit = commandTask->mUnit;

    if (!runtime->mTarget.HasTarget()) {
      commandTask->mTaskState = TASKSTATE_Waiting;
      WakeOwnerThreadForImmediateTick(commandTask);
      return;
    }

    switch (static_cast<int>(event)) {
      case 0:
      case 2:
        return;

      case 1:
        commandTask->mTaskState = TASKSTATE_5;
        break;

      case 8:
        *commandTask->mDispatchResult = static_cast<EAiResult>(1);
        commandTask->mTaskState = TASKSTATE_6;
        break;

      case 9: {
        const WeakPtr<Entity>& focusWeak = unit->FocusEntityRef.AsWeakPtr<Entity>();
        if (focusWeak.ownerLinkSlot != nullptr && !focusWeak.IsSentinel()) {
          Entity* const focusEntity = unit->GetFocusEntity();
          Unit* const targetUnit = focusEntity != nullptr ? focusEntity->IsUnit() : nullptr;
          if (targetUnit != nullptr) {
            const SFootprint& targetFootprint = focusEntity->GetFootprint();
            SOCellPos candidateDestination = targetFootprint.ToCellPos(targetUnit->AiNavigator->GetGoalPos());

            if (QueryMeleeSpaceForTarget(*unit, *targetUnit, &candidateDestination)) {
              runtime->mDestination = candidateDestination;
              FreeSpot();

              CAiTarget updatedTarget{};
              (void)updatedTarget.UpdateTarget(unit->GetFocusEntity());
              runtime->mTarget = updatedTarget;

              const Wm3::Vector3f reserveCenter =
                COORDS_ToWorldPos(unit->SimulationRef->mMapData, runtime->mDestination, unit->GetFootprint());
              const SCoordsVec2 reserveCenterXZ{reserveCenter.x, reserveCenter.z};
              gpg::Rect2i reserveRect{};
              COORDS_ToGridRect(&reserveRect, reserveCenterXZ, unit->GetFootprint());
              unit->ReserveOgridRect(reserveRect);
              runtime->mPlanted = true;

              RefreshMeleeNavigationGoal();
              commandTask->mTaskState = TASKSTATE_Complete;
              commandTask->TaskResume(false, 0);
            }
          }
        }
        break;
      }

      default:
        commandTask->mTaskState = TASKSTATE_Waiting;
        break;
    }

    WakeOwnerThreadForImmediateTick(commandTask);
  }

  /**
   * Address: 0x00616390 (FUN_00616390)
   *
   * What it does:
   * Scans nearby enemy units, scores melee candidates, and selects one target
   * plus destination cell for waiting-state engagement logic.
   */
  Unit* CUnitMeleeAttackTargetTask::SelectWaitingMeleeTarget(bool* const outHasImmediateMeleeSpace)
  {
    if (outHasImmediateMeleeSpace != nullptr) {
      *outHasImmediateMeleeSpace = false;
    }

    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    Unit* const ownerUnit = commandTask->mUnit;
    if (ownerUnit == nullptr || ownerUnit->SimulationRef == nullptr || ownerUnit->SimulationRef->mOGrid == nullptr) {
      return nullptr;
    }

    CArmyImpl* const ownerArmy = ownerUnit->ArmyRef;
    if (ownerArmy == nullptr) {
      return nullptr;
    }

    CAiAttackerImpl* const ownerAttacker = ownerUnit->AiAttacker;
    CAiReconDBImpl* const reconDb = ownerArmy->GetReconDB();
    const Wm3::Vector3f ownerPosition = ownerUnit->GetPosition();
    const float guardScanRadius = ownerUnit->GetBlueprint()->AI.GuardScanRadius;
    const float guardScanRadiusSq = guardScanRadius * guardScanRadius;

    EntityGatherVector nearbyEntities{};
    GatherUnitEntitiesAroundPoint(nearbyEntities, *ownerUnit->SimulationRef->mOGrid, ownerPosition, guardScanRadius);

    EntitySetTemplate<Entity> candidateSet{};
    const int nearbyCount = static_cast<int>(nearbyEntities.end_ - nearbyEntities.start_);
    for (int index = 0; index < nearbyCount; ++index) {
      Entity* const candidateEntity = nearbyEntities.start_[index];
      Unit* const candidateUnit = candidateEntity ? candidateEntity->IsUnit() : nullptr;
      if (candidateUnit == nullptr) {
        continue;
      }

      if (candidateUnit->IsDead() || candidateUnit->DestroyQueued()) {
        continue;
      }

      const int candidateArmyIndex = candidateEntity->GetArmyIndex();
      if (candidateArmyIndex < 0 || !ownerArmy->IsEnemy(static_cast<std::uint32_t>(candidateArmyIndex))) {
        continue;
      }

      if (candidateEntity->IsInCategory("BENIGN")) {
        continue;
      }

      if (reconDb == nullptr || reconDb->ReconGetBlip(candidateUnit) == nullptr) {
        continue;
      }

      if (ownerAttacker != nullptr && !ownerAttacker->CanAttackTarget(&runtime->mTarget)) {
        continue;
      }

      const Wm3::Vector3f candidatePosition = candidateUnit->GetPosition();
      const float deltaX = ownerPosition.x - candidatePosition.x;
      const float deltaZ = ownerPosition.z - candidatePosition.z;
      if (((deltaX * deltaX) + (deltaZ * deltaZ)) > guardScanRadiusSq) {
        continue;
      }

      (void)candidateSet.Add(candidateEntity);
    }

    Entity* bestReachableEntity = nullptr;
    Entity* bestFallbackEntity = nullptr;
    float bestReachableScore = std::numeric_limits<float>::infinity();
    float bestFallbackScore = std::numeric_limits<float>::infinity();

    for (Entity* const* it = candidateSet.begin(); it != candidateSet.end(); ++it) {
      Entity* const candidateEntity = *it;
      Unit* const candidateUnit = candidateEntity ? candidateEntity->IsUnit() : nullptr;
      if (candidateUnit == nullptr) {
        continue;
      }

      const Wm3::Vector3f candidatePosition = candidateUnit->GetPosition();
      const float dx = ownerPosition.x - candidatePosition.x;
      const float dz = ownerPosition.z - candidatePosition.z;
      float weightedScore = (dx * dx) + (dz * dz);

      if (candidateUnit->IsUnitState(UNITSTATE_Attacking) && candidateUnit->GetFocusEntity() != nullptr) {
        if (runtime->mTarget.HasTarget() && candidateEntity == runtime->mTarget.GetEntity()) {
          weightedScore = 0.0f;
        } else {
          Entity* const focusedEntity = const_cast<Entity*>(candidateUnit->GetFocusEntity());
          const Unit* const focusedUnit = focusedEntity ? focusedEntity->IsUnit() : nullptr;
          weightedScore *= (focusedUnit == ownerUnit) ? 0.25f : 4.0f;
        }
      }

      if (weightedScore < bestReachableScore) {
        SOCellPos candidateDestination{};
        if (
          candidateUnit->mIsMelee && candidateUnit->IsUnitState(UNITSTATE_Attacking)
          && candidateUnit->GetFocusEntity() == nullptr
        ) {
          candidateDestination = ComputeMeleeMidpointDestinationCell(*ownerUnit, *candidateUnit);
        } else {
          candidateDestination = ComputeDestinationCellFromUnitGoalOrPosition(*candidateUnit);
        }

        if (QueryMeleeSpaceForTarget(*ownerUnit, *candidateUnit, &candidateDestination)) {
          bestReachableEntity = candidateEntity;
          runtime->mDestination = candidateDestination;
          bestReachableScore = weightedScore;
        }
      }

      if (weightedScore < bestFallbackScore) {
        bestFallbackScore = weightedScore;
        bestFallbackEntity = candidateEntity;
      }
    }

    if (bestReachableEntity != nullptr) {
      if (outHasImmediateMeleeSpace != nullptr) {
        *outHasImmediateMeleeSpace = true;
      }
      return bestReachableEntity->IsUnit();
    }

    if (bestFallbackEntity != nullptr) {
      return bestFallbackEntity->IsUnit();
    }

    return nullptr;
  }

  /**
   * Address: 0x00616C70 (FUN_00616C70, Moho::CUnitMeleeAttackTargetTask::TaskTick)
   *
   * What it does:
   * Advances one melee attack task-state tick and returns the scheduler
   * result code for task-thread control flow.
   */
  int CUnitMeleeAttackTargetTask::TaskTick()
  {
    CUnitMeleeAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    Unit* const unit = commandTask->mUnit;
    if (unit == nullptr) {
      return -1;
    }

    IAiNavigator* const navigator = unit->AiNavigator;

    if (!runtime->mTarget.HasTarget()) {
      CUnitCommandQueue* const commandQueue = unit->CommandQueue;
      if (commandQueue != nullptr && commandQueue->mCommandVec.size() >= 2u) {
        if (CUnitCommand* const nextCommand = commandQueue->mCommandVec[1].GetObjectPtr(); nextCommand != nullptr) {
          return -1;
        }
      }
    }

    switch (commandTask->mTaskState) {
      case TASKSTATE_Preparing: {
        CUnitCommand* const command = runtime->mCommand;
        if (command == nullptr) {
          return -1;
        }
        if (command->IsCoordinating() && !command->IsDone()) {
          return 10;
        }

        commandTask->mTaskState = TASKSTATE_Starting;
        return 0;
      }

      case TASKSTATE_Waiting: {
        if (runtime->mPlanted) {
          unit->FreeOgridRect();
          runtime->mPlanted = false;
        }

        bool hasImmediateMeleeSpace = false;
        Unit* const selectedTarget = SelectWaitingMeleeTarget(&hasImmediateMeleeSpace);
        if (selectedTarget == nullptr) {
          commandTask->mTaskState = TASKSTATE_6;
          return 1;
        }

        (void)runtime->mTarget.UpdateTarget(static_cast<Entity*>(selectedTarget));
        if (!hasImmediateMeleeSpace) {
          RefreshMeleeNavigationGoal();
          SetUnitFocusEntity(*unit, nullptr);
          commandTask->mTaskState = TASKSTATE_Processing;
          return 5;
        }

        const Wm3::Vector3f reserveCenter =
          COORDS_ToWorldPos(unit->SimulationRef->mMapData, runtime->mDestination, unit->GetFootprint());
        const SCoordsVec2 reserveCenterXZ{reserveCenter.x, reserveCenter.z};
        gpg::Rect2i reserveRect{};
        COORDS_ToGridRect(&reserveRect, reserveCenterXZ, unit->GetFootprint());
        unit->ReserveOgridRect(reserveRect);
        runtime->mPlanted = true;

        RefreshMeleeNavigationGoal();
        SetUnitFocusEntity(*unit, static_cast<Entity*>(selectedTarget));
        commandTask->mTaskState = TASKSTATE_Complete;

        if (selectedTarget->IsUnitState(UNITSTATE_Attacking) && selectedTarget->GetFocusEntity() == nullptr) {
          if (CAiAttackerImpl* const targetAttacker = selectedTarget->AiAttacker; targetAttacker != nullptr) {
            targetAttacker->ForceEngage(static_cast<Entity*>(unit));
          }
        }

        return 1;
      }

      case TASKSTATE_Starting:
        if (CAiAttackerImpl* const attacker = unit->AiAttacker; attacker != nullptr) {
          if (Broadcaster* const attackerListenerHead = AiAttackerListenerHead(attacker); attackerListenerHead != nullptr)
          {
            runtime->mAiAttackerListenerLink.ListLinkBefore(attackerListenerHead);
          }
        }
        RefreshMeleeNavigationGoal();
        commandTask->mTaskState = TASKSTATE_Processing;
        return 1;

      case TASKSTATE_Processing: {
        if (runtime->mFormation != nullptr) {
          Unit* const formationLead = unit->mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
          if (formationLead != unit && runtime->mIgnoreFormationUpdates) {
            if (HasFormationLeadDesiredTarget()) {
              runtime->mFormation = nullptr;
              runtime->mIgnoreFormationUpdates = false;
              if (navigator != nullptr) {
                navigator->IgnoreFormation(true);
              }
              commandTask->mTaskState = TASKSTATE_Waiting;
              return 1;
            }
            return 1;
          }
        }

        if (!InRange()) {
          if (navigator == nullptr || navigator->GetStatus() != AINAVSTATUS_Idle) {
            if (runtime->mHasMobileTarget && runtime->mTarget.HasTarget()) {
              const Wm3::Vector3f targetPos = runtime->mTarget.GetTargetPosGun(false);
              const float dx = runtime->mTargetPosition.x - targetPos.x;
              const float dy = runtime->mTargetPosition.y - targetPos.y;
              const float dz = runtime->mTargetPosition.z - targetPos.z;
              if (std::sqrt((dx * dx) + (dy * dy) + (dz * dz)) > 10.0f) {
                UpdateTarget();
                UpdatePosition();
              }
            }
          } else {
            commandTask->mTaskState = TASKSTATE_Starting;
          }

          return 1;
        }

        runtime->mFormation = nullptr;
        runtime->mIgnoreFormationUpdates = false;
        if (navigator != nullptr) {
          navigator->IgnoreFormation(true);
        }
        commandTask->mTaskState = TASKSTATE_Waiting;
        return 1;
      }

      case TASKSTATE_Complete: {
        const SFootprint& ownerFootprint = unit->GetFootprint();
        const Wm3::Vector3f destinationCenter{
          static_cast<float>(runtime->mDestination.x) + (static_cast<float>(ownerFootprint.mSizeX) * 0.5f),
          0.0f,
          static_cast<float>(runtime->mDestination.z) + (static_cast<float>(ownerFootprint.mSizeZ) * 0.5f),
        };

        if (IsDestinationCellInMeleeContactRange()) {
          if (IsAtFootprintOriginCell(*unit, destinationCenter)) {
            (void)UpdateDesiredTarget(&runtime->mTarget);
            commandTask->mTaskState = TASKSTATE_5;
          }
        } else {
          CAiTarget clearTarget{};
          clearTarget.targetType = EAiTargetType::AITARGET_Entity;
          clearTarget.targetEntity.ClearLinkState();
          clearTarget.position = Wm3::Vector3f::Zero();
          clearTarget.targetPoint = -1;
          clearTarget.targetIsMobile = false;
          clearTarget.PickTargetPoint();

          (void)UpdateDesiredTarget(&clearTarget);
          commandTask->mTaskState = TASKSTATE_Waiting;
        }

        return 1;
      }

      case TASKSTATE_5:
        FreeSpot();
        return -2;

      case TASKSTATE_6: {
        const Wm3::Vector3f currentPosition = unit->GetPosition();
        const SCoordsVec2 centerXZ{currentPosition.x, currentPosition.z};
        gpg::Rect2i reserveRect{};
        COORDS_ToGridRect(&reserveRect, centerXZ, unit->GetFootprint());
        unit->ReserveOgridRect(reserveRect);
        runtime->mPlanted = true;

        SetDestinationGoalFromWorldPosition(currentPosition);
        commandTask->mTaskState = TASKSTATE_7;
        return 20;
      }

      case TASKSTATE_7:
        FreeSpot();
        return -1;

      default:
        gpg::HandleAssertFailure(kMeleeTaskAssertText, kMeleeTaskAssertLine, kMeleeTaskSourcePath);
        return -1;
    }
  }

  /**
   * Address: 0x006177B0 (FUN_006177B0)
   *
   * What it does:
   * Resolves melee-task RTTI and binds this helper's load/save callbacks into
   * the reflected type descriptor.
   */
  void CUnitMeleeAttackTargetTaskSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = CUnitMeleeAttackTargetTask::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(CUnitMeleeAttackTargetTask));
      CUnitMeleeAttackTargetTask::sType = type;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00617B50 (FUN_00617B50, gpg::RRef_CUnitMeleeAttackTargetTask)
   *
   * What it does:
   * Builds one typed reflection reference for
   * `moho::CUnitMeleeAttackTargetTask*`, preserving dynamic-derived ownership
   * and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitMeleeAttackTargetTask(
    gpg::RRef* const outRef,
    moho::CUnitMeleeAttackTargetTask* const value
  )
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitMeleeAttackTargetTaskType());
    return outRef;
  }
} // namespace gpg
