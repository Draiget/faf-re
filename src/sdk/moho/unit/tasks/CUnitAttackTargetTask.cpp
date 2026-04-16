#include "moho/unit/tasks/CUnitAttackTargetTask.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IFormationInstanceCountedPtrReflection.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/entity/Entity.h"
#include "moho/math/Vector3f.h"
#include "moho/path/SNavGoal.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/task/CCommandTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CUnitMeleeAttackTargetTask.h"

namespace moho
{
  [[nodiscard]]
  bool PrepareMove(int moveFlags, Unit* unit, Wm3::Vector3f* inOutPos, gpg::Rect2f* outSkirtRect, bool useWholeMap);

  /**
   * Address: 0x00452D40 (FUN_00452D40, Moho::MultQuadVec)
   *
   * What it does:
   * Rotates one vector by quaternion and stores result in `dest`.
   */
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
} // namespace moho

namespace
{
  struct CUnitAttackTargetTaskRuntimeView
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
    moho::UnitWeapon* mWeapon{};                                     // +0x5C
    moho::CAiTarget mTarget{};                                       // +0x60
    Wm3::Vector3f mTargetPosition{};                                 // +0x80
    std::uint8_t mHasMobileTarget{};                                 // +0x8C
    std::uint8_t mIgnoreFormationUpdates{};                          // +0x8D
    std::uint8_t mIsGrounded{};                                      // +0x8E
    std::uint8_t mPad008F{};                                         // +0x8F
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
    offsetof(CUnitAttackTargetTaskRuntimeView, mAiAttackerListenerVftable) == 0x34,
    "CUnitAttackTargetTaskRuntimeView::mAiAttackerListenerVftable offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mCommandEventListenerVftable) == 0x44,
    "CUnitAttackTargetTaskRuntimeView::mCommandEventListenerVftable offset must be 0x44"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mDispatchTask) == 0x50,
    "CUnitAttackTargetTaskRuntimeView::mDispatchTask offset must be 0x50"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mCommand) == 0x54,
    "CUnitAttackTargetTaskRuntimeView::mCommand offset must be 0x54"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mFormation) == 0x58,
    "CUnitAttackTargetTaskRuntimeView::mFormation offset must be 0x58"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mWeapon) == 0x5C,
    "CUnitAttackTargetTaskRuntimeView::mWeapon offset must be 0x5C"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mTarget) == 0x60,
    "CUnitAttackTargetTaskRuntimeView::mTarget offset must be 0x60"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mTargetPosition) == 0x80,
    "CUnitAttackTargetTaskRuntimeView::mTargetPosition offset must be 0x80"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mHasMobileTarget) == 0x8C,
    "CUnitAttackTargetTaskRuntimeView::mHasMobileTarget offset must be 0x8C"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mIgnoreFormationUpdates) == 0x8D,
    "CUnitAttackTargetTaskRuntimeView::mIgnoreFormationUpdates offset must be 0x8D"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mIsGrounded) == 0x8E,
    "CUnitAttackTargetTaskRuntimeView::mIsGrounded offset must be 0x8E"
  );

  [[nodiscard]] CUnitAttackTargetTaskRuntimeView* AsRuntimeView(
    moho::CUnitAttackTargetTask* const task
  ) noexcept
  {
    return reinterpret_cast<CUnitAttackTargetTaskRuntimeView*>(task);
  }

  [[nodiscard]] const CUnitAttackTargetTaskRuntimeView* AsRuntimeView(
    const moho::CUnitAttackTargetTask* const task
  ) noexcept
  {
    return reinterpret_cast<const CUnitAttackTargetTaskRuntimeView*>(task);
  }

  [[nodiscard]] moho::CCommandTask* AsCommandTask(CUnitAttackTargetTaskRuntimeView* const runtime) noexcept
  {
    return reinterpret_cast<moho::CCommandTask*>(runtime->mCommandTaskStorage);
  }

  [[nodiscard]] const moho::CCommandTask* AsCommandTask(const CUnitAttackTargetTaskRuntimeView* const runtime) noexcept
  {
    return reinterpret_cast<const moho::CCommandTask*>(runtime->mCommandTaskStorage);
  }

  [[nodiscard]] bool IsNullOrSentinelPointer(const void* const pointer) noexcept
  {
    return pointer == nullptr || reinterpret_cast<std::uintptr_t>(pointer) == 0x4u;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCAiTargetType()
  {
    gpg::RType* type = moho::CAiTarget::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CAiTarget));
      moho::CAiTarget::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return type;
  }

  /**
   * Address: 0x005F45F0 (FUN_005F45F0)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for
   * `CUnitAttackTargetTask`.
   */
  [[nodiscard]] gpg::RType* CachedCUnitAttackTargetTaskType()
  {
    gpg::RType* type = moho::CUnitAttackTargetTask::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CUnitAttackTargetTask));
      moho::CUnitAttackTargetTask::sType = type;
    }
    return type;
  }

  struct CUnitAttackTargetTaskSerializerStartupNode
  {
    void* mVtable = nullptr;
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
    gpg::RType::load_func_t mLoad = nullptr;
    gpg::RType::save_func_t mSave = nullptr;
  };
  static_assert(
    sizeof(CUnitAttackTargetTaskSerializerStartupNode) == 0x14,
    "CUnitAttackTargetTaskSerializerStartupNode size must be 0x14"
  );

  CUnitAttackTargetTaskSerializerStartupNode gCUnitAttackTargetTaskSerializer{};

  void DeserializeCUnitAttackTargetTaskSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitAttackTargetTask*>(static_cast<std::uintptr_t>(objectPtr));
    task->MemberDeserialize(archive);
  }

  void SerializeCUnitAttackTargetTaskSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitAttackTargetTask*>(static_cast<std::uintptr_t>(objectPtr));
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x005F44C0 (FUN_005F44C0)
   *
   * What it does:
   * Initializes callback lanes for global `CUnitAttackTargetTaskSerializer`
   * helper storage and returns that helper object.
   */
  [[maybe_unused]] [[nodiscard]] CUnitAttackTargetTaskSerializerStartupNode*
  InitializeCUnitAttackTargetTaskSerializerStartupThunk()
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gCUnitAttackTargetTaskSerializer.mNext);
    gCUnitAttackTargetTaskSerializer.mPrev = self;
    gCUnitAttackTargetTaskSerializer.mNext = self;
    gCUnitAttackTargetTaskSerializer.mLoad = &DeserializeCUnitAttackTargetTaskSerializerCallback;
    gCUnitAttackTargetTaskSerializer.mSave = &SerializeCUnitAttackTargetTaskSerializerCallback;
    return &gCUnitAttackTargetTaskSerializer;
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

  [[nodiscard]] int RoundToCellCoord(const float value) noexcept
  {
    return static_cast<int>(std::lrintf(value));
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

  class UnitAttackTaskStateGate
  {
  public:
    virtual ~UnitAttackTaskStateGate() = default;
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
    virtual bool IsAttackTaskStateReady() = 0;
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

  void SetWeaponTarget(moho::UnitWeapon* const weapon, const moho::CAiTarget& target)
  {
    if (weapon == nullptr) {
      return;
    }

    weapon->mTarget = target;
    weapon->PickNewTargetAimSpot();
  }

  void FireWeapon(moho::UnitWeapon* const weapon)
  {
    if (weapon == nullptr) {
      return;
    }

    (void)weapon->RunScript("OnFire");
    ++weapon->mShotsAtTarget;
  }

  [[nodiscard]] bool HasEntityMoved(const moho::Entity& entity) noexcept
  {
    return entity.Position.x != entity.PrevPosition.x || entity.Position.y != entity.PrevPosition.y
      || entity.Position.z != entity.PrevPosition.z;
  }

  constexpr const char* kAttackTaskAssertText = "Reached the supposably unreachable.";
  constexpr const int kAttackTaskAssertLine = 683;
  constexpr const char* kAttackTaskSourcePath = "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitAttack.cpp";
} // namespace

namespace moho
{
  gpg::RType* CUnitAttackTargetTask::sType = nullptr;

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
   * Address: 0x005F2850 (FUN_005F2850, Moho::CUnitAttackTargetTask::CUnitAttackTargetTask)
   *
   * What it does:
   * Initializes one detached ranged attack-target task with self-linked
   * listener nodes and default target/cache lanes.
   */
  CUnitAttackTargetTask::CUnitAttackTargetTask()
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
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
    runtime->mWeapon = nullptr;

    runtime->mTarget.targetType = EAiTargetType::AITARGET_Entity;
    runtime->mTarget.targetEntity.ClearLinkState();
    runtime->mTarget.targetPoint = -1;
    runtime->mTarget.targetIsMobile = false;
    runtime->mTarget.PickTargetPoint();

    runtime->mTargetPosition = Wm3::Vector3f::Zero();
    runtime->mHasMobileTarget = 0u;
    runtime->mIgnoreFormationUpdates = 0u;
    runtime->mIsGrounded = 1u;
    runtime->mPad008F = 0u;
  }

  /**
   * Address: 0x005F2980 (FUN_005F2980, Moho::CUnitAttackTargetTask::CUnitAttackTargetTask)
   *
   * What it does:
   * Initializes one ranged attack-target task from dispatch context, target
   * payload, formation lane, and overcharge toggle state.
   */
  CUnitAttackTargetTask::CUnitAttackTargetTask(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    CAiFormationInstance* const formation,
    const bool ignoreFormation,
    const bool enableOverchargeWeapon
  )
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
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
    runtime->mWeapon = nullptr;

    runtime->mTarget.targetType = EAiTargetType::AITARGET_None;
    runtime->mTarget.targetEntity.ClearLinkState();
    runtime->mTarget.position = Wm3::Vector3f::Zero();
    runtime->mTarget.targetPoint = -1;
    runtime->mTarget.targetIsMobile = false;
    if (target != nullptr) {
      runtime->mTarget = *target;
    }

    runtime->mTargetPosition = Wm3::Vector3f::Zero();
    runtime->mHasMobileTarget = 0u;
    runtime->mIgnoreFormationUpdates = ignoreFormation ? 1u : 0u;
    runtime->mIsGrounded = 1u;
    runtime->mPad008F = 0u;

    CCommandTask* const commandTask = AsCommandTask(runtime);
    Unit* const unit = commandTask->mUnit;
    if (unit == nullptr) {
      commandTask->mTaskState = TASKSTATE_Preparing;
      return;
    }

    unit->UnitStateMask |= (1ull << UNITSTATE_Attacking);

    if (runtime->mIgnoreFormationUpdates == 0u) {
      if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
        navigator->IgnoreFormation(true);
      }
    }

    if (CUnitCommandQueue* const commandQueue = unit->CommandQueue; commandQueue != nullptr) {
      runtime->mCommand = commandQueue->GetCurrentCommand();
    }
    if (runtime->mCommand != nullptr) {
      runtime->mCommand->mUnknownFlag142 = true;
      if (Broadcaster* const commandListenerHead = CommandEventListenerHead(runtime->mCommand); commandListenerHead != nullptr)
      {
        runtime->mCommandEventListenerLink.ListLinkBefore(commandListenerHead);
      }
    }

    if (!unit->IsMobile()) {
      runtime->mFormation = nullptr;
    }

    if (unit->IsInCategory("TARGETCHASER")) {
      runtime->mFormation = nullptr;
    }

    CAiAttackerImpl* const attacker = unit->AiAttacker;
    if (attacker != nullptr) {
      runtime->mAiAttackerListenerLink.ListUnlink();

      if (enableOverchargeWeapon) {
        const int weaponCount = attacker->GetWeaponCount();
        for (int weaponIndex = 0; weaponIndex < weaponCount; ++weaponIndex) {
          UnitWeapon* const weapon = attacker->GetWeapon(weaponIndex);
          if (weapon != nullptr && weapon->mWeaponBlueprint != nullptr && weapon->mWeaponBlueprint->OverChargeWeapon != 0u) {
            runtime->mWeapon = weapon;
            (void)weapon->RunScript("OnEnableWeapon");
            break;
          }
        }
      }
    }

    runtime->mHasMobileTarget =
      (runtime->mTarget.targetEntity.GetObjectPtr() != nullptr && runtime->mTarget.targetIsMobile) ? 1u : 0u;

    UpdatePos();

    if (unit->IsUnitState(UNITSTATE_Immobile) && unit->GetBlueprint()->AI.NeedUnpack && attacker != nullptr) {
      CAiTarget clearTarget{};
      attacker->SetDesiredTarget(&clearTarget);
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (blueprint != nullptr && blueprint->Air.CanFly != 0u) {
      runtime->mIsGrounded = 0u;
    }

    commandTask->mTaskState = TASKSTATE_Preparing;
  }

  /**
   * Address: 0x005F4160 (FUN_005F4160, Moho::CUnitAttackTargetTask::~CUnitAttackTargetTask)
   *
   * What it does:
   * Clears attack-task unit/listener lanes, disables temporary weapon state,
   * and tears down the embedded command-task base slice.
   */
  CUnitAttackTargetTask::~CUnitAttackTargetTask()
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    Unit* const unit = commandTask->mUnit;

    if (unit != nullptr) {
      unit->UnitStateMask &= ~(1ull << UNITSTATE_Attacking);
    }

    runtime->mCommandEventListenerLink.ListUnlink();

    if (unit != nullptr) {
      if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
        navigator->IgnoreFormation(false);
      }
    }

    if (runtime->mWeapon != nullptr) {
      (void)runtime->mWeapon->RunScript("OnDisableWeapon");
    }

    if (unit != nullptr) {
      if (CAiAttackerImpl* const attacker = unit->AiAttacker; attacker != nullptr) {
        runtime->mAiAttackerListenerLink.ListUnlink();
        attacker->Stop();
      }

      if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
        navigator->IgnoreFormation(false);
        navigator->AbortMove();
      }
    }

    runtime->mTarget.targetEntity.UnlinkFromOwnerChain();
    runtime->mCommandEventListenerLink.ListResetLinks();
    runtime->mAiAttackerListenerLink.ListResetLinks();

    commandTask->~CCommandTask();
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
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    IAiNavigator* const navigator = AsCommandTask(runtime)->mUnit->AiNavigator;
    if (navigator == nullptr || weapon == nullptr || weapon->mWeaponBlueprint == nullptr) {
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
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    IAiNavigator* const navigator = AsCommandTask(runtime)->mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    SAiNavigatorGoal goal{};
    goal.mPos1.x0 = static_cast<int>(targetCell.x);
    goal.mPos1.z0 = static_cast<int>(targetCell.z);
    goal.mPos1.x1 = goal.mPos1.x0 + 1;
    goal.mPos1.z1 = goal.mPos1.z0 + 1;
    goal.mPos2 = gpg::Rect2i{};
    goal.mLayer = static_cast<ELayer>(0);
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
      runtime->mTargetPosition = runtime->mTarget.GetTargetPosGun(false);
    }

    if (!IsValidVector3f(runtime->mTargetPosition)) {
      runtime->mTargetPosition = AsCommandTask(runtime)->mUnit->GetPosition();
    }
  }

  /**
   * Address: 0x005F2DF0 (FUN_005F2DF0, CUnitAttackTargetTask::SetPosGoalFromWorldPosition helper)
   *
   * What it does:
   * Converts one world-space position to owner-footprint cell origin and
   * routes it through `SetPosGoal`.
   */
  void CUnitAttackTargetTask::SetPosGoalFromWorldPosition(const Wm3::Vector3f& position)
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    const SFootprint& footprint = AsCommandTask(runtime)->mUnit->GetFootprint();

    SOCellPos targetCell{};
    targetCell.x = static_cast<std::int16_t>(position.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    targetCell.z = static_cast<std::int16_t>(position.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));
    SetPosGoal(targetCell);
  }

  /**
   * Address: 0x005F2F00 (FUN_005F2F00, CUnitAttackTargetTask::IsWithinHorizontalDistance helper)
   *
   * What it does:
   * Returns true when horizontal distance from owner to target cache is
   * below `distance`.
   */
  bool CUnitAttackTargetTask::IsWithinHorizontalDistance(const float distance) const
  {
    const CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    const Wm3::Vector3f unitPos = AsCommandTask(runtime)->mUnit->GetPosition();

    float deltaX = 0.0f;
    float deltaZ = 0.0f;
    if (runtime->mTarget.HasTarget()) {
      const Wm3::Vector3f targetPos = const_cast<moho::CAiTarget&>(runtime->mTarget).GetTargetPosGun(false);
      deltaX = unitPos.x - targetPos.x;
      deltaZ = unitPos.z - targetPos.z;
    } else {
      deltaX = unitPos.x - runtime->mTargetPosition.x;
      deltaZ = unitPos.z - runtime->mTargetPosition.z;
    }

    const float horizontalDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
    return distance > horizontalDistance;
  }

  /**
   * Address: 0x005F2FB0 (FUN_005F2FB0, CUnitAttackTargetTask::HasFormationLeadDesiredTarget helper)
   *
   * What it does:
   * Returns true when formation-lead attacker already has one desired target
   * while this task is still honoring formation updates.
   */
  bool CUnitAttackTargetTask::HasFormationLeadDesiredTarget() const
  {
    const CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    if (runtime->mIgnoreFormationUpdates == 0u || runtime->mFormation == nullptr) {
      return false;
    }

    const Unit* const owner = AsCommandTask(runtime)->mUnit;
    if (owner == nullptr) {
      return false;
    }

    Unit* const formationLead = owner->mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
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
   * Address: 0x005F3370 (FUN_005F3370, CUnitAttackTargetTask::RefreshNavigationGoal helper)
   *
   * What it does:
   * Refreshes navigation destination from current target/formation context.
   */
  void CUnitAttackTargetTask::RefreshNavigationGoal()
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    if (!runtime->mTarget.HasTarget()) {
      return;
    }

    if (runtime->mFormation != nullptr) {
      SCoordsVec2 targetCoords{};
      const Wm3::Vector3f targetPosition = runtime->mTarget.GetTargetPosGun(false);
      targetCoords.x = targetPosition.x;
      targetCoords.z = targetPosition.z;
      runtime->mFormation->Func3(targetCoords);

      SOCellPos adjustedPosition{};
      runtime->mFormation->GetAdjustedFormationPosition(&adjustedPosition, AsCommandTask(runtime)->mUnit, nullptr);
      SetPosGoal(adjustedPosition);
      return;
    }

    if (runtime->mWeapon != nullptr) {
      if (Unit* const unit = AsCommandTask(runtime)->mUnit; unit != nullptr && unit->AiAttacker != nullptr) {
        (void)unit->AiAttacker->TargetIsWithinWeaponAttackRange(runtime->mWeapon, &runtime->mTarget);
      }
    }
  }

  /**
   * Address: 0x005F3420 (FUN_005F3420, CUnitAttackTargetTask::AbortNavigation helper)
   *
   * What it does:
   * Re-enables formation influence on navigator and aborts current move.
   */
  void CUnitAttackTargetTask::AbortNavigation()
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    IAiNavigator* const navigator = AsCommandTask(runtime)->mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    navigator->IgnoreFormation(false);
    navigator->AbortMove();
  }

  /**
   * Address: 0x005F3020 (FUN_005F3020, Moho::CUnitAttackTargetTask::Update)
   *
   * What it does:
   * Refreshes formation/target-driven navigation goals, updates current
   * attack position cache, and applies per-layer targeting movement.
   */
  void CUnitAttackTargetTask::Update()
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    Unit* const unit = commandTask->mUnit;
    if (unit == nullptr) {
      return;
    }

    CAiAttackerImpl* const attacker = unit->AiAttacker;
    const RUnitBlueprint* const blueprint = unit->GetBlueprint();

    if (unit->IsUnitState(UNITSTATE_Immobile) && blueprint != nullptr && blueprint->AI.NeedUnpack && attacker != nullptr) {
      CAiTarget clearTarget{};
      attacker->SetDesiredTarget(&clearTarget);
    }

    if (runtime->mFormation != nullptr) {
      if (runtime->mHasMobileTarget != 0u) {
        UpdatePos();

        const Wm3::Vector3f targetPosition = runtime->mTargetPosition;
        SCoordsVec2 formationCenter{};
        formationCenter.x = targetPosition.x;
        formationCenter.z = targetPosition.z;
        runtime->mFormation->Func3(formationCenter);
      } else {
        if (!runtime->mFormation->Func17(unit, true)) {
          gpg::Warnf(" formation does not contain attackin unit! ");
          gpg::Warnf(" -- Unit id = (%d) -- ", unit->id_);
        }

        SOCellPos adjustedPosition{};
        runtime->mFormation->GetAdjustedFormationPosition(&adjustedPosition, unit, nullptr);

        const SFootprint& footprint = unit->GetFootprint();
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

      if (runtime->mIsGrounded != 0u) {
        if (attacker != nullptr) {
          UnitWeapon* const targetWeapon = attacker->GetTargetWeapon(&runtime->mTarget);
          if (targetWeapon != nullptr) {
            SCoordsVec2 formationPosition{};
            runtime->mFormation->GetFormationPosition(&formationPosition, unit, nullptr);

            const Wm3::Vector3f weaponGoalPosition{formationPosition.x, 0.0f, formationPosition.z};
            SetWeaponGoal(weaponGoalPosition, targetWeapon);
          } else {
            SOCellPos adjustedPosition{};
            runtime->mFormation->GetAdjustedFormationPosition(&adjustedPosition, unit, nullptr);
            SetPosGoal(adjustedPosition);
          }
        } else {
          SOCellPos adjustedPosition{};
          runtime->mFormation->GetAdjustedFormationPosition(&adjustedPosition, unit, nullptr);
          SetPosGoal(adjustedPosition);
        }
      } else {
        const Wm3::Vector3f targetPosition = runtime->mTarget.HasTarget() ? runtime->mTarget.GetTargetPosGun(false)
                                                                           : runtime->mTargetPosition;
        SetPosGoalFromWorldPosition(targetPosition);
      }
    } else {
      UpdatePos();

      if (runtime->mIsGrounded != 0u && attacker != nullptr) {
        UnitWeapon* const targetWeapon = attacker->GetTargetWeapon(&runtime->mTarget);
        if (targetWeapon != nullptr) {
          SetWeaponGoal(runtime->mTarget.GetTargetPosGun(false), targetWeapon);
          runtime->mIsGrounded = 0u;
          return;
        }
      }

      if (runtime->mHasMobileTarget == 0u) {
        const Wm3::Vector3f targetPosition = runtime->mTarget.HasTarget() ? runtime->mTarget.GetTargetPosGun(false)
                                                                           : runtime->mTargetPosition;
        SetPosGoalFromWorldPosition(targetPosition);
      } else {
        Entity* const destinationEntity = runtime->mTarget.targetEntity.GetObjectPtr();
        if (destinationEntity != nullptr) {
          if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
            navigator->SetDestUnit(destinationEntity->IsUnit());
          }
        } else {
          SetPosGoalFromWorldPosition(runtime->mTargetPosition);
        }
      }
    }

    runtime->mIsGrounded = 0u;
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

    auto ownerStateReady = [commandTask]() -> bool {
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
   * Address: 0x005F4000 (FUN_005F4000, Moho::Listener_CommandEvent_CUnitAttackTargetTask::Receive)
   *
   * What it does:
   * Synchronizes task target payload from current command lane, refreshes
   * attacker desired-target state for valid command/sim combinations, and
   * wakes owner-thread flow.
   */
  void CUnitAttackTargetTask::HandleCommandEvent(const ECommandEvent)
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    if (runtime->mCommand == nullptr) {
      commandTask->mTaskState = TASKSTATE_5;
      WakeOwnerThreadForImmediateTick(commandTask);
      return;
    }

    const bool hasCommandEntityTarget =
      runtime->mCommand->mTarget.targetEntity.ownerLinkSlot != nullptr
      && !runtime->mCommand->mTarget.targetEntity.IsSentinel();
    const bool invalidSimPointer = IsNullOrSentinelPointer(commandTask->mSim);
    if (!hasCommandEntityTarget && !invalidSimPointer) {
      commandTask->mTaskState = TASKSTATE_5;
      WakeOwnerThreadForImmediateTick(commandTask);
      return;
    }

    runtime->mTarget = runtime->mCommand->mTarget;

    Unit* const unit = commandTask->mUnit;
    CAiAttackerImpl* const attacker = (unit != nullptr) ? unit->AiAttacker : nullptr;
    if (attacker != nullptr) {
      if (!invalidSimPointer) {
        CAiTarget* const desiredTarget = attacker->GetDesiredTarget();
        if (desiredTarget != nullptr && desiredTarget->HasTarget()) {
          (void)UpdateAttacker(&runtime->mTarget);
        }
      } else {
        attacker->OnWeaponHaltFire();

        CAiTarget clearTarget{};
        clearTarget.targetType = EAiTargetType::AITARGET_None;
        clearTarget.targetEntity.ClearLinkState();
        clearTarget.targetPoint = -1;
        clearTarget.targetIsMobile = false;
        (void)UpdateAttacker(&clearTarget);
      }
    }

    commandTask->mTaskState = TASKSTATE_Waiting;
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
    Entity* const desiredEntityTarget = (desiredTarget != nullptr) ? desiredTarget->targetEntity.GetObjectPtr() : nullptr;
    Entity* const currentEntityTarget =
      (currentDesiredTarget != nullptr) ? currentDesiredTarget->targetEntity.GetObjectPtr() : nullptr;
    if (desiredEntityTarget == currentEntityTarget) {
      attacker->ResetReportingState();
      return false;
    }

    attacker->SetDesiredTarget(desiredTarget);
    if (Broadcaster* const listenerHead = AiAttackerListenerHead(attacker); listenerHead != nullptr) {
      runtime->mAiAttackerListenerLink.ListLinkBefore(listenerHead);
    }
    return true;
  }

  /**
   * Address: 0x005F4DC0 (FUN_005F4DC0, Moho::CUnitAttackTargetTask::MemberDeserialize)
   *
   * What it does:
   * Deserializes base command-task state, attack-task pointer lanes, target
   * payload, and boolean state flags.
   */
  void CUnitAttackTargetTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    const gpg::RRef ownerRef{};

    archive->Read(CachedCCommandTaskType(), commandTask, ownerRef);
    archive->ReadPointer_CCommandTask(&runtime->mDispatchTask, &ownerRef);
    archive->ReadPointer_CUnitCommand(&runtime->mCommand, &ownerRef);

    IFormationInstance* formationBase = static_cast<IFormationInstance*>(runtime->mFormation);
    archive->ReadPointer_IFormationInstance(&formationBase, &ownerRef);
    runtime->mFormation = static_cast<CAiFormationInstance*>(formationBase);

    archive->ReadPointer_UnitWeapon(&runtime->mWeapon, &ownerRef);
    archive->Read(CachedCAiTargetType(), &runtime->mTarget, ownerRef);
    archive->Read(CachedVector3fType(), &runtime->mTargetPosition, ownerRef);

    bool hasMobileTarget = (runtime->mHasMobileTarget != 0u);
    archive->ReadBool(&hasMobileTarget);
    runtime->mHasMobileTarget = hasMobileTarget ? 1u : 0u;

    bool ignoreFormationUpdates = (runtime->mIgnoreFormationUpdates != 0u);
    archive->ReadBool(&ignoreFormationUpdates);
    runtime->mIgnoreFormationUpdates = ignoreFormationUpdates ? 1u : 0u;

    bool grounded = (runtime->mIsGrounded != 0u);
    archive->ReadBool(&grounded);
    runtime->mIsGrounded = grounded ? 1u : 0u;
  }

  /**
   * Address: 0x005F4F00 (FUN_005F4F00, Moho::CUnitAttackTargetTask::MemberSerialize)
   *
   * What it does:
   * Serializes base command-task state, attack-task pointer lanes, target
   * payload, and boolean state flags.
   */
  void CUnitAttackTargetTask::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    const gpg::RRef ownerRef{};

    archive->Write(CachedCCommandTaskType(), commandTask, ownerRef);

    gpg::RRef pointerRef{};
    (void)gpg::RRef_CCommandTask(&pointerRef, runtime->mDispatchTask);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    (void)gpg::RRef_CUnitCommand(&pointerRef, runtime->mCommand);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    (void)gpg::RRef_IFormationInstance(&pointerRef, static_cast<IFormationInstance*>(runtime->mFormation));
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    (void)gpg::RRef_UnitWeapon(&pointerRef, runtime->mWeapon);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedCAiTargetType(), &runtime->mTarget, ownerRef);
    archive->Write(CachedVector3fType(), &runtime->mTargetPosition, ownerRef);
    archive->WriteBool(runtime->mHasMobileTarget != 0u);
    archive->WriteBool(runtime->mIgnoreFormationUpdates != 0u);
    archive->WriteBool(runtime->mIsGrounded != 0u);
  }

  /**
   * Address: 0x005F34C0 (FUN_005F34C0, Moho::CUnitAttackTargetTask::TaskTick)
   *
   * What it does:
   * Advances one ranged attack-target task tick through preparation,
   * movement/range management, attack handoff, and final fire gating.
   */
  int CUnitAttackTargetTask::TaskTick()
  {
    CUnitAttackTargetTaskRuntimeView* const runtime = AsRuntimeView(this);
    CCommandTask* const commandTask = AsCommandTask(runtime);
    Unit* const unit = commandTask->mUnit;
    if (unit == nullptr) {
      return -1;
    }

    CAiAttackerImpl* const attacker = unit->AiAttacker;
    IAiNavigator* const navigator = unit->AiNavigator;

    UnitWeapon* weapon = runtime->mWeapon;
    if (weapon == nullptr && attacker != nullptr) {
      weapon = attacker->GetTargetWeapon(&runtime->mTarget);
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    const bool autoSurfaceAttackMode =
      blueprint != nullptr && blueprint->AI.AutoSurfaceToAttack != 0u
      && blueprint->Physics.MotionType == RULEUMT_SurfacingSub && unit->mCurrentLayer == LAYER_Sub;

    const bool directFireCategory = unit->IsInCategory("DIRECTFIRE");

    if (!runtime->mTarget.HasTarget()) {
      CUnitCommandQueue* const commandQueue = unit->CommandQueue;
      if (commandQueue != nullptr && commandQueue->mCommandVec.size() >= 2u) {
        CUnitCommand* const nextCommand = commandQueue->mCommandVec[1].GetObjectPtr();
        if (nextCommand != nullptr) {
          return -1;
        }
      }
    }

    if (weapon == nullptr && runtime->mIgnoreFormationUpdates == 0u && !directFireCategory && !autoSurfaceAttackMode) {
      return -1;
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

        commandTask->mTaskState = TASKSTATE_Waiting;
        return 0;
      }

      case TASKSTATE_Waiting:
        if (unit->IsMobile()) {
          const bool noTarget = runtime->mTarget.NoTarget();
          if (autoSurfaceAttackMode && weapon == nullptr && runtime->mTarget.HasTarget() && !noTarget) {
            if (!unit->IsAutoSurfaceMode()) {
              return -1;
            }

            const SOCellPos targetCell = unit->GetFootprint().ToCellPos(unit->GetPosition());
            SAiNavigatorGoal surfaceGoal(targetCell);
            surfaceGoal.mLayer = LAYER_Water;
            if (unit->AiCommandDispatch != nullptr) {
              unit->AiCommandDispatch->SetNewTargetLayer(surfaceGoal);
            }
          }

          Update();
          commandTask->mTaskState = TASKSTATE_Processing;
          return 0;
        }

        (void)UpdateAttacker(&runtime->mTarget);
        commandTask->mTaskState = TASKSTATE_Complete;
        return 0;

      case TASKSTATE_Starting:
        if (attacker == nullptr) {
          return -1;
        }

        if (!attacker->IsTooClose(&runtime->mTarget)) {
          Update();
          commandTask->mTaskState = TASKSTATE_Processing;
          return 0;
        }

        {
          const Wm3::Vector3f targetPosition = runtime->mTarget.GetTargetPosGun(false);
          Wm3::Vector3f moveOffset = unit->GetPosition() - targetPosition;
          if (blueprint != nullptr) {
            (void)VecSetLength(&moveOffset, blueprint->AI.GuardScanRadius);
          }

          Wm3::Vector3f movePosition = runtime->mTarget.GetTargetPosGun(false) + moveOffset;
          gpg::Rect2f moveSkirt{};
          const bool useWholeMap = (unit->ArmyRef != nullptr) ? unit->ArmyRef->UseWholeMap() : false;
          (void)PrepareMove(0, unit, &movePosition, &moveSkirt, useWholeMap);

          if (navigator != nullptr) {
            const SOCellPos moveCell = unit->GetFootprint().ToCellPos(movePosition);
            navigator->SetGoal(SNavGoal(moveCell));

            if (unit->IsUnitState(UNITSTATE_Immobile) && blueprint != nullptr && blueprint->AI.NeedUnpack && attacker != nullptr)
            {
              CAiTarget clearTarget{};
              attacker->SetDesiredTarget(&clearTarget);
            }
          }
        }
        return 10;

      case TASKSTATE_Processing: {
        if (runtime->mFormation != nullptr) {
          Unit* const formationLead = unit->mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
          if (formationLead != unit && runtime->mIgnoreFormationUpdates != 0u) {
            if (!HasFormationLeadDesiredTarget()) {
              return 1;
            }

            runtime->mFormation = nullptr;
            runtime->mIgnoreFormationUpdates = 0u;
            if (navigator != nullptr) {
              navigator->IgnoreFormation(true);
            }

            Update();
            return 1;
          }
        }

        const bool noTarget = runtime->mTarget.NoTarget();
        if (!runtime->mTarget.HasTarget() || noTarget) {
          if (navigator == nullptr || (attacker != nullptr && attacker->VectorIsWithinAttackRange(&runtime->mTargetPosition))) {
            return -1;
          }

          if (navigator->GetStatus() == AINAVSTATUS_Idle) {
            Update();
          }
          return 1;
        }

        const bool targetInWeaponRange =
          attacker != nullptr && attacker->TargetIsWithinWeaponAttackRange(weapon, &runtime->mTarget);
        const float engageDistance = (blueprint != nullptr) ? blueprint->Air.EngageDistance : 0.0f;

        if (!targetInWeaponRange && !IsWithinHorizontalDistance(engageDistance)) {
          if (attacker != nullptr && attacker->IsTooClose(&runtime->mTarget)) {
            commandTask->mTaskState = TASKSTATE_Starting;
            return 1;
          }

          if (navigator != nullptr && navigator->GetStatus() == AINAVSTATUS_Idle) {
            Update();
            return 1;
          }

          if (runtime->mHasMobileTarget != 0u) {
            const Wm3::Vector3f targetPosition = runtime->mTarget.GetTargetPosGun(false);
            const float deltaX = runtime->mTargetPosition.x - targetPosition.x;
            const float deltaY = runtime->mTargetPosition.y - targetPosition.y;
            const float deltaZ = runtime->mTargetPosition.z - targetPosition.z;
            const float distance = std::sqrt((deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ));
            const float threshold = (blueprint != nullptr && blueprint->Air.CanFly != 0u) ? 2.0f : 10.0f;

            if (distance > threshold) {
              const Wm3::Vector3f candidatePosition = runtime->mTarget.GetTargetPosGun(false);
              if (!UnitWontFitAt(candidatePosition, unit)) {
                RefreshNavigationGoal();
                UpdatePos();
              }
            }
          }

          return 1;
        }

        if (attacker == nullptr) {
          if (navigator == nullptr) {
            return -1;
          }

          if (navigator->GetStatus() == AINAVSTATUS_Idle) {
            Update();
          }
          return 1;
        }

        if (!attacker->CanAttackTarget(&runtime->mTarget)) {
          return -1;
        }

        runtime->mFormation = nullptr;
        runtime->mIgnoreFormationUpdates = 0u;
        if (navigator != nullptr) {
          navigator->IgnoreFormation(true);
        }

        (void)UpdateAttacker(&runtime->mTarget);

        if (runtime->mWeapon == nullptr) {
          return -2;
        }

        SetWeaponTarget(runtime->mWeapon, runtime->mTarget);
        commandTask->mTaskState = TASKSTATE_Complete;
        return 1;
      }

      case TASKSTATE_Complete:
        if (blueprint != nullptr && blueprint->Air.CanFly == 0u) {
          AbortNavigation();
        }

        if (blueprint != nullptr && blueprint->AI.AttackAngle > 0.0f && runtime->mTarget.HasTarget()) {
          const VTransform& transform = unit->GetTransform();
          const float forwardX = ((transform.orient_.w * transform.orient_.y) + (transform.orient_.z * transform.orient_.x))
            * 2.0f;
          const float forwardZ =
            1.0f - (((transform.orient_.z * transform.orient_.z) + (transform.orient_.y * transform.orient_.y)) * 2.0f);

          Wm3::Vector3f toTarget = runtime->mTarget.GetTargetPosGun(false) - unit->GetPosition();
          (void)Wm3::Vector3f::Normalize(&toTarget);

          float rollRadians = blueprint->AI.AttackAngle * 0.017453292f;
          if (((toTarget.z * forwardX) - (forwardZ * toTarget.x)) <= 0.0f) {
            rollRadians = -rollRadians;
          }

          const Wm3::Vector3f rollAxis{0.0f, 1.0f, 0.0f};
          Wm3::Quaternionf rollRotation{};
          (void)EulerRollToQuat(&rollAxis, &rollRotation, rollRadians);

          Wm3::Vector3f facing{};
          (void)MultQuadVec(&facing, &toTarget, &rollRotation);
          if (unit->UnitMotion != nullptr) {
            unit->UnitMotion->SetFacing(facing);
          }
          return 10;
        }

        if (runtime->mWeapon == nullptr) {
          return -2;
        }

        if (!runtime->mWeapon->RunScriptBool("CanWeaponFire")) {
          return 10;
        }

        if (HasEntityMoved(*unit) && unit->IsMobile() && runtime->mWeapon->mCanFire == 0u) {
          Update();
          commandTask->mTaskState = TASKSTATE_Processing;
          return 1;
        }

        if (runtime->mWeapon->mEnabled != 0u && UnitWeapon::CanFire(runtime->mWeapon, &runtime->mTarget)) {
          FireWeapon(runtime->mWeapon);
          commandTask->mTaskState = TASKSTATE_5;
          return 10;
        }

        return 1;

      case TASKSTATE_5:
        AbortNavigation();
        return -1;

      default:
        gpg::HandleAssertFailure(kAttackTaskAssertText, kAttackTaskAssertLine, kAttackTaskSourcePath);
        return -1;
    }
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x005F4C10 (FUN_005F4C10, gpg::RRef_CUnitAttackTargetTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitAttackTargetTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitAttackTargetTask(
    gpg::RRef* const outRef,
    moho::CUnitAttackTargetTask* const value
  )
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitAttackTargetTaskType());
    return outRef;
  }
} // namespace gpg
