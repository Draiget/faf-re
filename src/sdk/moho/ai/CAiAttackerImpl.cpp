// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/EAiAttackerEvent.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/misc/Listener.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptObject.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/CSimConCommand.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"
#include "lua/LuaObject.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/Vector.h"

#include <cmath>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>

using namespace moho;

namespace moho
{
  struct WeaponExtraRefSubobject
  {
    std::uint8_t pad_00[0x64];
    std::int32_t extraValue; // +0x64 (subobject-relative payload word)
  };

  static_assert(
    offsetof(WeaponExtraRefSubobject, extraValue) == 0x64,
    "WeaponExtraRefSubobject::extraValue offset must be 0x64"
  );

  int cfunc_CAiAttackerImplGetUnit(lua_State* luaState);
  int cfunc_CAiAttackerImplGetUnitL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplAttackerWeaponsBusy(lua_State* luaState);
  int cfunc_CAiAttackerImplAttackerWeaponsBusyL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplGetWeaponCount(lua_State* luaState);
  int cfunc_CAiAttackerImplGetWeaponCountL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplSetDesiredTarget(lua_State* luaState);
  int cfunc_CAiAttackerImplSetDesiredTargetL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplGetDesiredTarget(lua_State* luaState);
  int cfunc_CAiAttackerImplGetDesiredTargetL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplStop(lua_State* luaState);
  int cfunc_CAiAttackerImplStopL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplCanAttackTarget(lua_State* luaState);
  int cfunc_CAiAttackerImplCanAttackTargetL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplFindBestEnemy(lua_State* luaState);
  int cfunc_CAiAttackerImplFindBestEnemyL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplGetTargetWeapon(lua_State* luaState);
  int cfunc_CAiAttackerImplGetTargetWeaponL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplGetPrimaryWeapon(lua_State* luaState);
  int cfunc_CAiAttackerImplGetPrimaryWeaponL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplGetMaxWeaponRange(lua_State* luaState);
  int cfunc_CAiAttackerImplGetMaxWeaponRangeL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplIsTooClose(lua_State* luaState);
  int cfunc_CAiAttackerImplIsTooCloseL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplIsWithinAttackRange(lua_State* luaState);
  int cfunc_CAiAttackerImplIsWithinAttackRangeL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplIsTargetExempt(lua_State* luaState);
  int cfunc_CAiAttackerImplIsTargetExemptL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplHasSlavedTarget(lua_State* luaState);
  int cfunc_CAiAttackerImplHasSlavedTargetL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplResetReportingState(lua_State* luaState);
  int cfunc_CAiAttackerImplResetReportingStateL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplForceEngage(lua_State* luaState);
  int cfunc_CAiAttackerImplForceEngageL(LuaPlus::LuaState* state);

  bool AI_TestForTerrainBlockage(
    const Unit* unit,
    const Wm3::Vector3f& targetPosition,
    ERuleBPUnitWeaponBallisticArc ballisticArc
  );
} // namespace moho

namespace
{
  constexpr const char* kAiAttackerImplLuaClassName = "CAiAttackerImpl";
  constexpr const char* kAiAttackerImplGetUnitName = "GetUnit";
  constexpr const char* kAiAttackerImplGetUnitHelpText = "Returns the unit this attacker is bound to.";
  constexpr const char* kAiAttackerImplAttackerWeaponsBusyName = "AttackerWeaponsBusy";
  constexpr const char* kAiAttackerImplAttackerWeaponsBusyHelpText =
    "Returns if the attacker has any weapon that is currently attacking any enemies";
  constexpr const char* kAiAttackerImplGetWeaponCountName = "GetWeaponCount";
  constexpr const char* kAiAttackerImplGetWeaponCountHelpText = "Return the count of weapons";
  constexpr const char* kAiAttackerImplSetDesiredTargetName = "SetDesiredTarget";
  constexpr const char* kAiAttackerImplSetDesiredTargetHelpText = "Set the desired target";
  constexpr const char* kAiAttackerImplGetDesiredTargetName = "GetDesiredTarget";
  constexpr const char* kAiAttackerImplGetDesiredTargetHelpText = "Get the desired target";
  constexpr const char* kAiAttackerImplStopName = "Stop";
  constexpr const char* kAiAttackerImplStopHelpText = "Stop the attacker";
  constexpr const char* kAiAttackerImplCanAttackTargetName = "CanAttackTarget";
  constexpr const char* kAiAttackerImplCanAttackTargetHelpText =
    "Loop through the weapons to see if the target can be attacked";
  constexpr const char* kAiAttackerImplFindBestEnemyName = "FindBestEnemy";
  constexpr const char* kAiAttackerImplFindBestEnemyHelpText = "Find the best enemy target for a weapon";
  constexpr const char* kAiAttackerImplGetTargetWeaponName = "GetTargetWeapon";
  constexpr const char* kAiAttackerImplGetTargetWeaponHelpText =
    "Loop through the weapons to find one that we can use to attack target";
  constexpr const char* kAiAttackerImplGetPrimaryWeaponName = "GetPrimaryWeapon";
  constexpr const char* kAiAttackerImplGetPrimaryWeaponHelpText =
    "Loop through the weapons to find our primary weapon";
  constexpr const char* kAiAttackerImplGetMaxWeaponRangeName = "GetMaxWeaponRange";
  constexpr const char* kAiAttackerImplGetMaxWeaponRangeHelpText =
    "Loop through the weapons to find the weapon with the longest range that is not manual fire";
  constexpr const char* kAiAttackerImplIsTooCloseName = "IsTooClose";
  constexpr const char* kAiAttackerImplIsTooCloseHelpText = "Check if the target is too close to our weapons";
  constexpr const char* kAiAttackerImplIsWithinAttackRangeName = "IsWithinAttackRange";
  constexpr const char* kAiAttackerImplIsWithinAttackRangeHelpText =
    "Check if the target is within any weapon range";
  constexpr const char* kAiAttackerImplIsTargetExemptName = "IsTargetExempt";
  constexpr const char* kAiAttackerImplIsTargetExemptHelpText = "Check if the target is exempt from being attacked";
  constexpr const char* kAiAttackerImplHasSlavedTargetName = "HasSlavedTarget";
  constexpr const char* kAiAttackerImplHasSlavedTargetHelpText =
    "Check if the attack has a slaved weapon that currently has a target";
  constexpr const char* kAiAttackerImplResetReportingStateName = "ResetReportingState";
  constexpr const char* kAiAttackerImplResetReportingStateHelpText = "Reset reporting state";
  constexpr const char* kAiAttackerImplForceEngageName = "ForceEngage";
  constexpr const char* kAiAttackerImplForceEngageHelpText = "Force to engage enemy target";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";

  constexpr std::int32_t kExtraDataMissingValue = static_cast<std::int32_t>(0xF0000000u);
  constexpr EAiAttackerEvent kAiAttackerEventCannotTarget = static_cast<EAiAttackerEvent>(0x8);
  constexpr EAiAttackerEvent kAiAttackerEventCanTarget = static_cast<EAiAttackerEvent>(0x9);
  constexpr const char* kEngineerCategoryName = "ENGINEER";
  constexpr const char* kWeaponTerrainBlockageConVarName = "WeaponTerrainBlockageTest";
  constexpr std::array<float, 4> kBallisticArcHeightFactors{
    0.70700002f,
    0.29300001f,
    -0.29300001f,
    -0.70700002f,
  };
  constexpr float kDegreesToRadians = 0.017453292f;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCAiAttackerImplIndex = 0;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59A00 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F599F0 = nullptr;

  struct WeaponEmitterEntryView
  {
    std::uint8_t pad_00[0xA8];
    std::int32_t extraKey; // +0xA8
    std::uint8_t pad_AC[0x24];
    WeaponExtraRefSubobject* extraRef; // +0xD0 (secondary-subobject pointer)
  };
  static_assert(
    offsetof(WeaponEmitterEntryView, extraKey) == 0xA8, "WeaponEmitterEntryView::extraKey offset must be 0xA8"
  );
  static_assert(
    offsetof(WeaponEmitterEntryView, extraRef) == 0xD0, "WeaponEmitterEntryView::extraRef offset must be 0xD0"
  );

  struct CAiAttackerImplRuntimeView
  {
    std::uint8_t pad_00[0x40];
    Unit* mUnit;                                   // +0x40
    CTaskStage mStage;                             // +0x44
    msvc8::vector<UnitWeapon*> mWeapons;           // +0x58
    WeakPtr<CTaskThread> mThread;                  // +0x68
    msvc8::vector<CAcquireTargetTask*> mTasks;     // +0x70
    CAiTarget mDesiredTarget;       // +0x80
    EAiAttackerEvent mReportingState; // +0xA0
  };

  static_assert(offsetof(CAiAttackerImplRuntimeView, mUnit) == 0x40, "CAiAttackerImpl::mUnit offset must be 0x40");
  static_assert(offsetof(CAiAttackerImplRuntimeView, mStage) == 0x44, "CAiAttackerImpl::mStage offset must be 0x44");
  static_assert(
    offsetof(CAiAttackerImplRuntimeView, mWeapons) == 0x58, "CAiAttackerImpl::mWeapons offset must be 0x58"
  );
  static_assert(
    offsetof(CAiAttackerImplRuntimeView, mThread) == 0x68, "CAiAttackerImpl::mThread offset must be 0x68"
  );
  static_assert(
    offsetof(CAiAttackerImplRuntimeView, mTasks) == 0x70, "CAiAttackerImpl::mTasks offset must be 0x70"
  );
  static_assert(
    offsetof(CAiAttackerImplRuntimeView, mDesiredTarget) == 0x80,
    "CAiAttackerImpl::mDesiredTarget offset must be 0x80"
  );
  static_assert(
    offsetof(CAiAttackerImplRuntimeView, mReportingState) == 0xA0,
    "CAiAttackerImpl::mReportingState offset must be 0xA0"
  );
  static_assert(sizeof(CAiAttackerImplRuntimeView) == 0xA4, "CAiAttackerImpl runtime view size must be 0xA4");

  [[nodiscard]] CAiAttackerImplRuntimeView* AsRuntimeView(CAiAttackerImpl* const object) noexcept
  {
    return reinterpret_cast<CAiAttackerImplRuntimeView*>(object);
  }

  [[nodiscard]] const CAiAttackerImplRuntimeView* AsRuntimeView(const CAiAttackerImpl* const object) noexcept
  {
    return reinterpret_cast<const CAiAttackerImplRuntimeView*>(object);
  }

  [[nodiscard]] IAiAttacker* AsAiAttackerBase(CAiAttackerImpl* const object) noexcept
  {
    return reinterpret_cast<IAiAttacker*>(object);
  }

  [[nodiscard]] const IAiAttacker* AsAiAttackerBase(const CAiAttackerImpl* const object) noexcept
  {
    return reinterpret_cast<const IAiAttacker*>(object);
  }

  [[nodiscard]] CScriptObject* AsScriptObjectBase(CAiAttackerImpl* const object) noexcept
  {
    return reinterpret_cast<CScriptObject*>(reinterpret_cast<std::uint8_t*>(object) + 0x0C);
  }

  struct ProjectileImpactBroadcasterRuntimeView
  {
    std::uint8_t pad_00[0x270];
    WeakPtr<void> mImpactBroadcaster; // +0x270
  };

  static_assert(
    offsetof(ProjectileImpactBroadcasterRuntimeView, mImpactBroadcaster) == 0x270,
    "Projectile impact broadcaster offset must be 0x270"
  );

  enum class WeaponTargetRangeStatus : std::int32_t
  {
    Available = 0,
    InsideMinRange = 1,
    NoSolution = 2,
    OutsideMaxRange = 3,
  };

  [[nodiscard]] float NormalizeAngleRadians(float angleRadians) noexcept
  {
    constexpr float kPi = 3.14159265358979323846f;
    constexpr float kTwoPi = 6.28318530717958647692f;

    float normalized = std::fmod(angleRadians + kPi, kTwoPi);
    if (normalized < 0.0f) {
      normalized += kTwoPi;
    }
    return normalized - kPi;
  }

  [[nodiscard]] WeaponTargetRangeStatus EvaluateWeaponTargetSolutionStatusGun(
    UnitWeapon* const weapon, const Wm3::Vector3f& targetPos, float* const inOutDistanceSq
  )
  {
    if (weapon == nullptr || weapon->mUnit == nullptr) {
      return WeaponTargetRangeStatus::NoSolution;
    }

    float distSq = 0.0f;
    if (inOutDistanceSq != nullptr && *inOutDistanceSq > 0.0f) {
      distSq = *inOutDistanceSq;
    } else {
      const Wm3::Vector3f& unitPos = weapon->mUnit->GetPosition();
      const float dx = targetPos.x - unitPos.x;
      const float dz = targetPos.z - unitPos.z;
      distSq = (dx * dx) + (dz * dz);
    }

    if (const RUnitBlueprintWeapon* const blueprint = weapon->mAttributes.mBlueprint; blueprint != nullptr) {
      if (weapon->mAttributes.mMaxRadiusSq < 0.0f) {
        weapon->mAttributes.mMaxRadiusSq = blueprint->MaxRadius * blueprint->MaxRadius;
      }
      if (weapon->mAttributes.mMinRadiusSq < 0.0f) {
        weapon->mAttributes.mMinRadiusSq = blueprint->MinRadius * blueprint->MinRadius;
      }
    }

    if (distSq > weapon->mAttributes.mMaxRadiusSq) {
      return WeaponTargetRangeStatus::OutsideMaxRange;
    }
    if (weapon->mAttributes.mMinRadiusSq >= distSq) {
      return WeaponTargetRangeStatus::InsideMinRange;
    }

    float maxHeightDiff = weapon->mAttributes.mMaxHeightDiff;
    if (maxHeightDiff < 0.0f && weapon->mAttributes.mBlueprint != nullptr) {
      maxHeightDiff = weapon->mAttributes.mBlueprint->MaxHeightDiff;
    }
    if (std::fabs(targetPos.y - weapon->mUnit->GetPosition().y) > maxHeightDiff) {
      return WeaponTargetRangeStatus::OutsideMaxRange;
    }

    if (weapon->mWeaponBlueprint != nullptr && weapon->mWeaponBlueprint->HeadingArcRange < 180.0f) {
      Wm3::Vector3f muzzlePos = weapon->mUnit->GetPosition();
      if (weapon->mBone >= 0) {
        muzzlePos = weapon->mUnit->GetBoneWorldTransform(weapon->mBone).pos_;
      }

      const float targetHeading = std::atan2(targetPos.x - muzzlePos.x, targetPos.z - muzzlePos.z);
      const Wm3::Vector3f unitForward = weapon->mUnit->GetTransform().orient_.Rotate(Wm3::Vector3f{0.0f, 0.0f, 1.0f});
      const float unitHeading = std::atan2(unitForward.x, unitForward.z);
      const float arcCenterRadians = weapon->mWeaponBlueprint->HeadingArcCenter * kDegreesToRadians;
      const float arcRangeRadians = weapon->mWeaponBlueprint->HeadingArcRange * kDegreesToRadians;
      const float headingDelta = NormalizeAngleRadians(targetHeading - unitHeading - arcCenterRadians);

      if (std::fabs(headingDelta) > arcRangeRadians) {
        return WeaponTargetRangeStatus::NoSolution;
      }
    }

    if (inOutDistanceSq != nullptr) {
      *inOutDistanceSq = distSq;
    }
    return WeaponTargetRangeStatus::Available;
  }

  [[nodiscard]] WeaponTargetRangeStatus ResolveWeaponTargetRangeStatus(UnitWeapon* const weapon, CAiTarget* const target)
  {
    if (weapon == nullptr || target == nullptr) {
      return WeaponTargetRangeStatus::OutsideMaxRange;
    }

    const Wm3::Vector3f targetPos = target->GetTargetPosGun(true);
    return EvaluateWeaponTargetSolutionStatusGun(weapon, targetPos, nullptr);
  }

  [[nodiscard]] bool CanWeaponPickEntityTarget(UnitWeapon* const weapon, Entity* const targetEntity)
  {
    if (weapon == nullptr || targetEntity == nullptr) {
      return false;
    }

    CAiTarget target{};
    target.UpdateTarget(targetEntity);
    return UnitWeapon::CanAttackTarget(&target, weapon);
  }

  [[nodiscard]] CAiTarget BuildClearedTarget()
  {
    CAiTarget target{};
    target.targetType = EAiTargetType::AITARGET_None;
    target.targetEntity.ownerLinkSlot = nullptr;
    target.targetEntity.nextInOwner = nullptr;
    target.targetPoint = -1;
    target.targetIsMobile = false;
    return target;
  }

  [[nodiscard]] CSimConVarBase* FindSimConVarByName(const char* const name)
  {
    if (name == nullptr || *name == '\0') {
      return nullptr;
    }

    CSimConCommand* const command = moho::FindRegisteredSimConCommand(name);
    return dynamic_cast<CSimConVarBase*>(command);
  }

  [[nodiscard]] bool ReadSimConVarBoolByName(Sim* const sim, const char* const name, const bool defaultValue)
  {
    if (sim == nullptr) {
      return defaultValue;
    }

    CSimConVarBase* const conVar = FindSimConVarByName(name);
    if (conVar == nullptr) {
      return defaultValue;
    }

    CSimConVarInstanceBase* const instance = sim->GetSimVar(conVar);
    if (instance == nullptr) {
      return defaultValue;
    }

    const void* const valueStorage = instance->GetValueStorage();
    if (valueStorage == nullptr) {
      return defaultValue;
    }

    return *static_cast<const bool*>(valueStorage);
  }

  [[nodiscard]] bool SegmentIntersectsTerrain(
    const STIMap* const mapData,
    const Wm3::Vector3f& startPosition,
    const Wm3::Vector3f& endPosition
  )
  {
    if (mapData == nullptr || mapData->mHeightField == nullptr) {
      return false;
    }

    Wm3::Vector3f direction{
      endPosition.x - startPosition.x,
      endPosition.y - startPosition.y,
      endPosition.z - startPosition.z,
    };
    const float length = Wm3::Vector3f::Normalize(&direction);
    if (length <= 0.0f) {
      return false;
    }

    GeomLine3 line{};
    line.pos = startPosition;
    line.dir = direction;
    line.closest = 0.0f;
    line.farthest = length;

    CGeomHitResult hit{};
    const Wm3::Vector3f intersection = mapData->mHeightField->Intersection(line, &hit);
    return Wm3::Vector3fIsntNaN(&intersection) && hit.distance <= length;
  }

  void AttachTaskToStage(CTask* const task, CTaskStage* const stage, const bool owning)
  {
    if (task == nullptr || stage == nullptr || task->mOwnerThread != nullptr) {
      return;
    }

    CTaskThread* const thread = new CTaskThread(stage);
    if (thread == nullptr) {
      return;
    }

    task->mAutoDelete = owning;
    task->mOwnerThread = thread;
    task->mSubtask = thread->mTaskTop;
    thread->mTaskTop = task;
  }

  /**
   * Address: 0x005D9520 (FUN_005D9520, helper for CAcquireTargetTask scheduling)
   *
   * What it does:
   * Updates acquire-target task pending-frame countdown and unstages its thread
   * when schedule changes require immediate processing.
   */
  void RefreshAcquireTargetTaskScheduling(CAcquireTargetTask* const task)
  {
    if (task == nullptr || task->mWeapon == nullptr) {
      return;
    }

    int pendingFrames = 0;
    CAiTarget* const desiredTarget =
      (task->mAttacker != nullptr) ? task->mAttacker->GetDesiredTarget() : nullptr;

    if (desiredTarget != nullptr && desiredTarget->targetType == EAiTargetType::AITARGET_None) {
      if (task->mWeapon->mWeaponBlueprint != nullptr && task->mWeapon->mWeaponBlueprint->NeedPrep != 0u) {
        pendingFrames = 2;
      } else {
        const float checkInterval =
          (task->mWeapon->mWeaponBlueprint != nullptr) ? task->mWeapon->mWeaponBlueprint->TargetCheckInterval : 0.0f;
        const int roundedFrames = static_cast<int>(std::ceil(checkInterval * 10.0f));
        pendingFrames = (roundedFrames > 1) ? roundedFrames : 1;
      }
    }

    CTaskThread* const ownerThread = task->mOwnerThread;
    if (ownerThread == nullptr) {
      return;
    }

    ownerThread->mPendingFrames = pendingFrames;
    if (ownerThread->mStaged) {
      ownerThread->Unstage();
    }
  }

  template <class TBroadcaster, class TListener>
  void BindManyToOneListener(TBroadcaster* const broadcaster, TListener* const listener) noexcept
  {
    if (broadcaster == nullptr) {
      return;
    }

    auto& weakLink = reinterpret_cast<WeakPtr<void>&>(*broadcaster);
    const void* const ownerLinkSlot = (listener != nullptr)
                                        ? reinterpret_cast<const void*>(
                                            reinterpret_cast<std::uintptr_t>(listener) + WeakPtr<void>::kOwnerLinkOffset
                                          )
                                        : nullptr;
    weakLink.ResetFromOwnerLinkSlot(const_cast<void*>(ownerLinkSlot));
  }

  [[nodiscard]] CAcquireTargetTask*
  FindAcquireTaskForWeapon(msvc8::vector<CAcquireTargetTask*>& tasks, UnitWeapon* const weapon) noexcept
  {
    for (CAcquireTargetTask* const task : tasks) {
      if (task != nullptr && task->mWeapon == weapon) {
        return task;
      }
    }
    return nullptr;
  }

  [[nodiscard]] Listener<EAiAttackerEvent>* ListenerFromBroadcasterLink(Broadcaster* const node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    auto* const bytePtr = reinterpret_cast<std::uint8_t*>(node);
    return reinterpret_cast<Listener<EAiAttackerEvent>*>(bytePtr - offsetof(Listener<EAiAttackerEvent>, mListenerLink));
  }

  /**
   * Address: 0x005DB480 (FUN_005DB480, broadcaster dispatch helper)
   *
   * What it does:
   * Dispatches one attacker event to current listeners while preserving
   * iteration safety for listeners that relink/unlink during callbacks.
   */
  void BroadcastAiAttackerEvent(CAiAttackerImpl* const attacker, const EAiAttackerEvent event)
  {
    if (attacker == nullptr) {
      return;
    }

    Broadcaster& broadcaster = AsAiAttackerBase(attacker)->mListeners;
    Broadcaster detached{};

    if (broadcaster.mPrev == &broadcaster) {
      return;
    }

    detached.mPrev = broadcaster.mPrev;
    detached.mNext = broadcaster.mNext;
    detached.mNext->mPrev = &detached;
    detached.mPrev->mNext = &detached;
    broadcaster.mPrev = &broadcaster;
    broadcaster.mNext = &broadcaster;

    while (detached.mPrev != &detached) {
      Broadcaster* const listenerLink = static_cast<Broadcaster*>(detached.mPrev);
      listenerLink->ListLinkAfter(&broadcaster);

      if (Listener<EAiAttackerEvent>* const listener = ListenerFromBroadcasterLink(listenerLink); listener != nullptr) {
        listener->OnEvent(event);
      }
    }

    detached.mNext->mPrev = detached.mPrev;
    detached.mPrev->mNext = detached.mNext;
  }

  template <CScrLuaInitForm* (*Target)()>
  [[nodiscard]] CScrLuaInitForm* ForwardAiAttackerLuaThunk() noexcept
  {
    return Target();
  }

  template <std::int32_t* TargetIndex>
  int RegisterRecoveredFactoryIndex() noexcept
  {
    const int index = moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    *TargetIndex = index;
    return index;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  void RequireLuaArgCount(LuaPlus::LuaState* const state, const char* const helpText, const int expectedArgs)
  {
    if (!state || !state->m_state) {
      return;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != expectedArgs) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, helpText, expectedArgs, argumentCount);
    }
  }

  [[nodiscard]] CAiAttackerImpl* ResolveAiAttackerLuaSelf(LuaPlus::LuaState* const state, const char* const helpText)
  {
    if (!state || !state->m_state) {
      return nullptr;
    }

    RequireLuaArgCount(state, helpText, 1);
    const LuaPlus::LuaObject selfObject(LuaPlus::LuaStackObject(state, 1));
    return SCR_FromLua_CAiAttackerImpl(selfObject, state);
  }

  [[nodiscard]] CAiAttackerImpl*
  ResolveAiAttackerLuaSelfWithTargetArg(LuaPlus::LuaState* const state, const char* const helpText, CAiTarget& outTarget)
  {
    if (!state || !state->m_state) {
      return nullptr;
    }

    RequireLuaArgCount(state, helpText, 2);
    const LuaPlus::LuaObject selfObject(LuaPlus::LuaStackObject(state, 1));
    CAiAttackerImpl* const attacker = SCR_FromLua_CAiAttackerImpl(selfObject, state);
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    SCR_FromLuaCopy_CAiTarget(outTarget, targetObject);
    return attacker;
  }

  struct CAiAttackerImplLuaFunctionThunksBootstrap
  {
    CAiAttackerImplLuaFunctionThunksBootstrap()
    {
      (void)moho::register_CAiAttackerImplLuaInitFormAnchor();
      (void)moho::register_CAiAttackerImplGetUnit_LuaFuncDef();
      (void)moho::register_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef();
      (void)moho::register_CAiAttackerImplGetWeaponCount_LuaFuncDef();
      (void)moho::register_CAiAttackerImplSetDesiredTarget_LuaFuncDef();
      (void)moho::register_CAiAttackerImplGetDesiredTarget_LuaFuncDef();
      (void)moho::register_CAiAttackerImplStop_LuaFuncDef();
      (void)moho::register_CAiAttackerImplCanAttackTarget_LuaFuncDef();
      (void)moho::register_CAiAttackerImplFindBestEnemy_LuaFuncDef();
      (void)moho::register_CAiAttackerImplGetTargetWeapon_LuaFuncDef();
      (void)moho::register_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef();
      (void)moho::register_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef();
      (void)moho::register_CAiAttackerImplIsWithinAttackRange_LuaFuncDef();
      (void)moho::register_CAiAttackerImplIsTooClose_LuaFuncDef();
      (void)moho::register_CAiAttackerImplIsTargetExempt_LuaFuncDef();
      (void)moho::register_CAiAttackerImplHasSlavedTarget_LuaFuncDef();
      (void)moho::register_CAiAttackerImplResetReportingState_LuaFuncDef();
      (void)moho::register_CAiAttackerImplForceEngage_LuaFuncDef();
      (void)moho::register_CScrLuaMetatableFactory_CAiAttackerImpl_Index();
    }
  };

  [[maybe_unused]] CAiAttackerImplLuaFunctionThunksBootstrap gCAiAttackerImplLuaFunctionThunksBootstrap;
} // namespace

bool CAiAttackerImpl::TryGetWeaponExtraData(const int index, WeaponExtraData& out) const
{
  out.key = 0;
  out.ref = nullptr;

  if (index < 0) {
    return false;
  }

  auto* self = const_cast<CAiAttackerImpl*>(this);
  if (!self) {
    return false;
  }

  const int count = self->GetWeaponCount();
  if (index >= count) {
    return false;
  }

  const void* rawWeapon = self->GetWeapon(index);
  if (!rawWeapon) {
    return false;
  }

  const auto* entry = reinterpret_cast<const WeaponEmitterEntryView*>(rawWeapon);
  out.key = entry->extraKey;
  out.ref = entry->extraRef;
  return true;
}

std::int32_t CAiAttackerImpl::ReadExtraDataValue(const WeaponExtraRefSubobject* const ref)
{
  if (!ref) {
    return kExtraDataMissingValue;
  }

  return ref->extraValue;
}

/**
 * Address: 0x005D6D30 (FUN_005D6D30, Moho::CAiAttackerImpl::WeaponsOnDestroy)
 *
 * What it does:
 * Broadcasts `OnDestroy` to each live weapon script-object lane.
 */
void CAiAttackerImpl::WeaponsOnDestroy()
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  for (UnitWeapon* const weapon : view->mWeapons) {
    if (weapon) {
      (void)weapon->RunScript("OnDestroy");
    }
  }
}

/**
 * Address: 0x005D5D60 (FUN_005D5D60, Moho::CAiAttackerImpl::GetUnit)
 *
 * What it does:
 * Returns the owning attacker unit pointer lane.
 */
Unit* CAiAttackerImpl::GetUnit()
{
  return AsRuntimeView(this)->mUnit;
}

/**
 * Address: 0x005D6D80 (FUN_005D6D80, Moho::CAiAttackerImpl::WeaponsBusy)
 *
 * What it does:
 * Reports whether any weapon currently carries a non-empty target type.
 */
bool CAiAttackerImpl::WeaponsBusy()
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  for (const UnitWeapon* const weapon : view->mWeapons) {
    if (weapon && weapon->mTarget.targetType != EAiTargetType::AITARGET_None) {
      return true;
    }
  }
  return false;
}

/**
 * Address: 0x005D5D80 (FUN_005D5D80, Moho::CAiAttackerImpl::GetTaskStage)
 *
 * What it does:
 * Returns the embedded task-stage lane used by attacker worker tasks.
 */
CTaskStage* CAiAttackerImpl::GetTaskStage()
{
  return &AsRuntimeView(this)->mStage;
}

/**
 * Address: 0x005D76E0 (FUN_005D76E0, Moho::CAiAttackerImpl::CreateWeapon)
 *
 * What it does:
 * Allocates one weapon for this attacker, binds task threads for fire/target
 * control, and stores the weapon/task lanes into attacker-owned vectors.
 */
UnitWeapon* CAiAttackerImpl::CreateWeapon(RUnitBlueprintWeapon* const weaponBlueprint)
{
  CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  const int weaponIndex = static_cast<int>(view->mWeapons.size());

  UnitWeapon* weapon = static_cast<UnitWeapon*>(::operator new(sizeof(UnitWeapon), std::nothrow));
  if (weapon != nullptr) {
    weapon = new (weapon) UnitWeapon(this, weaponBlueprint, weaponIndex);
  }

  view->mWeapons.push_back(weapon);

  if (weaponBlueprint->ManualFire == 0u) {
    CAcquireTargetTask* const task = new CAcquireTargetTask(weapon, this);
    AttachTaskToStage(task, &view->mStage, false);
    view->mTasks.push_back(task);
  }

  view->mUnit->NeedSyncGameData = true;

  return weapon;
}

/**
 * Address: 0x005D5D90 (FUN_005D5D90, Moho::CAiAttackerImpl::GetWeaponCount)
 *
 * What it does:
 * Returns the current attacker weapon vector length.
 */
int CAiAttackerImpl::GetWeaponCount()
{
  return static_cast<int>(AsRuntimeView(this)->mWeapons.size());
}

/**
 * Address: 0x005D77D0 (FUN_005D77D0, Moho::CAiAttackerImpl::GetWeapon)
 *
 * What it does:
 * Returns one attacker weapon by index and raises fatal error for invalid
 * index lanes.
 */
UnitWeapon* CAiAttackerImpl::GetWeapon(const int index)
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  const unsigned int weaponCount = static_cast<unsigned int>(view->mWeapons.size());
  const unsigned int weaponIndex = static_cast<unsigned int>(index);
  if (weaponIndex >= weaponCount) {
    gpg::Die("Invalid weapon index %i passed to AttackerGetWeaponByIndex.", index);
    return nullptr;
  }

  return view->mWeapons[static_cast<std::size_t>(weaponIndex)];
}

/**
 * Address: 0x005D75B0 (FUN_005D75B0, Moho::CAiAttackerImpl::SetDesiredTarget)
 *
 * What it does:
 * Stores desired-target state, clears per-weapon active targets, refreshes
 * acquire-task scheduling, and emits `CannotTarget` when state was previously set.
 */
void CAiAttackerImpl::SetDesiredTarget(CAiTarget* const target)
{
  CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  view->mDesiredTarget = (target != nullptr) ? *target : BuildClearedTarget();

  const CAiTarget clearedTarget = BuildClearedTarget();
  const bool hasDesiredTarget = (target != nullptr) && target->HasTarget();

  for (UnitWeapon* const weapon : view->mWeapons) {
    if (weapon == nullptr) {
      continue;
    }

    weapon->mTarget = clearedTarget;

    if (weapon->mWeaponBlueprint != nullptr && weapon->mWeaponBlueprint->NeedPrep != 0u && hasDesiredTarget) {
      weapon->NotifyOnGotTarget();
    }
  }

  for (CAcquireTargetTask* const task : view->mTasks) {
    RefreshAcquireTargetTaskScheduling(task);
  }

  if (view->mReportingState != static_cast<EAiAttackerEvent>(0)) {
    view->mReportingState = kAiAttackerEventCannotTarget;
    BroadcastAiAttackerEvent(this, kAiAttackerEventCannotTarget);
  }
}

/**
 * Address: 0x005D5D70 (FUN_005D5D70, Moho::CAiAttackerImpl::GetDesiredTarget)
 *
 * What it does:
 * Returns the owned desired-target payload lane.
 */
CAiTarget* CAiAttackerImpl::GetDesiredTarget()
{
  return &AsRuntimeView(this)->mDesiredTarget;
}

/**
 * Address: 0x005D7570 (FUN_005D7570, Moho::CAiAttackerImpl::OnWeaponHaltFire)
 *
 * What it does:
 * Broadcasts `OnHaltFire` to each live weapon script-object lane.
 */
void CAiAttackerImpl::OnWeaponHaltFire()
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  for (UnitWeapon* const weapon : view->mWeapons) {
    if (weapon) {
      (void)weapon->RunScript("OnHaltFire");
    }
  }
}

/**
 * Address: 0x005D6FA0 (FUN_005D6FA0, Moho::CAiAttackerImpl::CanAttackTarget)
 *
 * What it does:
 * Returns true when any owned weapon can attack the provided target payload.
 */
bool CAiAttackerImpl::CanAttackTarget(CAiTarget* const target)
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (!view->mUnit || view->mUnit->IsBeingBuilt()) {
    return false;
  }

  for (UnitWeapon* const weapon : view->mWeapons) {
    if (UnitWeapon::CanAttackTarget(target, weapon)) {
      return true;
    }
  }

  return false;
}

/**
 * Address: 0x005D6F40 (FUN_005D6F40, Moho::CAiAttackerImpl::PickTarget)
 *
 * What it does:
 * Tests one entity against each owned weapon's target-point eligibility and
 * returns true when any weapon can pick that target.
 */
bool CAiAttackerImpl::PickTarget(Entity* const targetEntity)
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (targetEntity == nullptr || !view->mUnit || view->mUnit->IsBeingBuilt()) {
    return false;
  }

  for (UnitWeapon* const weapon : view->mWeapons) {
    if (CanWeaponPickEntityTarget(weapon, targetEntity)) {
      return true;
    }
  }

  return false;
}

/**
 * Address: 0x005D6490 (FUN_005D6490, Moho::AI_TestForTerrainBlockage)
 *
 * What it does:
 * Tests direct or ballistic quarter-segment lanes from the firing unit to
 * `targetPosition` against terrain-heightfield intersections.
 */
bool moho::AI_TestForTerrainBlockage(
  const Unit* const unit,
  const Wm3::Vector3f& targetPosition,
  const ERuleBPUnitWeaponBallisticArc ballisticArc
)
{
  if (unit == nullptr || unit->mCurrentLayer == LAYER_Air || unit->SimulationRef == nullptr) {
    return false;
  }

  const STIMap* const mapData = unit->SimulationRef->mMapData;
  if (mapData == nullptr || mapData->mHeightField == nullptr) {
    return false;
  }

  Wm3::Vector3f unitTop = unit->GetPosition();
  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  const float sizeZ = (blueprint != nullptr) ? blueprint->mSizeZ : 0.0f;
  unitTop.y = (sizeZ * 2.0f) + unitTop.y;

  Wm3::Vector3f adjustedTarget = targetPosition;
  adjustedTarget.y += 0.25f;

  if (ballisticArc == RULEUBA_None) {
    return SegmentIntersectsTerrain(mapData, unitTop, adjustedTarget);
  }

  const Wm3::Vector3f quarterDelta{
    (adjustedTarget.x - unitTop.x) * 0.25f,
    (adjustedTarget.y - unitTop.y) * 0.25f,
    (adjustedTarget.z - unitTop.z) * 0.25f,
  };

  const float quarterDistance = Wm3::Vector3f::Length(quarterDelta);
  Wm3::Vector3f previousPos = unitTop;

  for (const float arcFactor : kBallisticArcHeightFactors) {
    Wm3::Vector3f currentPos{
      previousPos.x + quarterDelta.x,
      previousPos.y + quarterDelta.y,
      previousPos.z + quarterDelta.z,
    };

    const float arcScale = (ballisticArc == RULEUBA_LowArc) ? 0.5f : 2.0f;
    currentPos.y += arcFactor * quarterDistance * arcScale;

    if (SegmentIntersectsTerrain(mapData, previousPos, currentPos)) {
      return true;
    }

    previousPos = currentPos;
  }

  return false;
}

/**
 * Address: 0x005D7A10 (FUN_005D7A10, Moho::CAiAttackerImpl::FindBestEnemy)
 *
 * What it does:
 * Scores candidate enemy entities in `entities` and returns the highest
 * priority/closest eligible target for `weapon`.
 */
Entity* CAiAttackerImpl::FindBestEnemy(
  UnitWeapon* const weapon,
  gpg::core::FastVectorN<SWeakRefSlot, 20>* const entities,
  const float range,
  const bool use3DDistance
)
{
  if (weapon == nullptr || entities == nullptr || entities->begin() == entities->end()) {
    return nullptr;
  }

  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  Unit* const unit = view->mUnit;
  if (unit == nullptr || unit->ArmyRef == nullptr || unit->SimulationRef == nullptr || unit->SimulationRef->mRules == nullptr) {
    return nullptr;
  }

  CArmyImpl* const army = unit->ArmyRef;
  const Wm3::Vector3f unitPosition = unit->GetPosition();
  const Wm3::Vector3f weaponForward = UnitWeapon::GetForwardVector(weapon);

  const auto* const benignRange = unit->SimulationRef->mRules->GetEntityCategory("BENIGN");
  const auto* const benignCategory = reinterpret_cast<const EntityCategorySet*>(benignRange);

  const bool tryTerrainBlockage =
    ReadSimConVarBoolByName(unit->SimulationRef, kWeaponTerrainBlockageConVarName, false);
  const float maxRangeSq = range * range;

  Entity* bestEntity = nullptr;
  float bestDistance = std::numeric_limits<float>::infinity();
  WeaponTargetRangeStatus bestSolution = WeaponTargetRangeStatus::OutsideMaxRange;
  std::uint32_t bestCategory = 9999u;

  for (const SWeakRefSlot& slot : *entities) {
    std::uint32_t closestSeenCategory = 9999u;
    Entity* const candidate = slot.ResolveObjectPtr<Entity>();
    if (candidate == nullptr || candidate->Dead != 0u || candidate->DestroyQueuedFlag != 0u) {
      continue;
    }

    ReconBlip* reconBlip = candidate->IsReconBlip();
    if (reconBlip == nullptr) {
      Unit* const candidateUnit = candidate->IsUnit();
      if (candidateUnit == nullptr) {
        continue;
      }

      CAiReconDBImpl* const reconDb = army->GetReconDB();
      reconBlip = (reconDb != nullptr) ? reconDb->ReconGetBlip(candidateUnit) : nullptr;
    }
    if (reconBlip == nullptr) {
      continue;
    }

    const Wm3::Vector3f candidatePosition = candidate->Position;
    const float xDistance = unitPosition.x - candidatePosition.x;
    const float zDistance = unitPosition.z - candidatePosition.z;
    float distanceSq = (xDistance * xDistance) + (zDistance * zDistance);
    if (distanceSq > maxRangeSq) {
      continue;
    }

    const std::uint32_t candidateArmyId = (candidate->ArmyRef != nullptr)
                                            ? static_cast<std::uint32_t>(candidate->ArmyRef->ArmyId)
                                            : static_cast<std::uint32_t>(-1);
    if (!army->IsEnemy(candidateArmyId)) {
      continue;
    }

    const REntityBlueprint* const candidateBlueprint = candidate->BluePrint;
    if (candidateBlueprint == nullptr) {
      continue;
    }

    if (benignCategory != nullptr && EntityCategory::HasBlueprint(candidateBlueprint, benignCategory)) {
      continue;
    }

    const bool isAirLayer = candidate->mCurrentLayer == LAYER_Air;
    const bool isBeingBuilt = candidate->IsBeingBuilt();
    if ((candidate->mAttachInfo.GetAttachTargetEntity() != nullptr && (isAirLayer || isBeingBuilt))
        || (isAirLayer && isBeingBuilt)) {
      continue;
    }

    if (UnitWeapon::IsEntityBlacklisted(weapon, candidate) || IsTargetExempt(candidate)) {
      continue;
    }

    if (Unit* const candidateUnit = candidate->IsUnit();
        candidateUnit != nullptr && candidateUnit->IsUnitState(UNITSTATE_DoNotTarget)) {
      continue;
    }

    if (!isAirLayer) {
      const STIMap* const candidateMap = (candidate->SimulationRef != nullptr) ? candidate->SimulationRef->mMapData : nullptr;
      if (candidateMap == nullptr) {
        continue;
      }

      const gpg::Rect2i& playableRect = candidateMap->mPlayableRect;
      if (candidatePosition.x < static_cast<float>(playableRect.x0)
          || candidatePosition.z < static_cast<float>(playableRect.z0)
          || candidatePosition.x > static_cast<float>(playableRect.x1)
          || candidatePosition.z > static_cast<float>(playableRect.z1)) {
        continue;
      }
    }

    if (!CanWeaponPickEntityTarget(weapon, candidate)) {
      continue;
    }

    const WeaponTargetRangeStatus solutionStatus =
      EvaluateWeaponTargetSolutionStatusGun(weapon, candidatePosition, &distanceSq);
    if ((solutionStatus == WeaponTargetRangeStatus::InsideMinRange || solutionStatus == WeaponTargetRangeStatus::NoSolution)
        && (!unit->IsMobile()
            || weapon->mWeaponBlueprint == nullptr
            || (weapon->mWeaponBlueprint->AutoInitiateAttackCommand == 0u
                && weapon->mWeaponBlueprint->SlavedToBody == 0u))) {
      continue;
    }

    if (tryTerrainBlockage && weapon->mWeaponBlueprint != nullptr
        && moho::AI_TestForTerrainBlockage(unit, candidatePosition, weapon->mWeaponBlueprint->BallisticArc)) {
      continue;
    }

    if (const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
        unitBlueprint != nullptr && unitBlueprint->AI.NeedUnpack != 0u
        && solutionStatus != WeaponTargetRangeStatus::Available) {
      continue;
    }

    float usedDistance = distanceSq;
    if (use3DDistance) {
      Wm3::Vector3f toTarget{
        xDistance,
        unitPosition.y - candidatePosition.y,
        zDistance,
      };
      Wm3::Vector3f::Normalize(&toTarget);
      usedDistance = Wm3::Vector3f::Dot(toTarget, weaponForward);
    }

    if (solutionStatus != WeaponTargetRangeStatus::Available
        && weapon->mWeaponBlueprint != nullptr
        && weapon->mWeaponBlueprint->AutoInitiateAttackCommand == 0u) {
      if (use3DDistance) {
        usedDistance += 4.0f;
      } else {
        usedDistance *= 4.0f;
      }
    }

    const bool seenEver =
      (static_cast<std::uint32_t>(reconBlip->GetFlags(army)) & static_cast<std::uint32_t>(RECON_LOSEver)) != 0u;
    Entity* const currentTarget = weapon->mTarget.targetEntity.GetObjectPtr();

    const std::size_t priorityCount = weapon->mTargetPriorities.size();
    for (std::size_t categoryIndex = 0; categoryIndex < priorityCount; ++categoryIndex) {
      const std::uint32_t categoryLane = static_cast<std::uint32_t>(categoryIndex);

      if (categoryLane > bestCategory
          || (solutionStatus > bestSolution && bestEntity != nullptr)) {
        break;
      }

      if (!EntityCategory::HasBlueprint(candidateBlueprint, &weapon->mTargetPriorities[categoryIndex])) {
        continue;
      }

      if (seenEver) {
        closestSeenCategory = categoryLane;
      }

      bool shouldSetBest = false;
      if (bestCategory > closestSeenCategory) {
        shouldSetBest = true;
      } else if (currentTarget != nullptr) {
        const bool shouldSkip =
          currentTarget == bestEntity || (bestDistance <= usedDistance && currentTarget != candidate);
        shouldSetBest = !shouldSkip;
      } else {
        shouldSetBest = bestDistance > usedDistance;
      }

      if (shouldSetBest) {
        bestDistance = usedDistance;
        bestEntity = candidate;
        bestSolution = solutionStatus;
        bestCategory = closestSeenCategory;
      }
    }
  }

  return bestEntity;
}

/**
 * Address: 0x005D6DC0 (FUN_005D6DC0, Moho::CAiAttackerImpl::GetTargetWeapon)
 *
 * What it does:
 * Returns the first weapon that can attack the provided target payload.
 */
UnitWeapon* CAiAttackerImpl::GetTargetWeapon(CAiTarget* const target)
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (!view->mUnit || view->mUnit->IsBeingBuilt()) {
    return nullptr;
  }

  for (UnitWeapon* const weapon : view->mWeapons) {
    if (UnitWeapon::CanAttackTarget(target, weapon)) {
      return weapon;
    }
  }

  return nullptr;
}

/**
 * Address: 0x005D6E30 (FUN_005D6E30, Moho::CAiAttackerImpl::GetPrimaryWeapon)
 *
 * What it does:
 * Returns the first non-null weapon with stable weapon index `0`.
 */
UnitWeapon* CAiAttackerImpl::GetPrimaryWeapon()
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (!view->mUnit || view->mUnit->IsBeingBuilt()) {
    return nullptr;
  }

  for (UnitWeapon* const weapon : view->mWeapons) {
    if (weapon && weapon->mWeaponIndex == 0) {
      return weapon;
    }
  }

  return nullptr;
}

/**
 * Address: 0x005D6E80 (FUN_005D6E80, Moho::CAiAttackerImpl::GetMaxWeaponRange)
 *
 * What it does:
 * Scans enabled non-manual-fire weapons and returns the max of direct radius
 * and tracking-radius-adjusted range lanes.
 */
float CAiAttackerImpl::GetMaxWeaponRange()
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (!view->mUnit || view->mUnit->IsBeingBuilt()) {
    return 0.0f;
  }

  float maxRange = 0.0f;
  for (UnitWeapon* const weapon : view->mWeapons) {
    if (!weapon || weapon->mEnabled == 0u) {
      continue;
    }

    const RUnitBlueprintWeapon* const weaponBlueprint = weapon->mWeaponBlueprint;
    if (weaponBlueprint && weaponBlueprint->ManualFire != 0u) {
      continue;
    }

    float weaponRange = weapon->mAttributes.mMaxRadius;
    if (weaponRange < 0.0f && weapon->mAttributes.mBlueprint) {
      weaponRange = weapon->mAttributes.mBlueprint->MaxRadius;
    }

    if (weaponRange > maxRange) {
      maxRange = weaponRange;
    }

    if (weaponBlueprint) {
      const float trackingRange = weaponBlueprint->TrackingRadius * weaponRange;
      if (trackingRange > maxRange) {
        maxRange = trackingRange;
      }
    }
  }

  return maxRange;
}

/**
 * Address: 0x005D7190 (FUN_005D7190, Moho::CAiAttackerImpl::VectorIsWithinWeaponAttackRange)
 *
 * What it does:
 * Checks XZ-plane range against one weapon's cached max-radius-squared lane.
 */
bool CAiAttackerImpl::VectorIsWithinWeaponAttackRange(UnitWeapon* const weapon, const Wm3::Vector3f* const targetPos)
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (!view->mUnit || view->mUnit->IsBeingBuilt() || !weapon || !targetPos) {
    return false;
  }

  const Wm3::Vector3f& unitPos = view->mUnit->GetPosition();
  const float dx = unitPos.x - targetPos->x;
  const float dz = unitPos.z - targetPos->z;
  const float distSq = (dz * dz) + (dx * dx);

  if (weapon->mAttributes.mBlueprint && weapon->mAttributes.mMaxRadiusSq < 0.0f) {
    weapon->mAttributes.mMaxRadiusSq = weapon->mAttributes.mBlueprint->MaxRadius * weapon->mAttributes.mBlueprint->MaxRadius;
  }

  return distSq <= weapon->mAttributes.mMaxRadiusSq;
}

/**
 * Address: 0x005D70E0 (FUN_005D70E0, Moho::CAiAttackerImpl::VectorIsWithinAttackRange)
 *
 * What it does:
 * Checks whether any enabled weapon covers the provided XZ-plane position.
 */
bool CAiAttackerImpl::VectorIsWithinAttackRange(const Wm3::Vector3f* const targetPos)
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (!view->mUnit || view->mUnit->IsBeingBuilt() || !targetPos) {
    return false;
  }

  const Wm3::Vector3f& unitPos = view->mUnit->GetPosition();
  const float dx = unitPos.x - targetPos->x;
  const float dz = unitPos.z - targetPos->z;
  const float distSq = (dz * dz) + (dx * dx);

  for (UnitWeapon* const weapon : view->mWeapons) {
    if (!weapon || weapon->mEnabled == 0u) {
      continue;
    }

    if (weapon->mAttributes.mBlueprint && weapon->mAttributes.mMaxRadiusSq < 0.0f) {
      weapon->mAttributes.mMaxRadiusSq = weapon->mAttributes.mBlueprint->MaxRadius * weapon->mAttributes.mBlueprint->MaxRadius;
    }

    if (weapon->mAttributes.mMaxRadiusSq > distSq) {
      return true;
    }
  }

  return false;
}

/**
 * Address: 0x005D7090 (FUN_005D7090, Moho::CAiAttackerImpl::TargetIsWithinWeaponAttackRange)
 *
 * What it does:
 * Validates one target against one weapon and returns true only when the
 * weapon can attack and target solution status is `Available`.
 */
bool CAiAttackerImpl::TargetIsWithinWeaponAttackRange(UnitWeapon* const weapon, CAiTarget* const target)
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (!view->mUnit || view->mUnit->IsBeingBuilt() || weapon == nullptr || target == nullptr || weapon->mEnabled == 0u) {
    return false;
  }

  if (!UnitWeapon::CanAttackTarget(target, weapon)) {
    return false;
  }

  return ResolveWeaponTargetRangeStatus(weapon, target) == WeaponTargetRangeStatus::Available;
}

/**
 * Address: 0x005D7000 (FUN_005D7000, Moho::CAiAttackerImpl::TargetIsWithinAttackRange)
 *
 * What it does:
 * Returns true when any enabled weapon can attack the target and reports an
 * available firing solution.
 */
bool CAiAttackerImpl::TargetIsWithinAttackRange(CAiTarget* const target)
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (!view->mUnit || view->mUnit->IsBeingBuilt() || target == nullptr) {
    return false;
  }

  for (UnitWeapon* const weapon : view->mWeapons) {
    if (weapon == nullptr || weapon->mEnabled == 0u) {
      continue;
    }

    if (UnitWeapon::CanAttackTarget(target, weapon)
        && ResolveWeaponTargetRangeStatus(weapon, target) == WeaponTargetRangeStatus::Available) {
      return true;
    }
  }

  return false;
}

/**
 * Address: 0x005D7210 (FUN_005D7210, Moho::CAiAttackerImpl::IsTooClose)
 *
 * What it does:
 * Reports whether the target is in the min-range-only lane for all eligible
 * weapons while no enabled eligible weapon has an available solution.
 */
bool CAiAttackerImpl::IsTooClose(CAiTarget* const target)
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (!view->mUnit || view->mUnit->IsBeingBuilt() || target == nullptr) {
    return false;
  }

  bool isTooClose = false;
  for (UnitWeapon* const weapon : view->mWeapons) {
    if (weapon == nullptr || !UnitWeapon::CanAttackTarget(target, weapon)) {
      continue;
    }

    const WeaponTargetRangeStatus status = ResolveWeaponTargetRangeStatus(weapon, target);
    if (status == WeaponTargetRangeStatus::Available) {
      if (weapon->mEnabled != 0u) {
        return false;
      }
    } else if (status == WeaponTargetRangeStatus::InsideMinRange) {
      isTooClose = true;
    }
  }

  return isTooClose;
}

/**
 * Address: 0x005D7340 (FUN_005D7340, Moho::CAiAttackerImpl::IsTargetExempt)
 *
 * What it does:
 * Exempts targets currently used by reclaim/capture commands or targets in
 * `UNITSTATE_BeingCaptured` that are focused by live engineer units.
 */
bool CAiAttackerImpl::IsTargetExempt(Entity* const target)
{
  if (target == nullptr) {
    return false;
  }

  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  Unit* const ownerUnit = view->mUnit;
  if (ownerUnit != nullptr && ownerUnit->CommandQueue != nullptr) {
    const msvc8::vector<WeakPtr<CUnitCommand>> commandSnapshot = ownerUnit->CommandQueue->mCommandVec;
    for (const WeakPtr<CUnitCommand>& weakCommand : commandSnapshot) {
      CUnitCommand* const command = weakCommand.GetObjectPtr();
      if (command == nullptr) {
        continue;
      }

      const EUnitCommandType commandType = command->mVarDat.mCmdType;
      if (commandType != EUnitCommandType::UNITCOMMAND_Reclaim
          && commandType != EUnitCommandType::UNITCOMMAND_Capture) {
        continue;
      }

      if (command->mTarget.GetEntity() == target) {
        return true;
      }
    }
  }

  Unit* const targetUnit = target->IsUnit();
  if (targetUnit == nullptr || !targetUnit->IsUnitState(UNITSTATE_BeingCaptured)) {
    return false;
  }
  if (ownerUnit == nullptr || ownerUnit->ArmyRef == nullptr || ownerUnit->SimulationRef == nullptr
      || ownerUnit->SimulationRef->mRules == nullptr) {
    return false;
  }

  const auto* const engineerCategory = ownerUnit->SimulationRef->mRules->GetEntityCategory(kEngineerCategoryName);
  if (engineerCategory == nullptr) {
    return false;
  }

  SEntitySetTemplateUnit engineerUnits{};
  ownerUnit->ArmyRef->GetUnits(&engineerUnits, const_cast<void*>(static_cast<const void*>(engineerCategory)));
  for (Entity* const* it = engineerUnits.mVec.begin(); it != engineerUnits.mVec.end(); ++it) {
    Unit* const engineer = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (engineer == nullptr || engineer->IsDead() || engineer->DestroyQueued()) {
      continue;
    }

    if (engineer->FocusEntityRef.ResolveObjectPtr<Entity>() == target) {
      return true;
    }
  }

  return false;
}

/**
 * Address: 0x005D72B0 (FUN_005D72B0, Moho::CAiAttackerImpl::HasSlavedTarget)
 *
 * What it does:
 * Returns the first slaved-weapon target and optionally outputs that weapon.
 */
CAiTarget* CAiAttackerImpl::HasSlavedTarget(UnitWeapon** const outWeapon)
{
  const CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (outWeapon) {
    *outWeapon = nullptr;
  }

  for (UnitWeapon* const weapon : view->mWeapons) {
    if (!weapon || !weapon->mTarget.HasTarget()) {
      continue;
    }

    const RUnitBlueprintWeapon* const weaponBlueprint = weapon->mWeaponBlueprint;
    if (weaponBlueprint && weaponBlueprint->SlavedToBody != 0u) {
      if (outWeapon) {
        *outWeapon = weapon;
      }
      return &weapon->mTarget;
    }
  }

  return nullptr;
}

/**
 * Address: 0x005D5DB0 (FUN_005D5DB0, Moho::CAiAttackerImpl::ResetReportingState)
 *
 * What it does:
 * Clears attacker reporting-state flags to the zero/default lane.
 */
void CAiAttackerImpl::ResetReportingState()
{
  AsRuntimeView(this)->mReportingState = static_cast<EAiAttackerEvent>(0);
}

/**
 * Address: 0x005D7800 (FUN_005D7800, Moho::CAiAttackerImpl::TransmitProjectileImpactEvent)
 *
 * What it does:
 * Finds the acquire-target task for `weapon` and binds projectile impact
 * broadcaster ownership to that task's projectile-impact listener lane.
 */
void CAiAttackerImpl::TransmitProjectileImpactEvent(UnitWeapon* const weapon, Projectile* const projectile)
{
  CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  CAcquireTargetTask* const task = FindAcquireTaskForWeapon(view->mTasks, weapon);
  if (projectile == nullptr) {
    return;
  }

  auto* const projectileView = reinterpret_cast<ProjectileImpactBroadcasterRuntimeView*>(projectile);
  auto* const listener = (task != nullptr) ? static_cast<ManyToOneListener_EProjectileImpactEvent*>(task) : nullptr;
  BindManyToOneListener(&projectileView->mImpactBroadcaster, listener);
}

/**
 * Address: 0x005D7870 (FUN_005D7870, Moho::CAiAttackerImpl::TransmitBeamImpactEvent)
 *
 * What it does:
 * Finds the acquire-target task for `weapon` and binds collision-beam
 * broadcaster ownership to that task's collision-beam listener lane.
 */
void CAiAttackerImpl::TransmitBeamImpactEvent(UnitWeapon* const weapon, CollisionBeamEntity* const beam)
{
  CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  CAcquireTargetTask* const task = FindAcquireTaskForWeapon(view->mTasks, weapon);
  if (beam == nullptr) {
    return;
  }

  auto* const listener = (task != nullptr) ? static_cast<ManyToOneListener_ECollisionBeamEvent*>(task) : nullptr;
  BindManyToOneListener(&beam->mListener, listener);
}

/**
 * Address: 0x005D8650 (FUN_005D8650, Moho::CAiAttackerImpl::ForceEngage)
 *
 * What it does:
 * Sets unit focus entity, dispatches script callback for resolved focus,
 * marks sync-dirty focus state, and notifies attacker listeners of can-target.
 */
void CAiAttackerImpl::ForceEngage(Entity* const target)
{
  CAiAttackerImplRuntimeView* const view = AsRuntimeView(this);
  if (view->mUnit == nullptr) {
    return;
  }

  view->mUnit->FocusEntityRef.ResetObjectPtr<Entity>(target);
  if (view->mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
    (void)view->mUnit->RunScript("OnAssignedFocusEntity");
  }

  view->mUnit->NeedSyncGameData = true;
  BroadcastAiAttackerEvent(this, kAiAttackerEventCanTarget);
}

/**
 * Address: 0x005D5DC0 (FUN_005D5DC0, Moho::CAiAttackerImpl::PushStack)
 *
 * What it does:
 * Pushes this attacker's Lua object wrapper onto the provided Lua stack.
 */
void CAiAttackerImpl::PushStack(LuaPlus::LuaState* const luaState)
{
  if (luaState == nullptr) {
    return;
  }

  AsScriptObjectBase(this)->mLuaObj.PushStack(luaState);
}

/**
 * Address: 0x005D56F0 (FUN_005D56F0, CAiAttackerImpl::Stop)
 *
 * What it does:
 * Applies one "clear target" payload through `SetDesiredTarget` and unlinks
 * the temporary weak-target node produced by the setter lane.
 */
void CAiAttackerImpl::Stop()
{
  CAiTarget stopTarget{};
  std::memset(&stopTarget, 0, 0x0C);
  stopTarget.targetPoint = -1;
  stopTarget.targetIsMobile = false;
  SetDesiredTarget(&stopTarget);
  stopTarget.targetEntity.UnlinkFromOwnerChain();
}

/**
 * Address: 0x005D9930 (FUN_005D9930, cfunc_CAiAttackerImplGetUnit)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplGetUnitL`.
 */
int moho::cfunc_CAiAttackerImplGetUnit(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplGetUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005D99B0 (FUN_005D99B0, cfunc_CAiAttackerImplGetUnitL)
 *
 * What it does:
 * Resolves attacker self and pushes the bound `Unit` Lua object.
 */
int moho::cfunc_CAiAttackerImplGetUnitL(LuaPlus::LuaState* const state)
{
  CAiAttackerImpl* const attacker = ResolveAiAttackerLuaSelf(state, kAiAttackerImplGetUnitHelpText);
  if (!attacker) {
    return 0;
  }

  Unit* const unit = attacker->GetUnit();
  unit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x005D9A70 (FUN_005D9A70, cfunc_CAiAttackerImplAttackerWeaponsBusy)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplAttackerWeaponsBusyL`.
 */
int moho::cfunc_CAiAttackerImplAttackerWeaponsBusy(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplAttackerWeaponsBusyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005D9AF0 (FUN_005D9AF0, cfunc_CAiAttackerImplAttackerWeaponsBusyL)
 *
 * What it does:
 * Resolves attacker self and returns whether any attacker weapon is busy.
 */
int moho::cfunc_CAiAttackerImplAttackerWeaponsBusyL(LuaPlus::LuaState* const state)
{
  CAiAttackerImpl* const attacker = ResolveAiAttackerLuaSelf(state, kAiAttackerImplAttackerWeaponsBusyHelpText);
  if (!attacker || !state || !state->m_state) {
    return 0;
  }

  lua_pushboolean(state->m_state, attacker->WeaponsBusy() ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x005D9BB0 (FUN_005D9BB0, cfunc_CAiAttackerImplGetWeaponCount)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplGetWeaponCountL`.
 */
int moho::cfunc_CAiAttackerImplGetWeaponCount(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplGetWeaponCountL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005D9C30 (FUN_005D9C30, cfunc_CAiAttackerImplGetWeaponCountL)
 *
 * What it does:
 * Resolves attacker self and pushes weapon-count as Lua number.
 */
int moho::cfunc_CAiAttackerImplGetWeaponCountL(LuaPlus::LuaState* const state)
{
  CAiAttackerImpl* const attacker = ResolveAiAttackerLuaSelf(state, kAiAttackerImplGetWeaponCountHelpText);
  if (!attacker || !state || !state->m_state) {
    return 0;
  }

  lua_pushnumber(state->m_state, static_cast<float>(attacker->GetWeaponCount()));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x005D9D00 (FUN_005D9D00, cfunc_CAiAttackerImplSetDesiredTarget)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplSetDesiredTargetL`.
 */
int moho::cfunc_CAiAttackerImplSetDesiredTarget(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplSetDesiredTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005D9D80 (FUN_005D9D80, cfunc_CAiAttackerImplSetDesiredTargetL)
 *
 * What it does:
 * Resolves `(attacker, target)` and applies desired-target state.
 */
int moho::cfunc_CAiAttackerImplSetDesiredTargetL(LuaPlus::LuaState* const state)
{
  CAiTarget target{};
  CAiAttackerImpl* const attacker =
    ResolveAiAttackerLuaSelfWithTargetArg(state, kAiAttackerImplSetDesiredTargetHelpText, target);
  if (!attacker) {
    return 0;
  }

  attacker->SetDesiredTarget(&target);
  target.targetEntity.UnlinkFromOwnerChain();
  return 0;
}

/**
 * Address: 0x005D9EA0 (FUN_005D9EA0, cfunc_CAiAttackerImplGetDesiredTarget)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplGetDesiredTargetL`.
 */
int moho::cfunc_CAiAttackerImplGetDesiredTarget(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplGetDesiredTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005D9F20 (FUN_005D9F20, cfunc_CAiAttackerImplGetDesiredTargetL)
 *
 * What it does:
 * Resolves attacker self and pushes current desired target as Lua object.
 */
int moho::cfunc_CAiAttackerImplGetDesiredTargetL(LuaPlus::LuaState* const state)
{
  CAiAttackerImpl* const attacker = ResolveAiAttackerLuaSelf(state, kAiAttackerImplGetDesiredTargetHelpText);
  if (!attacker) {
    return 0;
  }

  LuaPlus::LuaObject targetObject;
  SCR_ToLua_CAiTarget(targetObject, state, *attacker->GetDesiredTarget());
  targetObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x005DA000 (FUN_005DA000, cfunc_CAiAttackerImplStop)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplStopL`.
 */
int moho::cfunc_CAiAttackerImplStop(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplStopL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DA080 (FUN_005DA080, cfunc_CAiAttackerImplStopL)
 *
 * What it does:
 * Resolves attacker self and applies `CAiAttackerImpl::Stop()`.
 */
int moho::cfunc_CAiAttackerImplStopL(LuaPlus::LuaState* const state)
{
  CAiAttackerImpl* const attacker = ResolveAiAttackerLuaSelf(state, kAiAttackerImplStopHelpText);
  if (!attacker) {
    return 0;
  }

  attacker->Stop();
  return 0;
}

/**
 * Address: 0x005DA130 (FUN_005DA130, cfunc_CAiAttackerImplCanAttackTarget)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplCanAttackTargetL`.
 */
int moho::cfunc_CAiAttackerImplCanAttackTarget(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplCanAttackTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DA1B0 (FUN_005DA1B0, cfunc_CAiAttackerImplCanAttackTargetL)
 *
 * What it does:
 * Resolves `(attacker, target)` and returns attack-eligibility as Lua bool.
 */
int moho::cfunc_CAiAttackerImplCanAttackTargetL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CAiTarget target{};
  CAiAttackerImpl* const attacker =
    ResolveAiAttackerLuaSelfWithTargetArg(state, kAiAttackerImplCanAttackTargetHelpText, target);
  if (!attacker) {
    return 0;
  }

  lua_pushboolean(state->m_state, attacker->CanAttackTarget(&target) ? 1 : 0);
  (void)lua_gettop(state->m_state);
  target.targetEntity.UnlinkFromOwnerChain();
  return 1;
}

/**
 * Address: 0x005DA2E0 (FUN_005DA2E0, cfunc_CAiAttackerImplFindBestEnemy)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplFindBestEnemyL`.
 */
int moho::cfunc_CAiAttackerImplFindBestEnemy(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplFindBestEnemyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DA360 (FUN_005DA360, cfunc_CAiAttackerImplFindBestEnemyL)
 *
 * What it does:
 * Resolves `(attacker, maxRange)`, queries best enemy from primary weapon,
 * and pushes resulting entity Lua object when found.
 */
int moho::cfunc_CAiAttackerImplFindBestEnemyL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  RequireLuaArgCount(state, kAiAttackerImplFindBestEnemyHelpText, 2);
  const LuaPlus::LuaObject selfObject(LuaPlus::LuaStackObject(state, 1));
  CAiAttackerImpl* const attacker = SCR_FromLua_CAiAttackerImpl(selfObject, state);
  if (!attacker) {
    return 0;
  }

  UnitWeapon* const primaryWeapon = attacker->GetPrimaryWeapon();
  if (!primaryWeapon) {
    return 1;
  }

  lua_State* const rawState = state->m_state;
  LuaPlus::LuaStackObject maxRangeObject(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&maxRangeObject, "number");
  }

  const float maxRange = static_cast<float>(lua_tonumber(rawState, 2));
  Unit* const unit = attacker->GetUnit();
  Entity* const bestEnemy = attacker->FindBestEnemy(primaryWeapon, &unit->mBlipsInRange, maxRange, false);
  if (bestEnemy) {
    bestEnemy->mLuaObj.PushStack(state);
  }

  return 1;
}

/**
 * Address: 0x005DA490 (FUN_005DA490, cfunc_CAiAttackerImplGetTargetWeapon)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplGetTargetWeaponL`.
 */
int moho::cfunc_CAiAttackerImplGetTargetWeapon(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplGetTargetWeaponL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DA510 (FUN_005DA510, cfunc_CAiAttackerImplGetTargetWeaponL)
 *
 * What it does:
 * Resolves `(attacker, target)` and pushes target-weapon index when available.
 */
int moho::cfunc_CAiAttackerImplGetTargetWeaponL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CAiTarget target{};
  CAiAttackerImpl* const attacker =
    ResolveAiAttackerLuaSelfWithTargetArg(state, kAiAttackerImplGetTargetWeaponHelpText, target);
  if (!attacker) {
    return 0;
  }

  UnitWeapon* const weapon = attacker->GetTargetWeapon(&target);
  target.targetEntity.UnlinkFromOwnerChain();
  if (weapon) {
    lua_pushnumber(state->m_state, static_cast<float>(weapon->mWeaponIndex));
    (void)lua_gettop(state->m_state);
  }
  return 1;
}

/**
 * Address: 0x005DA650 (FUN_005DA650, cfunc_CAiAttackerImplGetPrimaryWeapon)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplGetPrimaryWeaponL`.
 */
int moho::cfunc_CAiAttackerImplGetPrimaryWeapon(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplGetPrimaryWeaponL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DA6D0 (FUN_005DA6D0, cfunc_CAiAttackerImplGetPrimaryWeaponL)
 *
 * What it does:
 * Resolves attacker self and pushes primary-weapon index when available.
 */
int moho::cfunc_CAiAttackerImplGetPrimaryWeaponL(LuaPlus::LuaState* const state)
{
  CAiAttackerImpl* const attacker = ResolveAiAttackerLuaSelf(state, kAiAttackerImplGetPrimaryWeaponHelpText);
  if (!attacker || !state || !state->m_state) {
    return 0;
  }

  UnitWeapon* const weapon = attacker->GetPrimaryWeapon();
  if (weapon) {
    lua_pushnumber(state->m_state, static_cast<float>(weapon->mWeaponIndex));
    (void)lua_gettop(state->m_state);
  }
  return 1;
}

/**
 * Address: 0x005DA7A0 (FUN_005DA7A0, cfunc_CAiAttackerImplGetMaxWeaponRange)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplGetMaxWeaponRangeL`.
 */
int moho::cfunc_CAiAttackerImplGetMaxWeaponRange(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplGetMaxWeaponRangeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DA820 (FUN_005DA820, cfunc_CAiAttackerImplGetMaxWeaponRangeL)
 *
 * What it does:
 * Resolves attacker self and pushes max weapon range as Lua number.
 */
int moho::cfunc_CAiAttackerImplGetMaxWeaponRangeL(LuaPlus::LuaState* const state)
{
  CAiAttackerImpl* const attacker = ResolveAiAttackerLuaSelf(state, kAiAttackerImplGetMaxWeaponRangeHelpText);
  if (!attacker || !state || !state->m_state) {
    return 0;
  }

  lua_pushnumber(state->m_state, attacker->GetMaxWeaponRange());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x005DA8E0 (FUN_005DA8E0, cfunc_CAiAttackerImplIsWithinAttackRange)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplIsWithinAttackRangeL`.
 */
int moho::cfunc_CAiAttackerImplIsWithinAttackRange(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplIsWithinAttackRangeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DA960 (FUN_005DA960, cfunc_CAiAttackerImplIsWithinAttackRangeL)
 *
 * What it does:
 * Resolves `(attacker[, weaponIndex], target)` and returns whether the target
 * (either a CAiTarget table or a Vector3 world position) is within the
 * attacker's weapon range. When `weaponIndex` is supplied the check is
 * performed against that specific weapon; otherwise against any weapon.
 */
int moho::cfunc_CAiAttackerImplIsWithinAttackRangeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kAiAttackerImplIsWithinAttackRangeHelpText,
      2,
      3,
      argumentCount
    );
  }

  const LuaPlus::LuaObject selfObject(LuaPlus::LuaStackObject(state, 1));
  CAiAttackerImpl* const attacker = SCR_FromLua_CAiAttackerImpl(selfObject, state);
  if (!attacker) {
    return 0;
  }

  bool result = false;
  if (argumentCount == 3) {
    LuaPlus::LuaStackObject weaponIndexObject(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&weaponIndexObject, "integer");
    }
    const int weaponIndex = static_cast<int>(lua_tonumber(rawState, 2));
    UnitWeapon* const weapon = attacker->GetWeapon(weaponIndex);
    if (!weapon) {
      LuaPlus::LuaState::Error(state, "Unable to find weapon %i", weaponIndex);
    }

    lua_pushstring(rawState, "Type");
    lua_gettable(rawState, 3);
    const bool hasTypeField = lua_type(rawState, lua_gettop(rawState)) != LUA_TNIL;

    const LuaPlus::LuaObject argObject(LuaPlus::LuaStackObject(state, 3));
    if (hasTypeField) {
      CAiTarget target{};
      SCR_FromLuaCopy_CAiTarget(target, argObject);
      result = attacker->TargetIsWithinWeaponAttackRange(weapon, &target);
      target.targetEntity.UnlinkFromOwnerChain();
    } else {
      const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(argObject);
      result = attacker->VectorIsWithinWeaponAttackRange(weapon, &position);
    }
  } else {
    lua_pushstring(rawState, "Type");
    lua_gettable(rawState, 2);
    const bool hasTypeField = lua_type(rawState, lua_gettop(rawState)) != LUA_TNIL;

    const LuaPlus::LuaObject argObject(LuaPlus::LuaStackObject(state, 2));
    if (hasTypeField) {
      CAiTarget target{};
      SCR_FromLuaCopy_CAiTarget(target, argObject);
      result = attacker->TargetIsWithinAttackRange(&target);
      target.targetEntity.UnlinkFromOwnerChain();
    } else {
      const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(argObject);
      result = attacker->VectorIsWithinAttackRange(&position);
    }
  }

  lua_pushboolean(rawState, result ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005DA900 (FUN_005DA900, func_CAiAttackerImplIsWithinAttackRange_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:IsWithinAttackRange()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplIsWithinAttackRange_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplIsWithinAttackRangeName,
    &moho::cfunc_CAiAttackerImplIsWithinAttackRange,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplIsWithinAttackRangeHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DACE0 (FUN_005DACE0, cfunc_CAiAttackerImplIsTooClose)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplIsTooCloseL`.
 */
int moho::cfunc_CAiAttackerImplIsTooClose(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplIsTooCloseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DAD60 (FUN_005DAD60, cfunc_CAiAttackerImplIsTooCloseL)
 *
 * What it does:
 * Resolves `(attacker, target)` and returns close-range bool status.
 */
int moho::cfunc_CAiAttackerImplIsTooCloseL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CAiTarget target{};
  CAiAttackerImpl* const attacker = ResolveAiAttackerLuaSelfWithTargetArg(state, kAiAttackerImplIsTooCloseHelpText, target);
  if (!attacker) {
    return 0;
  }

  lua_pushboolean(state->m_state, attacker->IsTooClose(&target) ? 1 : 0);
  (void)lua_gettop(state->m_state);
  target.targetEntity.UnlinkFromOwnerChain();
  return 1;
}

/**
 * Address: 0x005D9950 (FUN_005D9950, func_CAiAttackerImplGetUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:GetUnit()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplGetUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplGetUnitName,
    &moho::cfunc_CAiAttackerImplGetUnit,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplGetUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x005D9A90 (FUN_005D9A90, func_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:AttackerWeaponsBusy()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplAttackerWeaponsBusyName,
    &moho::cfunc_CAiAttackerImplAttackerWeaponsBusy,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplAttackerWeaponsBusyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005D9BD0 (FUN_005D9BD0, func_CAiAttackerImplGetWeaponCount_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:GetWeaponCount()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplGetWeaponCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplGetWeaponCountName,
    &moho::cfunc_CAiAttackerImplGetWeaponCount,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplGetWeaponCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x005D9D20 (FUN_005D9D20, func_CAiAttackerImplSetDesiredTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:SetDesiredTarget()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplSetDesiredTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplSetDesiredTargetName,
    &moho::cfunc_CAiAttackerImplSetDesiredTarget,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplSetDesiredTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x005D9EC0 (FUN_005D9EC0, func_CAiAttackerImplGetDesiredTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:GetDesiredTarget()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplGetDesiredTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplGetDesiredTargetName,
    &moho::cfunc_CAiAttackerImplGetDesiredTarget,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplGetDesiredTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DA020 (FUN_005DA020, func_CAiAttackerImplStop_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:Stop()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplStop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplStopName,
    &moho::cfunc_CAiAttackerImplStop,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplStopHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DA150 (FUN_005DA150, func_CAiAttackerImplCanAttackTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:CanAttackTarget()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplCanAttackTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplCanAttackTargetName,
    &moho::cfunc_CAiAttackerImplCanAttackTarget,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplCanAttackTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DA300 (FUN_005DA300, func_CAiAttackerImplFindBestEnemy_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:FindBestEnemy()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplFindBestEnemy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplFindBestEnemyName,
    &moho::cfunc_CAiAttackerImplFindBestEnemy,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplFindBestEnemyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DA4B0 (FUN_005DA4B0, func_CAiAttackerImplGetTargetWeapon_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:GetTargetWeapon()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplGetTargetWeapon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplGetTargetWeaponName,
    &moho::cfunc_CAiAttackerImplGetTargetWeapon,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplGetTargetWeaponHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DA670 (FUN_005DA670, func_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:GetPrimaryWeapon()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplGetPrimaryWeaponName,
    &moho::cfunc_CAiAttackerImplGetPrimaryWeapon,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplGetPrimaryWeaponHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DA7C0 (FUN_005DA7C0, func_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:GetMaxWeaponRange()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplGetMaxWeaponRangeName,
    &moho::cfunc_CAiAttackerImplGetMaxWeaponRange,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplGetMaxWeaponRangeHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DAD00 (FUN_005DAD00, func_CAiAttackerImplIsTooClose_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:IsTooClose()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplIsTooClose_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplIsTooCloseName,
    &moho::cfunc_CAiAttackerImplIsTooClose,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplIsTooCloseHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DAF10 (FUN_005DAF10, cfunc_CAiAttackerImplIsTargetExemptL)
 *
 * What it does:
 * Reads attacker + target entity from Lua and returns attacker
 * `IsTargetExempt(...)` predicate result.
 */
int moho::cfunc_CAiAttackerImplIsTargetExemptL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiAttackerImplIsTargetExemptHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject attackerObject(LuaPlus::LuaStackObject(state, 1));
  CAiAttackerImpl* const attacker = SCR_FromLua_CAiAttackerImpl(attackerObject, state);
  const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const targetEntity = SCR_FromLua_Entity(targetObject, state);

  const bool isExempt = attacker->IsTargetExempt(targetEntity);
  lua_pushboolean(state->m_state, isExempt ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x005DAE90 (FUN_005DAE90, cfunc_CAiAttackerImplIsTargetExempt)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiAttackerImplIsTargetExemptL`.
 */
int moho::cfunc_CAiAttackerImplIsTargetExempt(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplIsTargetExemptL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DAEB0 (FUN_005DAEB0, func_CAiAttackerImplIsTargetExempt_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:IsTargetExempt()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplIsTargetExempt_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplIsTargetExemptName,
    &moho::cfunc_CAiAttackerImplIsTargetExempt,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplIsTargetExemptHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DB090 (FUN_005DB090, cfunc_CAiAttackerImplHasSlavedTargetL)
 *
 * What it does:
 * Resolves an attacker slaved-target pointer and pushes a serialized
 * `CAiTarget` Lua object or `nil` when no slaved target exists.
 */
int moho::cfunc_CAiAttackerImplHasSlavedTargetL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiAttackerImplHasSlavedTargetHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject attackerObject(LuaPlus::LuaStackObject(state, 1));
  CAiAttackerImpl* const attacker = SCR_FromLua_CAiAttackerImpl(attackerObject, state);

  UnitWeapon* slavedWeapon = nullptr;
  CAiTarget* const slavedTarget = attacker->HasSlavedTarget(&slavedWeapon);
  (void)slavedWeapon;
  if (slavedTarget) {
    LuaPlus::LuaObject targetObject;
    SCR_ToLua_CAiTarget(targetObject, state, *slavedTarget);
    targetObject.PushStack(state);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }
  return 1;
}

/**
 * Address: 0x005DB010 (FUN_005DB010, cfunc_CAiAttackerImplHasSlavedTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiAttackerImplHasSlavedTargetL`.
 */
int moho::cfunc_CAiAttackerImplHasSlavedTarget(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplHasSlavedTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DB030 (FUN_005DB030, func_CAiAttackerImplHasSlavedTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:HasSlavedTarget()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplHasSlavedTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplHasSlavedTargetName,
    &moho::cfunc_CAiAttackerImplHasSlavedTarget,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplHasSlavedTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DB220 (FUN_005DB220, cfunc_CAiAttackerImplResetReportingStateL)
 *
 * What it does:
 * Resolves attacker from Lua and dispatches `ResetReportingState()`.
 */
int moho::cfunc_CAiAttackerImplResetReportingStateL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(
      state, kLuaExpectedArgsWarning, kAiAttackerImplResetReportingStateHelpText, 1, argumentCount
    );
  }

  const LuaPlus::LuaObject attackerObject(LuaPlus::LuaStackObject(state, 1));
  CAiAttackerImpl* const attacker = SCR_FromLua_CAiAttackerImpl(attackerObject, state);
  attacker->ResetReportingState();
  return 0;
}

/**
 * Address: 0x005DB1A0 (FUN_005DB1A0, cfunc_CAiAttackerImplResetReportingState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiAttackerImplResetReportingStateL`.
 */
int moho::cfunc_CAiAttackerImplResetReportingState(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplResetReportingStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DB1C0 (FUN_005DB1C0, func_CAiAttackerImplResetReportingState_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:ResetReportingState()` into the sim Lua init
 * set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplResetReportingState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplResetReportingStateName,
    &moho::cfunc_CAiAttackerImplResetReportingState,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplResetReportingStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x005DB350 (FUN_005DB350, cfunc_CAiAttackerImplForceEngageL)
 *
 * What it does:
 * Resolves attacker + target entity and dispatches `ForceEngage(...)`.
 *
 * Note:
 * The original binary compares against expected arg count `1` while still
 * reading stack slot `2`; this recovery preserves that behavior.
 */
int moho::cfunc_CAiAttackerImplForceEngageL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiAttackerImplForceEngageHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject attackerObject(LuaPlus::LuaStackObject(state, 1));
  CAiAttackerImpl* const attacker = SCR_FromLua_CAiAttackerImpl(attackerObject, state);
  const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const targetEntity = SCR_FromLua_Entity(targetObject, state);
  attacker->ForceEngage(targetEntity);
  return 0;
}

/**
 * Address: 0x005DB2D0 (FUN_005DB2D0, cfunc_CAiAttackerImplForceEngage)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiAttackerImplForceEngageL`.
 */
int moho::cfunc_CAiAttackerImplForceEngage(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplForceEngageL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005DB2F0 (FUN_005DB2F0, func_CAiAttackerImplForceEngage_LuaFuncDef)
 *
 * What it does:
 * Publishes `CAiAttackerImpl:ForceEngage()` into the sim Lua init set.
 */
CScrLuaInitForm* moho::func_CAiAttackerImplForceEngage_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiAttackerImplForceEngageName,
    &moho::cfunc_CAiAttackerImplForceEngage,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiAttackerImplLuaClassName,
    kAiAttackerImplForceEngageHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BCE970 (FUN_00BCE970, register_CAiAttackerImplLuaInitFormAnchor)
 *
 * What it does:
 * Saves current `sim` Lua-init form head and re-links it to recovered
 * attacker-Lua anchor lane `off_F599F0`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplLuaInitFormAnchor()
{
  CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
  if (simSet == nullptr) {
    gRecoveredSimLuaInitFormPrev_off_F59A00 = nullptr;
    return nullptr;
  }

  CScrLuaInitForm* const previousHead = simSet->mForms;
  gRecoveredSimLuaInitFormPrev_off_F59A00 = previousHead;
  simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gRecoveredSimLuaInitFormAnchor_off_F599F0);
  return previousHead;
}

/**
 * Address: 0x00BCE990 (FUN_00BCE990, register_CAiAttackerImplGetUnit_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetUnit_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetUnit_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetUnit_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9A0 (FUN_00BCE9A0, register_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9B0 (FUN_00BCE9B0, register_CAiAttackerImplGetWeaponCount_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetWeaponCount_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetWeaponCount_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetWeaponCount_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9C0 (FUN_00BCE9C0, register_CAiAttackerImplSetDesiredTarget_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplSetDesiredTarget_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplSetDesiredTarget_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplSetDesiredTarget_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9D0 (FUN_00BCE9D0, register_CAiAttackerImplGetDesiredTarget_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetDesiredTarget_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetDesiredTarget_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetDesiredTarget_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9E0 (FUN_00BCE9E0, register_CAiAttackerImplStop_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplStop_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplStop_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplStop_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9F0 (FUN_00BCE9F0, register_CAiAttackerImplCanAttackTarget_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplCanAttackTarget_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplCanAttackTarget_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplCanAttackTarget_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA00 (FUN_00BCEA00, register_CAiAttackerImplFindBestEnemy_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplFindBestEnemy_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplFindBestEnemy_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplFindBestEnemy_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA10 (FUN_00BCEA10, register_CAiAttackerImplGetTargetWeapon_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetTargetWeapon_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetTargetWeapon_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetTargetWeapon_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA20 (FUN_00BCEA20, register_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA30 (FUN_00BCEA30, register_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA40 (FUN_00BCEA40, register_CAiAttackerImplIsWithinAttackRange_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplIsWithinAttackRange_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplIsWithinAttackRange_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplIsWithinAttackRange_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA50 (FUN_00BCEA50, register_CAiAttackerImplIsTooClose_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplIsTooClose_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplIsTooClose_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplIsTooClose_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA60 (FUN_00BCEA60, register_CAiAttackerImplIsTargetExempt_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplIsTargetExempt_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplIsTargetExempt_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplIsTargetExempt_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA70 (FUN_00BCEA70, register_CAiAttackerImplHasSlavedTarget_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplHasSlavedTarget_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplHasSlavedTarget_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplHasSlavedTarget_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA80 (FUN_00BCEA80, register_CAiAttackerImplResetReportingState_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplResetReportingState_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplResetReportingState_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplResetReportingState_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA90 (FUN_00BCEA90, register_CAiAttackerImplForceEngage_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplForceEngage_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplForceEngage_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplForceEngage_LuaFuncDef>();
}

/**
 * Address: 0x00BCEB20 (FUN_00BCEB20, register_CScrLuaMetatableFactory_CAiAttackerImpl_Index)
 *
 * What it does:
 * Allocates and stores the recovered startup Lua factory index lane for
 * `CScrLuaMetatableFactory<CAiAttackerImpl>`.
 */
int moho::register_CScrLuaMetatableFactory_CAiAttackerImpl_Index()
{
  return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCAiAttackerImplIndex>();
}
