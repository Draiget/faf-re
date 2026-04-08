// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/script/CScriptEvent.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "lua/LuaObject.h"

#include <cstddef>
#include <cstring>
#include <cstdint>

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
  int cfunc_CAiAttackerImplIsTargetExempt(lua_State* luaState);
  int cfunc_CAiAttackerImplIsTargetExemptL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplHasSlavedTarget(lua_State* luaState);
  int cfunc_CAiAttackerImplHasSlavedTargetL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplResetReportingState(lua_State* luaState);
  int cfunc_CAiAttackerImplResetReportingStateL(LuaPlus::LuaState* state);
  int cfunc_CAiAttackerImplForceEngage(lua_State* luaState);
  int cfunc_CAiAttackerImplForceEngageL(LuaPlus::LuaState* state);
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

  [[nodiscard]] moho::CScrLuaInitFormSet* FindSimLuaInitSet() noexcept
  {
    for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, "sim") == 0) {
        return set;
      }
    }

    return nullptr;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindSimLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
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
  return cfunc_CAiAttackerImplGetUnitL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplAttackerWeaponsBusyL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplGetWeaponCountL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplSetDesiredTargetL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplGetDesiredTargetL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplStopL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplCanAttackTargetL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplFindBestEnemyL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplGetTargetWeaponL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplGetPrimaryWeaponL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplGetMaxWeaponRangeL(ResolveBindingState(luaContext));
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
 * Address: 0x005DACE0 (FUN_005DACE0, cfunc_CAiAttackerImplIsTooClose)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiAttackerImplIsTooCloseL`.
 */
int moho::cfunc_CAiAttackerImplIsTooClose(lua_State* const luaContext)
{
  return cfunc_CAiAttackerImplIsTooCloseL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplIsTargetExemptL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplHasSlavedTargetL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplResetReportingStateL(ResolveBindingState(luaContext));
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
  return cfunc_CAiAttackerImplForceEngageL(ResolveBindingState(luaContext));
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
  CScrLuaInitFormSet* const simSet = FindSimLuaInitSet();
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
