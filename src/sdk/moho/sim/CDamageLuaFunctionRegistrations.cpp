#include "moho/sim/CDamageLuaFunctionRegistrations.h"

#include <cstring>

#include "moho/entity/Entity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CDamage.h"

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kCDamageLuaClassName = "CDamage";
  constexpr const char* kCDamageGetInstigatorHelpText = "CDamage:GetInstigator()";
  constexpr const char* kCDamageSetInstigatorHelpText = "CDamage:SetInstigator()";
  constexpr const char* kCDamageGetTargetHelpText = "CDamage:GetTarget()";
  constexpr const char* kCDamageSetTargetHelpText = "CDamage:SetTarget()";
  constexpr const char* kDamageHelpText = "Damage(instigator, target, amount, damageType)";
  constexpr const char* kDamageAreaHelpText =
    "DamageArea(instigator,location,radius,amount,damageType,damageFriendly,[damageSelf])";
  constexpr const char* kDamageRingHelpText =
    "DamageRing(instigator,location,minRadius,maxRadius,amount,damageType,damageFriendly,[damageSelf])";

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
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

  void RequireLuaArgCount(
    LuaPlus::LuaState* const state, const char* const helpText, const int expectedCount
  )
  {
    if (!state || !state->m_state) {
      return;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != expectedCount) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, helpText, expectedCount, argumentCount);
    }
  }

  void PushEntityOrNil(LuaPlus::LuaState* const state, moho::Entity* const entity)
  {
    if (!state || !state->m_state) {
      return;
    }

    if (entity != nullptr && entity->Dead == 0u) {
      entity->mLuaObj.PushStack(state);
      return;
    }

    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }
} // namespace

namespace moho
{
  CScrLuaMetatableFactory<CDamage> CScrLuaMetatableFactory<CDamage>::sInstance{};

  /**
   * Address: 0x10015880 (constructor shape)
   *
   * What it does:
   * Stores one metatable-factory index used by `CScrLuaObjectFactory::Get`.
   */
  CScrLuaMetatableFactory<CDamage>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CDamage>& CScrLuaMetatableFactory<CDamage>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x00739CF0 (FUN_00739CF0, Moho::CScrLuaMetatableFactory<Moho::CDamage>::Create)
   *
   * What it does:
   * Creates the default metatable used by `CDamage` Lua userdata.
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<CDamage>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x0073A810 (FUN_0073A810, func_CreateLuaCDamage)
   *
   * What it does:
   * Resolves one cached Lua metatable object for CDamage userdata creation.
   */
  LuaPlus::LuaObject* func_CreateLuaCDamage(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    *object = CScrLuaMetatableFactory<CDamage>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x00738BD0 (FUN_00738BD0, cfunc_Damage)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_DamageL`.
   */
  int cfunc_Damage(lua_State* const luaContext)
  {
    return cfunc_DamageL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00738BF0 (FUN_00738BF0, func_Damage_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `Damage`.
   */
  CScrLuaInitForm* func_Damage_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Damage",
      &cfunc_Damage,
      nullptr,
      "<global>",
      kDamageHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00738C50 (FUN_00738C50, cfunc_DamageL)
   *
   * What it does:
   * Builds one transient `CDamage` payload from Lua args and dispatches it to
   * `SIM_Damage`.
   */
  int cfunc_DamageL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 5) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kDamageHelpText, 5, argumentCount);
    }

    Sim* const sim = lua_getglobaluserdata(state->m_state);
    CDamage damage(sim);

    if (lua_type(state->m_state, 1) != LUA_TNIL) {
      const LuaPlus::LuaObject instigatorObject(LuaPlus::LuaStackObject(state, 1));
      Entity* const instigator = SCR_FromLua_EntityOpt(instigatorObject);
      damage.mInstigator.ResetFromObject(instigator);
    }

    const LuaPlus::LuaObject originObject(LuaPlus::LuaStackObject(state, 2));
    damage.mOrigin = SCR_FromLuaCopy<Wm3::Vec3f>(originObject);

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 3));
    Entity* const target = SCR_FromLua_Entity(targetObject, state);
    damage.mTarget.ResetFromObject(target);

    damage.mMethod = CDamage_SINGLE_TARGET;

    LuaPlus::LuaStackObject amountArg(state, 4);
    if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
      amountArg.TypeError("number");
    }
    damage.mAmount = static_cast<float>(lua_tonumber(state->m_state, 4));

    LuaPlus::LuaStackObject damageTypeArg(state, 5);
    const char* damageType = lua_tostring(state->m_state, 5);
    if (!damageType) {
      damageTypeArg.TypeError("string");
      damageType = "";
    }
    damage.mType.assign_owned(damageType);

    Entity* const damageTarget = damage.mTarget.GetObjectPtr();
    if (damageTarget != nullptr) {
      damage.mVector.x = damageTarget->Position.x - damage.mOrigin.x;
      damage.mVector.y = damageTarget->Position.y - damage.mOrigin.y;
      damage.mVector.z = damageTarget->Position.z - damage.mOrigin.z;
    }

    if (damage.mAmount == 0.0f) {
      LuaPlus::LuaState::Error(state, "0 damage specified.");
    }

    SIM_Damage(sim, damage);
    return 1;
  }

  /**
   * Address: 0x00BDB790 (FUN_00BDB790, register_Damage_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_Damage_LuaFuncDef`.
   */
  CScrLuaInitForm* register_Damage_LuaFuncDef()
  {
    return func_Damage_LuaFuncDef();
  }

  /**
   * Address: 0x00738F40 (FUN_00738F40, cfunc_DamageArea)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_DamageAreaL`.
   */
  int cfunc_DamageArea(lua_State* const luaContext)
  {
    return cfunc_DamageAreaL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00738F60 (FUN_00738F60, func_DamageArea_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `DamageArea`.
   */
  CScrLuaInitForm* func_DamageArea_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "DamageArea",
      &cfunc_DamageArea,
      nullptr,
      "<global>",
      kDamageAreaHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00738FC0 (FUN_00738FC0, cfunc_DamageAreaL)
   *
   * What it does:
   * Builds one transient area-effect `CDamage` payload from Lua args and
   * dispatches it to `SIM_Damage`.
   */
  int cfunc_DamageAreaL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 6 || argumentCount > 7) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kDamageAreaHelpText,
        6,
        7,
        argumentCount
      );
    }

    Sim* const sim = lua_getglobaluserdata(state->m_state);
    CDamage damage(sim);

    if (lua_type(state->m_state, 1) != LUA_TNIL) {
      const LuaPlus::LuaObject instigatorObject(LuaPlus::LuaStackObject(state, 1));
      Entity* const instigator = SCR_FromLua_EntityOpt(instigatorObject);
      damage.mInstigator.ResetFromObject(instigator);
    }

    const LuaPlus::LuaObject originObject(LuaPlus::LuaStackObject(state, 2));
    damage.mOrigin = SCR_FromLuaCopy<Wm3::Vec3f>(originObject);

    LuaPlus::LuaStackObject radiusArg(state, 3);
    if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
      radiusArg.TypeError("number");
    }
    damage.mRadius = static_cast<float>(lua_tonumber(state->m_state, 3));

    LuaPlus::LuaStackObject amountArg(state, 4);
    if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
      amountArg.TypeError("number");
    }
    damage.mAmount = static_cast<float>(lua_tonumber(state->m_state, 4));

    LuaPlus::LuaStackObject damageTypeArg(state, 5);
    const char* damageType = lua_tostring(state->m_state, 5);
    if (!damageType) {
      damageTypeArg.TypeError("string");
      damageType = "";
    }
    damage.mType.assign_owned(damageType);

    damage.mDamageFriendly = LuaPlus::LuaStackObject(state, 6).GetBoolean() ? 1u : 0u;
    if (argumentCount == 7) {
      damage.mDamageSelf = LuaPlus::LuaStackObject(state, 7).GetBoolean() ? 1u : 0u;
    } else {
      damage.mDamageSelf = 0u;
    }

    damage.mMethod = CDamage_AREA_EFFECT;
    if (damage.mAmount == 0.0f) {
      LuaPlus::LuaState::Error(state, "0 damage specified.");
    }
    if (damage.mRadius == 0.0f) {
      LuaPlus::LuaState::Error(state, "0 radius specified.");
    }

    SIM_Damage(sim, damage);
    return 1;
  }

  /**
   * Address: 0x00BDB7A0 (FUN_00BDB7A0, register_DamageArea_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_DamageArea_LuaFuncDef`.
   */
  CScrLuaInitForm* register_DamageArea_LuaFuncDef()
  {
    return func_DamageArea_LuaFuncDef();
  }

  /**
   * Address: 0x007392C0 (FUN_007392C0, cfunc_DamageRing)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_DamageRingL`.
   */
  int cfunc_DamageRing(lua_State* const luaContext)
  {
    return cfunc_DamageRingL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007392E0 (FUN_007392E0, func_DamageRing_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `DamageRing`.
   */
  CScrLuaInitForm* func_DamageRing_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "DamageRing",
      &cfunc_DamageRing,
      nullptr,
      "<global>",
      kDamageRingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00739340 (FUN_00739340, cfunc_DamageRingL)
   *
   * What it does:
   * Builds one transient ring-effect `CDamage` payload from Lua args and
   * dispatches it to `SIM_Damage`.
   */
  int cfunc_DamageRingL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 7 || argumentCount > 8) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kDamageRingHelpText,
        7,
        8,
        argumentCount
      );
    }

    Sim* const sim = lua_getglobaluserdata(state->m_state);
    CDamage damage(sim);

    if (lua_type(state->m_state, 1) != LUA_TNIL) {
      const LuaPlus::LuaObject instigatorObject(LuaPlus::LuaStackObject(state, 1));
      Entity* const instigator = SCR_FromLua_EntityOpt(instigatorObject);
      damage.mInstigator.ResetFromObject(instigator);
    }

    const LuaPlus::LuaObject originObject(LuaPlus::LuaStackObject(state, 2));
    damage.mOrigin = SCR_FromLuaCopy<Wm3::Vec3f>(originObject);

    LuaPlus::LuaStackObject minRadiusArg(state, 3);
    if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
      minRadiusArg.TypeError("number");
    }
    damage.mRadius = static_cast<float>(lua_tonumber(state->m_state, 3));

    LuaPlus::LuaStackObject maxRadiusArg(state, 4);
    if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
      maxRadiusArg.TypeError("number");
    }
    damage.mMaxRadius = static_cast<float>(lua_tonumber(state->m_state, 4));

    LuaPlus::LuaStackObject amountArg(state, 5);
    if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
      amountArg.TypeError("number");
    }
    damage.mAmount = static_cast<float>(lua_tonumber(state->m_state, 5));

    LuaPlus::LuaStackObject damageTypeArg(state, 6);
    const char* damageType = lua_tostring(state->m_state, 6);
    if (!damageType) {
      damageTypeArg.TypeError("string");
      damageType = "";
    }
    damage.mType.assign_owned(damageType);

    damage.mDamageFriendly = LuaPlus::LuaStackObject(state, 7).GetBoolean() ? 1u : 0u;
    if (argumentCount == 8) {
      damage.mDamageSelf = LuaPlus::LuaStackObject(state, 8).GetBoolean() ? 1u : 0u;
    } else {
      damage.mDamageSelf = 0u;
    }

    damage.mMethod = CDamage_RING_EFFECT;
    if (damage.mAmount == 0.0f) {
      LuaPlus::LuaState::Error(state, "0 damage specified.");
    }
    if (damage.mRadius == 0.0f) {
      LuaPlus::LuaState::Error(state, "0 min radius specified.");
    }
    if (damage.mMaxRadius == 0.0f) {
      LuaPlus::LuaState::Error(state, "0 max radius specified.");
    }
    if (damage.mRadius >= damage.mMaxRadius) {
      LuaPlus::LuaState::Error(state, "Max radius must be greater than min radius.");
    }

    SIM_Damage(sim, damage);
    return 1;
  }

  /**
   * Address: 0x00BDB7B0 (FUN_00BDB7B0, register_DamageRing_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_DamageRing_LuaFuncDef`.
   */
  CScrLuaInitForm* register_DamageRing_LuaFuncDef()
  {
    return func_DamageRing_LuaFuncDef();
  }

  /**
   * Address: 0x00738630 (FUN_00738630, cfunc_CDamageGetInstigator)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CDamageGetInstigatorL`.
   */
  int cfunc_CDamageGetInstigator(lua_State* const luaContext)
  {
    return cfunc_CDamageGetInstigatorL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007386B0 (FUN_007386B0, cfunc_CDamageGetInstigatorL)
   *
   * What it does:
   * Resolves one `CDamage` object and pushes its live instigator entity Lua
   * object, or `nil` when missing/dead.
   */
  int cfunc_CDamageGetInstigatorL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    RequireLuaArgCount(state, kCDamageGetInstigatorHelpText, 1);

    const LuaPlus::LuaObject damageObject(LuaPlus::LuaStackObject(state, 1));
    CDamage* const damage = SCR_FromLua_CDamage(damageObject, state);
    if (!damage) {
      return 0;
    }

    PushEntityOrNil(state, damage->mInstigator.GetObjectPtr());
    return 1;
  }

  /**
   * Address: 0x00738650 (FUN_00738650, func_CDamageGetInstigator_LuaFuncDef)
   *
   * What it does:
   * Publishes `CDamage:GetInstigator()` Lua binder definition in the `sim`
   * init-form set.
   */
  CScrLuaInitForm* func_CDamageGetInstigator_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetInstigator",
      &cfunc_CDamageGetInstigator,
      &CScrLuaMetatableFactory<CDamage>::Instance(),
      kCDamageLuaClassName,
      kCDamageGetInstigatorHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00738790 (FUN_00738790, cfunc_CDamageSetInstigator)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CDamageSetInstigatorL`.
   */
  int cfunc_CDamageSetInstigator(lua_State* const luaContext)
  {
    return cfunc_CDamageSetInstigatorL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00738810 (FUN_00738810, cfunc_CDamageSetInstigatorL)
   *
   * What it does:
   * Resolves `CDamage` + `Entity` Lua args and stores the instigator weak link.
   */
  int cfunc_CDamageSetInstigatorL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    RequireLuaArgCount(state, kCDamageSetInstigatorHelpText, 2);

    const LuaPlus::LuaObject damageObject(LuaPlus::LuaStackObject(state, 1));
    CDamage* const damage = SCR_FromLua_CDamage(damageObject, state);
    if (!damage) {
      return 0;
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const instigator = SCR_FromLua_Entity(entityObject, state);
    damage->mInstigator.ResetFromObject(instigator);
    return 0;
  }

  /**
   * Address: 0x007387B0 (FUN_007387B0, func_CDamageSetInstigator_LuaFuncDef)
   *
   * What it does:
   * Publishes `CDamage:SetInstigator()` Lua binder definition in the `sim`
   * init-form set.
   */
  CScrLuaInitForm* func_CDamageSetInstigator_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetInstigator",
      &cfunc_CDamageSetInstigator,
      &CScrLuaMetatableFactory<CDamage>::Instance(),
      kCDamageLuaClassName,
      kCDamageSetInstigatorHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00738900 (FUN_00738900, cfunc_CDamageGetTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CDamageGetTargetL`.
   */
  int cfunc_CDamageGetTarget(lua_State* const luaContext)
  {
    return cfunc_CDamageGetTargetL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00738980 (FUN_00738980, cfunc_CDamageGetTargetL)
   *
   * What it does:
   * Resolves one `CDamage` object and pushes its live target entity Lua object,
   * or `nil` when missing/dead.
   */
  int cfunc_CDamageGetTargetL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    // Preserve binary behavior: this lane validates against 2 args.
    RequireLuaArgCount(state, kCDamageGetTargetHelpText, 2);

    const LuaPlus::LuaObject damageObject(LuaPlus::LuaStackObject(state, 1));
    CDamage* const damage = SCR_FromLua_CDamage(damageObject, state);
    if (!damage) {
      return 0;
    }

    PushEntityOrNil(state, damage->mTarget.GetObjectPtr());
    return 1;
  }

  /**
   * Address: 0x00738920 (FUN_00738920, func_CDamageGetTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `CDamage:GetTarget()` Lua binder definition in the `sim`
   * init-form set.
   */
  CScrLuaInitForm* func_CDamageGetTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetTarget",
      &cfunc_CDamageGetTarget,
      &CScrLuaMetatableFactory<CDamage>::Instance(),
      kCDamageLuaClassName,
      kCDamageGetTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00738A60 (FUN_00738A60, cfunc_CDamageSetTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CDamageSetTargetL`.
   */
  int cfunc_CDamageSetTarget(lua_State* const luaContext)
  {
    return cfunc_CDamageSetTargetL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00738AE0 (FUN_00738AE0, cfunc_CDamageSetTargetL)
   *
   * What it does:
   * Resolves `CDamage` + `Entity` Lua args and stores the target weak link.
   */
  int cfunc_CDamageSetTargetL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    // Preserve binary behavior: this lane validates against 1 arg, then reads arg #2.
    RequireLuaArgCount(state, kCDamageSetTargetHelpText, 1);

    const LuaPlus::LuaObject damageObject(LuaPlus::LuaStackObject(state, 1));
    CDamage* const damage = SCR_FromLua_CDamage(damageObject, state);
    if (!damage) {
      return 0;
    }

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const target = SCR_FromLua_Entity(entityObject, state);
    damage->mTarget.ResetFromObject(target);
    return 0;
  }

  /**
   * Address: 0x00738A80 (FUN_00738A80, func_CDamageSetTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes `CDamage:SetTarget()` Lua binder definition in the `sim`
   * init-form set.
   */
  CScrLuaInitForm* func_CDamageSetTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetTarget",
      &cfunc_CDamageSetTarget,
      &CScrLuaMetatableFactory<CDamage>::Instance(),
      kCDamageLuaClassName,
      kCDamageSetTargetHelpText
    );
    return &binder;
  }
} // namespace moho
