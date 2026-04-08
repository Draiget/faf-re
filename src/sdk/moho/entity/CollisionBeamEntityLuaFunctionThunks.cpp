#include "moho/entity/CollisionBeamEntity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptEvent.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"

#include <cstring>

struct lua_State;

namespace moho
{
  int cfunc_CollisionBeamEntity__init(lua_State* luaContext);
  /**
   * Address: 0x00673C40 (FUN_00673C40, cfunc_CollisionBeamEntity__initL)
   *
   * What it does:
   * Creates one collision-beam entity from Lua args, applies attach/bone setup
   * from the spec table, and returns the created beam Lua object.
   */
  int cfunc_CollisionBeamEntity__initL(LuaPlus::LuaState* state);
  int cfunc_CollisionBeamEntitySetBeamFx(lua_State* luaContext);
  int cfunc_CollisionBeamEntitySetBeamFxL(LuaPlus::LuaState* state);
  int cfunc_CollisionBeamEntityDisable(lua_State* luaContext);
  int cfunc_CollisionBeamEntityDisableL(LuaPlus::LuaState* state);
  int cfunc_CollisionBeamEntityEnable(lua_State* luaContext);
  /**
   * Address: 0x006742D0 (FUN_006742D0, cfunc_CollisionBeamEntityEnableL)
   *
   * What it does:
   * Resolves one beam argument, runs script callback `OnEnable`, and enables
   * collision-check updates.
   */
  int cfunc_CollisionBeamEntityEnableL(LuaPlus::LuaState* state);
  int cfunc_CollisionBeamEntityIsEnabled(lua_State* luaContext);
  int cfunc_CollisionBeamEntityIsEnabledL(LuaPlus::LuaState* state);
  int cfunc_CollisionBeamEntityGetLauncher(lua_State* luaContext);
  int cfunc_CollisionBeamEntityGetLauncherL(LuaPlus::LuaState* state);

  template <>
  class CScrLuaMetatableFactory<CollisionBeamEntity> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CollisionBeamEntity>) == 0x08,
    "CScrLuaMetatableFactory<CollisionBeamEntity> size must be 0x8"
  );

  CScrLuaMetatableFactory<CollisionBeamEntity> CScrLuaMetatableFactory<CollisionBeamEntity>::sInstance{};

  CScrLuaMetatableFactory<CollisionBeamEntity>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CollisionBeamEntity>& CScrLuaMetatableFactory<CollisionBeamEntity>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CollisionBeamEntity>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }
} // namespace moho

namespace
{
  constexpr const char* kCollisionBeamEntityClassName = "CollisionBeamEntity";
  constexpr const char* kCollisionBeamEntityInitName = "__init";
  constexpr const char* kCollisionBeamEntitySetBeamFxName = "SetBeamFx";
  constexpr const char* kCollisionBeamEntityDisableName = "Disable";
  constexpr const char* kCollisionBeamEntityEnableName = "Enable";
  constexpr const char* kCollisionBeamEntityIsEnabledName = "IsEnabled";
  constexpr const char* kCollisionBeamEntityGetLauncherName = "GetLauncher";
  constexpr const char* kCollisionBeamEntityInitHelpText = "beam = CreateCollisionBeam(spec)\n"
                                                           "spec is a table with the following fields defined:\n"
                                                           "    spec.Weapon = <weapon to attach to>\n"
                                                           "    spec.OtherBone = <bone of weapon's unit to attach to>\n"
                                                           "    spec.CollisionCheckInterval = <interval in ticks>\n"
                                                           "    spec.BeamBone = <which end of beam to attach>";
  constexpr const char* kCollisionBeamEntitySetBeamFxHelpText =
    "CollisionBeamEntity:SetBeamFx(beamEmitter, checkCollision) -- set an emitter to be controlled by this beam. "
    "Its length parameter will be set from the beam entity's collision distance.";
  constexpr const char* kCollisionBeamEntityDisableHelpText = "CollisionBeamEntity:Disable()";
  constexpr const char* kCollisionBeamEntityEnableHelpText = "CollisionBeamEntity:Enable()";
  constexpr const char* kCollisionBeamEntityIsEnabledHelpText = "bool = CollisionBeamEntity:IsEnabled()";
  constexpr const char* kCollisionBeamEntityGetLauncherHelpText = "CollisionBeamEntity:GetLauncher()";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedArgsRangeWarning = "%s\n  expected between %d and %d args, but got %d";

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

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardCollisionBeamLuaThunk() noexcept
  {
    return Target();
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00673BC0 (FUN_00673BC0, cfunc_CollisionBeamEntity__init)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CollisionBeamEntity__initL`.
   */
  int cfunc_CollisionBeamEntity__init(lua_State* const luaContext)
  {
    return cfunc_CollisionBeamEntity__initL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00673C40 (FUN_00673C40, cfunc_CollisionBeamEntity__initL)
   *
   * What it does:
   * Creates one collision beam from Lua constructor args, applies collision
   * interval and attach-bone setup from the spec table, and pushes the created
   * beam Lua object.
   */
  int cfunc_CollisionBeamEntity__initL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCollisionBeamEntityInitHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaStackObject constructorObject(state, 1);

    lua_pushstring(rawState, "Weapon");
    lua_gettable(rawState, 2);
    const LuaPlus::LuaObject weaponObject(LuaPlus::LuaStackObject(state, lua_gettop(rawState)));
    UnitWeapon* const launcherWeapon = SCR_FromLua_UnitWeapon(weaponObject, state);

    const LuaPlus::LuaObject beamLuaObject(constructorObject);
    CollisionBeamEntity* const beamEntity = new CollisionBeamEntity(beamLuaObject, launcherWeapon);

    lua_pushstring(rawState, "CollisionCheckInterval");
    lua_gettable(rawState, 2);
    const LuaPlus::LuaStackObject intervalArg(state, lua_gettop(rawState));
    if (lua_type(rawState, intervalArg.m_stackIndex) != 3) {
      intervalArg.TypeError("integer");
    }
    beamEntity->mCollisionCheckInterval = static_cast<std::int32_t>(lua_tonumber(rawState, intervalArg.m_stackIndex));

    lua_pushstring(rawState, "BeamBone");
    lua_gettable(rawState, 2);
    LuaPlus::LuaStackObject beamBoneArg(state, lua_gettop(rawState));
    const int beamBoneIndex = ENTSCR_ResolveBoneIndex(beamEntity, beamBoneArg, true);

    Entity* launcherEntity = nullptr;
    if (launcherWeapon != nullptr && launcherWeapon->mUnit != nullptr) {
      launcherEntity = static_cast<Entity*>(launcherWeapon->mUnit);
    }

    lua_pushstring(rawState, "OtherBone");
    lua_gettable(rawState, 2);
    LuaPlus::LuaStackObject otherBoneArg(state, lua_gettop(rawState));
    const int otherBoneIndex = ENTSCR_ResolveBoneIndex(launcherEntity, otherBoneArg, true);

    SEntAttachInfo attachInfo = SEntAttachInfo::MakeDetached();
    attachInfo.TargetWeakLink().ResetFromObject(launcherEntity);
    attachInfo.mParentBoneIndex = otherBoneIndex;
    attachInfo.mChildBoneIndex = beamBoneIndex;
    (void)beamEntity->AttachTo(attachInfo);

    beamEntity->mLuaObj.PushStack(state);
    attachInfo.TargetWeakLink().UnlinkFromOwnerChain();
    return 1;
  }

  /**
   * Address: 0x00673F60 (FUN_00673F60, cfunc_CollisionBeamEntitySetBeamFx)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CollisionBeamEntitySetBeamFxL`.
   */
  int cfunc_CollisionBeamEntitySetBeamFx(lua_State* const luaContext)
  {
    return cfunc_CollisionBeamEntitySetBeamFxL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00673FE0 (FUN_00673FE0, cfunc_CollisionBeamEntitySetBeamFxL)
   *
   * What it does:
   * Resolves `(beam, beamEmitter, [checkCollision])`, updates beam-emitter weak
   * ownership, and optionally runs one collision-check pass when a launcher is
   * present.
   */
  int cfunc_CollisionBeamEntitySetBeamFxL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(
        state, kLuaExpectedArgsRangeWarning, kCollisionBeamEntitySetBeamFxHelpText, 2, 3, argumentCount
      );
    }

    const LuaPlus::LuaObject beamObject(LuaPlus::LuaStackObject(state, 1));
    CollisionBeamEntity* const beamEntity = SCR_FromLua_CollisionBeamEntity(beamObject, state);

    const LuaPlus::LuaObject emitterObject(LuaPlus::LuaStackObject(state, 2));
    IEffect* const beamEmitter = SCR_FromLua_IEffect(emitterObject, state);

    const bool checkCollision = (argumentCount >= 3) ? LuaPlus::LuaStackObject(state, 3).GetBoolean() : true;
    beamEntity->mEffect.ResetFromObject(beamEmitter);

    if (checkCollision && beamEntity->mLauncher.GetObject() != nullptr) {
      beamEntity->CheckCollision();
    }

    return 0;
  }

  /**
   * Address: 0x00674120 (FUN_00674120, cfunc_CollisionBeamEntityDisable)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CollisionBeamEntityDisableL`.
   */
  int cfunc_CollisionBeamEntityDisable(lua_State* const luaContext)
  {
    return cfunc_CollisionBeamEntityDisableL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006741A0 (FUN_006741A0, cfunc_CollisionBeamEntityDisableL)
   *
   * What it does:
   * Resolves one beam argument, runs script callback `OnDisable`, and clears
   * the runtime enabled flag.
   */
  int cfunc_CollisionBeamEntityDisableL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCollisionBeamEntityDisableHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject beamObject(LuaPlus::LuaStackObject(state, 1));
    CollisionBeamEntity* const beamEntity = SCR_FromLua_CollisionBeamEntity(beamObject, state);
    beamEntity->RunScript("OnDisable");
    beamEntity->mEnabled = 0;
    return 0;
  }

  /**
   * Address: 0x00674250 (FUN_00674250, cfunc_CollisionBeamEntityEnable)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CollisionBeamEntityEnableL`.
   */
  int cfunc_CollisionBeamEntityEnable(lua_State* const luaContext)
  {
    return cfunc_CollisionBeamEntityEnableL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006742D0 (FUN_006742D0, cfunc_CollisionBeamEntityEnableL)
   *
   * What it does:
   * Resolves one beam argument, runs script callback `OnEnable`, and enables
   * collision-check updates.
   */
  int cfunc_CollisionBeamEntityEnableL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCollisionBeamEntityEnableHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject beamObject(LuaPlus::LuaStackObject(state, 1));
    CollisionBeamEntity* const beamEntity = SCR_FromLua_CollisionBeamEntity(beamObject, state);
    beamEntity->RunScript("OnEnable");
    beamEntity->EnableCollisionCheck(1);
    return 0;
  }

  /**
   * Address: 0x00674380 (FUN_00674380, cfunc_CollisionBeamEntityIsEnabled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CollisionBeamEntityIsEnabledL`.
   */
  int cfunc_CollisionBeamEntityIsEnabled(lua_State* const luaContext)
  {
    return cfunc_CollisionBeamEntityIsEnabledL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00674400 (FUN_00674400, cfunc_CollisionBeamEntityIsEnabledL)
   *
   * What it does:
   * Resolves one beam argument and pushes whether its runtime enabled flag is
   * currently set.
   */
  int cfunc_CollisionBeamEntityIsEnabledL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCollisionBeamEntityIsEnabledHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject beamObject(LuaPlus::LuaStackObject(state, 1));
    const CollisionBeamEntity* const beamEntity = SCR_FromLua_CollisionBeamEntity(beamObject, state);
    lua_pushboolean(rawState, beamEntity->mEnabled != 0);
    lua_gettop(rawState);
    return 1;
  }

  /**
   * Address: 0x006744C0 (FUN_006744C0, cfunc_CollisionBeamEntityGetLauncher)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CollisionBeamEntityGetLauncherL`.
   */
  int cfunc_CollisionBeamEntityGetLauncher(lua_State* const luaContext)
  {
    return cfunc_CollisionBeamEntityGetLauncherL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00674540 (FUN_00674540, cfunc_CollisionBeamEntityGetLauncherL)
   *
   * What it does:
   * Resolves one beam argument and pushes launcher unit Lua object when
   * available; otherwise pushes `nil`.
   */
  int cfunc_CollisionBeamEntityGetLauncherL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCollisionBeamEntityGetLauncherHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject beamObject(LuaPlus::LuaStackObject(state, 1));
    const CollisionBeamEntity* const beamEntity = SCR_FromLua_CollisionBeamEntity(beamObject, state);

    const UnitWeapon* const launcherWeapon = beamEntity->mLauncher.GetObject();
    Unit* const launcherUnit = launcherWeapon ? launcherWeapon->mUnit : nullptr;
    if (launcherUnit != nullptr) {
      LuaPlus::LuaObject launcherObject = launcherUnit->GetLuaObject();
      if (launcherObject) {
        launcherObject.PushStack(state);
        return 1;
      }
    }

    lua_pushnil(rawState);
    lua_gettop(rawState);
    return 1;
  }

  /**
   * Address: 0x00673BE0 (FUN_00673BE0, func_CollisionBeamEntity__init_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CollisionBeamEntity:__init(spec)` Lua binder.
   */
  CScrLuaInitForm* func_CollisionBeamEntity__init_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCollisionBeamEntityInitName,
      &cfunc_CollisionBeamEntity__init,
      &CScrLuaMetatableFactory<CollisionBeamEntity>::Instance(),
      kCollisionBeamEntityClassName,
      kCollisionBeamEntityInitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00673F80 (FUN_00673F80, func_CollisionBeamEntitySetBeamFx_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CollisionBeamEntity:SetBeamFx(...)` Lua binder.
   */
  CScrLuaInitForm* func_CollisionBeamEntitySetBeamFx_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCollisionBeamEntitySetBeamFxName,
      &cfunc_CollisionBeamEntitySetBeamFx,
      &CScrLuaMetatableFactory<CollisionBeamEntity>::Instance(),
      kCollisionBeamEntityClassName,
      kCollisionBeamEntitySetBeamFxHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00674140 (FUN_00674140, func_CollisionBeamEntityDisable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CollisionBeamEntity:Disable()` Lua binder.
   */
  CScrLuaInitForm* func_CollisionBeamEntityDisable_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCollisionBeamEntityDisableName,
      &cfunc_CollisionBeamEntityDisable,
      &CScrLuaMetatableFactory<CollisionBeamEntity>::Instance(),
      kCollisionBeamEntityClassName,
      kCollisionBeamEntityDisableHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00674270 (FUN_00674270, func_CollisionBeamEntityEnable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CollisionBeamEntity:Enable()` Lua binder.
   */
  CScrLuaInitForm* func_CollisionBeamEntityEnable_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCollisionBeamEntityEnableName,
      &cfunc_CollisionBeamEntityEnable,
      &CScrLuaMetatableFactory<CollisionBeamEntity>::Instance(),
      kCollisionBeamEntityClassName,
      kCollisionBeamEntityEnableHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006743A0 (FUN_006743A0, func_CollisionBeamEntityIsEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CollisionBeamEntity:IsEnabled()` Lua binder.
   */
  CScrLuaInitForm* func_CollisionBeamEntityIsEnabled_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCollisionBeamEntityIsEnabledName,
      &cfunc_CollisionBeamEntityIsEnabled,
      &CScrLuaMetatableFactory<CollisionBeamEntity>::Instance(),
      kCollisionBeamEntityClassName,
      kCollisionBeamEntityIsEnabledHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006744E0 (FUN_006744E0, func_CollisionBeamEntityGetLauncher_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CollisionBeamEntity:GetLauncher()` Lua binder.
   */
  CScrLuaInitForm* func_CollisionBeamEntityGetLauncher_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCollisionBeamEntityGetLauncherName,
      &cfunc_CollisionBeamEntityGetLauncher,
      &CScrLuaMetatableFactory<CollisionBeamEntity>::Instance(),
      kCollisionBeamEntityClassName,
      kCollisionBeamEntityGetLauncherHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BD4D10 (FUN_00BD4D10, register_CollisionBeamEntity__init_LuaFuncDef)
   */
  CScrLuaInitForm* register_CollisionBeamEntity__init_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntity__init_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D20 (FUN_00BD4D20, j_func_CollisionBeamEntitySetBeamFx_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CollisionBeamEntitySetBeamFx_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntitySetBeamFx_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D30 (FUN_00BD4D30, j_func_CollisionBeamEntityDisable_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CollisionBeamEntityDisable_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntityDisable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D40 (FUN_00BD4D40, register_CollisionBeamEntityEnable_LuaFuncDef)
   */
  CScrLuaInitForm* register_CollisionBeamEntityEnable_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntityEnable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D50 (FUN_00BD4D50, register_CollisionBeamEntityIsEnabled_LuaFuncDef)
   */
  CScrLuaInitForm* register_CollisionBeamEntityIsEnabled_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntityIsEnabled_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D60 (FUN_00BD4D60, register_CollisionBeamEntityGetLauncher_LuaFuncDef)
   */
  CScrLuaInitForm* register_CollisionBeamEntityGetLauncher_LuaFuncDef()
  {
    return ForwardCollisionBeamLuaThunk<&func_CollisionBeamEntityGetLauncher_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD4D70 (FUN_00BD4D70, register_CScrLuaMetatableFactory_CollisionBeamEntity_Index)
   *
   * What it does:
   * Allocates the next Lua metatable-factory object index and stores it in the
   * recovered collision-beam metatable-factory startup index lane.
   */
  int register_CScrLuaMetatableFactory_CollisionBeamEntity_Index()
  {
    const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    CScrLuaMetatableFactory<CollisionBeamEntity>::Instance().SetFactoryObjectIndexForRecovery(index);
    return index;
  }
} // namespace moho

namespace
{
  struct CollisionBeamEntityLuaFunctionThunksBootstrap
  {
    CollisionBeamEntityLuaFunctionThunksBootstrap()
    {
      (void)moho::register_CollisionBeamEntity__init_LuaFuncDef();
      (void)moho::j_func_CollisionBeamEntitySetBeamFx_LuaFuncDef();
      (void)moho::j_func_CollisionBeamEntityDisable_LuaFuncDef();
      (void)moho::register_CollisionBeamEntityEnable_LuaFuncDef();
      (void)moho::register_CollisionBeamEntityIsEnabled_LuaFuncDef();
      (void)moho::register_CollisionBeamEntityGetLauncher_LuaFuncDef();
      (void)moho::register_CScrLuaMetatableFactory_CollisionBeamEntity_Index();
    }
  };

  [[maybe_unused]] CollisionBeamEntityLuaFunctionThunksBootstrap gCollisionBeamEntityLuaFunctionThunksBootstrap;
} // namespace
