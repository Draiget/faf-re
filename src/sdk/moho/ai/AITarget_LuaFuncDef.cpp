#include "moho/ai/AITarget_LuaFuncDef.h"

#include "moho/ai/CAiTarget.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/script/CScriptEvent.h"

namespace
{
  constexpr const char* kAITargetLuaHelpText = "Create a target object";
  constexpr const char* kLuaExpectedBetweenArgsWarning = "%s\n  expected between %d and %d args, but got %d";

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("core"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("core");
    return fallbackSet;
  }

  [[nodiscard]] Wm3::Vec3f ReadVector3FromLuaObject(const LuaPlus::LuaObject& object) noexcept
  {
    Wm3::Vec3f out = Wm3::Vec3f::Zero();
    if (!object.IsTable()) {
      return out;
    }

    const LuaPlus::LuaObject xObject = object[1];
    const LuaPlus::LuaObject yObject = object[2];
    const LuaPlus::LuaObject zObject = object[3];
    out.x = static_cast<float>(xObject.GetNumber());
    out.y = static_cast<float>(yObject.GetNumber());
    out.z = static_cast<float>(zObject.GetNumber());
    return out;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BCEC90 (FUN_00BCEC90, register_AITarget_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_AITarget_LuaFuncDef`.
   */
  void register_AITarget_LuaFuncDef()
  {
    func_AITarget_LuaFuncDef();
  }

  /**
   * Address: 0x005E3150 (FUN_005E3150, cfunc_AITarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_AITargetL`.
   */
  int cfunc_AITarget(lua_State* const luaContext)
  {
    return cfunc_AITargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x005E31D0 (FUN_005E31D0, cfunc_AITargetL)
   *
   * What it does:
   * Builds one `CAiTarget` from optional Lua arg#1 (`Entity` object or
   * position table) and returns the Lua target object payload.
   */
  int cfunc_AITargetL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount > 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedBetweenArgsWarning, kAITargetLuaHelpText, 0, 1, argumentCount);
    }

    LuaPlus::LuaObject argObject(LuaPlus::LuaStackObject(state, 1));
    CAiTarget target{};
    if (Entity* const entity = SCR_FromLuaNoError_Entity(argObject); entity != nullptr) {
      target.UpdateTarget(entity);
    } else if (lua_type(rawState, 1) == LUA_TTABLE) {
      target.targetType = EAiTargetType::AITARGET_Ground;
      target.targetEntity.ClearLinkState();
      target.position = ReadVector3FromLuaObject(argObject);
      target.targetPoint = -1;
      target.targetIsMobile = false;
    } else {
      target.targetType = EAiTargetType::AITARGET_None;
      target.targetEntity.ClearLinkState();
      target.targetPoint = -1;
      target.targetIsMobile = false;
    }

    LuaPlus::LuaObject targetObject;
    SCR_ToLua_CAiTarget(targetObject, state, target);
    targetObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x005E3170 (FUN_005E3170, func_AITarget_LuaFuncDef)
   *
   * What it does:
   * Initializes the `AITarget` Lua binder record and links it into the global
   * script init list.
   */
  void func_AITarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "AITarget",
      &cfunc_AITarget,
      nullptr,
      "<global>",
      kAITargetLuaHelpText
    );
    (void)binder;
  }
} // namespace moho
