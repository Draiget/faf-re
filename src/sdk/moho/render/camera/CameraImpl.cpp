#include "moho/render/camera/CameraImpl.h"

#include <cstring>

#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/script/CScriptEvent.h"

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kCameraImplLuaClassName = "CameraImpl";
  constexpr const char* kCameraImplMoveToName = "MoveTo";
  constexpr const char* kCameraImplMoveToHelpText = "Camera:MoveTo(position, orientationHPR, zoom, seconds)";

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet* FindUserLuaInitSet() noexcept
  {
    for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, "User") == 0) {
        return set;
      }
    }

    return nullptr;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindUserLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }
} // namespace

namespace moho
{
  CScrLuaMetatableFactory<CameraImpl> CScrLuaMetatableFactory<CameraImpl>::sInstance{};

  CScrLuaMetatableFactory<CameraImpl>& CScrLuaMetatableFactory<CameraImpl>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CameraImpl>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }
} // namespace moho

/**
 * Address: 0x007AB6E0 (FUN_007AB6E0, cfunc_CameraImplMoveTo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplMoveToL`.
 */
int moho::cfunc_CameraImplMoveTo(lua_State* const luaContext)
{
  return cfunc_CameraImplMoveToL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007AB760 (FUN_007AB760, cfunc_CameraImplMoveToL)
 *
 * What it does:
 * Validates `Camera:MoveTo(position, orientationHPR, zoom, seconds)`,
 * resolves typed camera/vector payloads from Lua, and dispatches manual camera
 * targeting with heading/pitch plus zoom/time lanes.
 */
int moho::cfunc_CameraImplMoveToL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCameraImplMoveToHelpText, 5, argumentCount);
  }

  const LuaPlus::LuaObject cameraObject(LuaPlus::LuaStackObject(state, 1));
  CameraImpl* const camera = SCR_FromLua_CameraImpl(cameraObject, state);

  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vec3f targetPosition = SCR_FromLuaCopy<Wm3::Vec3f>(positionObject);

  const LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 3));
  const Wm3::Vec3f orientationHpr = SCR_FromLuaCopy<Wm3::Vec3f>(orientationObject);

  const LuaPlus::LuaStackObject zoomObject(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    zoomObject.TypeError("number");
  }
  const float targetZoom = static_cast<float>(lua_tonumber(state->m_state, 4));

  const LuaPlus::LuaStackObject secondsObject(state, 5);
  if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
    secondsObject.TypeError("number");
  }
  const float transitionSeconds = static_cast<float>(lua_tonumber(state->m_state, 5));

  camera->TargetManual(targetPosition, orientationHpr.x, orientationHpr.y, targetZoom, transitionSeconds);
  return 0;
}

/**
 * Address: 0x007AB700 (FUN_007AB700, func_CameraImplMoveTo_LuaFuncDef)
 *
 * What it does:
 * Publishes Lua binder metadata for `CameraImpl:MoveTo`.
 */
moho::CScrLuaInitForm* moho::func_CameraImplMoveTo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kCameraImplMoveToName,
    &moho::cfunc_CameraImplMoveTo,
    &CScrLuaMetatableFactory<CameraImpl>::Instance(),
    kCameraImplLuaClassName,
    kCameraImplMoveToHelpText
  );
  return &binder;
}
