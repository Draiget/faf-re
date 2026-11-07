#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kInternalCreateMeshHelpText =
    "InternalCreateMesh(luaobj,parent) -- for internal use by CreateMesh()";
  constexpr const char* kCMauiMeshSetMeshHelpText = "SetMesh(meshBPName)";
  constexpr const char* kCMauiMeshSetOrientationHelpText = "SetOrientation(quaternion)";
}


/**
 * Address: 0x0079E590 (FUN_0079E590, cfunc_InternalCreateMesh)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateMeshL`.
 */
int moho::cfunc_InternalCreateMesh(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateMeshL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079E5B0 (FUN_0079E5B0, func_InternalCreateMesh_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateMesh(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateMesh_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateMesh",
    &moho::cfunc_InternalCreateMesh,
    nullptr,
    "<global>",
    kInternalCreateMeshHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079E610 (FUN_0079E610, cfunc_InternalCreateMeshL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiMesh`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateMeshL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kInternalCreateMeshHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x140)`.
  auto* const mesh = AllocateZeroedUiObject<CMauiMesh>(0x140u);
  new (mesh) CMauiMesh(&luaObject, parentControl);
  mesh->DoInit();
  mesh->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0079E740 (FUN_0079E740, cfunc_CMauiMeshSetMesh)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMeshSetMeshL`.
 */
int moho::cfunc_CMauiMeshSetMesh(
  lua_State* const luaContext
)
{
  return cfunc_CMauiMeshSetMeshL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079E760 (FUN_0079E760, func_CMauiMeshSetMesh_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMesh:SetMesh(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMeshSetMesh_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetMesh",
    &moho::cfunc_CMauiMeshSetMesh,
    &moho::CScrLuaMetatableFactory<moho::CMauiMesh>::Instance(),
    "CMauiMesh",
    kCMauiMeshSetMeshHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079E7C0 (FUN_0079E7C0, cfunc_CMauiMeshSetMeshL)
 *
 * What it does:
 * Reads one `CMauiMesh` plus mesh-path string and calls `SetMesh`.
 */
int moho::cfunc_CMauiMeshSetMeshL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiMeshSetMeshHelpText);

  LuaPlus::LuaObject meshObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMesh* const mesh = SCR_FromLua_CMauiMesh(meshObject, state);

  LuaPlus::LuaStackObject meshArg(state, 2);
  const char* meshBlueprintName = lua_tostring(state->m_state, 2);
  if (meshBlueprintName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&meshArg, "string");
    meshBlueprintName = "";
  }

  mesh->SetMesh(meshBlueprintName);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079E8B0 (FUN_0079E8B0, cfunc_CMauiMeshSetOrientation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiMeshSetOrientationL`.
 */
int moho::cfunc_CMauiMeshSetOrientation(
  lua_State* const luaContext
)
{
  return cfunc_CMauiMeshSetOrientationL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079E8D0 (FUN_0079E8D0, func_CMauiMeshSetOrientation_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMesh:SetOrientation(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMeshSetOrientation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetOrientation",
    &moho::cfunc_CMauiMeshSetOrientation,
    &moho::CScrLuaMetatableFactory<moho::CMauiMesh>::Instance(),
    "CMauiMesh",
    kCMauiMeshSetOrientationHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079E930 (FUN_0079E930, cfunc_CMauiMeshSetOrientationL)
 *
 * What it does:
 * Reads one `CMauiMesh` plus quaternion arg and stores mesh orientation
 * (`CMauiMesh::SetOrientation`, inlined here in the binary).
 */
int moho::cfunc_CMauiMeshSetOrientationL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiMeshSetOrientationHelpText);

  const LuaPlus::LuaObject meshObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMesh* const mesh = SCR_FromLua_CMauiMesh(meshObject, state);

  const LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Quaternionf orientation = SCR_FromLuaCopy<Wm3::Quaternionf>(orientationObject);
  mesh->SetOrientation(orientation);

  lua_settop(state->m_state, 1);
  return 1;
}
