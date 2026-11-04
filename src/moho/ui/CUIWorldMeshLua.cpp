#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kLuaExpectedBetweenArgsWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kInternalCreateWorldMeshHelpText =
    "InternalCreateWorldMesh(luaobj) -- for internal use by WorldMesh()";
  constexpr const char* kCUIWorldMeshDestroyHelpText = "WorldMesh:Destroy() -- destroy this world mesh";
  constexpr const char* kCUIWorldMeshSetMeshHelpText = "WorldMesh:SetMesh(meshDesc)";
  constexpr const char* kCUIWorldMeshSetStanceHelpText =
    "WorldMesh:SetStance(vector position, [quaternion orientation])";
  constexpr const char* kCUIWorldMeshSetHiddenHelpText = "WorldMesh:SetHidden(bool hidden)";
  constexpr const char* kCUIWorldMeshIsHiddenHelpText = "bool WorldMesh:IsHidden()";
  constexpr const char* kCUIWorldMeshSetAuxiliaryParameterHelpText = "WorldMesh:SetAuxiliaryParameter(float param)";
  constexpr const char* kCUIWorldMeshSetFractionCompleteParameterHelpText =
    "WorldMesh:SetFractionCompleteParameter(float param)";
  constexpr const char* kCUIWorldMeshSetFractionHealthParameterHelpText =
    "WorldMesh:SetFractionHealthParameter(float param)";
  constexpr const char* kCUIWorldMeshSetLifetimeParameterHelpText = "WorldMesh:SetLifetimeParameter(float param)";
  constexpr const char* kCUIWorldMeshSetColorHelpText = "WorldMesh:SetColor(bool hidden)";
  constexpr const char* kCUIWorldMeshSetScaleHelpText = "WorldMesh:SetScale(vector scale)";
  constexpr const char* kCUIWorldMeshGetInterpolatedPositionHelpText = "Vector WorldMesh:GetInterpolatedPosition()";
  constexpr const char* kCUIWorldMeshGetInterpolatedSphereHelpText = "Vector WorldMesh:GetInterpolatedSphere()";
  constexpr const char* kCUIWorldMeshGetInterpolatedAlignedBoxHelpText = "Vector WorldMesh:GetInterpolatedAlignedBox()";
  constexpr const char* kCUIWorldMeshGetInterpolatedOrientedBoxHelpText =
    "Vector WorldMesh:GetInterpolatedOrientedBox()";
  constexpr const char* kCUIWorldMeshGetInterpolatedScrollHelpText = "Vector WorldMesh:GetInterpolatedScroll()";

  [[nodiscard]] gpg::RType* CachedCUIWorldMeshType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CUIWorldMesh");
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("Moho::CUIWorldMesh");
      }
    }
    return cached;
  }

  /**
   * Address: 0x0086D840 (FUN_0086D840, func_GetCUIWorldMeshObjectOpt)
   *
   * What it does:
   * Resolves one optional `CUIWorldMesh` from Lua object payload; raises Lua
   * errors for non-game-object or incorrect-type payloads and returns null
   * for destroyed objects.
   */
  [[nodiscard]] moho::CUIWorldMesh* ResolveCUIWorldMeshOptionalOrError(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* const state
  )
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = moho::SCR_ScriptObjectSlot(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    gpg::RType* const worldMeshType = CachedCUIWorldMeshType();
    if (worldMeshType == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, worldMeshType);
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CUIWorldMesh*>(upcast.mObj);
  }
}


/**
 * Address: 0x0086BB30 (FUN_0086BB30, cfunc_InternalCreateWorldMesh)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateWorldMeshL`.
 */
int moho::cfunc_InternalCreateWorldMesh(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateWorldMeshL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086BB50 (FUN_0086BB50, func_InternalCreateWorldMesh_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateWorldMesh(luaobj)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateWorldMesh_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateWorldMesh",
    &moho::cfunc_InternalCreateWorldMesh,
    nullptr,
    "<global>",
    kInternalCreateWorldMeshHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086BBB0 (FUN_0086BBB0, cfunc_InternalCreateWorldMeshL)
 *
 * What it does:
 * Builds one `CUIWorldMesh` from one Lua object lane and pushes the
 * script-object handle to Lua.
 */
int moho::cfunc_InternalCreateWorldMeshL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kInternalCreateWorldMeshHelpText);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x38)`.
  auto* const worldMesh = AllocateZeroedUiObject<CUIWorldMesh>(0x38u);
  new (worldMesh) CUIWorldMesh(luaObject);
  static_cast<CScriptObject*>(worldMesh)->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086BC90 (FUN_0086BC90, cfunc_CUIWorldMeshDestroy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshDestroyL`.
 */
int moho::cfunc_CUIWorldMeshDestroy(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshDestroyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086BCB0 (FUN_0086BCB0, func_CUIWorldMeshDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:Destroy()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Destroy",
    &moho::cfunc_CUIWorldMeshDestroy,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshDestroyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086BDC0 (FUN_0086BDC0, cfunc_CUIWorldMeshSetMesh)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetMeshL`.
 */
int moho::cfunc_CUIWorldMeshSetMesh(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshSetMeshL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086BDE0 (FUN_0086BDE0, func_CUIWorldMeshSetMesh_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetMesh(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetMesh_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetMesh",
    &moho::cfunc_CUIWorldMeshSetMesh,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetMeshHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086BF50 (FUN_0086BF50, cfunc_CUIWorldMeshSetStance)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetStanceL`.
 */
int moho::cfunc_CUIWorldMeshSetStance(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshSetStanceL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086BF70 (FUN_0086BF70, func_CUIWorldMeshSetStance_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetStance(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetStance_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetStance",
    &moho::cfunc_CUIWorldMeshSetStance,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetStanceHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C1D0 (FUN_0086C1D0, cfunc_CUIWorldMeshSetHidden)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetHiddenL`.
 */
int moho::cfunc_CUIWorldMeshSetHidden(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshSetHiddenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C1F0 (FUN_0086C1F0, func_CUIWorldMeshSetHidden_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetHidden(bool)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetHidden_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetHidden",
    &moho::cfunc_CUIWorldMeshSetHidden,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetHiddenHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C310 (FUN_0086C310, cfunc_CUIWorldMeshIsHidden)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshIsHiddenL`.
 */
int moho::cfunc_CUIWorldMeshIsHidden(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshIsHiddenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C330 (FUN_0086C330, func_CUIWorldMeshIsHidden_LuaFuncDef)
 *
 * What it does:
 * Publishes the `bool WorldMesh:IsHidden()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshIsHidden_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsHidden",
    &moho::cfunc_CUIWorldMeshIsHidden,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshIsHiddenHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C450 (FUN_0086C450, cfunc_CUIWorldMeshSetAuxiliaryParameter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetAuxiliaryParameterL`.
 */
int moho::cfunc_CUIWorldMeshSetAuxiliaryParameter(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshSetAuxiliaryParameterL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C470 (FUN_0086C470, func_CUIWorldMeshSetAuxiliaryParameter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetAuxiliaryParameter(float)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetAuxiliaryParameter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetAuxiliaryParameter",
    &moho::cfunc_CUIWorldMeshSetAuxiliaryParameter,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetAuxiliaryParameterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C5D0 (FUN_0086C5D0, cfunc_CUIWorldMeshSetFractionCompleteParameter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetFractionCompleteParameterL`.
 */
int moho::cfunc_CUIWorldMeshSetFractionCompleteParameter(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshSetFractionCompleteParameterL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C5F0 (FUN_0086C5F0, func_CUIWorldMeshSetFractionCompleteParameter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetFractionCompleteParameter(float)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetFractionCompleteParameter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetFractionCompleteParameter",
    &moho::cfunc_CUIWorldMeshSetFractionCompleteParameter,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetFractionCompleteParameterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C750 (FUN_0086C750, cfunc_CUIWorldMeshSetFractionHealthParameter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetFractionHealthParameterL`.
 */
int moho::cfunc_CUIWorldMeshSetFractionHealthParameter(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshSetFractionHealthParameterL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C770 (FUN_0086C770, func_CUIWorldMeshSetFractionHealthParameter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetFractionHealthParameter(float)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetFractionHealthParameter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetFractionHealthParameter",
    &moho::cfunc_CUIWorldMeshSetFractionHealthParameter,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetFractionHealthParameterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086C8D0 (FUN_0086C8D0, cfunc_CUIWorldMeshSetLifetimeParameter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetLifetimeParameterL`.
 */
int moho::cfunc_CUIWorldMeshSetLifetimeParameter(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshSetLifetimeParameterL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086C8F0 (FUN_0086C8F0, func_CUIWorldMeshSetLifetimeParameter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetLifetimeParameter(float)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetLifetimeParameter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetLifetimeParameter",
    &moho::cfunc_CUIWorldMeshSetLifetimeParameter,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetLifetimeParameterHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086CA50 (FUN_0086CA50, cfunc_CUIWorldMeshSetColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetColorL`.
 */
int moho::cfunc_CUIWorldMeshSetColor(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshSetColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086CA70 (FUN_0086CA70, func_CUIWorldMeshSetColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetColor",
    &moho::cfunc_CUIWorldMeshSetColor,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086CBB0 (FUN_0086CBB0, cfunc_CUIWorldMeshSetScale)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshSetScaleL`.
 */
int moho::cfunc_CUIWorldMeshSetScale(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshSetScaleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086CBD0 (FUN_0086CBD0, func_CUIWorldMeshSetScale_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WorldMesh:SetScale(vector scale)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshSetScale_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetScale",
    &moho::cfunc_CUIWorldMeshSetScale,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshSetScaleHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086BD10 (FUN_0086BD10, cfunc_CUIWorldMeshDestroyL)
 *
 * What it does:
 * Resolves one optional `CUIWorldMesh` and destroys it when still alive.
 */
int moho::cfunc_CUIWorldMeshDestroyL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldMeshDestroyHelpText);

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = ResolveCUIWorldMeshOptionalOrError(worldMeshObject, state);
  if (worldMesh != nullptr) {
    CScriptObject** const scriptObjectSlot = moho::SCR_ScriptObjectSlot(worldMeshObject);
    if (scriptObjectSlot != nullptr && *scriptObjectSlot != nullptr) {
      delete *scriptObjectSlot;
    }
  }
  return 1;
}

/**
 * Address: 0x0086BE40 (FUN_0086BE40, cfunc_CUIWorldMeshSetMeshL)
 *
 * What it does:
 * Resolves one `CUIWorldMesh` plus descriptor-table argument and forwards the
 * table into `CUIWorldMesh::SetMesh`.
 */
int moho::cfunc_CUIWorldMeshSetMeshL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshSetMeshHelpText);

  if (lua_type(state->m_state, 2) != LUA_TTABLE) {
    gpg::Warnf("WorldMesh: Expected second parameter to be table");
    return 0;
  }

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  const LuaPlus::LuaObject meshDescriptorObject(LuaPlus::LuaStackObject(state, 2));
  if (worldMesh != nullptr) {
    worldMesh->SetMesh(meshDescriptorObject);
  }
  return 0;
}

/**
 * Address: 0x0086BFD0 (FUN_0086BFD0, cfunc_CUIWorldMeshSetStanceL)
 *
 * What it does:
 * Updates world-mesh stance from `(position[, orientation])` by forwarding
 * one identical start/end transform to mesh-instance stance state.
 */
int moho::cfunc_CUIWorldMeshSetStanceL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(
      state, kLuaExpectedBetweenArgsWarning, kCUIWorldMeshSetStanceHelpText, 2, 3, argumentCount
    );
  }

  Wm3::Quaternionf orientation = Wm3::Quaternionf::Identity();
  if (lua_gettop(state->m_state) >= 3) {
    LuaPlus::LuaObject orientationObject(LuaPlus::LuaStackObject(state, 3));
    orientation = SCR_FromLuaCopy<Wm3::Quaternionf>(orientationObject);
  }

  LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3f>(positionObject);

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);
  MeshInstance* const meshInstance = worldMesh->mMeshInstance;
  if (meshInstance != nullptr) {
    VTransform stance{};
    stance.orient_ = orientation;
    stance.pos_ = position;
    meshInstance->SetStance(stance, stance);
  }
  return 0;
}

/**
 * Address: 0x0086C250 (FUN_0086C250, cfunc_CUIWorldMeshSetHiddenL)
 *
 * What it does:
 * Writes hidden flag lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetHiddenL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshSetHiddenHelpText);

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaStackObject hiddenArg(state, 2);
  const bool hidden = LuaPlus::LuaStackObject::GetBoolean(&hiddenArg);

  MeshInstance* const meshInstance = worldMesh->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->isHidden = hidden ? static_cast<std::uint8_t>(1u) : static_cast<std::uint8_t>(0u);
  }
  return 0;
}

/**
 * Address: 0x0086C390 (FUN_0086C390, cfunc_CUIWorldMeshIsHiddenL)
 *
 * What it does:
 * Pushes current hidden flag from underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshIsHiddenL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCUIWorldMeshIsHiddenHelpText);

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  bool isHidden = false;
  MeshInstance* const meshInstance = worldMesh->mMeshInstance;
  if (meshInstance != nullptr) {
    isHidden = meshInstance->isHidden != 0;
  }

  lua_pushboolean(state->m_state, isHidden ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 0;
}

/**
 * Address: 0x0086C4D0 (FUN_0086C4D0, cfunc_CUIWorldMeshSetAuxiliaryParameterL)
 *
 * What it does:
 * Writes auxiliary scalar parameter lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetAuxiliaryParameterL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshSetAuxiliaryParameterHelpText);

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaStackObject valueArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&valueArg, "number");
  }
  const float value = lua_tonumber(state->m_state, 2);

  MeshInstance* const meshInstance = worldMesh->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->auxiliaryParameter = value;
  }
  return 0;
}

/**
 * Address: 0x0086C650 (FUN_0086C650, cfunc_CUIWorldMeshSetFractionCompleteParameterL)
 *
 * What it does:
 * Writes fraction-complete scalar parameter lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetFractionCompleteParameterL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshSetFractionCompleteParameterHelpText);

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaStackObject valueArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&valueArg, "number");
  }
  const float value = lua_tonumber(state->m_state, 2);

  MeshInstance* const meshInstance = worldMesh->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->fractionCompleteParameter = value;
  }
  return 0;
}

/**
 * Address: 0x0086C7D0 (FUN_0086C7D0, cfunc_CUIWorldMeshSetFractionHealthParameterL)
 *
 * What it does:
 * Writes fraction-health scalar parameter lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetFractionHealthParameterL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshSetFractionHealthParameterHelpText);

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaStackObject valueArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&valueArg, "number");
  }
  const float value = lua_tonumber(state->m_state, 2);

  MeshInstance* const meshInstance = worldMesh->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->fractionHealthParameter = value;
  }
  return 0;
}

/**
 * Address: 0x0086C950 (FUN_0086C950, cfunc_CUIWorldMeshSetLifetimeParameterL)
 *
 * What it does:
 * Writes lifetime scalar parameter lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetLifetimeParameterL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshSetLifetimeParameterHelpText);

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaStackObject valueArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&valueArg, "number");
  }
  const float value = lua_tonumber(state->m_state, 2);

  MeshInstance* const meshInstance = worldMesh->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->lifetimeParameter = value;
  }
  return 0;
}

/**
 * Address: 0x0086CAD0 (FUN_0086CAD0, cfunc_CUIWorldMeshSetColorL)
 *
 * What it does:
 * Decodes one Lua color payload and writes packed color lane on underlying
 * `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshSetColorHelpText);

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  const std::uint32_t color = SCR_DecodeColor(state, colorObject);

  MeshInstance* const meshInstance = worldMesh->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->color = static_cast<std::int32_t>(color);
  }
  return 0;
}

/**
 * Address: 0x0086CC30 (FUN_0086CC30, cfunc_CUIWorldMeshSetScaleL)
 *
 * What it does:
 * Writes local scale vector lane on underlying `MeshInstance`.
 */
int moho::cfunc_CUIWorldMeshSetScaleL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshSetScaleHelpText);

  LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  LuaPlus::LuaObject scaleObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f scale = SCR_FromLuaCopy<Wm3::Vector3f>(scaleObject);

  MeshInstance* const meshInstance = worldMesh->mMeshInstance;
  if (meshInstance != nullptr) {
    meshInstance->scale = scale;
  }
  return 0;
}

/**
 * Address: 0x0086CD40 (FUN_0086CD40, cfunc_CUIWorldMeshGetInterpolatedPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshGetInterpolatedPositionL`.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedPosition(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshGetInterpolatedPositionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086CD60 (FUN_0086CD60, func_CUIWorldMeshGetInterpolatedPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Vector WorldMesh:GetInterpolatedPosition()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshGetInterpolatedPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetInterpolatedPosition",
    &moho::cfunc_CUIWorldMeshGetInterpolatedPosition,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshGetInterpolatedPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086CDC0 (FUN_0086CDC0, cfunc_CUIWorldMeshGetInterpolatedPositionL)
 *
 * What it does:
 * Reads one `CUIWorldMesh` and returns current interpolated world position
 * vector from underlying `MeshInstance` state.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedPositionL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshGetInterpolatedPositionHelpText);

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  Wm3::Vector3f interpolatedPosition{};
  if (worldMesh != nullptr) {
    MeshInstance* const meshInstance = worldMesh->mMeshInstance;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      interpolatedPosition = meshInstance->interpolatedPosition;
    }
  }

  LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3f>(state, interpolatedPosition);
  positionObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086CF00 (FUN_0086CF00, cfunc_CUIWorldMeshGetInterpolatedSphere)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshGetInterpolatedSphereL`.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedSphere(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshGetInterpolatedSphereL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086CF20 (FUN_0086CF20, func_CUIWorldMeshGetInterpolatedSphere_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Vector WorldMesh:GetInterpolatedSphere()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshGetInterpolatedSphere_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetInterpolatedSphere",
    &moho::cfunc_CUIWorldMeshGetInterpolatedSphere,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshGetInterpolatedSphereHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086CF80 (FUN_0086CF80, cfunc_CUIWorldMeshGetInterpolatedSphereL)
 *
 * What it does:
 * Reads one `CUIWorldMesh` and returns current interpolated bounding sphere
 * payload (`vector` center + `radius`) from `MeshInstance` state.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedSphereL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshGetInterpolatedSphereHelpText);

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  // The owner accessor at 0x0086AF80 does exactly this -- refresh the mesh
  // instance's interpolated lanes and hand back its world sphere -- so call it
  // by name instead of reaching through a CUIWorldMesh at +0x34.
  Wm3::Sphere3f sphere{};
  sphere.Center = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
  sphere.Radius = 0.0f;
  if (worldMesh != nullptr) {
    (void)worldMesh->GetWorldSphere(sphere);
  }
  const Wm3::Vector3f center = sphere.Center;
  const float radius = sphere.Radius;

  LuaPlus::LuaObject sphereObject;
  sphereObject.AssignNewTable(state, 2, 0);
  LuaPlus::LuaObject centerObject = SCR_ToLua<Wm3::Vector3f>(state, center);
  sphereObject.SetObject("vector", centerObject);
  sphereObject.SetNumber("radius", radius);
  sphereObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086D0F0 (FUN_0086D0F0, cfunc_CUIWorldMeshGetInterpolatedAlignedBox)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL`.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedAlignedBox(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086D110 (FUN_0086D110, func_CUIWorldMeshGetInterpolatedAlignedBox_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Vector WorldMesh:GetInterpolatedAlignedBox()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshGetInterpolatedAlignedBox_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetInterpolatedAlignedBox",
    &moho::cfunc_CUIWorldMeshGetInterpolatedAlignedBox,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshGetInterpolatedAlignedBoxHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086D170 (FUN_0086D170, cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL)
 *
 * What it does:
 * Reads one `CUIWorldMesh` and returns current interpolated axis-aligned
 * bounds payload from `MeshInstance` state.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshGetInterpolatedAlignedBoxHelpText);

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  // Same story as the sphere lane: 0x0086AFC0 is the owner accessor for these
  // six floats, so call it rather than re-reading MeshInstance through a view.
  Wm3::AxisAlignedBox3f bounds{};
  bounds.Min = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
  bounds.Max = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
  if (worldMesh != nullptr) {
    (void)worldMesh->GetWorldBounds(bounds);
  }
  const float xMin = bounds.Min.x;
  const float yMin = bounds.Min.y;
  const float zMin = bounds.Min.z;
  const float xMax = bounds.Max.x;
  const float yMax = bounds.Max.y;
  const float zMax = bounds.Max.z;

  LuaPlus::LuaObject alignedBoxObject;
  alignedBoxObject.AssignNewTable(state, 6, 0);
  alignedBoxObject.SetNumber("xMin", xMin);
  alignedBoxObject.SetNumber("yMin", yMin);
  alignedBoxObject.SetNumber("zMin", zMin);
  alignedBoxObject.SetNumber("xMax", xMax);
  // FAF hot-patch (FA-Binary-Patches FixGetInterpolatedAlignedBox): 0x0086D2C0 and 0x0086D2D6
  // push "yMax" and "zMax"; the stock binary wrote all three maxima under "xMax".
  alignedBoxObject.SetNumber("yMax", yMax);
  alignedBoxObject.SetNumber("zMax", zMax);
  alignedBoxObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086D320 (FUN_0086D320, cfunc_CUIWorldMeshGetInterpolatedOrientedBox)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL`.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedOrientedBox(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086D340 (FUN_0086D340, func_CUIWorldMeshGetInterpolatedOrientedBox_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Vector WorldMesh:GetInterpolatedOrientedBox()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshGetInterpolatedOrientedBox_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetInterpolatedOrientedBox",
    &moho::cfunc_CUIWorldMeshGetInterpolatedOrientedBox,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshGetInterpolatedOrientedBoxHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086D3A0 (FUN_0086D3A0, cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL)
 *
 * What it does:
 * Reads one `CUIWorldMesh` and returns current interpolated oriented-box
 * payload from `MeshInstance` state.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshGetInterpolatedOrientedBoxHelpText);

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  Wm3::Box3f box{};
  if (worldMesh != nullptr) {
    MeshInstance* const meshInstance = worldMesh->mMeshInstance;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      box = meshInstance->box;
    }
  }

  const Wm3::Vector3f center(box.Center[0], box.Center[1], box.Center[2]);
  const Wm3::Vector3f xAxis(box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]);
  const Wm3::Vector3f yAxis(box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]);
  const Wm3::Vector3f zAxis(box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]);

  LuaPlus::LuaObject orientedBoxObject;
  orientedBoxObject.AssignNewTable(state, 7, 0);

  LuaPlus::LuaObject centerObject = SCR_ToLua<Wm3::Vector3f>(state, center);
  orientedBoxObject.SetObject("center", centerObject);

  LuaPlus::LuaObject xAxisObject = SCR_ToLua<Wm3::Vector3f>(state, xAxis);
  orientedBoxObject.SetObject("xAxis", xAxisObject);

  LuaPlus::LuaObject yAxisObject = SCR_ToLua<Wm3::Vector3f>(state, yAxis);
  orientedBoxObject.SetObject("yAxis", yAxisObject);

  LuaPlus::LuaObject zAxisObject = SCR_ToLua<Wm3::Vector3f>(state, zAxis);
  orientedBoxObject.SetObject("zAxis", zAxisObject);

  orientedBoxObject.SetNumber("xExtent", box.Extent[0]);
  orientedBoxObject.SetNumber("yExtent", box.Extent[1]);
  orientedBoxObject.SetNumber("zExtent", box.Extent[2]);
  orientedBoxObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086D5E0 (FUN_0086D5E0, cfunc_CUIWorldMeshGetInterpolatedScroll)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUIWorldMeshGetInterpolatedScrollL`.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedScroll(
  lua_State* const luaContext
)
{
  return cfunc_CUIWorldMeshGetInterpolatedScrollL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086D600 (FUN_0086D600, func_CUIWorldMeshGetInterpolatedScroll_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Vector WorldMesh:GetInterpolatedScroll()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUIWorldMeshGetInterpolatedScroll_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetInterpolatedScroll",
    &moho::cfunc_CUIWorldMeshGetInterpolatedScroll,
    &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
    "CUIWorldMesh",
    kCUIWorldMeshGetInterpolatedScrollHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086D660 (FUN_0086D660, cfunc_CUIWorldMeshGetInterpolatedScrollL)
 *
 * What it does:
 * Reads one `CUIWorldMesh` and returns current interpolated UV scroll vector
 * from underlying `MeshInstance` state.
 */
int moho::cfunc_CUIWorldMeshGetInterpolatedScrollL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCUIWorldMeshGetInterpolatedScrollHelpText);

  const LuaPlus::LuaObject worldMeshObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldMesh* const worldMesh = SCR_FromLua_CUIWorldMesh(worldMeshObject, state);

  Wm3::Vector2f interpolatedScroll{};
  if (worldMesh != nullptr) {
    MeshInstance* const meshInstance = worldMesh->mMeshInstance;
    if (meshInstance != nullptr) {
      const float t = MeshInstance::sCurrentInterpolant;
      interpolatedScroll.x = meshInstance->scroll1.x + (t * (meshInstance->scroll2.x - meshInstance->scroll1.x));
      interpolatedScroll.y = meshInstance->scroll1.y + (t * (meshInstance->scroll2.y - meshInstance->scroll1.y));
    }
  }

  LuaPlus::LuaObject interpolatedScrollObject = SCR_ToLua<Wm3::Vector2f>(state, interpolatedScroll);
  interpolatedScrollObject.PushStack(state);
  return 1;
}
