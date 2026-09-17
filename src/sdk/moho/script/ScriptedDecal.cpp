#include "moho/script/ScriptedDecal.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <typeinfo>

#include "lua/LuaRuntimeTypes.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaClassBinder.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/math/Vector3f.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/CWldTerrainDecal.h"
#include "moho/render/RCamManager.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/script/CScriptEvent.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "Wm3Vector2.h"

using namespace moho;

namespace moho
{
  template <>
  class CScrLuaMetatableFactory<ScriptedDecal> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<ScriptedDecal>) == 0x08, "CScrLuaMetatableFactory<ScriptedDecal> size must be 0x08");
} // namespace moho

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kScriptedDecalLuaClassName = "ScriptedDecal";

  constexpr const char* kScriptedDecalSetTextureName = "SetTexture";
  constexpr const char* kScriptedDecalSetTextureHelpText = "Set the texture and add it to the decal manager";
  constexpr const char* kScriptedDecalSetScaleName = "SetScale";
  constexpr const char* kScriptedDecalSetScaleHelpText = "Scale the text";
  constexpr const char* kScriptedDecalSetPositionByScreenName = "SetPositionByScreen";
  constexpr const char* kScriptedDecalSetPositionByScreenHelpText = "Set the position based on screen space mouse coords";
  constexpr const char* kScriptedDecalSetPositionName = "SetPosition";
  constexpr const char* kScriptedDecalSetPositionHelpText = "Set the position based on wolrd coords";
  constexpr const char* kScriptedDecalDestroyName = "Destroy";
  constexpr const char* kScriptedDecalDestroyHelpText = "Kill it";
  constexpr const char* kScriptedDecalCreateDecalName = "_c_CreateDecal";
  constexpr const char* kScriptedDecalCreateDecalHelpText = "Create a decal in the user layer";

  /**
   * Address: 0x0087F010 (FUN_0087F010)
   *
   * What it does:
   * Lazily resolves and caches reflection RTTI for `moho::ScriptedDecal`.
   */
  [[nodiscard]] gpg::RType* CachedScriptedDecalType()
  {
    if (!ScriptedDecal::sType) {
      ScriptedDecal::sType = gpg::LookupRType(typeid(ScriptedDecal));
    }
    return ScriptedDecal::sType;
  }

  /**
   * Address: 0x0087FA80 (FUN_0087FA80)
   *
   * What it does:
   * Adapter lane that forwards scripted-decal RTTI cache lookup to the
   * canonical cached-type helper.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedScriptedDecalTypeAdapter()
  {
    gpg::RType* result = ScriptedDecal::sType;
    if (!ScriptedDecal::sType) {
      result = gpg::LookupRType(typeid(ScriptedDecal));
      ScriptedDecal::sType = result;
    }
    return result;
  }

  [[nodiscard]] gpg::RRef MakeScriptedDecalRef(ScriptedDecal* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedScriptedDecalType();
    return ref;
  }

  [[nodiscard]] CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }

} // namespace

CScrLuaMetatableFactory<ScriptedDecal> CScrLuaMetatableFactory<ScriptedDecal>::sInstance{};

CScrLuaMetatableFactory<ScriptedDecal>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

CScrLuaMetatableFactory<ScriptedDecal>& CScrLuaMetatableFactory<ScriptedDecal>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject CScrLuaMetatableFactory<ScriptedDecal>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

gpg::RType* ScriptedDecal::sType = nullptr;

/**
 * Address: 0x0087EB60 (FUN_0087EB60, Moho::ScriptedDecal::ScriptedDecal)
 *
 * What it does:
 * Initializes one scripted decal from the active world session and the
 * supplied Lua object payload.
 */
ScriptedDecal::ScriptedDecal(CWldSession* const session, LuaPlus::LuaObject luaObject)
  : CScriptObject()
  , mDecal{}
  , mDynamicTexture{}
  , mDecalManager(session->mWldMap->mTerrainRes->GetDecalManager())
  , mWorldCamera(CAM_GetManager()->GetCamera("WorldCamera"))
  , mScale{1.0f, 1.0f, 1.0f}
  // The binary leaves the position lane uninitialized here (0x0087EB60 writes
  // +0x34..+0x40 and +0x4C..+0x54 and nothing else), and `SetScale` reads it
  // before any `SetPosition` supplies one - FAF's cursor decals are built as
  // SetTexture/SetScale and only positioned on the next frame. Zeroing it
  // keeps that first frame's decal at the map origin instead of at whatever
  // the allocator left behind.
  , mWorldPosition{}
{
  SetLuaObject(luaObject);
}

/**
 * Address: 0x0087EC20 (FUN_0087EC20, non-deleting body)
 *
 * What it does:
 * Hands this decal's terrain decal back to the manager. The weak lane's own
 * unlink, the texture release and the base teardown that follow it in the
 * binary are compiler-emitted member/base destruction.
 */
ScriptedDecal::~ScriptedDecal()
{
  if (CWldTerrainDecal* const decal = mDecal.GetObjectPtr(); decal != nullptr) {
    mDecalManager->DestroyDecal(decal);
  }
}

/**
 * Address: 0x0087F030 (FUN_0087F030, ?GetClass@ScriptedDecal@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* ScriptedDecal::GetClass() const
{
  return CachedScriptedDecalType();
}

/**
 * Address: 0x0087F050 (FUN_0087F050, ?GetDerivedObjectRef@ScriptedDecal@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef ScriptedDecal::GetDerivedObjectRef()
{
  return MakeScriptedDecalRef(this);
}

/**
 * Address: 0x0087F1E0 (FUN_0087F1E0, cfunc__c_CreateDecal)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc__c_CreateDecalL`.
 */
int moho::cfunc__c_CreateDecal(lua_State* const luaContext)
{
  return cfunc__c_CreateDecalL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F200 (FUN_0087F200, func__c_CreateDecal_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `_c_CreateDecal`.
 */
moho::CScrLuaInitForm* moho::func__c_CreateDecal_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalCreateDecalName,
    &moho::cfunc__c_CreateDecal,
    nullptr,
    "<global>",
    kScriptedDecalCreateDecalHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F260 (FUN_0087F260, cfunc__c_CreateDecalL)
 *
 * What it does:
 * Creates one scripted decal from the active world session and returns its
 * Lua object, or nil when no session is active.
 */
int moho::cfunc__c_CreateDecalL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kScriptedDecalCreateDecalHelpText, 1, argumentCount);
  }

  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
    ScriptedDecal* const decal = new ScriptedDecal(session, decalObject);
    decal->mLuaObj.PushStack(state);
    return 1;
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0087ECE0 (FUN_0087ECE0, Moho::ScriptedDecal::SetPosition)
 *
 * What it does:
 * Stores one world-space position, shifts the decal quad half its own extent
 * so it is centred on that point, and republishes the terrain decal's
 * transform. A NaN position is dropped without touching any lane.
 */
void ScriptedDecal::SetPosition(const Wm3::Vector3f& worldPosition)
{
  if (!IsValidVector3f(worldPosition)) {
    return;
  }

  if (mDecalManager != nullptr) {
    mDecalManager->MarkPendingChanges();
  }

  mWorldPosition = worldPosition;
  mWorldPosition.x -= mScale.x * 0.5f;
  mWorldPosition.z -= mScale.z * 0.5f;

  // 0x0087ED43 dereferences the weak lane without a null test, so the binary
  // faults here when no `SetTexture` call has built a decal yet. Skipping is
  // the only divergence, and it only covers the case the original crashed in.
  if (CWldTerrainDecal* const decal = mDecal.GetObjectPtr(); decal != nullptr) {
    decal->mPosition = mWorldPosition;
    decal->Update();
  }
}

/**
 * Address: 0x0087ED70 (FUN_0087ED70, Moho::ScriptedDecal::SetPositionByScreen)
 *
 * What it does:
 * Projects one screen-space point onto the terrain through the world camera
 * and applies the resulting world-space position.
 */
void ScriptedDecal::SetPositionByScreen(const Wm3::Vector2f& screenPoint)
{
  SetPosition(mWorldCamera->CameraScreenToSurface(screenPoint));
}

/**
 * Address: 0x0087ED90 (FUN_0087ED90, Moho::ScriptedDecal::SetScale)
 *
 * What it does:
 * Resizes this decal and the terrain decal it owns, then reapplies the current
 * position so the quad stays centred on it.
 */
void ScriptedDecal::SetScale(const Wm3::Vector3f& scale)
{
  mScale = scale;

  // Same missing null test as `SetPosition` above, at 0x0087EDA4.
  if (CWldTerrainDecal* const decal = mDecal.GetObjectPtr(); decal != nullptr) {
    decal->mScale = scale;
    decal->Update();
  }

  SetPosition(mWorldPosition);
}

/**
 * Address: 0x0087EDE0 (FUN_0087EDE0, Moho::ScriptedDecal::SetTexture)
 *
 * What it does:
 * Loads one texture by path and rebuilds this decal's terrain decal around it.
 * The previous decal is handed back to the manager, a fresh one is created
 * with the texture in name slot 0 and both distance-fade cutoffs pushed out to
 * FLT_MAX so the decal never fades with camera distance, and it is added to the
 * manager's splat list. A texture that fails to load leaves this decal without
 * a terrain decal, exactly as in the binary.
 */
void ScriptedDecal::SetTexture(const char* const texturePath)
{
  if (CWldTerrainDecal* const previousDecal = mDecal.GetObjectPtr(); previousDecal != nullptr) {
    mDecalManager->DestroyDecal(previousDecal);
  }

  ID3DDeviceResources::TextureResourceHandle loadedTexture;
  D3D_GetDevice()->GetResources()->GetTexture(loadedTexture, texturePath, 0, true);
  mDynamicTexture = loadedTexture;

  if (!mDynamicTexture) {
    return;
  }

  CWldTerrainDecal* const decal = mDecalManager->LoadDecal(nullptr);
  mDecal.Set(decal);

  decal->mFidelity = 0;
  decal->mType = WldTerrainDecalType_WaterAlbedo;
  decal->SetName(texturePath, 0);
  decal->mNearCutoff = 0.0f;
  decal->mCutoffLOD = std::numeric_limits<float>::max();
  decal->mEntry.UpdateDissolveCutoff(std::numeric_limits<float>::max());
  decal->EnableFlatOptimization(false);
  mDecalManager->AddSplat(decal);
}

/**
 * Address: 0x0087F360 (FUN_0087F360, cfunc_ScriptedDecalSetTexture)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalSetTextureL`.
 */
int moho::cfunc_ScriptedDecalSetTexture(lua_State* const luaContext)
{
  return cfunc_ScriptedDecalSetTextureL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F380 (FUN_0087F380, func_ScriptedDecalSetTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `ScriptedDecal:SetTexture(path)` Lua binder.
 */
CScrLuaInitForm* moho::func_ScriptedDecalSetTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalSetTextureName,
    &moho::cfunc_ScriptedDecalSetTexture,
    &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
    kScriptedDecalLuaClassName,
    kScriptedDecalSetTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F3E0 (FUN_0087F3E0, cfunc_ScriptedDecalSetTextureL)
 *
 * What it does:
 * Validates one scripted decal plus one texture-path string, then applies the texture.
 */
int moho::cfunc_ScriptedDecalSetTextureL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kScriptedDecalSetTextureHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
  ScriptedDecal* const decal = SCR_FromLua_ScriptedDecal(decalObject, state);

  const char* const texturePath = lua_tostring(rawState, 2);
  if (texturePath == nullptr) {
    LuaPlus::LuaStackObject textureArg(state, 2);
    LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
    return 0;
  }

  decal->SetTexture(texturePath);
  return 0;
}

/**
 * Address: 0x0087F4C0 (FUN_0087F4C0, cfunc_ScriptedDecalSetScale)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalSetScaleL`.
 */
int moho::cfunc_ScriptedDecalSetScale(lua_State* const luaContext)
{
  return cfunc_ScriptedDecalSetScaleL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F4E0 (FUN_0087F4E0, func_ScriptedDecalSetScale_LuaFuncDef)
 *
 * What it does:
 * Publishes the `ScriptedDecal:SetScale(scaleVec3)` Lua binder.
 */
CScrLuaInitForm* moho::func_ScriptedDecalSetScale_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalSetScaleName,
    &moho::cfunc_ScriptedDecalSetScale,
    &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
    kScriptedDecalLuaClassName,
    kScriptedDecalSetScaleHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F540 (FUN_0087F540, cfunc_ScriptedDecalSetScaleL)
 *
 * What it does:
 * Reads one scale vector, updates runtime decal scale lanes, and reapplies position.
 */
int moho::cfunc_ScriptedDecalSetScaleL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kScriptedDecalSetScaleHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
  ScriptedDecal* const decal = SCR_FromLua_ScriptedDecal(decalObject, state);

  const LuaPlus::LuaObject scaleObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f scale = SCR_FromLuaCopy<Wm3::Vector3f>(scaleObject);
  decal->SetScale(scale);
  return 0;
}

/**
 * Address: 0x0087F660 (FUN_0087F660, cfunc_ScriptedDecalSetPositionByScreen)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_ScriptedDecalSetPositionByScreenL`.
 */
int moho::cfunc_ScriptedDecalSetPositionByScreen(lua_State* const luaContext)
{
  return cfunc_ScriptedDecalSetPositionByScreenL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F680 (FUN_0087F680, func_ScriptedDecalSetPositionByScreen_LuaFuncDef)
 *
 * What it does:
 * Publishes the `ScriptedDecal:SetPositionByScreen(screenPoint)` Lua binder.
 */
CScrLuaInitForm* moho::func_ScriptedDecalSetPositionByScreen_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalSetPositionByScreenName,
    &moho::cfunc_ScriptedDecalSetPositionByScreen,
    &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
    kScriptedDecalLuaClassName,
    kScriptedDecalSetPositionByScreenHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F6E0 (FUN_0087F6E0, cfunc_ScriptedDecalSetPositionByScreenL)
 *
 * What it does:
 * Converts one screen-space point via world camera projection and applies it.
 */
int moho::cfunc_ScriptedDecalSetPositionByScreenL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kScriptedDecalSetPositionByScreenHelpText,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
  ScriptedDecal* const decal = SCR_FromLua_ScriptedDecal(decalObject, state);

  const LuaPlus::LuaObject screenPointObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector2f screenPoint = SCR_FromLuaCopy<Wm3::Vector2f>(screenPointObject);
  decal->SetPositionByScreen(screenPoint);
  return 0;
}

/**
 * Address: 0x0087F7E0 (FUN_0087F7E0, cfunc_ScriptedDecalSetPosition)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalSetPositionL`.
 */
int moho::cfunc_ScriptedDecalSetPosition(lua_State* const luaContext)
{
  return cfunc_ScriptedDecalSetPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F800 (FUN_0087F800, func_ScriptedDecalSetPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `ScriptedDecal:SetPosition(worldPoint)` Lua binder.
 */
CScrLuaInitForm* moho::func_ScriptedDecalSetPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalSetPositionName,
    &moho::cfunc_ScriptedDecalSetPosition,
    &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
    kScriptedDecalLuaClassName,
    kScriptedDecalSetPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F860 (FUN_0087F860, cfunc_ScriptedDecalSetPositionL)
 *
 * What it does:
 * Reads one world-space vector argument and applies it via `ScriptedDecal::SetPosition`.
 */
int moho::cfunc_ScriptedDecalSetPositionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kScriptedDecalSetPositionHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
  ScriptedDecal* const decal = SCR_FromLua_ScriptedDecal(decalObject, state);

  // 0x0087F8F7 stages the argument's stack index as 2, the same lane every
  // other binder in this file reads. The previous "binary parity" note here
  // claimed index 3, which is past the end of a `decal:SetPosition(pos)` call
  // and fed the decal a junk position every frame.
  const LuaPlus::LuaObject worldPointObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f worldPoint = SCR_FromLuaCopy<Wm3::Vector3f>(worldPointObject);
  decal->SetPosition(worldPoint);
  return 0;
}

/**
 * Address: 0x0087F950 (FUN_0087F950, cfunc_ScriptedDecalDestroy)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalDestroyL`.
 */
int moho::cfunc_ScriptedDecalDestroy(lua_State* const luaContext)
{
  return cfunc_ScriptedDecalDestroyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F970 (FUN_0087F970, func_ScriptedDecalDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `ScriptedDecal:Destroy()` Lua binder.
 */
CScrLuaInitForm* moho::func_ScriptedDecalDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalDestroyName,
    &moho::cfunc_ScriptedDecalDestroy,
    &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
    kScriptedDecalLuaClassName,
    kScriptedDecalDestroyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F9D0 (FUN_0087F9D0, cfunc_ScriptedDecalDestroyL)
 *
 * What it does:
 * Resolves one scripted decal object and destroys it through virtual delete lane.
 */
int moho::cfunc_ScriptedDecalDestroyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kScriptedDecalDestroyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
  ScriptedDecal* const decal = SCR_FromLua_ScriptedDecal(decalObject, state);
  if (decal != nullptr) {
    delete decal;
  }

  return 0;
}




namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  /**
   * Class-binder record at 0x00F5B6B8 (`.rdata`), the same table region as
   * the other already-recovered class binders (e.g. `"moho.AimManipulator"`
   * at 0x00F59A20). Its fields read:
   *
   *     name  0x00E498B4 -> "moho.userDecal_methods"
   *     group 0x00E498A4 -> "ScriptedDecal"
   *     help  0x00E00779 -> ""
   *
   * What it does:
   * Publishes `CScrLuaMetatableFactory<ScriptedDecal>`'s method table as
   * `moho.userDecal_methods`. `gamedata/lua/user/UserDecal.lua:3` does
   * `UserDecal = Class(moho.userDecal_methods) { ... }` at module load time
   * -- without this export that read is nil and the whole module fails to
   * load, same failure family as the `moho.IEffect` gap this session already
   * found and fixed (`f36336a0`).
   */
  CScrLuaInitForm* register_moho_userDecal_methods_ClassBinder()
  {
    static CScrLuaClassBinder binder(
      UserLuaInitSet(), "moho.userDecal_methods", &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
      kScriptedDecalLuaClassName, ""
    );
    return &binder;
  }

  struct ScriptedDecalLuaFuncDefBootstrap
  {
    ScriptedDecalLuaFuncDefBootstrap()
    {
      (void)::moho::func__c_CreateDecal_LuaFuncDef();
      (void)register_moho_userDecal_methods_ClassBinder();
      (void)::moho::func_ScriptedDecalSetTexture_LuaFuncDef();
      (void)::moho::func_ScriptedDecalSetScale_LuaFuncDef();
      (void)::moho::func_ScriptedDecalSetPositionByScreen_LuaFuncDef();
      (void)::moho::func_ScriptedDecalSetPosition_LuaFuncDef();
      (void)::moho::func_ScriptedDecalDestroy_LuaFuncDef();
    }
  };

  const ScriptedDecalLuaFuncDefBootstrap gScriptedDecalLuaFuncDefBootstrap{};
} // namespace
