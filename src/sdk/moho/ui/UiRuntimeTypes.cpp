#include "moho/ui/UiRuntimeTypes.h"

#include <Windows.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <new>
#include <typeinfo>
#include <vector>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"

namespace
{
  static_assert(
    sizeof(moho::CScriptLazyVar_float) >= sizeof(LuaPlus::LuaObject),
    "CScriptLazyVar_float must remain LuaObject-compatible"
  );

  [[nodiscard]] LuaPlus::LuaObject& AsLazyVarObject(moho::CScriptLazyVar_float& value) noexcept
  {
    return reinterpret_cast<LuaPlus::LuaObject&>(value);
  }

  [[nodiscard]] const LuaPlus::LuaObject& AsLazyVarObject(const moho::CScriptLazyVar_float& value) noexcept
  {
    return reinterpret_cast<const LuaPlus::LuaObject&>(value);
  }

  LuaPlus::LuaState* gUserLuaState = nullptr;
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kCursorSetDefaultTextureHelpText = "Cursor:SetDefaultTexture(filename, hotspotX, hotspotY)";
  constexpr const char* kCUIWorldViewZoomScaleHelpText =
    "ZoomScale(x, y, wheelRot, wheelDelta) - cause the world to zoom based on wheel rotation event";

  struct CameraZoomRuntimeView
  {
    void* vftable = nullptr;

    void SetZoomAnchor(float* const zoomAnchor)
    {
      using SetZoomAnchorFn = void(__thiscall*)(CameraZoomRuntimeView*, float*);
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<SetZoomAnchorFn>(table[30]);
      fn(this, zoomAnchor);
    }

    void ApplyWheelZoomRatio(const float zoomRatio)
    {
      using ApplyWheelZoomRatioFn = void(__thiscall*)(CameraZoomRuntimeView*, float);
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<ApplyWheelZoomRatioFn>(table[31]);
      fn(this, zoomRatio);
    }
  };

  struct CRenderWorldViewRuntimeView
  {
    void* vftable = nullptr;

    [[nodiscard]] CameraZoomRuntimeView* GetCamera()
    {
      using GetCameraFn = CameraZoomRuntimeView*(__thiscall*)(CRenderWorldViewRuntimeView*);
      auto** const table = reinterpret_cast<void**>(vftable);
      auto* const fn = reinterpret_cast<GetCameraFn>(table[3]);
      return fn(this);
    }
  };

  struct CUIWorldViewRuntimeView
  {
    std::uint8_t mUnknown00To11B[0x11C]{};
    CRenderWorldViewRuntimeView mRenderWorldView{};

    [[nodiscard]] static CUIWorldViewRuntimeView* FromWorldView(moho::CUIWorldView* worldView) noexcept
    {
      return reinterpret_cast<CUIWorldViewRuntimeView*>(worldView);
    }
  };

  static_assert(
    offsetof(CUIWorldViewRuntimeView, mRenderWorldView) == 0x11C,
    "CUIWorldViewRuntimeView::mRenderWorldView offset must be 0x11C"
  );

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  struct WindowEventHandlerChain
  {
    wxWindowBase* window = nullptr;
    std::vector<moho::wxEvtHandlerRuntime*> handlers{};
  };

  std::vector<WindowEventHandlerChain> gWindowEventHandlerChains;

  [[nodiscard]]
  std::vector<WindowEventHandlerChain>::iterator FindWindowEventHandlerChain(const wxWindowBase* const window)
  {
    return std::find_if(
      gWindowEventHandlerChains.begin(),
      gWindowEventHandlerChains.end(),
      [window](const WindowEventHandlerChain& chain) { return chain.window == window; }
    );
  }

  gpg::RType* CachedCScriptObjectPointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CScriptObject*));
    }
    return cached;
  }

  gpg::RType* CachedCMauiFrameType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CMauiFrame));
    }
    return cached;
  }

  gpg::RType* CachedCMauiCursorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CMauiCursor));
    }
    return cached;
  }

  LuaPlus::LuaObject GetTableFieldByName(const LuaPlus::LuaObject& tableObject, const char* const fieldName)
  {
    LuaPlus::LuaObject out{};
    LuaPlus::LuaState* const state = tableObject.GetActiveState();
    if (!state) {
      return out;
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return out;
    }

    const int savedTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(tableObject).PushStack(lstate);
    lua_pushstring(lstate, fieldName ? fieldName : "");
    lua_gettable(lstate, -2);
    out = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
    lua_settop(lstate, savedTop);
    return out;
  }

  gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int savedTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const raw = lua_touserdata(lstate, -1);
    if (raw) {
      out = *static_cast<gpg::RRef*>(raw);
    }
    lua_settop(lstate, savedTop);
    return out;
  }

  moho::CScriptObject** ExtractScriptObjectSlotFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = GetTableFieldByName(payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, CachedCScriptObjectPointerType());
    return static_cast<moho::CScriptObject**>(upcast.mObj);
  }

  [[nodiscard]] moho::CMauiFrame* ResolveFrameFromLuaObjectOrError(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kDestroyedGameObjectError = "Game object has been destroyed";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCMauiFrameType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CMauiFrame*>(upcast.mObj);
  }

  [[nodiscard]] moho::CMauiCursor* ResolveCursorFromLuaObjectOrError(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kDestroyedGameObjectError = "Game object has been destroyed";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCMauiCursorType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CMauiCursor*>(upcast.mObj);
  }

  /**
   * Address: 0x0040D820 (FUN_0040D820, func_round)
   *
   * What it does:
   * Applies x87-style nearby-int rounding and adjusts down by one when the
   * original value sits below the rounded lane.
   */
  [[nodiscard]] int FloorFrndintAdjustDown(const float value) noexcept
  {
    const float rounded = std::nearbyintf(value);
    return static_cast<int>(rounded) + ((value < rounded) ? -1 : 0);
  }

  [[nodiscard]] moho::CD3DPrimBatcher::Vertex MakeBorderVertex(
    const float x,
    const float y,
    const std::uint32_t color,
    const float u,
    const float v
  ) noexcept
  {
    moho::CD3DPrimBatcher::Vertex vertex{};
    vertex.mX = x;
    vertex.mY = y;
    vertex.mZ = 0.0f;
    vertex.mColor = color;
    vertex.mU = u;
    vertex.mV = v;
    return vertex;
  }

  void ApplyCursorDefaultTexture(moho::CMauiCursor* const cursor, const char* const texturePath)
  {
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    moho::ID3DDeviceResources* const resources = device->GetResources();
    moho::ID3DDeviceResources::TextureResourceHandle loadedTexture{};
    resources->GetTexture(loadedTexture, texturePath, 0, false);

    auto* const cursorView = moho::CMauiCursorTextureRuntimeView::FromCursor(cursor);
    if (loadedTexture.get() == cursorView->mDefaultTexture.get()) {
      return;
    }

    if (cursorView->mTexture.get() == cursorView->mDefaultTexture.get()) {
      cursorView->mTexture = loadedTexture;
      cursorView->mIsDefaultTexture = true;
    }

    cursorView->mDefaultTexture = loadedTexture;
  }
} // namespace

moho::EUIState moho::sUIState = moho::UIS_none;

/**
 * Address: 0x007836E0 (FUN_007836E0, ??0CScriptLazyVar_float@Moho@@QAE@@Z)
 *
 * What it does:
 * Imports `/lua/lazyvar.lua` and initializes this lazy-var from
 * `lazyvar.Create(0.0)`.
 */
moho::CScriptLazyVar_float::CScriptLazyVar_float(LuaPlus::LuaState* const state)
{
  LuaPlus::LuaObject& lazyVarObject = AsLazyVarObject(*this);
  new (&lazyVarObject) LuaPlus::LuaObject();

  if (state == nullptr || state->m_state == nullptr) {
    return;
  }

  LuaPlus::LuaObject lazyVarModule = SCR_Import(state, "/lua/lazyvar.lua");
  LuaPlus::LuaObject createFn = lazyVarModule.GetByName("Create");

  lua_State* const rawState = state->m_state;
  const int savedTop = lua_gettop(rawState);

  createFn.PushStack(state);
  lua_pushnumber(rawState, 0.0f);

  if (lua_pcall(rawState, 1, 1, 0) != 0) {
    LuaPlus::LuaStackObject errorStack(state, -1);
    const char* errorText = errorStack.GetString();
    if (errorText == nullptr) {
      errorStack.TypeError("string");
      errorText = "<non-string>";
    }
    gpg::Warnf("Error in lazyvar.Create(): %s", errorText);
  } else {
    LuaPlus::LuaObject created(state, -1);
    lazyVarObject = created;
  }

  lua_settop(rawState, savedTop);
}

/**
 * Address: 0x00783840 (FUN_00783840, Moho::CScriptLazyVar_float::GetValue)
 *
 * What it does:
 * Resolves lazy-var value lane `1`, evaluating the lazy callback when the
 * lane is nil and coercing error/non-number paths back to `0.0`.
 */
float moho::CScriptLazyVar_float::GetValue(const CScriptLazyVar_float* const value) noexcept
{
  if (value == nullptr) {
    return 0.0f;
  }

  const LuaPlus::LuaObject& lazyVarObject = AsLazyVarObject(*value);
  if (lazyVarObject.m_state == nullptr) {
    return 0.0f;
  }

  LuaPlus::LuaObject resolvedValue = lazyVarObject.GetByIndex(1);
  if (resolvedValue.IsNil()) {
    LuaPlus::LuaState* const activeState = lazyVarObject.GetActiveState();
    if (activeState == nullptr || activeState->m_state == nullptr) {
      return 0.0f;
    }

    lua_State* const rawState = activeState->m_state;
    const int savedTop = lua_gettop(rawState);

    lazyVarObject.PushStack(activeState);
    if (lua_pcall(rawState, 0, 1, 0) != 0) {
      LuaPlus::LuaStackObject errorStack(activeState, -1);
      const char* errorText = errorStack.GetString();
      if (errorText == nullptr) {
        errorStack.TypeError("string");
        errorText = "<non-string>";
      }
      gpg::Warnf("Evaluating LazyVar failed: %s", errorText);
      const_cast<LuaPlus::LuaObject&>(lazyVarObject).SetNumber(1, 0.0f);
      lua_settop(rawState, savedTop);
      return 0.0f;
    }

    resolvedValue = LuaPlus::LuaObject(LuaPlus::LuaStackObject(activeState, -1));
    lua_settop(rawState, savedTop);
  }

  if (resolvedValue.IsNumber()) {
    return static_cast<float>(resolvedValue.GetNumber());
  }

  const_cast<LuaPlus::LuaObject&>(lazyVarObject).SetNumber(1, 0.0f);
  gpg::Warnf("LazyVar has non-number value.");
  return 0.0f;
}

/**
 * Address: 0x007839E0 (FUN_007839E0, Moho::CScriptLazyVar_float::SetValue)
 *
 * What it does:
 * Calls the Lua-side `SetValue` method on this lazy-var with `next`.
 */
void moho::CScriptLazyVar_float::SetValue(CScriptLazyVar_float* const value, const float next) noexcept
{
  if (value == nullptr) {
    return;
  }

  LuaPlus::LuaObject& lazyVarObject = AsLazyVarObject(*value);
  LuaPlus::LuaState* const activeState = lazyVarObject.GetActiveState();
  if (activeState == nullptr || activeState->m_state == nullptr) {
    return;
  }

  lua_State* const rawState = activeState->m_state;
  const int savedTop = lua_gettop(rawState);

  lazyVarObject.PushStack(activeState);
  lua_pushstring(rawState, "SetValue");
  lua_gettable(rawState, -2);
  lazyVarObject.PushStack(activeState);
  lua_pushnumber(rawState, next);

  if (lua_pcall(rawState, 2, 0, 0) != 0) {
    LuaPlus::LuaStackObject errorStack(activeState, -1);
    const char* errorText = errorStack.GetString();
    if (errorText == nullptr) {
      errorStack.TypeError("string");
      errorText = "<non-string>";
    }
    gpg::Warnf("Setting LazyVar value failed: %s", errorText);
  }

  lua_settop(rawState, savedTop);
}

void moho::CMauiCursorLink::AssignCursor(CMauiCursor* const cursor) noexcept
{
  CMauiCursorLink** const nextOwnerHead =
    cursor != nullptr ? &CMauiCursorRuntimeView::FromCursor(cursor)->ownerChainHead : nullptr;
  if (nextOwnerHead == ownerHeadLink) {
    return;
  }

  if (ownerHeadLink != nullptr) {
    CMauiCursorLink** link = ownerHeadLink;
    while (*link != nullptr && *link != this) {
      link = &(*link)->nextInOwnerChain;
    }

    if (*link == this) {
      *link = nextInOwnerChain;
    }
  }

  ownerHeadLink = nextOwnerHead;
  if (ownerHeadLink != nullptr) {
    nextInOwnerChain = *ownerHeadLink;
    *ownerHeadLink = this;
  } else {
    nextInOwnerChain = nullptr;
  }
}

void moho::CMauiCursorLink::Unlink() noexcept
{
  AssignCursor(nullptr);
}

moho::CMauiCursor* moho::CMauiCursorLink::GetCursor() const noexcept
{
  if (ownerHeadLink == nullptr || ownerHeadLink == reinterpret_cast<CMauiCursorLink**>(0x4)) {
    return nullptr;
  }

  const std::uintptr_t rawAddress = reinterpret_cast<std::uintptr_t>(ownerHeadLink);
  const std::uintptr_t cursorAddress = rawAddress - offsetof(CMauiCursorRuntimeView, ownerChainHead);
  return reinterpret_cast<CMauiCursor*>(cursorAddress);
}

/**
 * Address: 0x0078D410 (FUN_0078D410, cfunc_CMauiCursorSetDefaultTextureL)
 *
 * What it does:
 * Reads one cursor object plus texture/hotspot Lua args and updates cursor
 * default texture/hotspot lanes.
 */
int moho::cfunc_CMauiCursorSetDefaultTextureL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCursorSetDefaultTextureHelpText, 4, argumentCount);
  }

  LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
  CMauiCursor* const cursor = ResolveCursorFromLuaObjectOrError(cursorObject, state);

  LuaPlus::LuaStackObject textureArg(state, 2);
  const char* texturePath = lua_tostring(state->m_state, 2);
  if (texturePath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
    texturePath = "";
  }
  ApplyCursorDefaultTexture(cursor, texturePath);

  LuaPlus::LuaStackObject hotspotYArg(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&hotspotYArg, "integer");
  }
  const int hotspotY = static_cast<int>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject hotspotXArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&hotspotXArg, "integer");
  }
  const int hotspotX = static_cast<int>(lua_tonumber(state->m_state, 3));

  CMauiCursorTextureRuntimeView* const cursorView = CMauiCursorTextureRuntimeView::FromCursor(cursor);
  cursorView->mDefaultHotspotY = hotspotY;
  cursorView->mDefaultHotspotX = hotspotX;
  return 0;
}

/**
 * Address: 0x008725B0 (FUN_008725B0, cfunc_CUIWorldViewZoomScale)
 *
 * What it does:
 * Unwraps the raw Lua callback context and forwards to
 * `cfunc_CUIWorldViewZoomScaleL`.
 */
int moho::cfunc_CUIWorldViewZoomScale(lua_State* const luaContext)
{
  return cfunc_CUIWorldViewZoomScaleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00872630 (FUN_00872630, cfunc_CUIWorldViewZoomScaleL)
 *
 * What it does:
 * Reads `CUIWorldView:ZoomScale` Lua args and forwards anchor and wheel
 * zoom lanes into the active world-view camera.
 */
int moho::cfunc_CUIWorldViewZoomScaleL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCUIWorldViewZoomScaleHelpText, 5, argumentCount);
  }

  LuaPlus::LuaObject worldViewObject(LuaPlus::LuaStackObject(state, 1));
  CUIWorldView* const worldView = SCR_FromLua_CUIWorldView(worldViewObject, state);
  CUIWorldViewRuntimeView* const worldViewView = CUIWorldViewRuntimeView::FromWorldView(worldView);
  if (CameraZoomRuntimeView* const camera = worldViewView->mRenderWorldView.GetCamera(); camera != nullptr) {
    LuaPlus::LuaStackObject yArg(state, 3);
    if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&yArg, "number");
    }
    const float y = static_cast<float>(lua_tonumber(state->m_state, 3));

    LuaPlus::LuaStackObject xArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&xArg, "number");
    }
    float zoomAnchor[2] = {static_cast<float>(lua_tonumber(state->m_state, 2)), y};
    camera->SetZoomAnchor(zoomAnchor);

    CameraZoomRuntimeView* const wheelCamera = worldViewView->mRenderWorldView.GetCamera();
    LuaPlus::LuaStackObject wheelDeltaArg(state, 5);
    if (lua_type(state->m_state, 5) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&wheelDeltaArg, "number");
    }
    const float wheelDelta = static_cast<float>(lua_tonumber(state->m_state, 5));

    LuaPlus::LuaStackObject wheelRotArg(state, 4);
    if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&wheelRotArg, "number");
    }
    const float wheelRotation = static_cast<float>(lua_tonumber(state->m_state, 4));
    wheelCamera->ApplyWheelZoomRatio(wheelRotation / wheelDelta);
  }

  return 0;
}

moho::CMauiControl* moho::CMauiControl::GetTopmostControl(CMauiControl* const root, const float x, const float y)
{
  (void)x;
  (void)y;
  return root;
}

/**
 * Address: 0x007961B0 (FUN_007961B0, Moho::CMauiFrame::Create)
 *
 * What it does:
 * Imports `/lua/maui/frame.lua`, calls `Frame()`, converts the return payload
 * to `CMauiFrame*`, and initializes the frame's weak self-owner lane.
 */
boost::shared_ptr<moho::CMauiFrame> moho::CMauiFrame::Create(LuaPlus::LuaState* const state)
{
  boost::shared_ptr<CMauiFrame> outFrame{};
  if (state == nullptr || state->m_state == nullptr) {
    return outFrame;
  }

  lua_State* const rawState = state->m_state;
  const int savedTop = lua_gettop(rawState);

  LuaPlus::LuaObject moduleObject = SCR_Import(state, "/lua/maui/frame.lua");
  LuaPlus::LuaObject frameFactory = moduleObject.GetByName("Frame");
  frameFactory.PushStack(state);

  const int callStatus = lua_pcall(rawState, 0, 1, 0);
  if (callStatus != 0) {
    const char* errorText = lua_tostring(rawState, -1);
    if (errorText == nullptr) {
      LuaPlus::LuaStackObject errorObject(state, -1);
      errorObject.TypeError("string");
      errorText = "<non-string>";
    }
    gpg::Warnf("Error in CMauiFrame::Create(): %s", errorText);
    lua_settop(rawState, savedTop);
    return outFrame;
  }

  LuaPlus::LuaObject frameLuaObject(state, -1);
  CMauiFrame* const frame = ResolveFrameFromLuaObjectOrError(frameLuaObject, state);
  if (frame != nullptr) {
    outFrame = boost::shared_ptr<CMauiFrame>(frame);
    CMauiFrameRuntimeView* const frameView = CMauiFrameRuntimeView::FromFrame(frame);
    frameView->mSelfWeak = outFrame;
  }

  lua_settop(rawState, savedTop);
  return outFrame;
}

void moho::CMauiFrame::DumpControlsUnder(CMauiFrame* const frame, const float x, const float y)
{
  (void)frame;
  (void)x;
  (void)y;
}

/**
 * Address: 0x00784F50 (FUN_00784F50, Moho::CMauiBorder::Draw)
 *
 * What it does:
 * Draws border corner quads, then optional horizontal and vertical body strips
 * using border lazy-var geometry and retained border textures.
 */
void moho::CMauiBorder::Draw(CD3DPrimBatcher* const primBatcher, const std::int32_t drawMask)
{
  (void)drawMask;
  if (primBatcher == nullptr) {
    return;
  }

  const CMauiBorderRuntimeView* const border = CMauiBorderRuntimeView::FromBorder(this);
  if (!border->mTex1 || !border->mTexHorz || !border->mTexUL || !border->mTexUR || !border->mTexLL || !border->mTexLR) {
    return;
  }

  const float left = CScriptLazyVar_float::GetValue(&border->mLeftLV);
  const float top = CScriptLazyVar_float::GetValue(&border->mTopLV);
  const float right = CScriptLazyVar_float::GetValue(&border->mRightLV);
  const float bottom = CScriptLazyVar_float::GetValue(&border->mBottomLV);
  const float borderWidth = static_cast<float>(FloorFrndintAdjustDown(CScriptLazyVar_float::GetValue(&border->mBorderWidthLV)));
  const float borderHeight = static_cast<float>(FloorFrndintAdjustDown(CScriptLazyVar_float::GetValue(&border->mBorderHeightLV)));

  const float innerLeft = left + borderWidth;
  const float innerRight = right - borderWidth;
  const float innerTop = top + borderHeight;
  const float innerBottom = bottom - borderHeight;

  const std::uint32_t color = border->mVertexAlpha;

  primBatcher->SetTexture(border->mTexUL);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, top, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerLeft, top, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerLeft, innerTop, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, innerTop, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  primBatcher->SetTexture(border->mTexUR);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerRight, top, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, top, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, innerTop, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerRight, innerTop, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  primBatcher->SetTexture(border->mTexLL);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, innerBottom, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerLeft, innerBottom, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerLeft, bottom, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, bottom, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  primBatcher->SetTexture(border->mTexLR);
  {
    const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerRight, innerBottom, color, 0.0f, 0.0f);
    const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, innerBottom, color, 1.0f, 0.0f);
    const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, bottom, color, 1.0f, 1.0f);
    const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerRight, bottom, color, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  if ((right - left) > (borderWidth * 2.0f)) {
    primBatcher->SetTexture(border->mTexHorz);
    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerLeft, top, color, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerRight, top, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerRight, innerTop, color, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerLeft, innerTop, color, 0.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerLeft, innerBottom, color, 0.0f, 1.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerRight, innerBottom, color, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerRight, bottom, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerLeft, bottom, color, 0.0f, 0.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  }

  if ((bottom - top) > (borderHeight * 2.0f)) {
    primBatcher->SetTexture(border->mTex1);
    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, innerTop, color, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(innerLeft, innerTop, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(innerLeft, innerBottom, color, 1.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, innerBottom, color, 0.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    {
      const CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(innerRight, innerTop, color, 1.0f, 0.0f);
      const CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, innerTop, color, 0.0f, 0.0f);
      const CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, innerBottom, color, 0.0f, 1.0f);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(innerRight, innerBottom, color, 1.0f, 1.0f);
      primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }
  }
}

/**
 * Address: 0x00795BD0 (FUN_00795BD0, func_CreateLuaEvent)
 *
 * What it does:
 * Builds one script-visible event payload table from one `SMauiEventData`
 * packet, including event type text, mouse/key lanes, modifier flags, and
 * optional source control object.
 */
LuaPlus::LuaObject* moho::CreateLuaEventObject(
  SMauiEventData* const eventData,
  LuaPlus::LuaObject* const outEvent,
  LuaPlus::LuaState* const state
)
{
  LuaPlus::LuaObject modifiers;
  modifiers.AssignNewTable(state, 6, 0);

  if ((eventData->mModifiers & MEM_Shift) != 0u) {
    modifiers.SetBoolean("Shift", true);
  }
  if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
    modifiers.SetBoolean("Ctrl", true);
  }
  if ((eventData->mModifiers & MEM_Alt) != 0u) {
    modifiers.SetBoolean("Alt", true);
  }
  if ((eventData->mModifiers & MEM_Left) != 0u) {
    modifiers.SetBoolean("Left", true);
  }
  if ((eventData->mModifiers & MEM_Middle) != 0u) {
    modifiers.SetBoolean("Middle", true);
  }
  if ((eventData->mModifiers & MEM_Right) != 0u) {
    modifiers.SetBoolean("Right", true);
  }

  new (outEvent) LuaPlus::LuaObject();
  outEvent->AssignNewTable(state, 0, 8u);

  gpg::RRef eventTypeRef{};
  gpg::RRef_EMauiEventType(&eventTypeRef, &eventData->mEventType);
  const auto eventTypeLexical = eventTypeRef.GetLexical();
  outEvent->SetString("Type", eventTypeLexical.c_str());

  outEvent->SetNumber("MouseX", eventData->mMousePos.x);
  outEvent->SetNumber("MouseY", eventData->mMousePos.y);
  outEvent->SetInteger("WheelRotation", eventData->mWheelRotation);
  outEvent->SetInteger("WheelDelta", eventData->mWheelData);
  outEvent->SetInteger("KeyCode", eventData->mKeyCode);
  outEvent->SetInteger("RawKeyCode", eventData->mRawKeyCode);
  outEvent->SetObject("Modifiers", modifiers);

  if (eventData->mSource != nullptr) {
    outEvent->SetObject("Control", eventData->mSource->mLuaObj);
  }

  return outEvent;
}

LuaPlus::LuaState* moho::USER_GetLuaState()
{
  return gUserLuaState;
}

bool moho::MAUI_StartMainScript()
{
  return true;
}

void moho::MAUI_UpdateCursor(CMauiCursor* const cursor)
{
  (void)cursor;
}

void moho::MAUI_ReleaseCursor(CMauiCursor* const cursor)
{
  (void)cursor;
}

void moho::MAUI_OnApplicationResize(const std::int32_t frameIdx, const std::int32_t width, const std::int32_t height)
{
  (void)frameIdx;
  (void)width;
  (void)height;
}

bool moho::UI_InitKeyHandler()
{
  return true;
}

void moho::UI_ClearInputCapture()
{
}

void moho::UI_ClearCurrentDragger()
{
}

void moho::UI_FactoryCommandQueueHandlerBeat()
{
}

bool moho::UI_LuaBeat()
{
  return true;
}

void moho::UI_UpdateCommandFeedbackBlips(const float deltaSeconds)
{
  (void)deltaSeconds;
}

void moho::UI_DumpCurrentInputCapture()
{
}

moho::wxEvtHandlerRuntime* moho::UI_CreateKeyHandler()
{
  return new CUIKeyHandlerRuntime{};
}

void moho::WX_PushEventHandler(wxWindowBase* const window, wxEvtHandlerRuntime* const handler)
{
  if (window == nullptr || handler == nullptr) {
    return;
  }

  auto chainIt = FindWindowEventHandlerChain(window);
  if (chainIt == gWindowEventHandlerChains.end()) {
    gWindowEventHandlerChains.push_back(WindowEventHandlerChain{window, {}});
    chainIt = gWindowEventHandlerChains.end() - 1;
  }

  chainIt->handlers.push_back(handler);
}

moho::wxEvtHandlerRuntime* moho::WX_PopEventHandler(wxWindowBase* const window, const bool deleteHandler)
{
  if (window == nullptr) {
    return nullptr;
  }

  const auto chainIt = FindWindowEventHandlerChain(window);
  if (chainIt == gWindowEventHandlerChains.end() || chainIt->handlers.empty()) {
    return nullptr;
  }

  wxEvtHandlerRuntime* const popped = chainIt->handlers.back();
  chainIt->handlers.pop_back();

  if (chainIt->handlers.empty()) {
    gWindowEventHandlerChains.erase(chainIt);
  }

  if (deleteHandler && popped != nullptr) {
    delete popped;
    return nullptr;
  }

  return popped;
}

void moho::WX_GetClientSize(wxWindowBase* const window, std::int32_t& outWidth, std::int32_t& outHeight)
{
  if (window == nullptr) {
    outWidth = 0;
    outHeight = 0;
    return;
  }

  window->DoGetClientSize(&outWidth, &outHeight);
}

void moho::WX_ScreenToClient(wxWindowBase* const window, std::int32_t& inOutX, std::int32_t& inOutY)
{
  if (window == nullptr) {
    return;
  }

  const HWND handle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(window->GetHandle()));
  if (handle == nullptr) {
    return;
  }

  POINT point{};
  point.x = inOutX;
  point.y = inOutY;
  if (::ScreenToClient(handle, &point) == FALSE) {
    return;
  }

  inOutX = point.x;
  inOutY = point.y;
}

bool moho::WX_GetCursorPosition(std::int32_t& outX, std::int32_t& outY)
{
  POINT cursorPosition{};
  if (::GetCursorPos(&cursorPosition) == FALSE) {
    outX = 0;
    outY = 0;
    return false;
  }

  outX = cursorPosition.x;
  outY = cursorPosition.y;
  return true;
}

const moho::VMatrix4& moho::UI_IdentityMatrix()
{
  static const VMatrix4 kIdentity = VMatrix4::Identity();
  return kIdentity;
}
