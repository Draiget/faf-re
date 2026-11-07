#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kCMauiLuaDraggerDestroyHelpText = "Dragger:Destroy() -- destroy this dragger";
  constexpr const char* kPostDraggerHelpText =
    "PostDragger(originFrame, keycode, dragger)\n"
    "Make 'dragger' the active dragger from a particular frame. You can pass nil to cancel the current dragger.";
  constexpr const char* kPostDraggerInvalidKeyError = "Invalid key specified. Must be LBUTTON or RBUTTON or MBUTTON";
}


/**
 * Address: 0x0078DE50 (FUN_0078DE50, Moho::CMauiLuaDragger::CMauiLuaDragger)
 *
 * IDA signature:
 * Moho::CMauiLuaDragger *__stdcall Moho::CMauiLuaDragger::CMauiLuaDragger(
 *     Moho::CMauiLuaDragger *this, LuaPlus::LuaObject *a2);
 *
 * What it does:
 * Runs the `CScriptObject` base constructor, installs both vtables (the
 * script-object one at +0x00 and the `IMauiDragger` one at +0x34), clears the
 * `IMauiDragger` base's weak-reference head at +0x38 (asm 0x0078DE77, part of
 * the inlined base constructor), and binds the owning Lua table.
 */
moho::CMauiLuaDragger::CMauiLuaDragger(
  const LuaPlus::LuaObject& luaObject
)
  : CScriptObject()
  , IMauiDragger()
{
  SetLuaObject(luaObject);
}
namespace
{

  constexpr std::int32_t kMauiLButtonCode = 301;
  constexpr std::int32_t kMauiRButtonCode = 302;
  constexpr std::int32_t kMauiMButtonCode = 304;
}


gpg::RType* moho::CMauiLuaDragger::sType = nullptr;

/**
 * Address: 0x0078DBD0 (FUN_0078DBD0, Moho::CMauiLuaDragger::StaticGetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiLuaDragger`, resolving it
 * via RTTI on first use.
 */
gpg::RType* moho::CMauiLuaDragger::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiLuaDragger));
  }
  return sType;
}

/**
 * Address: 0x0078DBF0 (FUN_0078DBF0, Moho::CMauiLuaDragger::GetClass)
 */
gpg::RType* moho::CMauiLuaDragger::GetClass() const
{
  return StaticGetClass();
}

/**
 * Address: 0x0078DC10 (FUN_0078DC10, Moho::CMauiLuaDragger::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiLuaDragger::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

/**
 * Address: 0x0078DF30 (FUN_0078DF30, Moho::CMauiLuaDragger::OnMove)
 *
 * What it does:
 * Invokes the script callback `OnMove(self, x, y)` with the pointer position
 * carried by the event.
 */
void moho::CMauiLuaDragger::DragMove(
  const SMauiEventData* const eventData
)
{
  RunScriptNum2("OnMove", eventData->mMousePos.x, eventData->mMousePos.y);
}

/**
 * Address: 0x0078DF50 (FUN_0078DF50, Moho::CMauiLuaDragger::OnRelease)
 *
 * What it does:
 * Invokes the script callback `OnRelease(self, x, y)`. This is the callback
 * `lua/maui/button.lua` installs to run `Button:OnClick`, so the whole
 * front-end click path terminates here.
 */
void moho::CMauiLuaDragger::DragRelease(
  const SMauiEventData* const eventData
)
{
  RunScriptNum2("OnRelease", eventData->mMousePos.x, eventData->mMousePos.y);
}

/**
 * Address: 0x0078DF70 (FUN_0078DF70, Moho::CMauiLuaDragger::OnCancel)
 *
 * What it does:
 * Invokes the script callback `OnCancel(self)` when a different dragger
 * replaces this one as the active dragger.
 */
void moho::CMauiLuaDragger::OnCurrentDraggerReplaced()
{
  (void)RunScript("OnCancel");
}
namespace
{

  [[nodiscard]] std::int32_t NormalizePostDraggerKeycode(
    const std::int32_t keyCode
  ) noexcept
  {
    if (keyCode == kMauiLButtonCode) {
      return kPostDraggerLeftButton;
    }
    if (keyCode == kMauiRButtonCode) {
      return kPostDraggerRightButton;
    }
    if (keyCode == kMauiMButtonCode) {
      return kPostDraggerMiddleButton;
    }
    return keyCode;
  }

  [[nodiscard]] bool IsValidPostDraggerKeycode(
    const std::int32_t keyCode
  ) noexcept
  {
    return keyCode == kPostDraggerLeftButton || keyCode == kPostDraggerMiddleButton ||
      keyCode == kPostDraggerRightButton;
  }

  [[nodiscard]] gpg::RType* CachedCMauiLuaDraggerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiLuaDragger");
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("Moho::CMauiLuaDragger");
      }
    }
    return cached;
  }

  /**
   * Address: 0x0078E6F0 (FUN_0078E6F0, func_GetCMauiLuaDraggerOpt)
   *
   * What it does:
   * Resolves one optional `CMauiLuaDragger` from Lua object payload; raises
   * Lua errors for non-game-object or incorrect-type payloads and returns
   * null for destroyed objects.
   */
  [[nodiscard]] moho::CMauiLuaDragger* ResolveCMauiLuaDraggerOptionalOrError(
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

    gpg::RType* const draggerType = CachedCMauiLuaDraggerType();
    if (draggerType == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, draggerType);
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CMauiLuaDragger*>(upcast.mObj);
  }
}


/**
 * Address: 0x0078DB50 (slot +0x04 of ??_7IMauiDragger@Moho@@6B@, VA 0x00E38DC0)
 * Mangled: ?DragMove@IMauiDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
 *
 * IDA signature:
 * void __thiscall Moho::IMauiDragger::DragMove(
 *     Moho::IMauiDragger *this@<ecx>, const Moho::SMauiEventData *eventData);
 *
 * What it does:
 * Nothing - the shipped body is a bare `retn 4`. Draggers that only care about
 * the release edge (`SelectionDragger`, and every dragger whose vtable keeps
 * 0x0078DB50 in slot +0x04) inherit this.
 */
void moho::IMauiDragger::DragMove(
  const moho::SMauiEventData* const /*eventData*/
)
{}

/**
 * Address: 0x0078DB60 (slot +0x08 of ??_7IMauiDragger@Moho@@6B@, VA 0x00E38DC0)
 * Mangled: ?DragRelease@IMauiDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
 *
 * IDA signature:
 * void __thiscall Moho::IMauiDragger::DragRelease(
 *     Moho::IMauiDragger *this@<ecx>, const Moho::SMauiEventData *eventData);
 *
 * What it does:
 * Destroys the dragger. The shipped body is MSVC's `delete this`: a null test
 * on `this`, the scalar-delete flag written over the incoming event argument
 * slot (`mov [esp+4], 1`), then a tail jump through vtable slot +0x00.
 */
void moho::IMauiDragger::DragRelease(
  const moho::SMauiEventData* const /*eventData*/
)
{
  delete this;
}

/**
 * Address: 0x0078DB80 (slot +0x0C of ??_7IMauiDragger@Moho@@6B@, VA 0x00E38DC0)
 * Mangled: ?OnCurrentDraggerReplaced@IMauiDragger@Moho@@UAEXXZ
 *
 * IDA signature:
 * void __thiscall Moho::IMauiDragger::OnCurrentDraggerReplaced(
 *     Moho::IMauiDragger *this@<ecx>);
 *
 * What it does:
 * Destroys the dragger. A dragger displaced as the current one is dropped on
 * the spot unless it overrides this; the body is again `delete this`
 * (`test ecx, ecx` / `push 1` / call through slot +0x00).
 */
void moho::IMauiDragger::OnCurrentDraggerReplaced()
{
  delete this;
}

/**
 * Address: 0x00823FE0 (FUN_00823FE0, ??0UICommandDragger@Moho@@QAE@@Z)
 *
 * IDA signature:
 * Moho::UICommandDragger *__stdcall Moho::UICommandDragger::UICommandDragger(
 *     Moho::UICommandDragger *this, Moho::CWldSession *session,
 *     Moho::CameraImpl *camera, int commandId);
 *
 * What it does:
 * Binds the dragger to the session/camera/dragged-command triple, acquires a
 * counted reference on the session's UI command graph (`allowCreate = true`,
 * pushed as the literal `1` at 0x00824013) and then tells the UI Lua layer the
 * drag has started.
 *
 * Field evidence, all from this function's own `.asm` (`esi` holds `this`):
 *   0x00824001 `mov [esi+4], ecx`   - inherited `WeakObject::weakLinkHead_`
 *   0x00824010 `mov [esi+0Ch], ecx` - `mCam`       (third stack argument)
 *   0x0082401A `mov [esi], offset ??_7UICommandDragger@Moho@@6B@`
 *   0x00824020 `mov [esi+8], eax`   - `mSession`   (second stack argument)
 *   0x00824023 `mov [esi+10h], edx` - `mCommandId` (fourth stack argument)
 *   0x00824015 `lea ecx, [esi+14h]` - hidden return buffer for the
 *                                     `boost::shared_ptr<UICommandGraph>`
 *                                     `GetCommandGraph` returns by value
 *   0x00824030 `mov edx, [esi+8]` / 0x00824033 `mov eax, [edx+10h]`
 *                                   - `mSession->mState`, the only argument of
 *                                     `func_OnCommandDragBegin`
 */
moho::UICommandDragger::UICommandDragger(
  moho::CWldSession* const session,
  moho::CameraImpl* const camera,
  const moho::CmdId commandId
)
  : mSession(session)
  , mCam(camera)
  , mCommandId(commandId)
  , mGraph(session->GetCommandGraph(true))
{
  func_OnCommandDragBegin(mSession->mState);
}

/**
 * Address: 0x008241B0 (FUN_008241B0, slot +0x04 of ??_7UICommandDragger@Moho@@6B@)
 * Mangled: ?DragMove@UICommandDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
 *
 * IDA signature:
 * void __thiscall Moho::UICommandDragger::DragMove(
 *     Moho::UICommandDragger *this@<ecx>, const Moho::SMauiEventData *eventData);
 *
 * What it does:
 * Unprojects the event's screen mouse position through the bound camera
 * into a world-surface point, then forwards it to `func_ProcessCommandDrag`
 * along with the dragged command's graph/id, `released = false`.
 */
void moho::UICommandDragger::DragMove(
  const moho::SMauiEventData* const eventData
)
{
  const Wm3::Vector2f mousePos(eventData->mMousePos.x, eventData->mMousePos.y);
  const Wm3::Vector3f surfacePoint = mCam->CameraScreenToSurface(mousePos);
  moho::ProcessCommandDrag(surfacePoint, *mGraph, mCommandId, false);
}

/**
 * Address: 0x00824210 (FUN_00824210, slot +0x08 of ??_7UICommandDragger@Moho@@6B@)
 * Mangled: ?DragRelease@UICommandDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
 *
 * IDA signature:
 * void __thiscall Moho::UICommandDragger::DragRelease(
 *     Moho::UICommandDragger *this@<ecx>, const Moho::SMauiEventData *eventData);
 *
 * What it does:
 * Unprojects the event's screen mouse position the same way `DragMove`
 * does, forwards it to `func_ProcessCommandDrag` with `released = true`,
 * notifies the UI Lua layer via `func_OnCommandDragEnd` (0x00824260-0x00824266:
 * `state` is read through `this->mSession->mState`), then deletes this
 * dragger (the inherited `IMauiDragger` `delete this` shape, slot +0x00).
 */
void moho::UICommandDragger::DragRelease(
  const moho::SMauiEventData* const eventData
)
{
  const Wm3::Vector2f mousePos(eventData->mMousePos.x, eventData->mMousePos.y);
  const Wm3::Vector3f surfacePoint = mCam->CameraScreenToSurface(mousePos);
  moho::ProcessCommandDrag(surfacePoint, *mGraph, mCommandId, true);
  func_OnCommandDragEnd(const_cast<moho::SMauiEventData*>(eventData), mCommandId, mSession->mState);
  delete this;
}

/**
 * Address: 0x00824290 (FUN_00824290, slot +0x0C of ??_7UICommandDragger@Moho@@6B@)
 * Mangled: ?OnCurrentDraggerReplaced@UICommandDragger@Moho@@UAEXXZ
 *
 * IDA signature:
 * void __thiscall Moho::UICommandDragger::OnCurrentDraggerReplaced(
 *     Moho::UICommandDragger *this@<ecx>);
 *
 * What it does:
 * Drops the drag preview this dragger's command left on its `mMapAB0` draw
 * node - `Moho::ReanchorCommandGraphDrawNode` (0x0082A030) re-anchors that
 * node to the command's own real position, resets its weight to a single
 * contributor and clears its resolved-position flag - then deletes this
 * dragger, the inherited `IMauiDragger` `delete this` shape (slot +0x00).
 */
void moho::UICommandDragger::OnCurrentDraggerReplaced()
{
  moho::ReanchorCommandGraphDrawNode(*mGraph, mCommandId);
  delete this;
}

/**
 * Address: 0x0078DDD0 (FUN_0078DDD0, sub_78DDD0)
 *
 * What it does:
 * Returns the keycode lane associated with the current dragger.
 */
static std::int32_t func_GetCurrentDraggerKeycode()
{
  return sCurrentDraggerKeycode;
}

/**
 * Address: 0x00823E40 (FUN_00823E40, func_OnCommandDragBegin)
 *
 * What it does:
 * Imports `/lua/ui/game/commandgraph.lua` and invokes
 * `OnCommandDragBegin()` on the active UI Lua state.
 *
 * Invocation: sole caller is `Moho::UICommandDragger::UICommandDragger`
 * (0x00823FE0), which tail-calls it at 0x00824037 with `mSession->mState`.
 */
static void func_OnCommandDragBegin(
  LuaPlus::LuaState* const state
)
{
  (void)InvokeUiLuaCallback(
    state, "/lua/ui/game/commandgraph.lua", "OnCommandDragBegin", [](LuaPlus::LuaFunction<void>& callbackFunction) {
    callbackFunction();
  }
  );
}

/**
 * Address: 0x00823F00 (FUN_00823F00, func_OnCommandDragEnd)
 *
 * What it does:
 * Builds one Maui-event Lua payload and invokes
 * `/lua/ui/game/commandgraph.lua:OnCommandDragEnd(event, cmdId)`.
 *
 * The second argument is the dragged command's id, not a boolean: the only
 * caller in the binary (`Moho::UICommandDragger::DragRelease`, 0x00824210)
 * loads it from `this->mCommandId` at 0x0082425D (`mov eax, [esi+10h]`) and
 * pushes it directly, and the receiving script declares
 * `function OnCommandDragEnd(event, cmdId)`.
 */
void func_OnCommandDragEnd(
  moho::SMauiEventData* const eventData,
  const std::int32_t commandId,
  LuaPlus::LuaState* const state
)
{
  LuaPlus::LuaObject eventObject{};
  (void)moho::CreateLuaEventObject(eventData, &eventObject, state);

  (void)InvokeUiLuaCallback(
    state,
    "/lua/ui/game/commandgraph.lua",
    "OnCommandDragEnd",
    [&eventObject, commandId](LuaPlus::LuaFunction<void>& callbackFunction) {
    callbackFunction(eventObject, commandId);
  }
  );
}

// Rows 0x00F5A488: EVT_MOUSE_EVENTS is the thirteen mouse rows, all bound to
// OnMouseMove (0x007A4970), in the order that macro lists them.
BEGIN_EVENT_TABLE(moho::CMauiWxEventMapper, wxEvtHandler)
  EVT_MOUSE_EVENTS(moho::CMauiWxEventMapper::OnMouseMove)
  EVT_KEY_UP(moho::CMauiWxEventMapper::OnKeyUp)
  EVT_KEY_DOWN(moho::CMauiWxEventMapper::OnKeyDown)
  EVT_CHAR(moho::CMauiWxEventMapper::OnChar)
END_EVENT_TABLE()

/**
 * Address: 0x0078E210 (FUN_0078E210, cfunc_PostDragger)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_PostDraggerL`.
 */
int moho::cfunc_PostDragger(
  lua_State* const luaContext
)
{
  return cfunc_PostDraggerL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078E230 (FUN_0078E230, func_PostDragger_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `PostDragger(originFrame, keycode, dragger)` Lua
 * binder.
 */
moho::CScrLuaInitForm* moho::func_PostDragger_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "PostDragger", &moho::cfunc_PostDragger, nullptr, "<global>", kPostDraggerHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078DC30 (FUN_0078DC30)
 *
 * What it does:
 * Initializes one `SMauiEventData` lane to the default unknown-event state
 * used by dragger posting paths.
 */
[[maybe_unused]] static moho::SMauiEventData* func_InitUnknownMauiEventData(
  moho::SMauiEventData* const eventData
) noexcept
{
  eventData->mEventType = moho::MET_Unknown;
  eventData->mMousePos.x = -1.0f;
  eventData->mMousePos.y = -1.0f;
  eventData->mWheelRotation = 0;
  eventData->mWheelData = 0;
  eventData->mKeyCode = 0;
  eventData->mRawKeyCode = 0;
  eventData->mModifiers = moho::MEM_None;
  eventData->mSource = nullptr;
  return eventData;
}

/**
 * Address: 0x0078E290 (FUN_0078E290, cfunc_PostDraggerL)
 *
 * What it does:
 * Reads `(originFrame, keycode, dragger)` from Lua, normalizes mouse-button
 * key lanes, and posts one dragger activation payload.
 */
int moho::cfunc_PostDraggerL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 3, kPostDraggerHelpText);

  CMauiFrame* originFrame = nullptr;
  if (lua_type(state->m_state, 1) != LUA_TNIL) {
    LuaPlus::LuaObject frameObject(LuaPlus::LuaStackObject(state, 1));
    originFrame = SCR_FromLua_CMauiFrame(frameObject, state);
  }

  std::int32_t keyCode = 0;
  if (lua_type(state->m_state, 2) == LUA_TNUMBER) {
    LuaPlus::LuaStackObject keyCodeArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&keyCodeArg, "integer");
    }
    keyCode = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));
  } else if (lua_isstring(state->m_state, 2) != 0) {
    LuaPlus::LuaStackObject keyCodeArg(state, 2);
    const char* keyCodeName = lua_tostring(state->m_state, 2);
    if (keyCodeName == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&keyCodeArg, "string");
      keyCodeName = "";
    }

    gpg::RRef keyCodeEnumRef{};
    keyCodeEnumRef = gpg::MakeRRef<moho::EMauiKeyCode>(reinterpret_cast<EMauiKeyCode*>(&keyCode));
    SCR_GetEnum(state, keyCodeName, keyCodeEnumRef);
  }

  keyCode = NormalizePostDraggerKeycode(keyCode);
  if (!IsValidPostDraggerKeycode(keyCode)) {
    LuaPlus::LuaState::Error(state, kPostDraggerInvalidKeyError);
  }

  IMauiDragger* dragger = nullptr;
  if (lua_type(state->m_state, 3) != LUA_TNIL) {
    LuaPlus::LuaObject draggerObject(LuaPlus::LuaStackObject(state, 3));
    CMauiLuaDragger* const luaDragger = SCR_FromLua_CMauiLuaDragger(draggerObject, state);
    dragger = static_cast<IMauiDragger*>(luaDragger);
  }

  SMauiEventData eventData{};
  (void)func_InitUnknownMauiEventData(&eventData);
  eventData.mKeyCode = keyCode;

  func_PostDragger(originFrame, dragger, &eventData);
  return 0;
}

/**
 * Address: 0x0078DF80 (FUN_0078DF80, cfunc_CMauiLuaDraggerDestroy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiLuaDraggerDestroyL`.
 */
int moho::cfunc_CMauiLuaDraggerDestroy(
  lua_State* const luaContext
)
{
  return cfunc_CMauiLuaDraggerDestroyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078DFA0 (FUN_0078DFA0, func_CMauiLuaDraggerDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiLuaDragger:Destroy()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiLuaDraggerDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Destroy",
    &moho::cfunc_CMauiLuaDraggerDestroy,
    &moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::Instance(),
    "CMauiLuaDragger",
    kCMauiLuaDraggerDestroyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078E000 (FUN_0078E000, cfunc_CMauiLuaDraggerDestroyL)
 *
 * What it does:
 * Resolves one optional `CMauiLuaDragger` and executes scalar deleting
 * destructor semantics when present.
 */
int moho::cfunc_CMauiLuaDraggerDestroyL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiLuaDraggerDestroyHelpText);

  LuaPlus::LuaObject draggerObject(LuaPlus::LuaStackObject(state, 1));
  CMauiLuaDragger* const dragger = ResolveCMauiLuaDraggerOptionalOrError(draggerObject, state);
  delete dragger;

  return 1;
}

void moho::UI_ClearCurrentDragger()
{
  if (func_GetCurrentDraggerKeycode() != 0) {
    sCurrentDraggerKeycode = 0;
  }
  sCurrentDragger.UnlinkFromOwnerChain();
  sCurrentDraggerKeycode = 0;
}
