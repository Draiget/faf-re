#include "moho/ui/UiPrivate.h"

namespace
{

  /// The control under the mouse as of the last mouse event (`0x010BDBA0`),
  /// rebound on every MET_MouseEnter / MET_MouseExit in `func_OnMouseMove`.
  moho::WeakPtr<moho::CMauiControl> gMouseOverControl{};
}


/**
 * Address: 0x007A48D0 (FUN_007A48D0, ??1CMauiWxEventMapper@Moho@@QAE@@Z)
 * Mangled: ??1CMauiWxEventMapper@Moho@@QAE@@Z
 *
 * What it does:
 * Unlinks the global mouse-over control sentinel (`stru_10BDBA0` = local
 * `gMouseOverControl`) and clears the global mouse-capture flag so
 * the next mapper instance starts with a clean tracking state.
 */
moho::CMauiWxEventMapper::~CMauiWxEventMapper()
{
  gMouseOverControl.ResetFromObject(nullptr);
  sMouseIsCaptured = 0;
}
namespace
{

  struct MauiEventDispatchGuard
  {
    MauiEventDispatchGuard() noexcept
    {
      ++gMauiEventDispatchDepth;
    }
    ~MauiEventDispatchGuard()
    {
      --gMauiEventDispatchDepth;
    }
    MauiEventDispatchGuard(const MauiEventDispatchGuard&) = delete;
    MauiEventDispatchGuard& operator=(const MauiEventDispatchGuard&) = delete;
  };
  /**
   * Builds one `moho::SMauiEventData` payload from a wxMouseEvent, translating
   * wheel-event coordinates from screen-space to client-space through
   * `windowRuntime->ScreenToClient`.
   */
  [[nodiscard]] moho::SMauiEventData BuildMauiEventPayloadFromWxMouse(
    const wxMouseEvent& mouseEvent,
    wxWindow* const window
  )
  {
    moho::SMauiEventData payload{};
    payload.mEventType = moho::MET_Unknown;
    payload.mMousePos.x = -1.0f;
    payload.mMousePos.y = -1.0f;

    if (window != nullptr && mouseEvent.GetEventType() == wxEVT_MOUSEWHEEL) {
      // Wheel events report screen coordinates; convert to client space.
      int clientX = mouseEvent.m_x;
      int clientY = mouseEvent.m_y;
      window->ScreenToClient(&clientX, &clientY);
      payload.mMousePos.x = static_cast<float>(clientX);
      payload.mMousePos.y = static_cast<float>(clientY);
    } else {
      payload.mMousePos.x = static_cast<float>(mouseEvent.m_x);
      payload.mMousePos.y = static_cast<float>(mouseEvent.m_y);
    }

    // Map the wxMouseEvent button/modifier flags onto the typed Maui
    // modifier bitmask. Bit layout proven by FUN_007A4970 disassembly.
    std::uint32_t modifierBits = 0u;
    if (mouseEvent.m_leftDown) {
      modifierBits |= moho::MEM_Left;
    }
    if (mouseEvent.m_middleDown) {
      modifierBits |= moho::MEM_Middle;
    }
    if (mouseEvent.m_rightDown) {
      modifierBits |= moho::MEM_Right;
    }
    if (mouseEvent.m_controlDown) {
      modifierBits |= moho::MEM_Ctrl;
    }
    if (mouseEvent.m_shiftDown) {
      modifierBits |= moho::MEM_Shift;
    }
    if (mouseEvent.m_altDown) {
      modifierBits |= moho::MEM_Alt;
    }
    payload.mModifiers = static_cast<moho::EMauiEventModifier>(modifierBits);

    return payload;
  }

  /**
   * Posts the global Lua `OnMouseButtonPress` callback by importing
   * `/lua/ui/uimain.lua` and invoking its `OnMouseButtonPress` field with a
   * fresh `{Type, x, y}` table. Caught exceptions are routed to `gpg::Warnf`
   * using the original binary's hard-coded error message lane.
   */
  void RunGlobalOnMouseButtonPressLuaCallback(
    LuaPlus::LuaState* const luaState,
    const bool isPress,
    const std::int32_t mouseX,
    const std::int32_t mouseY
  )
  {
    if (luaState == nullptr) {
      return;
    }

    LuaPlus::LuaObject payloadTable;
    payloadTable.AssignNewTable(luaState, 0, 0);
    payloadTable.SetString("Type", isPress ? "ButtonPress" : "ButtonDClick");
    payloadTable.SetNumber("x", static_cast<float>(mouseX));
    payloadTable.SetNumber("y", static_cast<float>(mouseY));

    try {
      LuaPlus::LuaObject uiMainModule = moho::SCR_Import(luaState, "/lua/ui/uimain.lua");
      LuaPlus::LuaObject onMouseButtonPress = uiMainModule["OnMouseButtonPress"];
      const LuaPlus::LuaFunction<void> callback(onMouseButtonPress);
      callback.Call_Object(payloadTable);
    } catch (const std::exception& exception) {
      const char* const message = exception.what() != nullptr ? exception.what() : "";
      gpg::Warnf("Error running '/lua/ui/game/construction.lua:OnMouseButtonPress': %s", message);
    }
  }
}


/**
 * Address: 0x007A4970 (FUN_007A4970, func_OnMouseMove)
 *
 * IDA signature:
 * void __userpurge func_OnMouseMove(Value *ecx0@<ecx>, ..., wxEvent *a5)
 *
 * What it does:
 * Static `wxEventTableEntry` mouse handler at `0x00F5A488` for the
 * `Moho::CMauiWxEventMapper` event-table family. For every wx mouse event:
 *  1. Builds one `moho::SMauiEventData` payload from the wxMouseEvent fields,
 *     translating wheel-event coordinates through the mapper window runtime.
 *  2. Hit-tests the input-capture stack first, then the mapper frame, to find
 *     the topmost `CMauiControl` under the cursor.
 *  3. Emits `MET_MouseExit` / `MET_MouseEnter` when the topmost control
 *     changes, updating the global mouse-over sentinel.
 *  4. Routes the event to the topmost control through
 *     `CMauiControl::PostEvent`, with special paths for active dragger
 *     interception, wheel rotation, button release, and button press /
 *     double-click (the latter also runs `/lua/ui/uimain.lua:OnMouseButtonPress`
 *     and notifies the previous keyboard-focus owner via
 *     `LosingKeyboardFocus`).
 */
void moho::CMauiWxEventMapper::OnMouseMove(
  wxMouseEvent& mouseEvent
)
{
  // Script reached from this event may destroy controls it is still walking;
  // see MauiEventDispatchGuard.
  const MauiEventDispatchGuard dispatchGuard;

  // ---- Step 1: Build typed Maui event payload from wx mouse event ----
  moho::SMauiEventData eventPayload = BuildMauiEventPayloadFromWxMouse(mouseEvent, mWindow);

  // ---- Step 2: Resolve topmost-control under the cursor ----
  // The control under the cursor, held weakly: script reached from the
  // PostEvent calls below may destroy it, and then this link reads null. The
  // binary keeps it on the stack too; its destructor is the 0x0079DB60 unlink
  // on every way out of this function.
  moho::WeakPtr<moho::CMauiControl> hitControl;

  moho::CMauiControl* hitRoot = ResolveTopInputCaptureControl();
  if (hitRoot == nullptr) {
    hitRoot = mFrame;
  }
  moho::CMauiControl* topmostControl = hitRoot != nullptr
    ? moho::CMauiControl::GetTopmostControl(hitRoot, eventPayload.mMousePos.x, eventPayload.mMousePos.y)
    : nullptr;
  hitControl.ResetFromObject(topmostControl);

  // When the initial hit-root yielded no topmost control, retry against the
  // mapper's owning frame so clicks on empty area inside the frame still
  // resolve a default target. If both attempts fail, there is no control to
  // route the event to.
  if (hitControl.GetObjectPtr() == nullptr) {
    moho::CMauiControl* const captureControl = ResolveTopInputCaptureControl();
    moho::CMauiControl* const fallbackRoot = captureControl != nullptr ? captureControl : mFrame;
    if (fallbackRoot == nullptr) {
      return;
    }
    hitControl.ResetFromObject(fallbackRoot);
  }

  moho::CMauiControl* const trackedControl = hitControl.GetObjectPtr();

  // ---- Step 3: Emit MouseEnter/MouseExit if the hovered control changed ----
  //
  // Every PostEvent below runs the control's Lua HandleEvent, and script is
  // free to destroy the control tree from inside it - the splash screen does
  // exactly that, calling parent:Destroy() the moment a click is seen. So the
  // tracking sentinel, not the raw pointer, is the live handle: it is an
  // intrusive link the control's destructor unlinks, and it has to be
  // re-resolved after anything that can re-enter script.
  moho::CMauiControl* const previousOver = gMouseOverControl.GetObjectPtr();
  if (trackedControl != previousOver) {
    if (previousOver != nullptr) {
      eventPayload.mEventType = moho::MET_MouseExit;
      eventPayload.mSource = previousOver;
      previousOver->PostEvent(eventPayload);
    }
    if (
      moho::CMauiControl* const enteredControl = hitControl.GetObjectPtr(); enteredControl != nullptr
    ) {
      eventPayload.mEventType = moho::MET_MouseEnter;
      eventPayload.mSource = enteredControl;
      enteredControl->PostEvent(eventPayload);
    }
    gMouseOverControl.ResetFromObject(hitControl.GetObjectPtr());
  }

  // ---- Step 4: Dispatch the wx mouse event into typed Maui paths ----
  const bool isPress = mouseEvent.ButtonDown();
  const bool isDoubleClick = mouseEvent.ButtonDClick();


  if (!isPress && !isDoubleClick) {
    // ---- Non-press paths: release / motion / wheel / skip ----
    if (mouseEvent.ButtonUp()) {
      eventPayload.mEventType = moho::MET_ButtonRelease;
      const std::int32_t buttonSelector = mouseEvent.GetButton();
      eventPayload.mKeyCode = static_cast<moho::EMauiKeyCode>(buttonSelector);
      eventPayload.mSource = trackedControl;

      moho::IMauiDragger* const activeDragger = func_GetCurrentDraggerFromMouseMoveLane();
      if (activeDragger != nullptr && buttonSelector == sCurrentDraggerKeycode) {
        activeDragger->DragRelease(&eventPayload);
        func_PostDragger(nullptr, nullptr, &eventPayload);
      } else if (trackedControl != nullptr) {
        trackedControl->PostEvent(eventPayload);
      }
      return;
    }

    if (mouseEvent.GetEventType() == wxEVT_MOTION) {
      eventPayload.mEventType = moho::MET_MouseMotion;
      eventPayload.mSource = trackedControl;

      moho::IMauiDragger* const activeDragger = func_GetCurrentDraggerFromMouseMoveLane();
      if (activeDragger != nullptr) {
        activeDragger->DragMove(&eventPayload);
        return;
      }
      if (sMouseIsCaptured != 0) {
        ::ReleaseCapture();
        sMouseIsCaptured = 0;
      }
      if (trackedControl != nullptr) {
        trackedControl->PostEvent(eventPayload);
      }
      return;
    }

    if (mouseEvent.m_wheelRotation != 0) {
      if (trackedControl == nullptr) {
        return;
      }
      eventPayload.mEventType = moho::MET_WheelRotation;
      eventPayload.mWheelRotation = mouseEvent.m_wheelRotation;
      eventPayload.mWheelData = mouseEvent.m_wheelDelta;
      eventPayload.mSource = trackedControl;
      trackedControl->PostEvent(eventPayload);
      return;
    }

    // No release / motion / wheel rotation: mark wx event as skipped so the
    // framework continues propagation up the wx event chain.
    mouseEvent.Skip();
    return;
  }

  // ---- Press / double-click path ----

  // Notify the currently focused control that focus is being taken away when
  // the user clicked on a different control.
  if (
    moho::CMauiControl* const focused = moho::Maui_CurrentFocusControl.GetObjectPtr();
    focused != nullptr && focused != trackedControl
  ) {
    focused->LosingKeyboardFocus();
  }

  // Run the global `/lua/ui/uimain.lua:OnMouseButtonPress` callback so script
  // code observes the press before the typed event reaches the topmost control.
  LuaPlus::LuaState* const luaState = moho::g_UIManager != nullptr ? moho::g_UIManager->mLuaState : nullptr;
  RunGlobalOnMouseButtonPressLuaCallback(luaState, isPress, mouseEvent.m_x, mouseEvent.m_y);

  // Both the focus notification above and the Lua callback just run can tear
  // down the control this press was aimed at, so ask the weak link for it again
  // rather than trusting the pointer resolved before either ran. Skipping the
  // last splash movie is the case that finds this: the click reaches script,
  // script destroys the splash screen group, and the stale pointer then walks
  // into a freed object.
  if (moho::CMauiControl* const pressTarget = hitControl.GetObjectPtr(); pressTarget != nullptr) {
    eventPayload.mEventType = isPress ? moho::MET_ButtonPress : moho::MET_ButtonDClick;
    eventPayload.mKeyCode = static_cast<moho::EMauiKeyCode>(mouseEvent.GetButton());
    eventPayload.mSource = pressTarget;
    pressTarget->PostEvent(eventPayload);
  }
}
namespace
{

  /**
   * Shared body of the three `CMauiWxEventMapper` keyboard event-table sinks
   * (FUN_007A4EF0 / FUN_007A4FD0 / FUN_007A50B0). The retail bodies are
   * byte-identical apart from the `EMauiEventType` constant they stamp into
   * the payload, so the mechanics live here and each sink supplies its type.
   *
   * Keyboard events carry no cursor position, so the payload's mouse lane is
   * stamped with the binary's `-1.0f` sentinel (`flt_E4F6E8`) and the wheel
   * lanes are zeroed. Delivery order is keyboard focus first; when no focus
   * control exists the top input-capture control receives the event instead.
   * `wxEvent::m_skipped` is set whenever nothing consumed the event, letting
   * wx continue its own propagation.
   */
  void DispatchMauiKeyEventToFocusOrCapture(
    wxKeyEvent& keyEvent,
    const moho::EMauiEventType eventType
  )
  {
    moho::SMauiEventData eventPayload{};
    eventPayload.mEventType = eventType;
    eventPayload.mMousePos.x = -1.0f;
    eventPayload.mMousePos.y = -1.0f;
    eventPayload.mWheelRotation = 0;
    eventPayload.mWheelData = 0;
    eventPayload.mKeyCode = keyEvent.m_keyCode;
    eventPayload.mRawKeyCode = keyEvent.m_rawCode;

    std::uint32_t modifierBits = 0u;
    if (keyEvent.m_shiftDown) {
      modifierBits |= moho::MEM_Shift;
    }
    if (keyEvent.m_controlDown) {
      modifierBits |= moho::MEM_Ctrl;
    }
    if (keyEvent.m_altDown) {
      modifierBits |= moho::MEM_Alt;
    }
    eventPayload.mModifiers = static_cast<moho::EMauiEventModifier>(modifierBits);
    eventPayload.mSource = nullptr;

    if (
      moho::CMauiControl* const focused = moho::Maui_CurrentFocusControl.GetObjectPtr(); focused != nullptr
    ) {
      eventPayload.mSource = focused;
      if (focused->HandleEvent(eventPayload)) {
        return;
      }

      keyEvent.Skip();
      return;
    }

    moho::CMauiControl* const captureControl = ResolveTopInputCaptureControl();
    if (captureControl == nullptr) {
      keyEvent.Skip();
      return;
    }

    eventPayload.mSource = captureControl;
    (void)captureControl->HandleEvent(eventPayload);
  }
}


/**
 * Address: 0x007A4FD0 (FUN_007A4FD0)
 *
 * What it does:
 * `wxEventTableEntry` key-release sink at `0x00F5A488`: delivers one
 * `MET_KeyUp` event to the keyboard-focus control, falling back to the top
 * input-capture control.
 */
void moho::CMauiWxEventMapper::OnKeyUp(
  wxKeyEvent& keyEvent
)
{
  const MauiEventDispatchGuard dispatchGuard;
  DispatchMauiKeyEventToFocusOrCapture(keyEvent, moho::MET_KeyUp);
}

/**
 * Address: 0x007A4EF0 (FUN_007A4EF0)
 *
 * What it does:
 * `wxEventTableEntry` key-press sink at `0x00F5A488`: delivers one
 * `MET_KeyDown` event to the keyboard-focus control, falling back to the top
 * input-capture control.
 */
void moho::CMauiWxEventMapper::OnKeyDown(
  wxKeyEvent& keyEvent
)
{
  const MauiEventDispatchGuard dispatchGuard;
  DispatchMauiKeyEventToFocusOrCapture(keyEvent, moho::MET_KeyDown);
}


/**
 * Address: 0x007A50B0 (FUN_007A50B0)
 *
 * What it does:
 * `wxEventTableEntry` translated-character sink at `0x00F5A488`: delivers one
 * `MET_Char` event to the keyboard-focus control, falling back to the top
 * input-capture control.
 */
void moho::CMauiWxEventMapper::OnChar(
  wxKeyEvent& keyEvent
)
{
  const MauiEventDispatchGuard dispatchGuard;
  DispatchMauiKeyEventToFocusOrCapture(keyEvent, moho::MET_Char);
}
