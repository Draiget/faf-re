---
name: project-ui-input-never-dispatched
description: The UI drew but was completely inert — pushed wx event handlers were never dispatched to, EMauiEventType was never registered, and every Ctrl keybinding was dropped. Fixed f0a96d0.
metadata:
  type: project
---

# The UI was inert: no click, hover or key reached a control — FIXED (f0a96d0)

Operator report: "profile manager displays stuff but it's not clickable at all."
Three defects, each hiding the next.

## 1. Pushed event handlers were never dispatched to

`CMauiFrame`'s ctor builds a `CMauiWxEventMapper`; `CUIManager::Init` pushes it
onto the head's input window with `WX_PushEventHandler`. But that function only
appended to `gWindowEventHandlerChains`, **a side table nothing ever read**.

The tell: the four sinks (`OnMouseMove`, `OnKeyUp`, `OnKeyDown`, `OnChar`) were
referenced *only* from `kCMauiWxEventMapperEventTableBindings`, a struct of
member-function pointers whose address is "published" so the linker keeps them.
**An address-taken-only publish struct is a smell that the real dispatch is
missing** — grep for a call site before assuming a handler runs.

`OnMouseMove` is the single mouse sink for the whole family and was already
fully recovered (hit test, enter/exit, drag, wheel, press/release). Nothing was
missing but the wiring.

Fix: `wxWindowBase::ProcessEvent` now offers the event to handlers pushed in
front of the window **before** its own tables (what `PushEventHandler` means).
The chain walk lives in the UI layer and is installed into the wx layer through
`WX_SetPushedEventHandlerDispatch`, so the wx layer still knows nothing about
MAUI.

**Event types are runtime-assigned in this build** — `wxNewEventType`
post-increments from 10000 in static-init order — so a handler in another TU
cannot compare against `wxEVT_*` names. `WX_ClassifyEventType` (WxRuntimeTypes)
maps a type to a `WxEventFamily` using the same `gWxEvt*` globals the window's
own tables use; the mapper switches on that. This stands in for the
compiler-emitted event table at binary `0x00F5A488`.

Also: the mapper's `mWindowRuntime` was left null. Only wheel events use it
(screen→client conversion), so clicks would have worked and only the wheel
would have been silently misplaced.

## 2. EMauiEventType was never registered

`EMauiEventTypeTypeInfo` existed, and its ctor calls `PreRegisterRType`, but
**nothing ever constructed an instance**. Invisible while no event could reach a
control; the moment dispatch worked, the first click aborted in
`CreateLuaEventObject` with *"Attempting to lookup the RType for enum
moho::EMauiEventType before it is registered."*

Pattern to copy (98 other descriptors use it): aligned storage + a
`construct_X`/`register_X` pair + a `XBootstrap` static + `GPG_PREREGISTER_INIT`
for phase-1 ordering. See `moho/ai/EAiResultTypeInfo.cpp` for the reference
shape. **A TypeInfo class with no static instance is dead** — check for the
bootstrap, not just the class.

## 3. Every Ctrl keybinding was dropped

`IN_ParseKeyModifiers` compared modifiers against `"ALT"` / `"CONTROL"` /
`"SHIFT"`. The shipped keymaps spell them `Alt-`, `Ctrl-`, `Shift-`
(`lua/keymap/defaultKeyMap.lua`: Ctrl 418, Shift 340, Alt 179). The compare is
`_stricmp`, so ALT and SHIFT matched regardless — but `"CONTROL"` never matched
`Ctrl`, so all 418 bindings logged *"Key map contains unrecognized modifier
string: Ctrl"* and **lost their modifier bit, staying bound to the bare key**.
The binary's three reference strings (0x10C1D08 / 0x10C1D24 / 0x10C1D40) are
runtime-initialised and their initialiser is not in the recovered evidence set,
so the game data is the evidence. Now `"CTRL"`; warnings 90 → 0.

## Verifying input without a human at the keyboard

PostMessage to the *top-level* window does nothing — the mapper is pushed on the
**input** window, which is a different HWND. Use real synthetic input so Windows
routes it: `SetForegroundWindow`, `SetCursorPos`, then `mouse_event(0x0002/
0x0004)`. A temporary `gpg::Logf` in the mapper's dispatch and in
`CMauiControl::HandleEvent` proves the whole chain:

    INPUTPROBE mapper got mouse event type=10014
    INPUTPROBE control HandleEvent type=2 at (181,765) name='Effect Helper ScreenGroup'

Related: [[project-texture-loading-never-worked]] (same session; the layout
collapse that made this dialog look broken), [[project-userdata-ref-and-ui-typeinfos]]
(the earlier 12-missing-TypeInfo instance of defect 2).
