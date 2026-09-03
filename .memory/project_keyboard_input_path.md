---
name: project-keyboard-input-path
description: FIXED (e94e39e, 4e42aec) - four defects between a keystroke and a character in a MAUI edit box, including wxWindow::SetFocus being an empty stub so the render child never held the Win32 focus.
metadata:
  type: project
---

# FIXED: nothing could be typed into the UI

Four independent defects, all on the path from a key press to a character.

## 1. wxKeyEvent members in the wrong order

The MAUI mapper reads the event through a layout view at the binary's
displacements. `wxWindow::CreateKeyEvent` (FUN_0096CCC0) pins them:

    m_x   [esi+0x20]   m_y          [esi+0x24]   m_keyCode  [esi+0x28]
    m_controlDown [esi+0x2C]   m_shiftDown [esi+0x2D]   m_altDown [esi+0x2E]
    m_rawCode     [esi+0x34]   m_rawFlags  [esi+0x38]

Ours declared the modifier bytes first, so `mKeyCode` read `m_x` and every
keystroke arrived carrying the **cursor's X coordinate** - the same value for
every key (the tell was `key=6012` for Z, o, r and g alike). Offset asserts are
in place now.

## 2. MAUI_SetKeyboardFocus called the wrong slot

The binary calls **vtable+0x44**. `CMauiControl`'s vtable has
`LosingKeyboardFocus` at +0x40 and `OnKeyboardFocusChange` at +0x44 - we were
calling the first. It runs unconditionally on the previous owner, including
when that is the control now being focused, which is the normal case: clicking
an edit focuses it once from script and again from
`CMauiEdit::HandleClickEvent`. `CMauiEdit` overrides `LosingKeyboardFocus` to
abandon focus, so the second acquire cleared the focus it had just set.

(The press path in `func_OnMouseMove` calls vtable+0x40 and really is
`LosingKeyboardFocus` - only `MAUI_SetKeyboardFocus` was wrong.)

## 3. CMauiEdit::ClearSelection is not a clear

FUN_007907B0 `retn 8`s and reads a 16-bit value out of its **second argument
slot** (`mov ax, [esp+28h+a3]`) into the wide buffer it converts and hands to
`ReplaceSelection`; its one call site in `HandleKeyEvent` pushes
`word ptr [edi+0x14]`, the low half of `SMauiEventData::mKeyCode`. It types a
character. IDA's name and its decompile (which drops the argument entirely) are
both wrong. Recovered without the argument it inserted an empty string, so each
keypress deleted the selection and typed nothing. Renamed `InsertChar`.

## 4. wxWindow::SetFocus was an empty stub

This is why real keyboards did nothing while posted `WM_CHAR` worked. Key
messages go to the focused HWND; the focus stayed on the top-level frame
because nothing ever called Win32 `SetFocus`, and the MAUI event mapper is
bound to the render **child**. Recovered from FUN_00967650.

**Test-harness trap:** posting to every window of the process delivers one
lParam in several client-coordinate frames, so one physical click lands on
several different controls. Post to the render child only (smallest visible
window). And posting bypasses focus entirely - to check focus routing use
`GetGUIThreadInfo` on the engine's UI thread and force the window foreground
first with `AttachThreadInput` + `SetForegroundWindow`, or `::SetFocus` fails
and clears the thread's focus instead.

**DPI:** this box is at 150%, so engine client coords are physical/1.5. A
posted lParam must be `engine_coord * 1.5`, and screenshot scripts must call
`SetProcessDPIAware()` first.

Related: [[project-button-onclick-solved]], [[project-maui-render-slot-not-override]].
